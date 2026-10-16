import copy
import contextlib
import gzip
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import stcvrc_observer as o


class ObserverTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.logs = self.base/'logs'; self.logs.mkdir()
        self.root = o.init_store(self.base/'data')
        gateway=patch.object(o,'physical_gateway',return_value={'status':'unavailable'})
        gateway.start();self.addCleanup(gateway.stop)
        curl=patch.object(o,'curl_capability',return_value=True)
        curl.start();self.addCleanup(curl.stop)
        binaries=patch.object(o,'binary_view',return_value={})
        binaries.start();self.addCleanup(binaries.stop)
        scheduler=patch.object(o,'scheduler_events',return_value={'status':'unavailable','events':[]})
        scheduler.start();self.addCleanup(scheduler.stop)

    def write_log(self, name, text):
        path = self.logs/name
        path.write_text(text, encoding='utf-8')
        return path

    def test_init_refuses_existing_unowned_data(self):
        path = self.base/'unowned'; path.mkdir(); (path/'keep').touch()
        with self.assertRaises(ValueError): o.init_store(path)

    def test_wrong_marker(self):
        (self.root/'.stcvrc-observer').write_text('wrong')
        with self.assertRaises(ValueError): o.init_store(self.root)

    def test_hardlinked_source_is_rejected(self):
        source=self.write_log('source.log','private')
        alias=self.logs/'alias.log'
        os.link(source,alias)
        with self.assertRaises(ValueError):o.shared_open(alias)

    def test_single_writer(self):
        with o.single_writer(self.root):
            with self.assertRaises(OSError):
                with o.single_writer(self.root): pass

    def test_profile_is_scoped_and_idempotent(self):
        original = {'proxies':[{'name':x,'type':'vless'} for x in o.LEAVES], 'rules':['MATCH,DIRECT'], 'dns':{'enable':True}}
        before = copy.deepcopy(original)
        result = o.observer_profile(original)
        self.assertEqual(original,before)
        self.assertEqual(result, o.observer_profile(result))
        self.assertEqual(result['rules'],before['rules'])
        self.assertEqual(result['dns'],before['dns'])
        self.assertTrue(all(x['listen']=='127.0.0.1' for x in result['listeners']))

    def test_listener_collision(self):
        original = {'proxies':[{'name':x,'type':'vless'} for x in o.LEAVES],
                    'listeners':[{'name':'other','port':18981}]}
        with self.assertRaises(ValueError): o.observer_profile(original)

    def test_classification_discards_private_data(self):
        line='[2026-09-22 01:02:03.123] LT-ROUTE tcp 192.0.2.13:445 i/o timeout SECRET https://private.invalid/path'
        result=o.classify_line(line)
        encoded=json.dumps(result)
        for value in ('192.0.2','SECRET','private.invalid'): self.assertNotIn(value,encoded)
        self.assertEqual(result['class'],'connection-timeout')
        self.assertFalse(result['sourceTimeHasOffset'])

    def test_endpoint_attribution_never_records_endpoint(self):
        result=o.classify_line('[OpenVPN] private-endpoint:123 ping-restart', {'LT-OPENVPN':'private-endpoint'})
        self.assertEqual(result['route'],'LT-OPENVPN')
        self.assertNotIn('private-endpoint',json.dumps(result))

    def test_no_event_for_ordinary_user_traffic(self):
        self.assertIsNone(o.classify_line('TCP user.example:443 matched Rule use GC'))

    def test_zero_decrypt_counter_is_not_decrypt_failure(self):
        result=o.classify_line('LT-OPENVPN stats data-decrypt-errors=0')
        self.assertEqual(result['class'],'vpn-statistics')
        self.assertEqual(result['dataDecryptErrors'],0)

    def test_reconnect_is_not_hidden_by_decrypt_counter(self):
        for count in (0, 3):
            with self.subTest(count=count):
                line=('2026-09-22 20:45:41 LT-OPENVPN control loop requested '
                      f'reconnect: ping-restart data-decrypt-errors={count}')
                result=o.classify_line(line)
                self.assertEqual(result['class'],'vpn-reconnect')
                self.assertEqual(result['dataDecryptErrors'],count)

    def test_auth_failure_is_not_hidden_by_decrypt_counter(self):
        result=o.classify_line('ELITECH-OPENVPN AUTH_FAILED data-decrypt-errors=0')
        self.assertEqual(result['class'],'vpn-auth')
        self.assertEqual(result['dataDecryptErrors'],0)

    def test_real_decrypt_error_is_retained_beside_counter(self):
        result=o.classify_line('LT-OPENVPN decrypt error data-decrypt-errors=1')
        self.assertEqual(result['class'],'vpn-decrypt')

    def test_new_core_link_errors_are_not_claimed_as_reconnects(self):
        for message in ('OpenVPN link closed while reading packet',
                        'error reading packet from OpenVPN link',
                        'error writing packet to OpenVPN link', 'error writing ping packet'):
            result=o.classify_line('[OpenVPN](LT-OPENVPN) '+message+': private detail')
            self.assertEqual(result['class'],'vpn-link-error')
            self.assertEqual(result['route'],'LT-OPENVPN')
            self.assertNotIn('private detail',json.dumps(result))

    def test_new_core_link_error_keeps_specific_auth_and_keepalive_cause(self):
        prefix='[OpenVPN](ELITECH-OPENVPN) OpenVPN link closed while reading packet: '
        for cause,kind in (('AUTH_FAILED','vpn-auth'),('ping-restart timeout','vpn-reconnect')):
            self.assertEqual(o.classify_line(prefix+cause)['class'],kind)

    def test_nonzero_cumulative_counter_is_still_statistics(self):
        result=o.classify_line('LT-OPENVPN stats data-decrypt-errors=3')
        self.assertEqual(result['class'],'vpn-statistics')
        self.assertEqual(result['dataDecryptErrors'],3)

    def test_reconnect_scan_counts_once_and_preserves_counter(self):
        self.write_log('one.log','LT-OPENVPN ping-restart data-decrypt-errors=0\n')
        state={}
        result=o.scan_logs(self.logs,state)
        self.assertEqual(result['counts'],{'vpn-reconnect:LT-OPENVPN':1})
        self.assertEqual(result['events'][0]['dataDecryptErrors'],0)
        self.assertEqual(o.scan_logs(self.logs,state)['counts'],{})

    def test_service_owner_layout_is_explicit_and_sid_derived(self):
        app=self.base/'app';sid='S-1-5-21-1-2-3-1001'
        layout=o.runtime_layout(app,sid)
        self.assertEqual(layout['kind'],'service-owner')
        self.assertEqual(layout['config'],o.SERVICE_ROOT/'users'/o.digest(sid.encode())/'runtime/config.yaml')
        self.assertEqual(layout['binaries']['core'],o.SERVICE_ROOT/'cores/verge-mihomo.exe')
        self.assertEqual(len(layout['logs']),3)
        self.assertEqual(layout['logs'][-1],o.SERVICE_ROOT/'logs')
        self.assertEqual(o.runtime_layout(app)['config'],app/'clash-verge.yaml')
        for invalid in ('..','S-1-5-18','S-1-5-21-1-2-3-1001/other'):
            with self.assertRaises(ValueError):o.runtime_layout(app,invalid)

    def test_three_log_roots_share_budget_and_keep_all_cursors(self):
        other=self.base/'core-logs';other.mkdir()
        service=self.base/'service-logs';service.mkdir()
        self.write_log('ui.log','LT-OPENVPN ping-restart\n')
        (other/'core.log').write_text('ELITECH-OPENVPN AUTH_FAILED\n')
        (service/'service.log').write_text('panic\n')
        roots=[self.logs,other,service];state={}
        first=o.scan_logs(roots,state)
        self.assertEqual(sum(first['counts'].values()),3)
        second=o.scan_logs(roots,state)
        self.assertEqual(second['counts'],{})
        self.assertEqual(second['missingSources'],0)
        self.assertEqual(len(state['logCursors']),3)
        bounded=o.scan_logs(roots,{},max_bytes=20)
        self.assertLessEqual(bounded['readBytes'],20)

    def test_three_log_roots_archive_old_files_with_one_limit(self):
        other=self.base/'core-logs';other.mkdir()
        service=self.base/'service-logs';service.mkdir()
        for root in (self.logs,other,service):
            (root/'old.log').write_text('old');os.utime(root/'old.log',(100,100))
            (root/'new.log').write_text('new')
        result=o.archive_logs([self.logs,other,service],self.root,{},time.time(),limit=3)
        self.assertEqual(result['newFiles'],1)
        self.assertEqual(result['deferred'],2)

    def test_missing_owner_config_does_not_fall_back_to_appdata(self):
        app=self.base/'app';app.mkdir()
        (app/'clash-verge.yaml').write_text('external-controller: 127.0.0.1:19097\n')
        with patch.object(o,'SERVICE_ROOT',self.base/'service'),patch.object(o,'api_get') as api,patch.object(o,'windows_events',return_value={'status':'ok','events':[]}):
            result=o.observe(app,self.root,'lab',service_owner_sid='S-1-5-21-1-2-3-1001')
        api.assert_not_called()
        self.assertNotEqual(result['components']['controller'],'ok')
        self.assertEqual(result['runtimeLayout'],'service-owner')

    def test_owner_config_used_without_disclosing_paths_or_secret(self):
        app=self.base/'app';app.mkdir();sid='S-1-5-21-1-2-3-1001'
        with patch.object(o,'SERVICE_ROOT',self.base/'service'):
            config=o.runtime_layout(app,sid)['config'];config.parent.mkdir(parents=True)
            config.write_text('external-controller: 127.0.0.1:19097\nsecret: PRIVATE_TOKEN\n')
            with patch.object(o,'api_get',return_value={}) as api,patch.object(o,'windows_events',return_value={'status':'ok','events':[]}):
                result=o.observe(app,self.root,'lab',service_owner_sid=sid)
        self.assertEqual(api.call_args.args[:2],(19097,'PRIVATE_TOKEN'))
        self.assertEqual(result['components']['controller'],'ok')
        self.assertNotIn('PRIVATE_TOKEN',json.dumps(result))
        self.assertNotIn(sid,json.dumps(result))

    def test_incremental_log_no_duplicates(self):
        path=self.write_log('one.log','LT-ROUTE i/o timeout\n')
        state={}
        self.assertEqual(sum(o.scan_logs(self.logs,state)['counts'].values()),1)
        self.assertEqual(o.scan_logs(self.logs,state)['counts'],{})
        with path.open('a') as f: f.write('ELITECH-ROUTE connection refused\n')
        result=o.scan_logs(self.logs,state)
        self.assertEqual(result['counts'],{'connection-refused:ELITECH-ROUTE':1})

    def test_partial_line_is_not_consumed(self):
        path=self.write_log('one.log','LT-ROUTE i/o ')
        state={}
        self.assertEqual(o.scan_logs(self.logs,state)['counts'],{})
        with path.open('a') as f: f.write('timeout\n')
        self.assertEqual(sum(o.scan_logs(self.logs,state)['counts'].values()),1)

    def test_rotation_identity_and_truncation(self):
        path=self.write_log('one.log','LT-ROUTE i/o timeout\n')
        state={}; o.scan_logs(self.logs,state)
        path.rename(self.logs/'old.log')
        self.write_log('one.log','GC i/o timeout\n')
        self.assertEqual(sum(o.scan_logs(self.logs,state)['counts'].values()),1)
        (self.logs/'old.log').write_text('ping-restart\n')
        result=o.scan_logs(self.logs,state)
        self.assertEqual(result['resets'],1)
        self.assertEqual(sum(result['counts'].values()),1)

    def test_scan_cap_and_missing_source(self):
        path=self.write_log('one.log','i/o timeout\n'*100)
        state={}; result=o.scan_logs(self.logs,state,max_bytes=100)
        self.assertEqual(result['readBytes'],100)
        self.assertGreater(result['backlogBytes'],0)
        path.unlink()
        self.assertEqual(o.scan_logs(self.logs,state)['missingSources'],1)

    def test_fresh_specific_health_not_general_alive(self):
        now=time.time(); url='https://private.invalid/'
        proxies={'VPS-LATENCY':{'testUrl':url,'now':'GC','type':'URLTest'},
                 '4VPS':{'alive':True,'extra':{url:{'alive':False,'history':[{'time':o.utc(now-1),'delay':0}]}}}}
        state={}
        first=o.native_view(proxies,state,now,'epoch')['leaves']['4VPS']
        self.assertTrue(first['fresh']);self.assertTrue(first['generalAlive']);self.assertFalse(first['testAlive'])
        self.assertTrue(first['newSample'])
        self.assertFalse(o.native_view(proxies,state,now,'epoch')['leaves']['4VPS']['newSample'])
        self.assertTrue(o.native_view(proxies,state,now,'new-epoch')['leaves']['4VPS']['newSample'])
        self.assertNotIn('private.invalid',json.dumps(first))

    def test_stale_missing_and_clock_future(self):
        now=time.time()
        for stamp in (None,o.utc(now-600),o.utc(now+20)):
            value={'VPS-LATENCY':{'testUrl':'x'},'GC':{'extra':{'x':{'history':[{'time':stamp,'delay':1}]}}}}
            self.assertFalse(o.native_view(value,{},now,'x')['leaves']['GC']['fresh'])

    def test_only_known_names_persist(self):
        value={'FOREIGN-EGRESS':{'now':'private-name','fixed':'token','type':'weird'}}
        self.assertNotIn('private-name',json.dumps(o.native_view(value,{},time.time(),'x')))

    def test_api_write_endpoint_rejected(self):
        with self.assertRaises(ValueError): o.api_get(1,'secret','/configs')

    def test_failed_archive_is_not_published_as_complete(self):
        old=self.write_log('old.log','x'*100000);os.utime(old,(100,100))
        self.write_log('new.log','new')
        @contextlib.contextmanager
        def failing_source(*args,**kwargs):
            class Reader:
                def read(self,size):raise OSError('fixture disk error')
            yield Reader()
        state={}
        with patch.object(o,'shared_open',side_effect=failing_source):
            result=o.archive_logs(self.logs,self.root,state,time.time())
        self.assertEqual(result['errors'],1)
        self.assertEqual(result['newFiles'],0)
        self.assertEqual(list((self.root/'archive').iterdir()),[])
        self.assertEqual(state['archives'],{})

    def test_stale_partial_archive_is_rebuilt_not_published(self):
        old=self.write_log('old.log','complete-source');os.utime(old,(100,100))
        self.write_log('new.log','new')
        partial=self.root/'archive'/('a'*64+'.gz.partial');partial.write_bytes(b'partial')
        state={};result=o.archive_logs(self.logs,self.root,state,time.time())
        self.assertEqual(result['newFiles'],1)
        self.assertFalse(partial.exists())
        files=list((self.root/'archive').glob('*.gz'))
        self.assertEqual(len(files),1)
        self.assertEqual(gzip.decompress(files[0].read_bytes()),b'complete-source')

    def test_closed_logs_archived_once(self):
        old=self.write_log('old.log','old\n'); os.utime(old,(100,100))
        self.write_log('active.log','active\n')
        state={}
        self.assertEqual(o.archive_logs(self.logs,self.root,state,time.time())['newFiles'],1)
        self.assertEqual(o.archive_logs(self.logs,self.root,state,time.time())['newFiles'],0)
        self.assertEqual(len(list((self.root/'archive').glob('*.gz'))),1)

    def test_archive_copy_budget(self):
        old=self.write_log('old.log','a'*100);os.utime(old,(100,100))
        self.write_log('active.log','active')
        result=o.archive_logs(self.logs,self.root,{},time.time(),limit=20)
        self.assertEqual(result['newFiles'],0);self.assertEqual(result['deferred'],1)

    def test_archive_index_forgets_removed_source_and_expired_archive(self):
        now=time.time()
        old=self.write_log('old.log','old\n');os.utime(old,(100,100))
        self.write_log('active.log','active\n')
        state={}
        o.archive_logs(self.logs,self.root,state,now-31*o.DAY)
        self.assertEqual(len(state['archives']),1)
        old.unlink()
        o.retention(self.root,state,now)
        o.archive_logs(self.logs,self.root,state,now)
        self.assertEqual(state['archives'],{})

    def test_archive_index_keeps_existing_source_after_archive_expiry(self):
        now=time.time()
        old=self.write_log('old.log','old\n');os.utime(old,(100,100))
        self.write_log('active.log','active\n')
        state={}
        o.archive_logs(self.logs,self.root,state,now-31*o.DAY)
        o.retention(self.root,state,now)
        self.assertEqual(o.archive_logs(self.logs,self.root,state,now)['newFiles'],0)
        self.assertEqual(len(state['archives']),1)
        self.assertEqual(list((self.root/'archive').iterdir()),[])

    def test_archive_index_keeps_retained_archive_without_source(self):
        now=time.time()
        old=self.write_log('old.log','old\n');os.utime(old,(100,100))
        self.write_log('active.log','active\n')
        state={}
        o.archive_logs(self.logs,self.root,state,now)
        old.unlink()
        o.archive_logs(self.logs,self.root,state,now)
        self.assertEqual(len(state['archives']),1)

    def test_retention_only_owned_old_files(self):
        now=time.time(); old=o.utc(now-31*o.DAY)[:10]
        path=self.root/'timeline'/(old+'.jsonl');path.write_text('{}\n')
        recent=self.root/'timeline'/(o.utc(now)[:10]+'.jsonl');recent.write_text('{}\n')
        result=o.retention(self.root,{},now)
        self.assertEqual(result['timelineFiles'],1);self.assertTrue(recent.exists())
        self.assertTrue(self.logs.exists())

    def test_retention_budget_explicit(self):
        now=time.time()
        for age in (1,2):
            (self.root/'timeline'/(o.utc(now-age*o.DAY)[:10]+'.jsonl')).write_text('x'*10)
        result=o.retention(self.root,{},now,timeline_limit=10)
        self.assertEqual(result['timelineFiles'],1);self.assertTrue(result['budgetLimited'])

    def test_retention_refuses_unexpected_file(self):
        (self.root/'archive'/'keep.txt').write_text('x')
        with self.assertRaises(ValueError):o.retention(self.root,{},time.time())

    def test_partial_record_repaired(self):
        now=o.utc(); path=self.root/'timeline'/(now[:10]+'.jsonl')
        path.write_text('{"ok":1}\n{"incomplete":')
        o.append_record(self.root,{'observedUtc':now})
        rows=[json.loads(line) for line in path.read_text().splitlines()]
        self.assertEqual(len(rows),2);self.assertTrue(rows[1]['repairedPartialRecord'])

    def test_recover_commit_before_append(self):
        record={'observedUtc':o.utc(),'sampleId':'first','schemaVersion':1}
        pending={'schemaVersion':1,'record':record,'state':{'schemaVersion':1,'sequence':1}}
        o.atomic_json(self.root/'pending.json',pending)
        self.assertTrue(o.recover_pending(self.root))
        self.assertEqual(json.loads((self.root/'state.json').read_text())['sequence'],1)
        self.assertFalse((self.root/'pending.json').exists())

    def test_recover_commit_after_append_does_not_duplicate(self):
        record={'observedUtc':o.utc(),'sampleId':'first','schemaVersion':1}
        o.append_record(self.root,record)
        o.atomic_json(self.root/'pending.json',{'schemaVersion':1,'record':record,'state':{'sequence':1}})
        o.recover_pending(self.root)
        path=self.root/'timeline'/(record['observedUtc'][:10]+'.jsonl')
        self.assertEqual(len(path.read_text().splitlines()),1)

    def test_invalid_pending_does_not_discard_evidence(self):
        (self.root/'pending.json').write_text('{')
        with self.assertRaises(ValueError):o.recover_pending(self.root)
        self.assertTrue((self.root/'pending.json').exists())

    def test_controller_absence_is_unknown_no_active_probe(self):
        app=self.base/'app'; app.mkdir();(app/'logs').mkdir()
        with patch.object(o,'windows_events',return_value={'status':'unavailable','events':[]}),patch.object(o,'body_probe') as probe:
            result=o.observe(app,self.root,'lab',True)
        self.assertEqual(result['components']['controller'],'io')
        self.assertEqual(result['applicationMode'],'disabled-or-listeners-missing')
        probe.assert_not_called()

    def test_corrupt_checkpoint_does_not_hide_gap(self):
        (self.root/'state.json').write_text('{')
        app=self.base/'app';app.mkdir();(app/'logs').mkdir()
        with patch.object(o,'windows_events',return_value={'status':'ok','events':[]}):
            result=o.observe(app,self.root,'lab')
        self.assertEqual(result['checkpoint'],'invalid')
        state=json.loads((self.root/'state.json').read_text())
        self.assertGreater(state['trafficSuspendedUntil'],time.time()+86000)

    def test_sleep_requires_paired_bounding_evidence(self):
        now=time.time();previous=now-3600
        power={'status':'ok','events':[
            {'id':42,'provider':'Microsoft-Windows-Kernel-Power','utc':o.utc(previous+30)},
            {'id':1,'provider':'Microsoft-Windows-Power-Troubleshooter','utc':o.utc(now-30)}]}
        self.assertEqual(o.gap_reason(previous,now,power),'confirmed-sleep')
        power['events'].pop()
        self.assertEqual(o.gap_reason(previous,now,power),'unexplained')
        self.assertEqual(o.gap_reason(now+1,now,{}),'clock-backwards')

    def test_completed_body_and_no_body_disclosure(self):
        result=o.subprocess.CompletedProcess([],0,b'ip=192.0.2.13\ntls=TLSv1.3\n\nSTCVRC_STATUS:200',b'')
        with patch.object(o.subprocess,'run',return_value=result):
            value=o.body_probe(18981,o.TARGETS[1])
        self.assertTrue(value['success']);self.assertTrue(value['bodyComplete'])
        self.assertNotIn('192.0.2',json.dumps(value))

    def test_body_error_is_not_http_success(self):
        for code,kind in ((28,'timeout'),(18,'incomplete-body'),(63,'body-limit')):
            result=o.subprocess.CompletedProcess([],code,b'partial\nSTCVRC_STATUS:200',b'private error')
            with patch.object(o.subprocess,'run',return_value=result):
                value=o.body_probe(18981,o.TARGETS[1])
            self.assertFalse(value['success']);self.assertEqual(value['errorClass'],kind)
            self.assertNotIn('private error',json.dumps(value))

    def test_empty_204_success(self):
        result=o.subprocess.CompletedProcess([],0,b'\nSTCVRC_STATUS:204',b'')
        with patch.object(o.subprocess,'run',return_value=result):
            value=o.body_probe(18981,o.TARGETS[0])
        self.assertTrue(value['success'])

    def test_openai_unauthenticated_response_has_a_body_contract(self):
        for body, valid in ((b'{"error":{"message":"Authentication required"}}',True),
                            (b'<html>unauthorized</html>',False),
                            (b'{}',False),(b'{"error":"blocked"}',False)):
            with self.subTest(body=body):
                response=o.subprocess.CompletedProcess([],0,body+b'\nSTCVRC_STATUS:401',b'')
                with patch.object(o.subprocess,'run',return_value=response):
                    value=o.body_probe(18981,o.TARGETS[2])
                self.assertEqual(value['success'],valid)
                self.assertNotIn('Authentication required',json.dumps(value))

    def test_openai_wrong_status_is_not_a_pass(self):
        response=o.subprocess.CompletedProcess([],0,b'blocked\nSTCVRC_STATUS:403',b'')
        with patch.object(o.subprocess,'run',return_value=response):
            value=o.body_probe(18981,o.TARGETS[2])
        self.assertFalse(value['success'])
        self.assertEqual(value['errorClass'],'http-status')

    def test_scheduled_payload_reservations_fit_daily_budget(self):
        daily=len(o.TARGETS)*len(o.LISTENERS)*8193*(o.DAY//300)
        self.assertLessEqual(daily,16*o.MIB)

    def test_body_content_contract_required(self):
        result=o.subprocess.CompletedProcess([],0,b'blockpage\nSTCVRC_STATUS:200',b'')
        with patch.object(o.subprocess,'run',return_value=result):
            value=o.body_probe(18981,o.TARGETS[1])
        self.assertEqual(value['errorClass'],'body-contract')

    def test_unsupported_curl_never_downloads(self):
        with patch.object(o,'curl_capability',return_value=False),patch.object(o.subprocess,'run') as run:
            value=o.body_probe(18981,o.TARGETS[0])
        self.assertEqual(value['errorClass'],'curl-capability');run.assert_not_called()

    def test_freshness_clock_is_taken_after_api_read(self):
        app=self.base/'app';app.mkdir();(app/'logs').mkdir()
        (app/'clash-verge.yaml').write_text('external-controller: 127.0.0.1:19097\n')
        clock=[time.time()]
        def api(port,secret,endpoint):
            if endpoint=='/proxies':
                clock[0]+=2
                return {'proxies':{'VPS-LATENCY':{'testUrl':'x'},'GC':{'extra':{'x':{'history':[{'time':o.utc(clock[0]-0.01),'delay':1}]}}}}}
            return {}
        with patch.object(o.time,'time',side_effect=lambda:clock[0]),patch.object(o,'api_get',side_effect=api),patch.object(o,'windows_events',return_value={'status':'ok','events':[]}):
            result=o.observe(app,self.root,'lab')
        self.assertTrue(result['native']['leaves']['GC']['fresh'])

    def test_boot_time_estimate_drift_does_not_duplicate_native_sample(self):
        app=self.base/'app';app.mkdir()
        (app/'clash-verge.yaml').write_text('external-controller: 127.0.0.1:19097\n')
        now=time.time()
        core={'role':'verge-mihomo.exe','pid':100,'parent':10,'startUtc':o.utc(now-100),'session':0}
        hosts=[{'bootUtc':o.utc(now-200+drift),'processes':[dict(core)]} for drift in (0,0.51,0.7)]
        hosts[2]['processes'][0].update(pid=101,startUtc=o.utc(now))
        proxies={'VPS-LATENCY':{'testUrl':'x'},'GC':{'extra':{'x':{'history':[{'time':o.utc(now-1),'delay':1}]}}}}
        def api(port,secret,endpoint):
            return {'proxies':proxies} if endpoint=='/proxies' else {}
        with patch.object(o,'host_view',side_effect=hosts),patch.object(o,'api_get',side_effect=api),patch.object(o,'windows_events',return_value={'status':'ok','events':[]}):
            records=[o.observe(app,self.root,'lab') for _ in range(3)]
        self.assertTrue(records[0]['native']['leaves']['GC']['newSample'])
        self.assertFalse(records[1]['native']['leaves']['GC']['newSample'])
        self.assertTrue(records[2]['native']['leaves']['GC']['newSample'])
        self.assertEqual(records[0]['coreEpoch'],records[1]['coreEpoch'])
        self.assertNotEqual(records[1]['coreEpoch'],records[2]['coreEpoch'])

    @unittest.skipUnless(os.name=='nt','Windows writer-sharing contract')
    def test_open_writer_is_not_archived(self):
        old=self.write_log('old.log','old');os.utime(old,(100,100))
        self.write_log('new.log','new')
        with old.open('ab'):
            result=o.archive_logs(self.logs,self.root,{},time.time())
        self.assertEqual(result['newFiles'],0)
        self.assertEqual(result['deferred'],1)
        self.assertEqual(list((self.root/'archive').iterdir()),[])

    def test_shutdown_requires_bounding_events(self):
        now=time.time();previous=now-3600
        events=[{'id':13,'provider':'Microsoft-Windows-Kernel-General','utc':o.utc(previous+10)},
                {'id':12,'provider':'Microsoft-Windows-Kernel-General','utc':o.utc(now-10)}]
        self.assertEqual(o.gap_reason(previous,now,{'status':'ok','events':events}),'confirmed-shutdown')
        self.assertEqual(o.gap_reason(previous,now,{'status':'ok','events':events[1:]}),'unexplained')

    def active_fixture(self):
        # This fixture tests scheduling/traffic, not live host enumeration latency.
        host=patch.object(o,'host_view',return_value={'processes':[]})
        host.start();self.addCleanup(host.stop)
        app=self.base/'app';app.mkdir();(app/'logs').mkdir()
        (app/'clash-verge.yaml').write_bytes(o.stmc_yaml.dump({'external-controller':'127.0.0.1:19097',
                                                           'listeners':copy.deepcopy(o.LISTENERS)}))
        api=patch.object(o,'api_get',return_value={});api.start();self.addCleanup(api.stop)
        events=patch.object(o,'windows_events',return_value={'status':'ok','events':[]})
        events.start();self.addCleanup(events.stop)
        return app

    def test_daily_traffic_limit_is_hard(self):
        app=self.active_fixture()
        o.atomic_json(self.root/'traffic.json',{'day':o.utc()[:10],'reserved':16*o.MIB-8193})
        with patch.object(o,'body_probe',return_value={'success':True}) as probe:
            result=o.observe(app,self.root,'lab',True)
        self.assertEqual(probe.call_count,1)
        self.assertEqual(result['traffic']['reservedBodyBytes'],16*o.MIB)
        self.assertEqual(sum(x.get('errorClass')=='budget-or-deadline' for x in result['application']),len(o.TARGETS)*len(o.LISTENERS)-1)

    def test_optional_api_failures_do_not_disable_application_checks(self):
        app=self.active_fixture()
        for endpoint, component in (('/providers/rules','providers'),('/version','version')):
            with self.subTest(endpoint=endpoint):
                def api(port,secret,path):
                    if path==endpoint:
                        raise OSError('private fixture failure')
                    return {}
                with patch.object(o,'api_get',side_effect=api),patch.object(o,'body_probe',return_value={'success':True}) as probe:
                    result=o.observe(app,self.root,'lab',True)
                self.assertEqual(result['components']['controller'],'ok')
                self.assertEqual(result['components'][component],'io')
                self.assertEqual(result['applicationMode'],'forced-leaves')
                self.assertEqual(probe.call_count,len(o.TARGETS)*len(o.LISTENERS))
                self.assertNotIn('private fixture failure',json.dumps(result))
                o.atomic_json(self.root/'traffic.json',{'day':o.utc()[:10],'reserved':0})

    def test_kill_after_reservation_does_not_reset_budget(self):
        app=self.active_fixture()
        with patch.object(o,'body_probe',side_effect=SystemExit):
            with self.assertRaises(SystemExit):o.observe(app,self.root,'lab',True)
        budget=json.loads((self.root/'traffic.json').read_text())
        self.assertEqual(budget['reserved'],8193)
        with patch.object(o,'body_probe') as probe:
            result=o.observe(app,self.root,'lab',True)
        probe.assert_not_called()
        self.assertEqual(result['traffic']['reservedBodyBytes'],8193)

    def test_active_checks_do_not_run_each_minute(self):
        app=self.active_fixture()
        with patch.object(o,'body_probe',return_value={'success':True}) as probe:
            first=o.observe(app,self.root,'lab',True)
            second=o.observe(app,self.root,'lab',True)
        self.assertEqual(probe.call_count,len(o.TARGETS)*len(o.LISTENERS))
        self.assertEqual(second['application'],[])
        self.assertEqual(second['traffic'],first['traffic'])

    def test_application_order_covers_both_leaves_per_target(self):
        app=self.active_fixture()
        with patch.object(o,'body_probe',return_value={'success':True}) as probe:
            result=o.observe(app,self.root,'lab',True)
        expected=[(listener['port'],target) for target in o.TARGETS for listener in o.LISTENERS]
        self.assertEqual([call.args for call in probe.call_args_list],expected)
        self.assertEqual(len(result['application']),len(expected))

    def test_slow_component_leaves_time_to_commit_unknowns(self):
        app=self.active_fixture()
        clock=[0.0]
        def slow_power(*args):
            clock[0]=34.0
            return {'status':'ok','events':[]}
        with patch.object(o.time,'monotonic',side_effect=lambda:clock[0]), \
                patch.object(o,'windows_events',side_effect=slow_power), \
                patch.object(o,'scheduler_events',return_value={}) as scheduler, \
                patch.object(o,'physical_gateway',return_value={}) as gateway, \
                patch.object(o,'body_probe',return_value={}) as probe:
            result=o.observe(app,self.root,'lab',True)
        scheduler.assert_not_called()
        gateway.assert_not_called()
        probe.assert_not_called()
        self.assertEqual(result['components']['scheduler'],'deadline')
        self.assertEqual(result['components']['gateway'],'deadline')
        self.assertEqual(result['stageDurationMs']['power'],34000)
        self.assertTrue(all(p['success'] is None for p in result['application']))
        self.assertEqual(json.loads((self.root/'state.json').read_text())['sequence'],1)

    def test_archive_deadline_defers_without_marking_source_captured(self):
        old=self.write_log('old.log','old');os.utime(old,(100,100))
        self.write_log('new.log','new')
        state={}
        with patch.object(o.time,'monotonic',return_value=10):
            result=o.archive_logs(self.logs,self.root,state,time.time(),deadline=9)
        self.assertEqual(result['newFiles'],0)
        self.assertGreaterEqual(result['deferred'],1)
        self.assertEqual(state['archives'],{})
        self.assertEqual(list((self.root/'archive').iterdir()),[])

    def test_host_record_exists_when_config_is_missing(self):
        app=self.base/'missing-app'
        with patch.object(o,'windows_events',return_value={'status':'ok','events':[]}):
            result=o.observe(app,self.root,'lab')
        self.assertEqual(result['components']['host'],'ok')
        self.assertIn('bootUtc',result['host'])
        if os.name=='nt':
            self.assertGreater(result['host']['awake100ns'],0)
            self.assertGreaterEqual(result['host']['uptimeMs'],result['host']['awake100ns']/10000-1000)

    def test_scheduler_unavailable_is_not_reported_as_no_failures(self):
        app=self.base/'missing-app'
        with patch.object(o,'windows_events',return_value={'status':'ok','events':[]}):
            result=o.observe(app,self.root,'lab')
        self.assertEqual(result['scheduler']['status'],'unavailable')

    def test_scheduler_refuses_unknown_task_names(self):
        with self.assertRaises(ValueError):SCHEDULER_EVENTS(time.time(),'private-task')

    @unittest.skipUnless(os.name=='nt','Windows task event reader')
    def test_scheduler_query_is_scoped_and_output_is_numeric(self):
        event={'id':203,'level':2,'record':12,'utc':o.utc(),'ErrorValue':2}
        payload={'status':'ok','enabled':True,'events':[event],'truncated':False}
        response=o.subprocess.CompletedProcess([],0,json.dumps(payload).encode(),b'')
        with patch.object(o.subprocess,'run',return_value=response) as run:
            result=SCHEDULER_EVENTS(time.time()-120,'STCVRC-Observer-Lab')
        command=run.call_args.args[0][-1]
        self.assertIn('Data[@Name="TaskName"]="\\STCVRC-Observer-Lab"',command)
        self.assertIn('-MaxEvents 100',command)
        self.assertNotIn('FormatDescription',command)
        self.assertEqual(result['events'],[event])

    @unittest.skipUnless(os.name=='nt','Windows task event reader')
    def test_scheduler_disabled_channel_remains_explicit(self):
        response=o.subprocess.CompletedProcess([],0,b'{"status":"disabled","enabled":false,"events":[]}',b'')
        with patch.object(o.subprocess,'run',return_value=response):
            result=SCHEDULER_EVENTS(time.time(),'STCVRC-Observer')
        self.assertEqual(result['status'],'disabled')
        self.assertFalse(result['enabled'])

    @unittest.skipUnless(os.name=='nt','Windows version-resource test')
    def test_windows_file_version_is_read_without_execution(self):
        version=o.file_version(Path(os.environ['WINDIR'])/'System32/notepad.exe')
        self.assertRegex(version,r'^\d+\.\d+\.\d+\.\d+$')

    @unittest.skipUnless(os.name=='nt','Windows route-selection contract')
    def test_physical_gateway_excludes_tun_and_uses_combined_metric(self):
        result=o.subprocess.CompletedProcess([],0,b'{"success":true,"delayMs":2}',b'')
        with patch.object(o.subprocess,'run',return_value=result) as run:
            # setUp substitutes the caller; inspect the original implementation here.
            value=PHYSICAL_GATEWAY()
        command=run.call_args.args[0][-1]
        self.assertIn('Get-NetAdapter -Physical',command)
        self.assertIn('$_.InterfaceIndex -in $physical',command)
        self.assertIn('$_.RouteMetric+$_.InterfaceMetric',command)
        self.assertEqual(value['scope'],'physical-ipv4-default')
        self.assertTrue(value['success'])


PHYSICAL_GATEWAY=o.physical_gateway
SCHEDULER_EVENTS=o.scheduler_events

if __name__=='__main__':unittest.main()
