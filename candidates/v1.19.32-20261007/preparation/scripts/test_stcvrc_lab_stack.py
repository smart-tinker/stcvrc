from pathlib import Path
import hashlib
import copy
import json
import os
import subprocess
import unittest

from stcvrc_lab_stack import STACKS, stack_inputs, native_identity_check, prelogin_observer_check, desktop_acceptance, inventory_comparison


class StackTests(unittest.TestCase):
    def test_inventory_requires_matching_collection_context(self):
        sample={'context':dict(schema=1,principalHash='principal',elevated=True,
                processBits=64,appDataHash='profile',hkcuRootHash='HKCU'),
                'componentHashes':dict.fromkeys(('routes','dns','services','tasks','firewall','hiddify','proxy','winhttp'),'hash')}
        self.assertTrue(inventory_comparison(sample,copy.deepcopy(sample))['baselineMatch'])
        for key in sample['context']:
            other=copy.deepcopy(sample)
            other['context'][key]='different'
            self.assertIsNone(inventory_comparison(sample,other)['baselineMatch'])
        self.assertIsNone(inventory_comparison({},sample)['baselineMatch'])
        other=copy.deepcopy(sample);other['componentHashes']['services']='changed'
        self.assertFalse(inventory_comparison(sample,other)['baselineMatch'])
        del other['componentHashes']['services']
        self.assertFalse(inventory_comparison(sample,other)['baselineMatch'])

    def test_corporate_baseline_changes_only_the_core(self):
        for key in STACKS['next']:
            source=STACKS['accepted'] if key in ('coreVersionToken','core','coreSha256') else STACKS['next']
            self.assertEqual(STACKS['next-baseline'][key],source[key])

    def test_desktop_acceptance_cannot_hide_failure_or_missing_evidence(self):
        report=dict.fromkeys(('pass','cleanupPass','baselineMatch','stagingRemoved','homeUnchanged'),True)
        self.assertTrue(desktop_acceptance(report))
        for key in report:
            self.assertFalse(desktop_acceptance({**report,key:False}))
            self.assertFalse(desktop_acceptance({k:v for k,v in report.items() if k!=key}))
        for key in ('error','cleanupError'):
            self.assertFalse(desktop_acceptance({**report,key:'failed'}))

    def test_prelogin_observer_requires_current_boot_trigger_without_desktop(self):
        boot='2026-09-23T04:00:00Z'
        row={'observedUtc':'2026-09-23T07:00:30+03:00','checkpoint':'ok',
             'components':{'host':'ok'},'scheduler':{'events':[{'id':118}]}}
        self.assertTrue(prelogin_observer_check([row],boot,0)['pass'])
        self.assertFalse(prelogin_observer_check([row],boot,1)['pass'])
        self.assertFalse(prelogin_observer_check([],boot,0)['pass'])
        self.assertFalse(prelogin_observer_check([row],'2026-09-23T04:01:00Z',0)['pass'])
        row['scheduler']['events']=[{'id':110}]
        self.assertFalse(prelogin_observer_check([row],boot,0)['pass'])

    def test_real_logon_verification_does_not_launch_ui(self):
        source=Path(__file__).with_name('uservm-stcvrc-ui-autostart.remote.ps1').read_text()
        verification=source.split('# VerifyLogon only reads the runtime;',1)[1].split("if($Action -eq 'Cleanup')",1)[0]
        self.assertNotIn('Start-ScheduledTask',verification)
        self.assertNotIn('Start-Ui',verification)
        self.assertIn('Where-Object id -eq 119',verification)
        self.assertIn('-not $logonProof.manualTriggered',verification)
        driver=Path(__file__).with_name('invoke-uservm-stcvrc-desktop-autostart.py').read_text()
        self.assertIn('if args.await_logon and not (args.reboot and args.observer_bundle):',driver)
        self.assertIn("step('VerifyLogon',120)",driver)

    def native_rows(self):
        row={'host':{'processes':[{'role':'verge-mihomo.exe','pid':1,'parent':2,'session':0,'startUtc':'2026-09-23T00:00:00Z'}]},
             'coreEpoch':'stable','native':{'leaves':{leaf:{'sourceUtc':'2026-09-23T00:01:00Z','newSample':True} for leaf in ('4VPS','GC')}}}
        second=copy.deepcopy(row)
        for item in second['native']['leaves'].values():item['newSample']=False
        return [row,second]

    def test_native_identity_requires_repeated_samples_for_both_leaves(self):
        self.assertFalse(native_identity_check([])['pass'])
        rows=self.native_rows()
        self.assertTrue(native_identity_check(rows)['pass'])
        del rows[1]['native']['leaves']['GC']['sourceUtc']
        self.assertFalse(native_identity_check(rows)['pass'])

    def test_native_identity_rejects_false_new_sample_and_unstable_epoch(self):
        rows=self.native_rows()
        rows[1]['native']['leaves']['GC']['newSample']=True
        self.assertFalse(native_identity_check(rows)['pass'])
        rows=self.native_rows();rows[1]['coreEpoch']='drifted'
        self.assertIn('epoch-changed-with-same-process',native_identity_check(rows)['violations'])

    def test_pinned_pairs_and_safe_names(self):
        root = Path(__file__).resolve().parents[1]
        for name in STACKS:
            with self.subTest(stack=name):
                manifest, inputs = stack_inputs(root, name)
                self.assertEqual(manifest['schema'], 1)
                self.assertEqual(len(inputs), 2)
                self.assertIn(manifest['uiVersion'], manifest['installerName'])
                for key in ('coreSha256', 'installerSha256'):
                    self.assertRegex(manifest[key], r'^[0-9a-f]{64}$')
                for filename, path in inputs.items():
                    self.assertEqual(Path(filename).name, filename)
                    self.assertTrue(path.is_relative_to(root / 'local/artifacts'))

    def test_unknown_stack_fails_closed(self):
        with self.assertRaises(KeyError):
            stack_inputs(Path('.'), 'unreviewed')

    def test_programdata_requires_explicit_preservation(self):
        text = Path(__file__).with_name('invoke-uservm-stcvrc-desktop-autostart.py').read_text()
        self.assertIn('if not args.preserve_service_state:', text)
        self.assertIn("parser.error('Desktop gate requires explicitly approved", text)
        remote = Path(__file__).with_name('uservm-stcvrc-desktop-autostart.remote.ps1').read_text()
        self.assertIn("'C:\\ProgramData\\clash-verge-service'", remote)
        self.assertIn("throw 'Original service state backup differs'", remote)
        self.assertIn("throw 'Lab state marker mismatch'", remote)
        self.assertIn("throw 'State root mismatch'", remote)
        self.assertIn("throw 'Preserved root ACL mismatch'", remote)

    def test_inventory_keeps_raw_instances_but_compares_templates(self):
        text = Path(__file__).with_name('uservm-stcvrc-safe-rollout.remote.ps1').read_text()
        self.assertIn('$type -band 128', text)
        self.assertIn('Where-Object {-not $_.PerUserInstance}', text)
        self.assertIn('allServices=$allServices', text)
        self.assertIn('inventory-before.json', text)

    def test_next_layout_and_device_prefix(self):
        source=Path(__file__).with_name('uservm-stcvrc-fullstack.remote.ps1')
        code=r'''
$ErrorActionPreference='Stop'
$t=$null;$e=$null;$ast=[Management.Automation.Language.Parser]::ParseFile('SOURCE',[ref]$t,[ref]$e)
if($e){throw 'Parse failure'}
foreach($name in @('Resolve-NormalizedPath','Get-StringSha256','Get-LabRuntimeLayout')){
 $f=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true)
 . ([ScriptBlock]::Create($f.Extent.Text))
}
$InstalledCorePath='C:\Program Files\Clash Verge\verge-mihomo.exe'
$AppRoot='C:\Users\Lab\AppData\Roaming\CVR'
$sid='S-1-5-21-1-2-3-1001'
$next=Get-LabRuntimeLayout @{schema=1;uiVersion='2.5.5'} $sid
$candidate=Get-LabRuntimeLayout @{schema=1;uiVersion='2.5.7'} $sid
$current=Get-LabRuntimeLayout @{schema=1;uiVersion='2.5.8'} $sid
$old=Get-LabRuntimeLayout @{schema=1;uiVersion='2.5.2'} $sid
$rejected=0
foreach($bad in @('\\?\UNC\server\share','\\.\PhysicalDrive0')){try{$null=Resolve-NormalizedPath $bad}catch{$rejected++}}
try{$null=Get-LabRuntimeLayout @{schema=1;uiVersion='2.5.6'} $sid}catch{$rejected++}
try{$null=Get-LabRuntimeLayout @{schema=1;uiVersion='2.5.5'} '..\other'}catch{$rejected++}
@{next=$next;candidate=$candidate;current=$current;old=$old;normalized=(Resolve-NormalizedPath '\\?\C:\ProgramData\clash-verge-service\cores\verge-mihomo.exe');rejected=$rejected}|ConvertTo-Json -Depth 4 -Compress
'''.replace('SOURCE',str(source).replace("'","''"))
        exe=Path(os.environ['WINDIR'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
        result=subprocess.run([str(exe),'-NoProfile','-NonInteractive','-Command',code],capture_output=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr.decode('utf-8',errors='replace'))
        value=json.loads(result.stdout.decode('utf-8-sig'))
        self.assertEqual(value['rejected'],4)
        self.assertTrue(value['next']['approved'])
        self.assertEqual(value['candidate'],value['next'])
        self.assertEqual(value['current'],value['next'])
        self.assertFalse(value['old']['approved'])
        self.assertEqual(value['next']['core'],value['normalized'])
        self.assertIn(hashlib.sha256(b'S-1-5-21-1-2-3-1001').hexdigest(),value['next']['config'])
        self.assertTrue(value['next']['config'].endswith(r'\runtime\config.yaml'))

    def test_approved_core_is_registered_and_read_back(self):
        remote=Path(__file__).with_name('uservm-stcvrc-safe-rollout.remote.ps1').read_text()
        self.assertIn("@('--install-core'",remote)
        self.assertIn("'--sha256',$stack.coreSha256",remote)
        self.assertIn('coreHash=$runtime.executingCoreHash',remote)
        library=Path(__file__).with_name('uservm-stcvrc-fullstack.remote.ps1').read_text()
        self.assertIn("throw 'Executing core hash differs from pinned candidate'",library)
        self.assertIn('parentPid -eq $service.ProcessId',library)
        self.assertIn('OwningProcess -ne $core[0].pid',library)


if __name__ == '__main__':
    unittest.main()
