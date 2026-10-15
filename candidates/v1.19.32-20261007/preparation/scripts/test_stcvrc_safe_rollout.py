import copy
import ast
import base64
import contextlib
import io
import json
import os
from pathlib import Path
import runpy
import shutil
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import stmc_yaml
from stcvrc_single_egress import build_provider_repair, four_choice_groups

SCRIPT = Path(__file__).with_name('stcvrc-safe-rollout.ps1')
PREPARE = runpy.run_path(str(Path(__file__).with_name('prepare-stcvrc-safe-rollout.py')))


class SafeRolloutTest(unittest.TestCase):
    def test_config_rollback_readback_uses_the_actual_starting_stack(self):
        source=SCRIPT.with_name('invoke-uservm-stcvrc-desktop-autostart.py').read_text()
        nodes=[n for n in ast.walk(ast.parse(source)) if isinstance(n,ast.AugAssign)
               and 'coreRollbackUi' in ast.unparse(n)]
        self.assertEqual(len(nodes),1)
        statement=compile(ast.Module(body=nodes,type_ignores=[]),'rollback-check','exec')
        for expected,actual,gate,initial,want in (
                ('accepted','accepted',True,True,True),
                ('next','next',True,True,True),
                ('next','accepted',True,True,False),
                ('next','next',False,True,False),
                ('next','next',True,False,False)):
            report={'pass':initial,'coreRollout':{'pass':gate},'coreRollbackUi':{'coreHash':actual.upper()}}
            exec(statement,{'report':report,'stack':{'coreSha256':expected},
                            'STACKS':{'accepted':{'coreSha256':'accepted'}}})
            self.assertEqual(report['pass'],want)

    @unittest.skipUnless(os.name == 'nt', 'PowerShell rollback adapter')
    def test_core_rollback_replays_changed_manual_selector(self):
        code = r'''
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('__SOURCE__',[ref]$tokens,[ref]$errors)
$f=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Restore-Old'},$true)
. ([ScriptBlock]::Create($f.Extent.Text))
$Root=$env:TEMP;$Core='core';$ExecutingCore='core';$ServiceName='lab'
$Plan=@{policy='core-update';oldVersion='old';entries=@(@{id='core';target='core';before='abc'})}
function State($Phase){}
function Read-Json($Path){@{cachePresent=$false}}
function Hash($Path){'abc'}
function Stop-Runtime {}
function Test-Path($LiteralPath){$false}
function Register-ApprovedCore($ExpectedHash){}
function Start-Service($Name){}
function Wait-Core($Version){}
function Check-OwnerRuntime {}
$script:selected='4VPS'
function Restore-Selectors {$script:selected='GC'}
function Check-Selectors {if($script:selected -cne 'GC'){throw 'Selector not restored'}}
function Check-Http {@()}
function Write-Json($Path,$Value){}
function Remove-GuardTask {}
$Ui='C:\Windows\System32\cmd.exe'
Restore-Old
if($script:selected -cne 'GC'){throw 'Missing selector replay'}
'''.replace('__SOURCE__',str(SCRIPT))
        shell = Path(os.environ['WINDIR'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
        result = subprocess.run([str(shell),'-NoProfile','-NonInteractive','-EncodedCommand',
            base64.b64encode(code.encode('utf-16le')).decode()],capture_output=True,timeout=20)
        self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace'))

    def test_ui_expectations_only_add_owner_pipe_and_disabled_dns_preference(self):
        settings={'enable_dns_settings':False,'enable_auto_launch':True,'start_page':'/home'}
        runtime={'dns':{'enable':False},'external-controller-pipe':r'\\.\pipe\verge-mihomo','rules':['MATCH,DIRECT']}
        expected_settings,expected_runtime=PREPARE['ui_migration_expectations'](settings,runtime,'one','S-1-5-21-1-2-3-4')
        self.assertEqual(stmc_yaml.load(expected_settings),{**settings,'start_page':'/','profile_dns_settings':{'one':{'enabled':False}}})
        result=stmc_yaml.load(expected_runtime)
        self.assertEqual(result['dns'],runtime['dns'])
        self.assertEqual(result['rules'],runtime['rules'])
        self.assertTrue(result['external-controller-pipe'].endswith(PREPARE['sha'](b'S-1-5-21-1-2-3-4')))
        self.assertNotIn('profile_dns_settings',settings)
        for invalid in ({'enable_dns_settings':True},{},{**settings,'profile_dns_settings':{'one':{'enabled':True}}}):
            with self.assertRaises(ValueError):
                PREPARE['ui_migration_expectations'](invalid,runtime,'one','S-1-5-21-1-2-3-4')

    def test_ui_migration_only_updates_implicit_tun_ipv6_default(self):
        settings = {'enable_dns_settings': False}
        runtime = {'ipv6': True, 'tun': {'enable': True}, 'dns': {
            'enhanced-mode': 'fake-ip', 'fake-ip-range6': 'fdfe:dcba:9876::1/64',
            'nameserver': ['192.0.2.1']}, 'rules': ['MATCH,DIRECT']}
        for label, delta, profile, changed in (
                ('implicit', {}, {'dns': {}}, True),
                ('explicit-old', {}, {'dns': {'fake-ip-range6': 'fdfe:dcba:9876::1/64'}}, False),
                ('explicit-custom', {}, {'dns': {'fake-ip-range6': 'fd00::/64'}}, False),
                ('profile-unknown', {}, None, False),
                ('ipv6-off', {'ipv6': False}, {}, False),
                ('tun-off', {'tun': {'enable': False}}, {}, False),
                ('redir-host', {'dns': {**runtime['dns'], 'enhanced-mode': 'redir-host'}}, {}, False),
                ('runtime-custom', {'dns': {**runtime['dns'], 'fake-ip-range6': 'fd00::/64'}}, {}, False)):
            with self.subTest(label=label):
                original = {**copy.deepcopy(runtime), **delta}
                before = copy.deepcopy(original)
                _, output = PREPARE['ui_migration_expectations'](
                    settings, original, 'one', 'S-1-5-21-1-2-3-4', profile)
                actual = stmc_yaml.load(output)
                expected = copy.deepcopy(before)
                expected['external-controller-pipe'] = actual['external-controller-pipe']
                if changed:
                    expected['dns']['fake-ip-range6'] = '2001:2::0/64'
                self.assertEqual(actual, expected)
                self.assertEqual(original, before)

    def test_ui_system_transaction_uses_existing_guard_and_owner_task(self):
        source=SCRIPT.read_text()
        apply=source[source.index("} elseif($Mode -eq 'Apply')"):source.index("} elseif($Mode -eq 'Confirm')")]
        restore=source[source.index('function Restore-Old'):source.index('function Stop-ApplyWorker')]
        self.assertLess(apply.index('watch-ready.json'),apply.index('Install-UiGeneration $true'))
        self.assertLess(apply.index('Install-UiGeneration $true'),apply.index('Register-UiService'))
        self.assertLess(restore.index('Install-UiGeneration $false'),restore.index('Register-UiService'))
        for block in (apply,restore):
            self.assertIn('Start-OwnerUi',block)
            self.assertIn('Restore-Selectors',block)
        self.assertIn('uiTaskHash',source)
        self.assertIn("$task.Principal.RunLevel -ne 'Limited'",source)
        self.assertIn('Invoke-CimMethod -InputObject $processes[0] -MethodName GetOwnerSid',source)
        self.assertIn("@('--install-service','--install-core'",source)
        self.assertIn("@('/S',('_?='+$InstallRoot))",source)
        self.assertIn('installer-worker.json',source)
    @unittest.skipUnless(os.name == 'nt', 'Windows installer adapter')
    def test_ui_migration_installer_bound_and_arguments(self):
        source=SCRIPT.with_name('uservm-stcvrc-safe-rollout.remote.ps1')
        code=r'''
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('__SOURCE__',[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Parse failure'}
$f=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Run-Installer'},$true)
. ([ScriptBlock]::Create($f.Extent.Text))
function Start-Process($FilePath,$ArgumentList,$WindowStyle,[switch]$PassThru){
 if($FilePath -cne 'fixture.exe' -or $WindowStyle -cne 'Hidden' -or -not $PassThru){throw 'Wrong launcher'}
 $script:arguments=@($ArgumentList)
 $p=[pscustomobject]@{Handle=1;ExitCode=$script:exitCode}
 $p|Add-Member ScriptMethod WaitForExit {param($ms) if($ms -and $ms -ne 120000){throw 'Unbounded wait'};return (-not $script:timeout)}
 $p|Add-Member ScriptMethod Kill {$script:killed=$true}
 $p|Add-Member ScriptMethod Dispose {}
 $p
}
$script:exitCode=0;$script:timeout=$false
Run-Installer fixture.exe
if(($script:arguments -join ',') -cne '/S'){throw 'Silent installer flag lost'}
Run-Installer fixture.exe @()
if($script:arguments|Where-Object {$_}){throw 'Service installer received UI flags'}
$script:exitCode=1;$failed=$false
try{Run-Installer fixture.exe}catch{$failed=$true}
if(-not $failed){throw 'Installer exit ignored'}
$script:exitCode=0;$script:timeout=$true;$failed=$false;$script:killed=$false
try{Run-Installer fixture.exe}catch{$failed=$true}
if(-not $failed -or -not $script:killed){throw 'Unbounded child'}
'''.replace('__SOURCE__',str(source).replace("'","''"))
        shell=Path(os.environ['WINDIR'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
        result=subprocess.run([str(shell),'-NoProfile','-NonInteractive','-EncodedCommand',
            base64.b64encode(code.encode('utf-16le')).decode()],capture_output=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace'))

    def test_ui_migration_has_preservation_and_guarded_selector_restore(self):
        source=SCRIPT.with_name('uservm-stcvrc-safe-rollout.remote.ps1').read_text()
        migration=source[source.index("if($Action -in @('UpgradeUi','RollbackUi'))"):source.index("if($Action -eq 'Canary')")]
        self.assertLess(migration.index('$null=& (Join-Path $control'),migration.index('    Stop-MigrationRuntime\n'))
        self.assertIn('RequireComplete=$true',migration)
        self.assertIn('Migration backup drift',migration)
        self.assertIn('Migration restore hash mismatch',migration)
        self.assertIn('--install-core',migration)
        self.assertIn("@('--install-service','--install-core'",migration)
        self.assertLess(migration.index('Start-Service -Name $ServiceName'),migration.index('$null=Start-Ui'))
        self.assertIn('UI migration service path mismatch',migration)
        self.assertNotIn('Set-ProxyGroup',migration)
        self.assertIn('Captured migration selector mismatch',migration)
        self.assertIn('$group.all -cnotcontains $entry.Value',migration)
        self.assertIn('-Method Put -Body @{name=$entry.Value}',migration)
        self.assertLess(migration.index('Run-Installer $ServiceUninstallPath @()'),migration.index('Run-Installer $uninstaller'))
        self.assertIn("@('/S',('_?='+$InstallRoot))",migration)
        self.assertIn('[Diagnostics.FileVersionInfo]::GetVersionInfo($UiPath)',migration)
        self.assertIn('$versionDeadline=(Get-Date).AddSeconds(30)',migration)

    def provider_fixture(self):
        return {'proxies': [{'name': 'GC', 'type': 'vless'}, {'name': '4VPS', 'type': 'vless'}],
                'proxy-groups': four_choice_groups() + [{'name': 'OTHER', 'type': 'select', 'proxies': ['DIRECT', 'REJECT']}],
                'rules': ['MATCH,FOREIGN-EGRESS'], 'dns': {'enable': False}, 'tun': {'enable': False},
                'mixed-port': 7897, 'external-controller': '127.0.0.1:9097', 'secret': 'fixture-only',
                'rule-providers': {name: {'type': 'http', 'proxy': 'VPS-DEFAULT', 'url': 'https://example/rules'}
                                   for name in ['ru-service-domains', 'tspu-foreign-domains']}}

    def test_provider_repair_stages_only_two_files_and_preserves_registry_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            app, bundle = root / 'app', root / 'bundle'
            (app / 'profiles').mkdir(parents=True)
            bundle.mkdir()
            (root / 'scripts').mkdir()
            shutil.copyfile(SCRIPT, root / 'scripts' / SCRIPT.name)
            preserver = SCRIPT.with_name('preserve-stcvrc-evidence.ps1')
            shutil.copyfile(preserver, root / 'scripts' / preserver.name)
            source = self.provider_fixture()
            data = stmc_yaml.dump(source)
            (app / 'profiles/one.yaml').write_bytes(data)
            (app / 'clash-verge.yaml').write_bytes(data)
            (app / 'verge.yaml').write_bytes(b'enable_tun_mode: false\nenable_dns_settings: false\n')
            registry = b'# preserve formatting and unrelated metadata\n' + stmc_yaml.dump({
                'current': 'one', 'items': [{'uid': 'one', 'type': 'local', 'file': 'one.yaml',
                'selected': [{'name': 'FOREIGN-EGRESS', 'now': 'GC'}, {'name': 'OTHER', 'now': 'REJECT'}]}]})
            (app / 'profiles.yaml').write_bytes(registry)
            (bundle / 'STCVRC-provider-repair.yaml').write_bytes(stmc_yaml.dump(build_provider_repair(source)))
            core = bundle / 'verge-mihomo.exe'
            core.write_bytes(b'fixture-core')
            validator = root / 'validator.exe'
            validator.write_bytes(b'fixture-validator')
            selectors = {'FOREIGN-EGRESS': 'GC', 'OTHER': 'REJECT'}
            (root / 'selectors.json').write_text(json.dumps(selectors))
            output = root / 'local/transaction'
            argv = ['prepare', '--provider-repair', '--lab', '--host', 'LABHOST',
                    '--app-root', str(app), '--old-core', str(core), '--bundle', str(bundle),
                    '--yaml-validator', str(validator), '--output', str(output),
                    '--target-app-root', r'C:\Users\FixtureService\AppData\Roaming\io.github.clash-verge-rev.clash-verge-rev',
                    '--target-transaction-root', r'C:\Users\FixtureService\stcvrc-fullstack-lab\transactions\stcvrc-safe-1',
                    '--selectors-json', str(root / 'selectors.json')]
            with patch.dict(PREPARE['main'].__globals__, PROJECT=root, NEW_CORE=PREPARE['sha'](core.read_bytes())), patch.object(sys, 'argv', argv), contextlib.redirect_stdout(io.StringIO()):
                PREPARE['main']()
            plan = json.loads((output / 'plan.json').read_text())
            self.assertEqual(plan['policy'], 'provider-repair')
            self.assertEqual(plan['selectors'], selectors)
            self.assertEqual(plan['evidenceScriptSha256'], PREPARE['sha'](preserver.read_bytes()))
            self.assertEqual((output / 'preserve-evidence.ps1').read_bytes(), preserver.read_bytes())
            self.assertEqual([e['id'] for e in plan['entries'] if e['replace']], ['profile', 'runtime'])
            self.assertEqual((output / 'registry.new').read_bytes(), registry)
            self.assertEqual((app / 'clash-verge.yaml').read_bytes(), data)
            next_core = root / 'next.exe'
            next_core.write_bytes(b'fixture-next-core')
            core_output = root / 'local/core-transaction'
            sid = 'S-1-5-21-1-2-3-1001'
            core_argv = [x for x in argv if x != '--provider-repair']
            start = core_argv.index('--bundle')
            del core_argv[start:start + 2]
            core_argv[core_argv.index('--output') + 1] = str(core_output)
            core_argv += ['--core-update', '--candidate-core', str(next_core), '--service-owner-sid', sid,
                          '--runtime-config', str(app / 'clash-verge.yaml')]
            pinned = copy.deepcopy(PREPARE['STACKS'])
            pinned['next'].update(coreSha256=PREPARE['sha'](next_core.read_bytes()), coreVersionToken='next-fixture')
            with patch.dict(PREPARE['main'].__globals__, PROJECT=root, NEW_CORE=PREPARE['sha'](core.read_bytes()), STACKS=pinned), patch.object(sys, 'argv', core_argv), contextlib.redirect_stdout(io.StringIO()):
                PREPARE['main']()
            core_plan = json.loads((core_output / 'plan.json').read_text())
            self.assertEqual(core_plan['policy'], 'core-update')
            self.assertEqual(core_plan['runtimeLayout'], 'approved')
            self.assertEqual(core_plan['uiVersion'], '2.5.5')
            self.assertEqual(core_plan['serviceOwnerSid'], sid)
            self.assertTrue(core_plan['serviceOwnerDirectory'].endswith(PREPARE['sha'](sid.encode('ascii'))))
            self.assertEqual([e['id'] for e in core_plan['entries'] if e['replace']], ['core'])
            self.assertEqual(core_plan['selectors'], selectors)
            self.assertEqual(len(core_plan['entries']), 4)
            self.assertFalse((core_output / 'registry.new').exists())
            self.assertFalse((core_output / 'runtime.new').exists())
            self.assertEqual((core_output / 'owner-runtime.before.yaml').read_bytes(), data)
            self.assertEqual(core_plan['ownerRuntimeSha256'], PREPARE['sha'](data))
            observer_argv=list(core_argv)
            observer_output=root/'local/observer-config-transaction'
            observer_argv[observer_argv.index('--old-core')+1]=str(next_core)
            observer_argv[observer_argv.index('--output')+1]=str(observer_output)
            observer_argv.append('--observer-config')
            with patch.dict(PREPARE['main'].__globals__, PROJECT=root, NEW_CORE=PREPARE['sha'](core.read_bytes()), STACKS=pinned), patch.object(sys,'argv',observer_argv), contextlib.redirect_stdout(io.StringIO()):
                PREPARE['main']()
            observer_plan=json.loads((observer_output/'plan.json').read_text())
            self.assertTrue(observer_plan['observerConfig'])
            self.assertEqual(observer_plan['oldVersion'],observer_plan['newVersion'])
            self.assertEqual([e['id'] for e in observer_plan['entries'] if e['replace']],['profile','settings'])
            self.assertFalse((observer_output/'core.new').exists())
            self.assertEqual(observer_plan['selectors'],selectors)
            observed=stmc_yaml.load((observer_output/'profile.new').read_bytes())
            self.assertEqual({k:v for k,v in observed.items() if k!='listeners'},source)
            self.assertEqual(len(observed['listeners']),2)
            self.assertTrue(all(x['listen']=='127.0.0.1' for x in observed['listeners']))
            observed_settings=stmc_yaml.load((observer_output/'settings.new').read_bytes())
            self.assertEqual(observed_settings['app_log_max_size'],4096)
            self.assertEqual(observed_settings['app_log_max_count'],32)
            self.assertEqual(observed_settings['auto_log_clean'],3)
            self.assertFalse(observed_settings['enable_dns_settings'])
            self.assertEqual((observer_output/'owner-runtime.before.yaml').read_bytes(),data)
            self.assertEqual(stmc_yaml.load((observer_output/'owner-runtime.expected.yaml').read_bytes()),observed)
            wrong_observer=list(observer_argv)
            wrong_observer[wrong_observer.index('--old-core')+1]=str(core)
            rejected_output=root/'local/rejected-observer-config'
            wrong_observer[wrong_observer.index('--output')+1]=str(rejected_output)
            with patch.dict(PREPARE['main'].__globals__, PROJECT=root, NEW_CORE=PREPARE['sha'](core.read_bytes()), STACKS=pinned), patch.object(sys,'argv',wrong_observer), self.assertRaisesRegex(ValueError,'must not change the core'):
                PREPARE['main']()
            self.assertFalse(rejected_output.exists())
            ui_argv=list(core_argv)
            ui_argv[ui_argv.index('--core-update')]='--ui-update'
            start=ui_argv.index('--runtime-config')
            del ui_argv[start:start+2]
            ui_output=root/'local/ui-transaction'
            ui_argv[ui_argv.index('--output')+1]=str(ui_output)
            for label in ('accepted','next'):
                installer=root/(label+'-setup.exe')
                installer.write_bytes(label.encode('ascii'))
                pinned[label].update(installer=installer.name,installerSha256=PREPARE['sha'](installer.read_bytes()))
            with patch.dict(PREPARE['main'].__globals__, PROJECT=root, NEW_CORE=PREPARE['sha'](core.read_bytes()), STACKS=pinned), patch.object(sys,'argv',ui_argv), contextlib.redirect_stdout(io.StringIO()):
                PREPARE['main']()
            ui_plan=json.loads((ui_output/'plan.json').read_text())
            self.assertEqual(ui_plan['policy'],'ui-update')
            self.assertEqual(ui_plan['runtimeLayout'],'ui-migration')
            self.assertEqual(len(ui_plan['entries']),5)
            self.assertEqual([e['id'] for e in ui_plan['entries'] if e['replace']],['core'])
            self.assertEqual(ui_plan['uiInstallers']['old'],PREPARE['sha'](b'accepted'))
            self.assertEqual((ui_output/'ui-new.exe').read_bytes(),b'next')
            self.assertFalse((ui_output/'settings.new').exists())
            self.assertFalse((ui_output/'runtime.new').exists())
            self.assertEqual(stmc_yaml.load((ui_output/'settings.expected.yaml').read_bytes())['profile_dns_settings'],{'one':{'enabled':False}})

    def test_provider_repair_requires_reviewed_topology_and_two_references(self):
        source = self.provider_fixture()
        self.assertEqual(PREPARE['provider_repair_names'](source), ['ru-service-domains', 'tspu-foreign-domains'])
        for mutation in (lambda s: s['proxy-groups'][0]['proxies'].reverse(),
                         lambda s: s['rule-providers']['ru-service-domains'].update(proxy='DIRECT')):
            changed = copy.deepcopy(source)
            mutation(changed)
            with self.assertRaises(ValueError):
                PREPARE['provider_repair_names'](changed)

    def test_provider_repair_captures_foreign_and_unrelated_selectors(self):
        source = self.provider_fixture()
        self.assertEqual(set(PREPARE['selector_groups'](source, True)), {'FOREIGN-EGRESS', 'OTHER'})
        self.assertEqual(set(PREPARE['selector_groups'](source)), {'OTHER'})

    def test_provider_repair_lab_never_copies_corporate_vpn(self):
        runner = runpy.run_path(str(Path(__file__).with_name('invoke-uservm-stcvrc-safe-rollout.py')))
        source = self.provider_fixture()
        source['proxies'].append({'name': 'CORP', 'type': 'openvpn', 'password': 'private-fixture'})
        result = runner['provider_lab_profile'](source)
        self.assertEqual({p['name'] for p in result['proxies']}, {'GC', '4VPS'})
        self.assertNotIn('private-fixture', str(result))
        self.assertFalse(result['tun']['enable'])
        self.assertFalse(result['dns']['enable'])
        self.assertEqual(result['rules'], ['MATCH,FOREIGN-EGRESS'])
        self.assertTrue(result['profile']['store-selected'])
        self.assertTrue(all(p['proxy'] == 'VPS-DEFAULT' for p in result['rule-providers'].values()))

    def test_rejected_lab_baseline_does_not_authorize_full_cleanup(self):
        source = Path(__file__).with_name('invoke-uservm-stcvrc-safe-rollout.py').read_text()
        self.assertIn('if driver_ready and baseline_accepted:', source)
        self.assertIn('elif lab_created:', source)
        self.assertLess(source.index("raise RuntimeError('VM full-stack preflight rejected')"),
                        source.index('baseline_accepted = True'))

    def test_provider_repair_does_not_reset_foreign_selection(self):
        source = SCRIPT.read_text()
        apply = source[source.index("} elseif($Mode -eq 'Apply')"):source.index("} elseif($Mode -eq 'Confirm')")]
        self.assertIn("elseif($Plan.policy -notin @('provider-repair','core-update','ui-update'))", apply)
        self.assertLess(apply.index('Check-Selectors'), apply.index('Stop-Runtime'))
        self.assertIn('Candidate-Check -RefreshProviders', apply)
        self.assertIn("if($Plan.policy -in @('provider-repair','core-update','ui-update') -and $foreign -in @('4VPS','GC'))", source)
        self.assertIn("$provider=(Api '/providers/rules').providers.$name", source)
        self.assertNotIn("$provider=Api ('/providers/rules/'+$name)", source)

    def test_completed_watchdog_serializes_task_cleanup(self):
        source = SCRIPT.read_text()
        self.assertIn("if($phase -in @('committed','rolled-back')){Acquire-Lock;Remove-GuardTask;exit 0}", source)
        self.assertLess(source.rindex('Remove-ApplyTask'), source.rindex('$Lock.Dispose()'))

    @unittest.skipUnless(os.name == 'nt', 'Windows PowerShell bounded retry')
    def test_http_retry_is_bounded_and_preserves_first_failure(self):
        source = str(SCRIPT).replace("'", "''")
        code = "$ErrorActionPreference='Stop';$source='" + source + "';" + r'''
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Parse failure'}
$f=$ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Check-Http'},$true)
. ([ScriptBlock]::Create($f[0].Extent.Text))
$Root=$env:TEMP
function Write-Json($Path,$Value){$script:evidence=$Value}
function Start-Sleep($Seconds){}
function Invoke-WebRequest($Uri,$Proxy,[switch]$UseBasicParsing,$TimeoutSec){
    $script:calls++
    if($script:alwaysFail -or $script:calls -eq 1){throw [Net.WebException]::new('fixture',[Net.WebExceptionStatus]::SendFailure)}
    @{StatusCode=$(if($Uri -like '*generate_204'){204}else{200})}
}
$script:calls=0;$script:alwaysFail=$false
$result=@(Check-Http)
if($script:calls -ne 3 -or $result.Count -ne 2 -or $result[0].attempts.Count -ne 2 -or $result[1].attempts.Count -ne 1){throw 'Retry sequence mismatch'}
if($result[0].attempts[0].webStatus -cne 'SendFailure' -or $result[0].status -ne 204){throw 'Failure evidence lost'}
$script:calls=0;$script:alwaysFail=$true;$failed=$false
try {$null=Check-Http}catch{$failed=$true}
if(-not $failed -or $script:calls -ne 2 -or $script:evidence.attempts.Count -ne 2){throw 'Retry not bounded'}
'''
        shell = Path(os.environ['WINDIR']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
        result = subprocess.run([str(shell), '-NoProfile', '-NonInteractive', '-EncodedCommand',
                                 base64.b64encode(code.encode('utf-16le')).decode()], capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))

    def test_metadata_only_foreign_pins_removed(self):
        old = {'current': 'one', 'items': [
            {'uid': 'one', 'type': 'local', 'option': {'script': 'opaque'}, 'selected': [
                {'name': 'FOREIGN-EGRESS', 'now': 'DIRECT'},
                {'name': 'VPS-DEFAULT', 'now': '4VPS'},
                {'name': 'ELITECH-ROUTE', 'now': 'DIRECT'}]},
            {'uid': 'two', 'type': 'local', 'selected': [{'name': 'VPS-DEFAULT', 'now': '4VPS'}]}]}
        before = copy.deepcopy(old)
        new = PREPARE['registry_candidate'](old, 'one')
        self.assertEqual(old, before)
        self.assertEqual(new['items'][0]['selected'], [{'name': 'ELITECH-ROUTE', 'now': 'DIRECT'}])
        self.assertEqual(new['items'][1], old['items'][1])
        self.assertEqual(new['items'][0]['option'], old['items'][0]['option'])

    def test_watchdog_armed_before_runtime_mutation(self):
        s = SCRIPT.read_text()
        apply = s[s.index("} elseif($Mode -eq 'Apply')"):s.index("} elseif($Mode -eq 'Confirm')")]
        self.assertLess(apply.index('Start-ScheduledTask'), apply.index('Stop-Runtime'))
        self.assertLess(apply.index('Independent SYSTEM watchdog not ready'), apply.index('Stop-Runtime'))
        self.assertIn('New-ScheduledTaskTrigger -AtStartup', apply)
        self.assertIn('-DontStopIfGoingOnBatteries', apply)
        self.assertIn("State 'awaiting-confirmation'", apply)
        self.assertNotIn("State 'committed'", apply)

    def test_history_required_before_runtime_or_deadline_mutation(self):
        source = SCRIPT.read_text()
        apply = source[source.index("} elseif($Mode -eq 'Apply')"):source.index("} elseif($Mode -eq 'Confirm')")]
        self.assertLess(apply.index("Preserve-History 'before'"), apply.index("State 'armed'"))
        self.assertLess(apply.index("Preserve-History 'before'"), apply.index('Stop-Runtime'))
        recovery = source[source.index('function Restore-Old'):source.index('function Stop-ApplyWorker')]
        self.assertIn("if($Plan.policy -ceq 'ui-update')", recovery)
        self.assertIn("try {Preserve-History 'rollback'}catch", recovery)

    @unittest.skipUnless(os.name == 'nt', 'Windows PowerShell history hook')
    def test_history_hook_fails_closed_and_checks_pinned_helper(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            helper = root / 'preserve-evidence.ps1'
            helper.write_text('''param($Destination,$AppDirectory,$Days,[switch]$RequireComplete,$ServiceOwnerDirectory)
if(-not $RequireComplete -or $Days -ne 14 -or $ServiceOwnerDirectory -cne 'fixture-owner'){throw 'Missing evidence boundary'}
if(Test-Path -LiteralPath (Join-Path $AppDirectory 'fail')){throw 'Fixture incomplete evidence'}
$null=New-Item -ItemType Directory -Path $Destination
@{status='preserved';host=$env:COMPUTERNAME}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $Destination 'manifest.json')
''', encoding='ascii')
            code = r'''
$ErrorActionPreference='Stop'
$env:PSModulePath=(Join-Path $PSHOME 'Modules')+';'+(Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules')
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('__SOURCE__',[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Parse failure'}
foreach($name in @('Hash','Read-Json','No-Reparse','Preserve-History')){
 $f=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
 . ([ScriptBlock]::Create($f.Extent.Text))
}
$Root='__ROOT__'
$helper=Join-Path $Root 'preserve-evidence.ps1'
$Plan=@{appRoot=$Root;serviceOwnerDirectory='fixture-owner';evidenceScriptSha256=(Hash $helper)}
function Write-Json($Path,$Value){$script:result=$Value}
Preserve-History before
if(-not $script:result.pass -or -not $script:result.manifestSha256){throw 'Missing preservation proof'}
$script:result=$null
$null=New-Item -ItemType File -Path (Join-Path $Root 'fail')
$failed=$false
try {Preserve-History before}catch{$failed=$true}
if(-not $failed -or $script:result){throw 'Incomplete copy did not block'}
$Plan.evidenceScriptSha256='invalid'
$failed=$false
try {Preserve-History before}catch{$failed=$true}
if(-not $failed){throw 'Unpinned helper accepted'}
'''.replace('__SOURCE__', str(SCRIPT).replace("'", "''")).replace('__ROOT__', str(root).replace("'", "''"))
            shell = Path(os.environ['WINDIR']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
            result = subprocess.run([str(shell), '-NoProfile', '-NonInteractive', '-EncodedCommand',
                                     base64.b64encode(code.encode('utf-16le')).decode()], capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))

    def test_confirmation_requires_consumer_and_deadline(self):
        s = SCRIPT.read_text()
        c = s[s.index("} elseif($Mode -eq 'Confirm')"):]
        self.assertIn('if(-not $ConsumerConfirmed)', c)
        self.assertIn('Confirmation too close to rollback deadline', c)
        self.assertLess(c.index('Candidate-Check'), c.index("State 'committed'"))

    def test_recovery_does_not_require_intact_candidate(self):
        s = SCRIPT.read_text()
        self.assertIn("$Mode -in @('Preflight','Launch','Apply') -and $e.replace", s)

    def test_approved_core_registered_in_both_directions_before_service_start(self):
        source = SCRIPT.read_text()
        apply = source[source.index("} elseif($Mode -eq 'Apply')"):source.index("} elseif($Mode -eq 'Confirm')")]
        restore = source[source.index('function Restore-Old'):source.index('function Stop-ApplyWorker')]
        for block in (apply, restore):
            self.assertLess(block.index('Register-ApprovedCore'), block.index('Start-Service'))
        self.assertIn("$c=@(Exact-Processes $ExecutingCore)", source)
        self.assertIn('Core-only mutation boundary mismatch', source)
        self.assertIn('Service owner profile mismatch', source)
        self.assertIn('Executing candidate core mismatch', source)
        self.assertIn('$child.createdUtc', source)
        self.assertNotIn('WriteAllText($Plan.serviceOwnerDirectory', source)
        check = source[source.index('function Check-OwnerRuntime'):source.index('function Preserve-History')]
        self.assertNotIn('Copy(', check)
        self.assertNotIn('WriteAllText', check)

    @unittest.skipUnless(os.name == 'nt', 'Windows PowerShell approved-copy contract')
    def test_approved_core_uses_official_helper_and_verifies_result(self):
        code = r'''
$ErrorActionPreference='Stop'
$env:PSModulePath=(Join-Path $PSHOME 'Modules')
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('__SOURCE__',[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Parse failure'}
$f=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Register-ApprovedCore'},$true)
. ([ScriptBlock]::Create($f.Extent.Text))
$Root=$env:TEMP;$Core='resource';$ExecutingCore='approved';$ApprovalHelper='official';$Plan=@{runtimeLayout='approved'}
function No-Reparse($Path){}
function Hash($Path){if($Path -ceq $Core){return 'expected'};return $script:approvedHash}
function Get-CimInstance($ClassName,$Filter){$null}
function Write-Json($Path,$Value){}
function Start-Process($FilePath,$ArgumentList,$WindowStyle,[switch]$PassThru){
 $script:calls++
 if($FilePath -cne 'official' -or $WindowStyle -cne 'Hidden' -or ($ArgumentList -join '|') -cne '--install-core|"resource"|--sha256|expected'){throw 'Unsupported approval call'}
 $p=[pscustomobject]@{Handle=1;Id=123;ExitCode=$script:helperExit}
 $p|Add-Member ScriptMethod WaitForExit {param($Milliseconds) if($Milliseconds -ne 90000){throw 'Missing bound'};return $true}
 $p|Add-Member ScriptMethod Dispose {}
 return $p
}
$script:calls=0;$script:helperExit=0;$script:approvedHash='expected'
Register-ApprovedCore 'expected'
if($script:calls -ne 1){throw 'Missing official approval'}
foreach($case in @('input','helper','copy')){
 $script:helperExit=0;$script:approvedHash='expected';$expected='expected'
 if($case -eq 'input'){$expected='wrong'}
 if($case -eq 'helper'){$script:helperExit=1}
 if($case -eq 'copy'){$script:approvedHash='wrong'}
 $failed=$false
 try {Register-ApprovedCore $expected}catch{$failed=$true}
 if(-not $failed){throw 'Invalid approval accepted'}
}
'''.replace('__SOURCE__', str(SCRIPT).replace("'", "''"))
        shell = Path(os.environ['WINDIR']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
        result = subprocess.run([str(shell), '-NoProfile', '-NonInteractive', '-EncodedCommand',
                                 base64.b64encode(code.encode('utf-16le')).decode()], capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))

    def test_launch_is_scheduler_owned(self):
        s = SCRIPT.read_text()
        launch = s[s.index("if($Mode -eq 'Launch'){"):s.index("if($Mode -eq 'Watch'){")]
        self.assertIn('-UserId \'SYSTEM\'', launch)
        self.assertIn('Start-ScheduledTask -TaskName $ApplyTaskName', launch)
        self.assertNotIn('Start-Process', launch)

    def test_ui_serialization_requires_pinned_semantic_comparison(self):
        s = SCRIPT.read_text()
        self.assertIn("@('runtime','registry','settings')", s)
        self.assertIn("if((Hash $expected) -cne $e.after)", s)
        self.assertIn("$equal -cne 'STCVRC_YAML_EQUAL'", s)
        self.assertIn('YAML validator hash mismatch', s)
        self.assertNotIn("'Watch','Rollback','Confirm'", s)


if __name__ == '__main__':
    unittest.main()
