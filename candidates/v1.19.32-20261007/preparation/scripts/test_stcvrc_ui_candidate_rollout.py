"""Exact approved UI pairs; no runtime or network access in these regressions."""
import base64
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import stmc_yaml
from stcvrc_single_egress import four_choice_groups

HERE = Path(__file__).parent
PREPARE = runpy.run_path(str(HERE / 'prepare-stcvrc-safe-rollout.py'))


class CandidateUiTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'nt', 'PowerShell exact UI-pair guard')
    def test_transaction_guard_accepts_only_reviewed_ui_pairs_and_layouts(self):
        code = r'''
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('__SOURCE__',[ref]$tokens,[ref]$errors)
$f=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Guard'},$true)
. ([ScriptBlock]::Create($f.Extent.Text))
$env:COMPUTERNAME='LABHOST';$Root='C:\Users\FixtureUser\stcvrc-fullstack-lab\transactions\stcvrc-safe-20261015-120000'
$Core='C:\Program Files\Clash Verge\verge-mihomo.exe';$ExecutingCore=$Core;$ServiceExe='service';$ApprovalHelper='helper'
$Mode='Watch';$LabPause='None'
function Hash($Path){'fixture'}
function No-Reparse($Path){}
function Assert-UiVersion($Expected){}
function Get-OwnerUiTask {}
function Get-CimInstance($Class,$Filter){@{LocalPath='C:\Users\FixtureUser'}}
$sid='S-1-5-21-1-2-3-1001'
$sha=[Security.Cryptography.SHA256]::Create()
try{$ownerHash=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::ASCII.GetBytes($sid)))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
$app='C:\Users\FixtureUser\AppData\Roaming\io.github.clash-verge-rev.clash-verge-rev'
$targets=@{core=$Core;profile=($app+'\profiles\one.yaml');runtime=($app+'\clash-verge.yaml');registry=($app+'\profiles.yaml');settings=($app+'\verge.yaml')}
$entries=@(foreach($id in $targets.Keys){[pscustomobject]@{id=$id;target=$targets[$id];replace=($id -ceq 'core')}})
$Plan=@{schema=1;host='LABHOST';lab=$true;root=$Root;appRoot=$app;policy='ui-update';runtimeLayout='ui-migration';uiTask='Clash Verge';uiInstallers=@{old='fixture';new='fixture'};settingsExpectedSha256='fixture';ownerRuntimeSha256='fixture';oldOwnerRuntimeSha256='fixture';serviceOwnerSid=$sid;serviceOwnerDirectory=('C:\ProgramData\clash-verge-service\users\'+$ownerHash);scriptSha256='fixture';yamlValidatorSha256='fixture';profileFile='one.yaml';entries=$entries}
foreach($pair in @(@('2.5.2','2.5.5','legacy'),@('2.5.2','2.5.8','legacy'),@('2.5.5','2.5.8','approved'))){
 $Plan.oldUiVersion=$pair[0];$Plan.uiVersion=$pair[1];$Plan.oldRuntimeLayout=$pair[2]
 Guard
}
foreach($pair in @(@('2.5.5','2.5.5','approved'),@('2.5.2','2.5.7','legacy'),@('2.5.5','2.5.8','legacy'))){
 $Plan.oldUiVersion=$pair[0];$Plan.uiVersion=$pair[1];$Plan.oldRuntimeLayout=$pair[2]
 $rejected=$false
 try{Guard}catch{$rejected=$true}
 if(-not $rejected){throw 'Unreviewed pair/layout admitted'}
}
$Plan.oldUiVersion='2.5.5';$Plan.uiVersion='2.5.8';$Plan.oldRuntimeLayout='approved';$Plan.oldOwnerRuntimeSha256='changed'
$rejected=$false
try{Guard}catch{$rejected=$true}
if(-not $rejected){throw 'Owner runtime backup drift admitted'}
'''.replace('__SOURCE__', str(HERE / 'stcvrc-safe-rollout.ps1').replace("'", "''"))
        shell = Path(os.environ['WINDIR']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
        result = subprocess.run([str(shell), '-NoProfile', '-NonInteractive', '-EncodedCommand',
                                 base64.b64encode(code.encode('utf-16le')).decode('ascii')],
                                capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))

    @unittest.skipUnless(os.name == 'nt', 'PowerShell initial layout adapter')
    def test_home_preflight_starts_from_approved_service_layout(self):
        source = (HERE / 'stcvrc-safe-rollout.ps1').read_text()
        initialization = source[source.index("$ApprovedCore="):source.index("$StatePath=")]
        code = r'''
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$Core='C:\Program Files\Clash Verge\verge-mihomo.exe'
$Plan=@{policy='ui-update';runtimeLayout='ui-migration';oldUiVersion='2.5.5';oldRuntimeLayout='approved'}
__INITIALIZATION__
if($ExecutingCore -cne $ApprovedCore -or $ServiceExe -cne 'C:\ProgramData\clash-verge-service\bin\clash-verge-service.exe'){throw 'Home preflight wrongly uses legacy layout'}
'''.replace('__INITIALIZATION__', initialization)
        shell = Path(os.environ['WINDIR']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
        result = subprocess.run([str(shell), '-NoProfile', '-NonInteractive', '-EncodedCommand',
                                 base64.b64encode(code.encode('utf-16le')).decode('ascii')],
                                capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))

    @unittest.skipUnless(os.name == 'nt', 'PowerShell owner-runtime adapter')
    def test_home_runtime_checkpoint_is_before_for_preflight_and_rollback(self):
        code = r'''
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('__SOURCE__',[ref]$tokens,[ref]$errors)
$f=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Check-OwnerRuntime'},$true)
. ([ScriptBlock]::Create($f.Extent.Text))
$Root='C:\fixture';$ApprovedCore='approved';$ExecutingCore='approved'
$Plan=@{policy='ui-update';oldUiVersion='2.5.5';oldRuntimeLayout='approved';serviceOwnerDirectory='C:\owner'}
function Assert-YamlEqual($Expected,$Actual){$script:expected=$Expected}
Check-OwnerRuntime
if($script:expected -cne 'C:\fixture\owner-runtime.before.yaml'){throw 'Old approved owner runtime not checked'}
Check-OwnerRuntime -Candidate
if($script:expected -cne 'C:\fixture\owner-runtime.expected.yaml'){throw 'Candidate runtime not checked'}
'''.replace('__SOURCE__', str(HERE / 'stcvrc-safe-rollout.ps1').replace("'", "''"))
        shell = Path(os.environ['WINDIR']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
        result = subprocess.run([str(shell), '-NoProfile', '-NonInteractive', '-EncodedCommand',
                                 base64.b64encode(code.encode('utf-16le')).decode('ascii')],
                                capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))

    @unittest.skipUnless(os.name == 'nt', 'PowerShell installer adapter')
    def test_downgrade_restores_home_approved_service_not_legacy_work_layout(self):
        code = r'''
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('__SOURCE__',[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Parse failure'}
foreach($name in @('Set-UiLayout','Install-UiGeneration')){
 $f=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
 . ([ScriptBlock]::Create($f.Extent.Text))
}
$Root='C:\fixture';$InstallRoot='C:\Program Files\Clash Verge'
$Core=Join-Path $InstallRoot 'verge-mihomo.exe'
$ApprovedCore='C:\ProgramData\clash-verge-service\cores\verge-mihomo.exe'
$ServiceUninstaller='fixture-service-uninstall.exe';$ServiceName='fixture'
function Test-Path($LiteralPath){$false}
function Get-Service($Name,$ErrorAction){}
function Run-UiInstaller($Path,$Arguments){}
function Assert-UiVersion($Expected){}
function Stop-Runtime {}
function Hash($Path){'fixture-hash'}
function Write-Json($Path,$Value){}
foreach($old in @('2.5.2','2.5.5')){
 $Plan=@{oldUiVersion=$old;uiVersion='2.5.8'}
 Install-UiGeneration $true
 if($ExecutingCore -cne $ApprovedCore){throw 'Candidate did not use approved core'}
 Install-UiGeneration $false
 $expectedCore=if($old -ceq '2.5.2'){$Core}else{$ApprovedCore}
 $expectedService=if($old -ceq '2.5.2'){Join-Path $InstallRoot 'resources\clash-verge-service.exe'}else{'C:\ProgramData\clash-verge-service\bin\clash-verge-service.exe'}
 if($ExecutingCore -cne $expectedCore -or $ServiceExe -cne $expectedService){throw 'Home downgrade incorrectly switched to legacy runtime'}
}
'''.replace('__SOURCE__', str(HERE / 'stcvrc-safe-rollout.ps1').replace("'", "''"))
        shell = Path(os.environ['WINDIR']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
        result = subprocess.run([str(shell), '-NoProfile', '-NonInteractive', '-EncodedCommand',
                                 base64.b64encode(code.encode('utf-16le')).decode('ascii')],
                                capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))

    def test_home_upgrade_uses_actual_owner_runtime_and_restores_approved_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'scripts').mkdir()
            for name in ('stcvrc-safe-rollout.ps1', 'preserve-stcvrc-evidence.ps1'):
                shutil.copyfile(HERE / name, root / 'scripts' / name)
            app = root / 'app'
            (app / 'profiles').mkdir(parents=True)
            sid = 'S-1-5-21-1-2-3-1001'
            profile = {'proxies': [], 'proxy-groups': four_choice_groups(),
                       'rules': ['MATCH,FOREIGN-EGRESS'], 'rule-providers': {},
                       'dns': {'enable': False}, 'tun': {'enable': False},
                       'mixed-port': 7897, 'external-controller': '127.0.0.1:9097',
                       'secret': 'fixture-only'}
            owner = {**profile, 'external-controller-pipe': r'\\.\pipe\verge-mihomo-sidecar-release-' + PREPARE['sha'](sid.encode('ascii'))}
            (root / 'owner.yaml').write_bytes(stmc_yaml.dump(owner))
            app_runtime = {**profile, 'historical-appdata-only': True}
            (app / 'clash-verge.yaml').write_bytes(stmc_yaml.dump(app_runtime))
            (app / 'profiles/one.yaml').write_bytes(stmc_yaml.dump(profile))
            (app / 'profiles.yaml').write_bytes(stmc_yaml.dump({'current': 'one', 'items': [
                {'uid': 'one', 'type': 'local', 'file': 'one.yaml'}]}))
            settings = {'enable_dns_settings': False, 'profile_dns_settings': {'one': {'enabled': False}},
                        'enable_tun_mode': False, 'start_page': '/', 'app_log_max_count': 32}
            (app / 'verge.yaml').write_bytes(stmc_yaml.dump(settings))
            (root / 'selectors.json').write_text(json.dumps({'FOREIGN-EGRESS': 'GC'}))
            pins = copy.deepcopy(PREPARE['STACKS'])
            pins['candidate']['uiVersion'] = '2.5.8'
            for name in ('accepted', 'next', 'candidate'):
                (root / (name + '.exe')).write_bytes(name.encode('ascii'))
                (root / (name + '-setup.exe')).write_bytes((name + '-setup').encode('ascii'))
                pins[name].update(core=name + '.exe', coreSha256=PREPARE['sha'](name.encode('ascii')),
                                  installer=name + '-setup.exe', installerSha256=PREPARE['sha']((name + '-setup').encode('ascii')))
            validator = root / 'validator.exe'
            validator.write_bytes(b'fixture-validator')
            output = root / 'local/transaction'
            argv = ['prepare', '--ui-update', '--source-stack', 'next', '--target-stack', 'candidate',
                    '--lab', '--host', 'LABHOST', '--app-root', str(app), '--old-core', str(root / 'next.exe'),
                    '--candidate-core', str(root / 'candidate.exe'), '--service-owner-sid', sid,
                    '--runtime-config', str(root / 'owner.yaml'), '--yaml-validator', str(validator),
                    '--output', str(output), '--target-app-root', r'C:\Users\FixtureUser\AppData\Roaming\io.github.clash-verge-rev.clash-verge-rev',
                    '--target-transaction-root', r'C:\Users\FixtureUser\stcvrc-fullstack-lab\transactions\stcvrc-safe-20261015-120000',
                    '--selectors-json', str(root / 'selectors.json')]
            with patch.dict(PREPARE['main'].__globals__, PROJECT=root, STACKS=pins), patch.object(sys, 'argv', argv), contextlib.redirect_stdout(io.StringIO()):
                PREPARE['main']()
            plan = json.loads((output / 'plan.json').read_text())
            self.assertEqual((plan['oldUiVersion'], plan['uiVersion']), ('2.5.5', '2.5.8'))
            self.assertEqual((plan['oldVersion'], plan['newVersion']), (pins['next']['coreVersionToken'], pins['candidate']['coreVersionToken']))
            self.assertEqual(plan['sourceStack'], 'next')
            self.assertEqual(plan['targetStack'], 'candidate')
            self.assertEqual(plan['oldRuntimeLayout'], 'approved')
            self.assertEqual(stmc_yaml.load((output / 'owner-runtime.before.yaml').read_bytes()), owner)
            self.assertEqual(stmc_yaml.load((output / 'owner-runtime.expected.yaml').read_bytes()), owner)
            self.assertEqual(stmc_yaml.load((output / 'settings.expected.yaml').read_bytes()), settings)
            runtime_entry = next(entry for entry in plan['entries'] if entry['id'] == 'runtime')
            self.assertEqual(runtime_entry['before'], PREPARE['sha']((app / 'clash-verge.yaml').read_bytes()))
            self.assertEqual([entry['id'] for entry in plan['entries'] if entry['replace']], ['core'])
            self.assertEqual(plan['uiInstallers']['old'], pins['next']['installerSha256'])
            self.assertEqual(plan['uiInstallers']['new'], pins['candidate']['installerSha256'])

            # Work is a separate legacy-layout baseline, not a copied Home plan.
            work_settings = {key: value for key, value in settings.items() if key != 'profile_dns_settings'}
            (app / 'verge.yaml').write_bytes(stmc_yaml.dump(work_settings))
            work_argv = list(argv)
            index = work_argv.index('--runtime-config')
            del work_argv[index:index + 2]
            work_argv[work_argv.index('--source-stack') + 1] = 'accepted'
            work_argv[work_argv.index('--old-core') + 1] = str(root / 'accepted.exe')
            work_output = root / 'local/work-transaction'
            work_argv[work_argv.index('--output') + 1] = str(work_output)
            with patch.dict(PREPARE['main'].__globals__, PROJECT=root, STACKS=pins), patch.object(sys, 'argv', work_argv), contextlib.redirect_stdout(io.StringIO()):
                PREPARE['main']()
            work = json.loads((work_output / 'plan.json').read_text())
            self.assertEqual((work['oldUiVersion'], work['uiVersion']), ('2.5.2', '2.5.8'))
            self.assertEqual(work['oldRuntimeLayout'], 'legacy')
            self.assertEqual(work['oldVersion'], pins['accepted']['coreVersionToken'])
            self.assertEqual(work['uiInstallers']['old'], pins['accepted']['installerSha256'])
            self.assertFalse((work_output / 'owner-runtime.before.yaml').exists())
            expected_work = stmc_yaml.load((work_output / 'owner-runtime.expected.yaml').read_bytes())
            self.assertEqual(expected_work['dns'], app_runtime['dns'])
            self.assertEqual(expected_work['external-controller-pipe'], owner['external-controller-pipe'])

            # Invalid source generation, absent required owner runtime, or crossed
            # legacy/approved snapshots fail before creating any transaction.
            for label, invalid, expected_error in (
                    ('wrong-core', [str(root / 'candidate.exe') if item == str(root / 'next.exe') else item for item in argv], ValueError),
                    ('missing-owner', [item for index, item in enumerate(argv) if index not in (argv.index('--runtime-config'), argv.index('--runtime-config') + 1)], SystemExit),
                    ('legacy-owner', work_argv + ['--runtime-config', str(root / 'owner.yaml')], SystemExit),
                    ('unreviewed-pair', [item if index != argv.index('--target-stack') + 1 else 'next' for index, item in enumerate(argv)], ValueError)):
                invalid_output = root / 'local' / label
                invalid[invalid.index('--output') + 1] = str(invalid_output)
                with self.subTest(rejected=label), patch.dict(PREPARE['main'].__globals__, PROJECT=root, STACKS=pins), patch.object(sys, 'argv', invalid), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(expected_error):
                        PREPARE['main']()
                self.assertFalse(invalid_output.exists())


if __name__ == '__main__':
    unittest.main()
