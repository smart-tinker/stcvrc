"""Installer boundaries without touching a real task, service or ProgramData."""
import base64
import ast
import os
from pathlib import Path
import subprocess
import unittest

SCRIPT = Path(__file__).with_name('install-stcvrc-observer-lab.ps1')


class ObserverInstallerTest(unittest.TestCase):
    @unittest.skipUnless(os.name == 'nt', 'PowerShell sampler syntax')
    def test_production_resource_sample_is_bounded_and_not_zero_on_missing_worker(self):
        source=SCRIPT.with_name('invoke-uservm-stcvrc-desktop-autostart.py').read_text()
        function=next(node for node in ast.parse(source).body
                      if isinstance(node,ast.FunctionDef) and node.name=='observer_sample')
        code=next(node.value for node in ast.walk(function)
                  if isinstance(node,ast.Constant) and isinstance(node.value,str)
                  and '$observedRunning=$false' in node.value)
        self.assertIn('AddSeconds(55)',code)
        self.assertLess(code.index('Start-ScheduledTask'),code.index('Get-CimInstance Win32_Process'))
        self.assertIn('completeCpuAccounting=$false',code)
        self.assertIn("resource['sampleCount']<1",source)
        encoded=base64.b64encode(code.encode('utf-8')).decode()
        check="$code=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"+encoded+"'));$t=$null;$e=$null;$null=[Management.Automation.Language.Parser]::ParseInput($code,[ref]$t,[ref]$e);if($e.Count){throw 'Sampler syntax'}"
        shell=Path(os.environ['WINDIR'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
        result=subprocess.run([str(shell),'-NoProfile','-NonInteractive','-EncodedCommand',
            base64.b64encode(check.encode('utf-16le')).decode()],capture_output=True,timeout=20)
        self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace'))

    def test_production_acceptance_is_guarded_uservm_only_and_restores_history(self):
        harness=SCRIPT.with_name('invoke-uservm-stcvrc-desktop-autostart.py').read_text()
        restore=SCRIPT.with_name('uservm-stcvrc-desktop-autostart.remote.ps1').read_text()
        self.assertIn('-Production -ExpectedComputerName LABHOST -Label home',harness)
        self.assertIn("args.observer_production and (not args.observer_bundle or args.stack not in ('next','candidate'))",harness)
        self.assertIn('productionRemoveTaskPreservesHistory',harness)
        self.assertIn("report['observerRootAbsent']",harness)
        self.assertIn("'error': None, 'pass':False",harness)
        self.assertIn("$sid -ceq 'S-1-5-18'",harness)
        self.assertIn('Translate([Security.Principal.SecurityIdentifier]).Value',harness)
        self.assertNotIn("$task.Principal.UserId -in @('SYSTEM','S-1-5-18')",harness)
        self.assertIn("'STCVRC-Observer*'",harness)
        block=restore[restore.index("} elseif($Action -eq 'Restore'){"):]
        self.assertLess(block.index("'observer-production.run'"),block.index('Read-Driver Cleanup'))
        self.assertIn("ReadAllText($observerIntent) -cne $runId",block)
        self.assertIn('-Action RemoveTask -Production -ExpectedComputerName LABHOST',block)
        self.assertNotIn('Remove-Item -LiteralPath $observerIntent',block)

    @unittest.skipUnless(os.name == 'nt', 'Windows PowerShell scope evaluation')
    def test_scopes_and_rejected_targets(self):
        code = r'''
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('__SOURCE__',[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Installer parse failure'}
$f=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Resolve-ObserverScope'},$true)
. ([ScriptBlock]::Create($f.Extent.Text))
$sid='S-1-5-21-1-2-3-1001'
$lab=Resolve-ObserverScope $false '' 'lab' '' 'LABHOST'
if($lab.root -cne 'C:\ProgramData\STCVRC-observer-lab' -or $lab.task -cne 'STCVRC-Observer-Lab'){throw 'Lab contract changed'}
foreach($label in @('home','work')){
 $prod=Resolve-ObserverScope $true 'FIXTURE' $label $sid 'FIXTURE'
 if($prod.root -cne 'C:\ProgramData\STCVRC-observer' -or $prod.task -cne 'STCVRC-Observer' -or $prod.value -cne 'STCVRC_OBSERVER_V1'){throw 'Production scope mismatch'}
}
$invalid=@(
 @($true,'OTHER','home',$sid,'FIXTURE'),
 @($true,'','home',$sid,'FIXTURE'),
 @($true,'FIXTURE','lab',$sid,'FIXTURE'),
 @($true,'FIXTURE','home','invalid','FIXTURE'),
 @($false,'','home','','LABHOST'),
 @($false,'','lab','','FIXTURE')
)
foreach($case in $invalid){
 $failed=$false
 try {$null=Resolve-ObserverScope @case}catch{$failed=$true}
 if(-not $failed){throw 'Unbound install accepted'}
}
'''.replace('__SOURCE__', str(SCRIPT).replace("'", "''"))
        shell = Path(os.environ['WINDIR']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
        result = subprocess.run([str(shell), '-NoProfile', '-NonInteractive', '-EncodedCommand',
                                 base64.b64encode(code.encode('utf-16le')).decode()],
                                capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))

    def test_input_checks_before_install_and_protected_copy_before_task(self):
        source = SCRIPT.read_text()
        mutation = source.index('$null=New-Item -ItemType Directory -Path $root')
        for check in ('Owner profile differs', 'Unreviewed owner-scoped UI version',
                      'Incomplete package manifest', 'Package hash mismatch',
                      'Assert-NoReparse $path', 'Unexpected lab app root'):
            self.assertLess(source.index(check), mutation)
        self.assertLess(source.index('Set-Acl -LiteralPath $root'), source.index('Copy-Item -LiteralPath'))
        self.assertLess(source.index('Protected manifest hash mismatch'), source.index('Register-ScheduledTask'))
        self.assertIn("@('S-1-5-18','S-1-5-32-544')", source)
        self.assertIn('$acl.SetAccessRuleProtection($true,$false)', source)

    def test_one_boot_minute_task_no_wake_no_runtime_control(self):
        source = SCRIPT.read_text()
        self.assertEqual(source.count('$null=Register-ScheduledTask'), 1)
        self.assertIn('New-ScheduledTaskTrigger -AtStartup', source)
        self.assertIn('-RepetitionInterval (New-TimeSpan -Minutes 1)', source)
        self.assertIn('-MultipleInstances IgnoreNew', source)
        self.assertIn("-UserId 'SYSTEM'", source)
        self.assertIn('--service-owner-sid ', source)
        for forbidden in ('-WakeToRun', 'Restart-Service', 'Stop-Service', 'Set-NetRoute',
                          'New-NetRoute', 'Remove-Item', 'controllerSecret'):
            self.assertNotIn(forbidden, source)

    def test_remove_task_preserves_history_and_requires_ownership(self):
        source = SCRIPT.read_text()
        removal = source[source.index("if($Action -eq 'RemoveTask')") :]
        self.assertIn("ReadAllText((Join-Path $root $marker)) -cne $markerValue", removal)
        self.assertIn('@($task.Actions).Count -ne 1', removal)
        self.assertLess(removal.index('Unexpected task action'), removal.index('Stop-ScheduledTask'))
        self.assertNotIn('Remove-Item', removal)


if __name__ == '__main__':
    unittest.main()
