"""Production Stop-Runtime control flow with temporary files and service effects."""
import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SOURCE = Path(__file__).with_name('stcvrc-safe-rollout.ps1')
SCRATCH = Path(os.environ.get('TMPDIR') or
               Path(os.environ['LOCALAPPDATA']) / 'hermes/cache/scratch')


@unittest.skipUnless(os.name == 'nt', 'Windows PowerShell transaction function')
class StopRuntimeTest(unittest.TestCase):
    def run_scenario(self, scenario):
        with tempfile.TemporaryDirectory(prefix='stcvrc-stop-runtime-', dir=SCRATCH) as temporary:
            root = Path(temporary).resolve()
            core = root / 'core.exe'
            candidate = root / 'candidate.exe'
            core.write_bytes(b'original-core')
            candidate.write_bytes(b'candidate-core')
            code = r"""
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$env:PSModulePath=(Join-Path $PSHOME 'Modules')+';'+(Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules')
Import-Module Microsoft.PowerShell.Utility
[Console]::OutputEncoding=[Text.Encoding]::UTF8
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('__SOURCE__',[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Production source parse failure'}
$function=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Stop-Runtime'},$true)
if(-not $function){throw 'Missing production Stop-Runtime'}
. ([ScriptBlock]::Create($function.Extent.Text))
$scenario='__SCENARIO__';$root='__ROOT__'
$ServiceName='fixture-clash-service';$Ui=Join-Path $root 'ui.exe'
$Core=Join-Path $root 'core.exe';$ExecutingCore=$Core;$ApprovedCore=$Core
$script:events=@();$script:coreEnumerations=0;$script:waitSeconds=$null
$script:controller=[pscustomobject]@{Status=$(if($scenario -ceq 'already-stopped'){'Stopped'}else{'Running'})}
$script:controller|Add-Member ScriptMethod WaitForStatus {
 param($Wanted,$Timeout)
 $script:events+='wait';$script:waitSeconds=$Timeout.TotalSeconds
 if([string]$Wanted -cne 'Stopped' -or $Timeout.TotalSeconds -ne 20){throw 'Wrong bounded stop wait'}
 if($scenario -in @('throw-never-stopped','normal-never-stopped')){throw [TimeoutException]::new('fixture-stop-timeout')}
 $this.Status='Stopped'
}
function Exact-Processes([string]$Path){
 if($Path -cne $Ui){$script:coreEnumerations++}
 return @()
}
function Stop-Process {param($Id,[switch]$Force) throw 'Unexpected real process boundary'}
function Get-Service {param($Name,$ErrorAction)
 if($Name -cne $ServiceName){throw 'Unexpected service identity'}
 if($scenario -ceq 'absent'){return $null}
 return $script:controller
}
function Stop-Service {param($Name,[switch]$Force)
 if($Name -cne $ServiceName -or -not $Force){throw 'Unexpected stop scope'}
 $script:events+='stop'
 if($scenario -ceq 'throw-already-stopped'){$script:controller.Status='Stopped'}
 if($scenario.StartsWith('throw-')){throw [InvalidOperationException]::new('fixture-stop-command-error')}
}
$copied=$false;$failure=$null
try {
 Stop-Runtime
 # Real temporary file mutation stands immediately after the production stop
 # boundary. An unconfirmed stop must never authorize a core replacement.
 [IO.File]::Copy((Join-Path $root 'candidate.exe'),$Core,$true)
 $copied=$true
} catch {$failure=@{type=$_.Exception.GetType().Name;message=$_.Exception.Message}}
@{pass=($null -eq $failure);failure=$failure;copied=$copied;events=$script:events;waitSeconds=$script:waitSeconds;coreEnumerations=$script:coreEnumerations;status=$script:controller.Status}|ConvertTo-Json -Depth 5 -Compress
""".replace('__SOURCE__', str(SOURCE).replace("'", "''")).replace(
                '__ROOT__', str(root).replace("'", "''")).replace('__SCENARIO__', scenario)
            shell = Path(os.environ['WINDIR']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
            completed = subprocess.run(
                [str(shell), '-NoProfile', '-NonInteractive', '-EncodedCommand',
                 base64.b64encode(code.encode('utf-16le')).decode('ascii')],
                capture_output=True, timeout=25)
            self.assertEqual(completed.returncode, 0,
                             completed.stderr.decode('utf-8-sig', errors='replace'))
            observed = json.loads(completed.stdout.decode('utf-8-sig').strip())
            observed['coreBytes'] = core.read_bytes()
            return observed

    def assert_confirmed(self, observed):
        self.assertTrue(observed['pass'], observed)
        self.assertTrue(observed['copied'], observed)
        self.assertEqual(observed['coreBytes'], b'candidate-core')
        self.assertGreater(observed['coreEnumerations'], 0)

    def assert_unconfirmed(self, observed, message):
        self.assertFalse(observed['pass'], observed)
        self.assertFalse(observed['copied'], observed)
        self.assertEqual(observed['coreBytes'], b'original-core')
        self.assertEqual(observed['coreEnumerations'], 0)
        self.assertIn(message, observed['failure']['message'])

    def test_stop_command_error_but_bounded_stopped_confirmation_proceeds(self):
        observed = self.run_scenario('throw-then-stopped')
        self.assert_confirmed(observed)
        self.assertEqual(observed['events'], ['stop', 'wait'])
        self.assertEqual(observed['waitSeconds'], 20)
        self.assertEqual(observed['status'], 'Stopped')

    def test_stop_command_error_after_terminal_stop_is_confirmed(self):
        observed = self.run_scenario('throw-already-stopped')
        self.assert_confirmed(observed)
        self.assertEqual(observed['events'], ['stop', 'wait'])

    def test_failed_stop_without_terminal_confirmation_preserves_core(self):
        observed = self.run_scenario('throw-never-stopped')
        self.assert_unconfirmed(observed, 'fixture-stop-command-error')
        self.assertEqual(observed['waitSeconds'], 20)
        self.assertEqual(observed['status'], 'Running')

    def test_successful_stop_request_without_terminal_confirmation_preserves_core(self):
        observed = self.run_scenario('normal-never-stopped')
        self.assert_unconfirmed(observed, 'fixture-stop-timeout')
        self.assertEqual(observed['waitSeconds'], 20)

    def test_already_stopped_service_does_not_receive_stop(self):
        observed = self.run_scenario('already-stopped')
        self.assert_confirmed(observed)
        self.assertEqual(observed['events'], [])
        self.assertIsNone(observed['waitSeconds'])

    def test_normal_stop_still_requires_bounded_confirmation(self):
        observed = self.run_scenario('normal')
        self.assert_confirmed(observed)
        self.assertEqual(observed['events'], ['stop', 'wait'])
        self.assertEqual(observed['waitSeconds'], 20)

    def test_absent_service_does_not_receive_stop(self):
        observed = self.run_scenario('absent')
        self.assert_confirmed(observed)
        self.assertEqual(observed['events'], [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
