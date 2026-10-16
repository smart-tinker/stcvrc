"""Real desktop preflight decisions with fixture inventory; no VM or mutations."""
import ast
import base64
import json
import os
from pathlib import Path
import subprocess
import unittest


HARNESS = Path(__file__).with_name('invoke-uservm-stcvrc-desktop-autostart.py')
APPROVED = 'S-1-5-21-1-2-3-1001'
FOREIGN = 'S-1-5-21-100-200-300-999'


def desktop_preflight():
    tree = ast.parse(HARNESS.read_text(encoding='utf-8'))
    scripts = [node.args[0].value for node in ast.walk(tree)
               if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
               and node.func.id == 'ps' and node.args
               and isinstance(node.args[0], ast.Constant)
               and isinstance(node.args[0].value, str)
               and 'Approved FixtureUser desktop missing' in node.args[0].value]
    if len(scripts) != 1:
        raise AssertionError('Expected one production desktop preflight')
    return scripts[0]


@unittest.skipUnless(os.name == 'nt', 'Production PowerShell desktop preflight')
class DesktopPreflightTest(unittest.TestCase):
    def execute(self, explorers):
        payload = json.dumps([{'SessionId': session, 'OwnerSid': sid,
                               'Name': 'explorer.exe', 'ProcessId': index + 10}
                              for index, (session, sid) in enumerate(explorers)])
        wrapper = r"""
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$env:PSModulePath=(Join-Path $PSHOME 'Modules')+';'+(Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules')
Import-Module Microsoft.PowerShell.Utility
[Console]::OutputEncoding=[Text.Encoding]::UTF8
$env:COMPUTERNAME='LABHOST'
$script:explorers='__FIXTURE__'|ConvertFrom-Json
function Get-CimInstance {
 param($ClassName,$Filter)
 if($ClassName -cne 'Win32_Process'){throw 'Unexpected inventory class'}
 if($Filter -ceq "Name='explorer.exe'"){return $script:explorers}
 if($Filter){throw 'Unexpected inventory filter'}
 return
}
function Invoke-CimMethod {
 param($InputObject,$MethodName)
 if($MethodName -cne 'GetOwnerSid'){throw 'Unexpected inventory method'}
 return [pscustomobject]@{Sid=$InputObject.OwnerSid}
}
function Get-ScheduledTask {param($TaskName,$ErrorAction) return}
function Test-Path {param($LiteralPath) return $false}
function Get-Item {param($LiteralPath,[switch]$Force) return [pscustomobject]@{Attributes=[IO.FileAttributes]::Directory}}
""".replace('__FIXTURE__', payload)
        # Every production system-inventory call above is a fixture. The actual
        # source condition/PowerShell pipeline is evaluated, not reimplemented.
        code = wrapper + '\n' + desktop_preflight() + "\n'PREFLIGHT_PASS'"
        shell = Path(os.environ['WINDIR']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
        return subprocess.run(
            [str(shell), '-NoProfile', '-NonInteractive', '-EncodedCommand',
             base64.b64encode(code.encode('utf-16le')).decode('ascii')],
            capture_output=True, timeout=20)

    def assert_admitted(self, explorers):
        result = self.execute(explorers)
        self.assertEqual(result.returncode, 0, result.stderr.decode('utf-8-sig', errors='replace'))
        self.assertEqual(result.stdout.decode('utf-8-sig').strip(), 'PREFLIGHT_PASS')

    def assert_rejected(self, explorers):
        result = self.execute(explorers)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Approved FixtureUser desktop missing',
                      result.stderr.decode('utf-8-sig', errors='replace'))

    def test_single_approved_explorer_is_admitted(self):
        self.assert_admitted([(1, APPROVED)])

    def test_duplicate_explorers_in_one_approved_session_are_admitted(self):
        self.assert_admitted([(1, APPROVED), (1, APPROVED)])

    def test_no_explorer_is_rejected(self):
        self.assert_rejected([])

    def test_only_foreign_explorers_cannot_grant_authority(self):
        self.assert_rejected([(1, FOREIGN), (1, FOREIGN)])

    def test_approved_session_zero_is_rejected(self):
        self.assert_rejected([(0, APPROVED)])

    def test_two_approved_interactive_sessions_are_rejected(self):
        self.assert_rejected([(1, APPROVED), (2, APPROVED)])

    def test_foreign_explorers_do_not_expand_approved_session(self):
        self.assert_admitted([(1, APPROVED), (2, FOREIGN), (3, FOREIGN)])

    def test_approved_session_zero_does_not_expand_interactive_session(self):
        self.assert_admitted([(1, APPROVED), (0, APPROVED)])


if __name__ == '__main__':
    unittest.main(verbosity=2)
