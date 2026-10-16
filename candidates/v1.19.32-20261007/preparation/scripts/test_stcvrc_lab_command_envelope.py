"""Exercise the real lab ps() envelope without importing its CLI or using SSH."""
import ast
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import subprocess
import unittest


HARNESS = Path(__file__).with_name('invoke-uservm-stcvrc-desktop-autostart.py')
TRANSPORT = Path(__file__).with_name('stcvrc_lab_transport.py')
PREFIX = "$ProgressPreference='SilentlyContinue';$ErrorActionPreference='Stop';"


def load_function(path, name, namespace):
    nodes = [node for node in ast.parse(path.read_text(encoding='utf-8')).body
             if isinstance(node, ast.FunctionDef) and node.name == name]
    if len(nodes) != 1:
        raise AssertionError('Expected one production function: ' + name)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), 'exec'), namespace)
    return namespace[name]


class LabCommandEnvelopeTest(unittest.TestCase):
    def setUp(self):
        self.access = {'SSH': 'fixture-ssh.exe',
                       'OPTIONS': ['-F', 'NUL', '-o', 'StrictHostKeyChecking=yes'],
                       'TARGET': 'fixture-user@fixture.invalid'}
        self.calls = []
        self.execute_locally = False
        self.namespace = {'base64': base64, 'gzip': gzip, 'json': json, 'CONNECT_SECONDS': 40,
                          'H': {'ACCESS': self.access}, 'local': Path('fixture-local'),
                          'transport_run': self.transport}
        load_function(TRANSPORT, 'command_budget', self.namespace)
        self.ps = load_function(HARNESS, 'ps', self.namespace)

    def transport(self, argv, timeout, diagnostics, *, read_only=False):
        self.assertEqual(argv[:-1], [self.access['SSH'], *self.access['OPTIONS'],
                         self.access['TARGET'], 'powershell', '-NoProfile',
                         '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand'])
        self.assertLessEqual(len(argv[-1]), 7500)
        self.assertEqual(diagnostics, Path('fixture-local/transport-errors'))
        decoded = base64.b64decode(argv[-1], validate=True).decode('utf-16le')
        self.calls.append({'argv': argv, 'timeout': timeout, 'readOnly': read_only,
                           'decoded': decoded})
        if self.execute_locally:
            # Never run the captured SSH argv: only its decoded PowerShell
            # payload is evaluated by this fixed local Windows executable.
            shell = Path(os.environ['WINDIR']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
            result = subprocess.run([str(shell), '-NoProfile', '-NonInteractive',
                                     '-Command', decoded], capture_output=True, timeout=20)
            if result.returncode:
                raise RuntimeError(result.stderr.decode('utf-8-sig', errors='replace'))
            return result.stdout.decode('utf-8-sig').strip()
        return '{"rootPresent":false}'

    def test_actual_atomic_cleanup_guard_fits_bounded_transport(self):
        source_commands = []

        def record_ps(code, timeout=60, *, read_only=False):
            source_commands.append(code)
            self.assertGreater(len(base64.b64encode((PREFIX + code).encode('utf-16le'))),
                               7500, 'Regression must exercise the real oversized guard')
            return self.ps(code, timeout, read_only=read_only)

        namespace = {'json': json, 'ps': record_ps,
                     'atomic_observer_baseline': lambda: {'rootAbsent': True}}
        cleanup = load_function(HARNESS, 'atomic_observer_cleanup', namespace)
        try:
            result = cleanup(r'C:\Users\FixtureUser\stcvrc-fullstack-lab\transactions\stcvrc-safe-20261016-040000')
        except ValueError as exc:
            self.fail('Actual cleanup guard must reach bounded transport: ' + str(exc))
        self.assertEqual(result, {'rootAbsent': True})
        self.assertEqual(len(source_commands), 1)
        self.assertIn('Observer cleanup claim mismatch', source_commands[0])
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.calls[0]['timeout'], 100)
        self.assertIs(self.calls[0]['readOnly'], True)

    def test_short_command_is_unchanged_with_original_transport_metadata(self):
        code = "'fixture-short'"
        self.ps(code, timeout=91, read_only=False)
        self.assertEqual(self.calls[0]['decoded'], PREFIX + code)
        self.assertEqual(self.calls[0]['timeout'], 131)
        self.assertIs(self.calls[0]['readOnly'], False)

    def test_exact_original_envelope_limit_keeps_direct_payload(self):
        code = next('#' + 'a' * length for length in range(2500, 2900)
                    if len(base64.b64encode((PREFIX + '#' + 'a' * length).encode('utf-16le'))) == 7500)
        self.ps(code)
        self.assertEqual(len(self.calls[0]['argv'][-1]), 7500)
        self.assertEqual(self.calls[0]['decoded'], PREFIX + code)

    @unittest.skipUnless(os.name == 'nt', 'Actual Windows PowerShell bootstrap')
    def test_native_compressed_roundtrip_preserves_unicode_quotes_and_newlines(self):
        original = 'Привет, \'single\' и "double"; $literal `tick\nстрока 2 🧪\n'
        code = '# compressible fixture comment\n' * 160
        code += "$value='" + original.replace("'", "''") + "';"
        code += '[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($value))'
        self.assertGreater(len(base64.b64encode((PREFIX + code).encode('utf-16le'))), 7500)
        self.execute_locally = True
        result = self.ps(code, timeout=17, read_only=True)
        self.assertEqual(base64.b64decode(result, validate=True).decode('utf-8'), original)
        self.assertEqual(self.calls[0]['timeout'], 57)
        self.assertIs(self.calls[0]['readOnly'], True)

    @unittest.skipUnless(os.name == 'nt', 'Actual Windows PowerShell bootstrap')
    def test_native_compressed_payload_error_is_not_swallowed(self):
        code = '# compressible fixture comment\n' * 160
        code += "throw 'fixture-envelope-original-failure'"
        self.execute_locally = True
        with self.assertRaisesRegex(RuntimeError, 'fixture-envelope-original-failure'):
            self.ps(code, read_only=False)
        self.assertEqual(len(self.calls), 1)
        self.assertIs(self.calls[0]['readOnly'], False)

    def test_incompressible_oversize_is_rejected_before_transport(self):
        noise = ''.join(hashlib.sha256(str(index).encode('ascii')).hexdigest()
                        for index in range(1024))
        with self.assertRaisesRegex(ValueError, 'oversized encoded command'):
            self.ps('#' + noise, read_only=False)
        self.assertEqual(self.calls, [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
