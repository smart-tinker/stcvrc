"""Real cleanup guard/filesystem regression; no VM, Scheduler, or system paths."""
import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import zipfile


HARNESS = Path(__file__).with_name('invoke-uservm-stcvrc-desktop-autostart.py')
SCRATCH = Path(os.environ.get('TMPDIR') or
               str(Path(os.environ['LOCALAPPDATA']) / 'hermes/cache/scratch'))
OBSERVER = r'C:\ProgramData\STCVRC-observer'


def load_function(name, namespace):
    """Execute the production function only, never its CLI/import entrypoint."""
    nodes = [node for node in ast.parse(HARNESS.read_text(encoding='utf-8')).body
             if isinstance(node, ast.FunctionDef) and node.name == name]
    if len(nodes) != 1:
        raise AssertionError('Expected one production function: ' + name)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(HARNESS), 'exec'),
         namespace)
    return namespace[name]


def tree_bytes(root):
    return {path.relative_to(root).as_posix(): path.read_bytes()
            for path in root.rglob('*') if path.is_file()}


@unittest.skipUnless(os.name == 'nt', 'Real PowerShell cleanup guard')
class AtomicObserverCleanupTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix='stcvrc-atomic-cleanup-', dir=SCRATCH)
        self.addCleanup(self.temporary.cleanup)
        self.sandbox = Path(self.temporary.name).resolve()
        self.root = self.sandbox / 'observer'
        self.transaction = self.sandbox / 'transaction'
        self.control = self.sandbox / 'control'
        self.local = self.sandbox / 'local'
        for path in (self.root, self.transaction, self.control, self.local):
            path.mkdir()
        (self.root / 'data' / 'timeline').mkdir(parents=True)
        (self.root / 'bin').mkdir()
        (self.root / '.stcvrc-observer').write_text('STCVRC_OBSERVER_V1')
        (self.root / '.stcvrc-transaction').write_text(str(self.transaction))
        self.history = b'{"sampleId":"owned-history","checkpoint":"ok"}\n'
        (self.root / 'data' / 'timeline' / 'fixture.jsonl').write_bytes(self.history)
        self.plan = {
            'lab': True, 'host': 'LABHOST', 'root': str(self.transaction),
            'observer': {'root': str(self.root), 'task': 'STCVRC-Observer',
                         'oldPresent': False}}
        self.write_plan()
        self.claim = {'root': str(self.root), 'transaction': str(self.transaction),
                      'planHash': hashlib.sha256(
                          (self.transaction / 'plan.json').read_bytes()).hexdigest()}
        (self.root / '.stcvrc-claim.json').write_text(json.dumps(self.claim), encoding='utf-8')
        self.write_json('observer-created.json', self.claim)
        self.write_json('state.json', {'phase': 'rolled-back'})
        self.write_json('rollback-result.json',
                        {'pass': True, 'observerRestored': True})
        self.calls = []
        self.transfers = []
        self.after_download = None
        namespace = {'json': json, 'ps': self.powershell,
                     'control': str(self.control), 'local': self.local,
                     'download': self.download}
        load_function('atomic_observer_baseline', namespace)
        self.cleanup = load_function('atomic_observer_cleanup', namespace)

    def write_json(self, name, value):
        (self.transaction / name).write_text(json.dumps(value), encoding='utf-8')

    def write_plan(self):
        self.write_json('plan.json', self.plan)
        self.write_json('armed.json', {'planHash': hashlib.sha256(
            (self.transaction / 'plan.json').read_bytes()).hexdigest()})

    def powershell(self, code, **kwargs):
        """Substitute only the fixed lab root and unavailable OS inventory calls.

        All production guard expressions, JSON reads, file checks, compression,
        and deletion execute in real Windows PowerShell on the temporary tree.
        """
        code = code.replace(OBSERVER, str(self.root))
        if OBSERVER in code or 'C:\\Users\\FixtureUser' in code:
            raise AssertionError('Fixture did not isolate a production path')
        self.calls.append(code)
        wrapper = r"""
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$env:PSModulePath=(Join-Path $PSHOME 'Modules')+';'+(Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules')
Import-Module Microsoft.PowerShell.Utility
Import-Module Microsoft.PowerShell.Archive
[Console]::OutputEncoding=[Text.Encoding]::UTF8
$env:COMPUTERNAME='LABHOST'
function Get-ScheduledTask {param($TaskName,$ErrorAction) return}
function Get-CimInstance {param($ClassName) return}
""" + code
        shell = Path(os.environ['WINDIR']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
        completed = subprocess.run(
            [str(shell), '-NoProfile', '-NonInteractive', '-EncodedCommand',
             base64.b64encode(wrapper.encode('utf-16le')).decode('ascii')],
            capture_output=True, timeout=35)
        if completed.returncode:
            raise RuntimeError(completed.stderr.decode('utf-8-sig', errors='replace'))
        return completed.stdout.decode('utf-8-sig').strip()

    def download(self, source, destination):
        source = Path(source).resolve()
        destination = Path(destination).resolve()
        if not source.is_relative_to(self.sandbox) or not destination.is_relative_to(self.sandbox):
            raise AssertionError('Transfer outside test sandbox')
        shutil.copyfile(source, destination)
        self.transfers.append(destination)
        if self.after_download:
            self.after_download()

    def assert_rejected_preserving_tree(self, expected):
        before = tree_bytes(self.root)
        with self.assertRaisesRegex(RuntimeError, expected):
            self.cleanup(str(self.transaction))
        self.assertEqual(tree_bytes(self.root), before)
        self.assertEqual(self.transfers, [])
        self.assertFalse(any('Remove-Item -LiteralPath $root -Recurse' in code
                             for code in self.calls))

    def test_owned_transaction_marker_is_archived_before_exact_cleanup(self):
        try:
            observed = self.cleanup(str(self.transaction))
        except RuntimeError as exc:
            self.fail('Owned rollback remainder must be archived and removed: ' + str(exc))
        self.assertEqual(observed, {'rootAbsent': True, 'taskAbsent': True,
                                    'workersAbsent': True})
        self.assertFalse(self.root.exists())
        self.assertEqual(len(self.transfers), 1)
        with zipfile.ZipFile(self.transfers[0]) as archive:
            rows = {name: archive.read(name) for name in archive.namelist()
                    if not name.endswith('/')}
        self.assertIn(self.history, rows.values())
        self.assertIn(str(self.transaction).encode(), rows.values())
        removal = next(i for i, code in enumerate(self.calls)
                       if 'Remove-Item -LiteralPath $root -Recurse' in code)
        archive = next(i for i, code in enumerate(self.calls)
                       if 'Compress-Archive -LiteralPath $root' in code)
        self.assertLess(archive, removal)

    def assert_hidden_blocks_cleanup(self, path, after_archive=False):
        before = tree_bytes(self.root)
        directories = {item.relative_to(self.root) for item in self.root.rglob('*')
                       if item.is_dir()}
        marked = []

        def mark_hidden():
            self.powershell("$item=Get-Item -LiteralPath '" + str(path) +
                            "' -Force;$item.Attributes=$item.Attributes -bor [IO.FileAttributes]::Hidden")
            self.assertTrue(path.stat().st_file_attributes & 2,
                            'Fixture must set the real Windows Hidden attribute')
            marked.append(path.stat().st_file_attributes)

        if after_archive:
            self.after_download = mark_hidden
        else:
            mark_hidden()
        with self.assertRaisesRegex(RuntimeError, 'Observer cleanup hidden content'):
            self.cleanup(str(self.transaction))
        self.assertEqual(len(marked), 1, 'Hidden fault must actually be injected')
        self.assertTrue(self.root.is_dir())
        self.assertEqual(tree_bytes(self.root), before)
        self.assertEqual({item.relative_to(self.root) for item in self.root.rglob('*')
                          if item.is_dir()}, directories)
        self.assertEqual(path.stat().st_file_attributes, marked[0])
        self.assertEqual(len(self.transfers), 1 if after_archive else 0)

    def test_hidden_data_file_blocks_cleanup(self):
        self.assert_hidden_blocks_cleanup(self.root / 'data/timeline/fixture.jsonl')

    def test_hidden_data_directory_blocks_cleanup(self):
        self.assert_hidden_blocks_cleanup(self.root / 'data/timeline')

    def test_hidden_root_blocks_cleanup(self):
        self.assert_hidden_blocks_cleanup(self.root)

    def test_data_file_hidden_after_archive_blocks_deletion(self):
        self.assert_hidden_blocks_cleanup(self.root / 'data/timeline/fixture.jsonl', True)

    def test_data_directory_hidden_after_archive_blocks_deletion(self):
        self.assert_hidden_blocks_cleanup(self.root / 'data/timeline', True)

    def test_root_hidden_after_archive_blocks_deletion(self):
        self.assert_hidden_blocks_cleanup(self.root, True)

    def test_wrong_observer_marker_is_preserved(self):
        (self.root / '.stcvrc-observer').write_text('FOREIGN_OBSERVER')
        self.assert_rejected_preserving_tree('Observer cleanup marker mismatch')

    def test_foreign_transaction_marker_is_preserved(self):
        (self.root / '.stcvrc-transaction').write_text(str(self.transaction) + '-foreign')
        self.assert_rejected_preserving_tree('Observer')

    def test_missing_embedded_claim_is_preserved(self):
        (self.root / '.stcvrc-claim.json').unlink()
        self.assert_rejected_preserving_tree('Observer')

    def test_embedded_claim_with_foreign_root_is_preserved(self):
        self.claim['root'] = str(self.root) + '-foreign'
        (self.root / '.stcvrc-claim.json').write_text(json.dumps(self.claim), encoding='utf-8')
        self.assert_rejected_preserving_tree('Observer')

    def test_embedded_claim_with_foreign_transaction_is_preserved(self):
        self.claim['transaction'] = str(self.transaction) + '-foreign'
        (self.root / '.stcvrc-claim.json').write_text(json.dumps(self.claim), encoding='utf-8')
        self.assert_rejected_preserving_tree('Observer')

    def test_embedded_claim_with_wrong_plan_hash_is_preserved(self):
        self.claim['planHash'] = '0' * 64
        (self.root / '.stcvrc-claim.json').write_text(json.dumps(self.claim), encoding='utf-8')
        self.assert_rejected_preserving_tree('Observer')

    def test_missing_transaction_marker_is_preserved(self):
        (self.root / '.stcvrc-transaction').unlink()
        self.assert_rejected_preserving_tree('Observer')

    def test_foreign_payload_is_preserved(self):
        (self.root / 'bin' / 'foreign.exe').write_bytes(b'foreign payload')
        self.assert_rejected_preserving_tree('Observer payload or unexpected file remains')

    def test_foreign_plan_path_is_preserved(self):
        self.plan['root'] = str(self.transaction) + '-foreign'
        self.write_plan()
        self.assert_rejected_preserving_tree('Observer lab cleanup scope mismatch')

    def test_foreign_observer_path_is_preserved(self):
        self.plan['observer']['root'] = str(self.root) + '-foreign'
        self.write_plan()
        self.assert_rejected_preserving_tree('Observer lab cleanup scope mismatch')

    def test_claim_change_after_archival_blocks_deletion(self):
        original = tree_bytes(self.root)
        self.after_download = lambda: (self.root / '.stcvrc-transaction').write_text('foreign')
        with self.assertRaisesRegex(RuntimeError, 'Observer'):
            self.cleanup(str(self.transaction))
        self.assertEqual(len(self.transfers), 1, 'Claim must be checked again after archival')
        after = tree_bytes(self.root)
        self.assertEqual(after.pop('.stcvrc-transaction'), b'foreign')
        original.pop('.stcvrc-transaction')
        self.assertEqual(after, original)

    def test_embedded_claim_change_after_archival_blocks_deletion(self):
        original = tree_bytes(self.root)
        foreign = dict(self.claim, transaction=str(self.transaction) + '-foreign')
        foreign_bytes = json.dumps(foreign).encode('utf-8')
        self.after_download = lambda: (self.root / '.stcvrc-claim.json').write_bytes(foreign_bytes)
        with self.assertRaisesRegex(RuntimeError, 'Observer'):
            self.cleanup(str(self.transaction))
        self.assertEqual(len(self.transfers), 1, 'Embedded claim must be checked again after archival')
        after = tree_bytes(self.root)
        self.assertEqual(after.pop('.stcvrc-claim.json'), foreign_bytes)
        original.pop('.stcvrc-claim.json')
        self.assertEqual(after, original)


if __name__ == '__main__':
    unittest.main(verbosity=2)
