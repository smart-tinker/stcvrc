import unittest
from lab import assess

class EvidenceTests(unittest.TestCase):
    def test_rekey_needs_two_epochs_and_continuous_stream(self):
        good = dict(baseline=True, direct_blocked=True, samples=100, expected=100,
                    rekeys=2, epochs=2, post_epoch_samples=20, inactivity=0, live=True)
        self.assertEqual(assess('rekey', good), 'PASS')
        for field, value in [('samples', 99), ('rekeys', 0), ('epochs', 0), ('post_epoch_samples', 0), ('live', False)]:
            self.assertEqual(assess('rekey', dict(good, **{field:value})), 'FAIL')
    def test_no_baseline_or_direct_bypass_is_invalid_not_upstream_bug(self):
        for field in ('baseline', 'direct_blocked'):
            self.assertEqual(assess('idle', {field:False}), 'INVALID')
    def test_idle_requires_no_server_timeout(self):
        evidence = dict(baseline=True, direct_blocked=True, live=True,
                        resumed=True, inactivity=1)
        self.assertEqual(assess('idle', evidence), 'FAIL')
        evidence['inactivity'] = 0
        self.assertEqual(assess('idle', evidence), 'PASS')

if __name__ == '__main__': unittest.main()

class ReportTests(unittest.TestCase):
    def test_missing_test_and_package_failure_cannot_pass(self):
        import json
        import pathlib
        import subprocess
        import sys
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            for variant in ('upstream','stcvrc'):
                for scenario in ('idle','rekey'):
                    (root/f'{variant}-{scenario}.json').write_text('{"verdict":"PASS"}')
                (root/f'url-{variant}.status').write_text('0')
            tests = [{'Test':name,'Action':'pass'} for name in
                     ('TestURLTestTolerance','TestURLTestSelectionLifecycle')]
            for events, status, expected in [(tests+[{'Action':'pass'}],0,'PASS'),
                                             (tests+[{'Action':'fail'}],1,'FAIL'),
                                             (tests[:1]+[{'Action':'pass'}],0,'INVALID')]:
                for variant in ('upstream','stcvrc'):
                    (root/f'url-{variant}.jsonl').write_text('\n'.join(map(json.dumps,events)))
                    (root/f'url-{variant}.status').write_text(str(status))
                result = subprocess.run([sys.executable,str(pathlib.Path(__file__).with_name('report.py')),d],
                                        text=True,capture_output=True)
                self.assertIn(f'| URLTest tolerance/lifecycle | {expected} | {expected} |', result.stdout)
                self.assertEqual(result.returncode, 1 if expected == 'INVALID' else 0)
