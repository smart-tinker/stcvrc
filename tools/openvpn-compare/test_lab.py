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
