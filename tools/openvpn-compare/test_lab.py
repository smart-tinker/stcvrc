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

    def test_recovery_requires_closed_outage_and_new_working_tunnel(self):
        evidence = dict(
            baseline=True, direct_blocked=True, live=True, inactivity=0,
            server_lost=True, outage_status=502, no_direct_bypass=True,
            server_restarted=True, new_handshake=True, recovered=True,
            recovery_samples=10, expected_recovery_samples=10,
        )
        self.assertEqual(assess('recovery', evidence), 'PASS')
        for field, value in [
            ('outage_status', 200), ('no_direct_bypass', False),
            ('new_handshake', False), ('recovered', False),
            ('recovery_samples', 9),
        ]:
            self.assertEqual(assess('recovery', dict(evidence, **{field:value})), 'FAIL')
        for field in ('server_lost', 'server_restarted'):
            self.assertEqual(assess('recovery', dict(evidence, **{field:False})), 'INVALID')

if __name__ == '__main__': unittest.main()
