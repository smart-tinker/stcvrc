import unittest
from lab import assess

class DeadlineEvidenceTests(unittest.TestCase):
    def test_deadline_requires_observed_timeout_and_valid_baseline(self):
        evidence = dict(baseline=True, direct_blocked=True, live=True, inactivity=0)
        self.assertEqual(assess('deadline', evidence), 'FAIL')
        evidence['timeout_observed'] = True
        self.assertEqual(assess('deadline', evidence), 'PASS')
        evidence['baseline'] = False
        self.assertEqual(assess('deadline', evidence), 'INVALID')
