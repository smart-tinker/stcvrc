import pathlib
import re
import unittest

HERE = pathlib.Path(__file__).resolve().parent
WORKFLOW = (HERE.parents[1] / ".github/workflows/stcvrc-network-lab.yml").read_text()
SCRIPT = (HERE / "ci.sh").read_text()


class CIContractTests(unittest.TestCase):
    def test_runner_and_review_gates(self):
        self.assertEqual(re.findall(r"runs-on: (.+)", WORKFLOW), ["ubuntu-24.04", "windows-2022"])
        self.assertIn("timeout-minutes: 20", WORKFLOW)
        self.assertIn("!github.event.repository.private", WORKFLOW)
        self.assertIn("!github.event.pull_request.draft", WORKFLOW)
        self.assertIn("github.event.pull_request.head.repo.full_name == github.repository", WORKFLOW)
        self.assertIn("permissions:\n  contents: read", WORKFLOW)

    def test_no_privileged_or_paid_automation_paths(self):
        for forbidden in ("pull_request_target", "workflow_run:", "schedule:", "push:",
                          "uses:", "secrets.", "GITHUB_TOKEN", "GH_TOKEN", "write-all",
                          "upload-artifact", "download-artifact", "actions/cache", "sudo ",
                          "--privileged", "self-hosted", "docker "):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, WORKFLOW + SCRIPT)

    def test_exact_inputs_and_separate_candidate_checkout(self):
        pins = dict(re.findall(r"readonly (\w+)=([0-9a-f]+)\n", SCRIPT))
        self.assertEqual(pins, {
            "SOURCE_COMMIT": "d888dfad5e785217778bb7515c931840d5307dd4",
            "GO_SHA256": "ccfe7ae822d2c2f41f4fe7c956199967a4dac22d0ee0d2b2bfdb440aab3b20c5",
            "XRAY_ZIP_SHA256": "e4bd9119f50ae7c41658b1abd0679ae06f98bd864a2907ff33f2f2cf7081b214",
            "XRAY_SHA256": "cc4b84d3069569f297a61f04b914f2bb37e9d202fd7b84cb50def1fc30fd40e1",
            "CORE_SHA256": "5c811c83dc2f8fae6dcb5933fde988f5d34bb3f87e6dbab6d130aeb30146809a",
        })
        self.assertIn('cd "$work/source"', SCRIPT)
        self.assertIn('-mod=readonly', SCRIPT)
        self.assertIn('--check-tls-rejection', SCRIPT)
        self.assertNotIn('build-windows.ps1', SCRIPT)

    def test_build_temporaries_and_cleanup_are_scoped(self):
        self.assertIn('${RUNNER_TEMP:-$HERE}/stcvrc-ci.XXXXXXXX', SCRIPT)
        self.assertIn('export TMPDIR="$work/tmp" GOTMPDIR="$work/tmp"', SCRIPT)
        self.assertIn('"$work/go/bin/go" clean -modcache', SCRIPT)
        self.assertIn('available_kb < 6 * 1024 * 1024', SCRIPT)
        self.assertNotIn('rm -rf /tmp', SCRIPT)


if __name__ == "__main__":
    unittest.main()
