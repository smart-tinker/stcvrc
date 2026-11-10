import pathlib
import re
import unittest

HERE = pathlib.Path(__file__).resolve().parent
WORKFLOW = (HERE.parents[1] / ".github/workflows/stcvrc-network-lab.yml").read_text()
WORKFLOWS = {path.name: path.read_text() for path in
             (HERE.parents[1] / ".github/workflows").glob("*.y*ml")}
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
        self.assertEqual(set(WORKFLOWS), {"test.yml", "stcvrc-network-lab.yml"})
        release_workflow = WORKFLOWS["test.yml"]
        release_job = release_workflow.split("\n  assemble-draft-rc:\n", 1)[1]
        self.assertIn("github.event_name == 'workflow_dispatch'", release_job)
        self.assertIn("github.repository == 'smart-tinker/stcvrc'", release_job)
        self.assertIn("github.ref == 'refs/heads/codex/cvr-2.5.9-release-cycle-20261102'", release_job)
        self.assertIn("runs-on: ubuntu-24.04", release_job)
        self.assertIn("permissions:\n      contents: write", release_job)
        self.assertIn("!github.event.repository.private", release_job)
        self.assertEqual(release_job.count("GH_TOKEN: ${{ github.token }}"), 1)
        self.assertEqual(release_workflow.count("GH_TOKEN: ${{ github.token }}"), 1)
        self.assertIn('gh api "repos/$repo/releases" --paginate', release_job)
        self.assertIn("releases/assets/$asset_id", release_job)
        self.assertNotIn("releases/tags/$tag", release_job)
        self.assertIn("cmp --silent", release_job)
        self.assertNotIn("GH_TOKEN:", release_workflow.split("\n  assemble-draft-rc:\n", 1)[0])
        for workflow in WORKFLOWS.values():
            self.assertIn("push:\n    branches: [main]", workflow)
            self.assertIn("pull_request:\n    branches: [main]", workflow)
            self.assertIn("permissions:\n  contents: read", workflow)
            self.assertIn("!github.event.repository.private", workflow)
            self.assertIn("!github.event.pull_request.draft", workflow)
            self.assertIn("github.event.pull_request.head.repo.full_name == github.repository", workflow)
            self.assertTrue(set(re.findall(r"runs-on: (.+)", workflow)) <= {"ubuntu-24.04", "windows-2022"})
        for forbidden in ("pull_request_target", "workflow_run:", "schedule:", "tags:",
                          "uses:", "secrets.", "GITHUB_TOKEN", "write-all",
                          "upload-artifact", "download-artifact", "actions/cache", "sudo ",
                          "--privileged", "self-hosted", "docker ", "--force", "/dispatches"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, "\n".join(WORKFLOWS.values()) + SCRIPT)

    def test_draft_rc_waits_for_profile_contract(self):
        release_workflow = WORKFLOWS["test.yml"]
        release_job = release_workflow.split("\n  assemble-draft-rc:\n", 1)[1]
        self.assertIn("needs:\n      - source\n      - profile-contract\n      - cvr-2-5-10-package\n      - cvr-windows-payload", release_job)

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


    def test_windows_installer_update_gate_is_wired_into_existing_runner(self):
        workflow = WORKFLOWS["test.yml"]
        job = workflow.split("\n  cvr-windows-payload:\n", 1)[1].split("\n  assemble-draft-rc:\n", 1)[0]
        self.assertIn("windows_install_update.ps1", job,
                      "pinned Windows install/update smoke is not wired into the existing job")
        self.assertIn("Install 2.5.8 then update to 2.5.10", job)


if __name__ == "__main__":
    unittest.main()
