import pathlib
import re
import unittest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
WORKFLOW = (ROOT / ".github/workflows/stcvrc-network-lab.yml").read_text()
WORKFLOWS = {path.name: path.read_text() for path in
             (ROOT / ".github/workflows").glob("*.y*ml")}
SCRIPT = (HERE / "ci.sh").read_text()
DEPENDABOT_PATH = ROOT / ".github/dependabot.yml"
DEPENDABOT = DEPENDABOT_PATH.read_text() if DEPENDABOT_PATH.is_file() else ""


class CIContractTests(unittest.TestCase):
    def test_runner_and_review_gates(self):
        self.assertEqual(re.findall(r"runs-on: (.+)", WORKFLOW), ["ubuntu-24.04", "windows-2022"])
        self.assertIn("timeout-minutes: 20", WORKFLOW)
        self.assertIn("!github.event.repository.private", WORKFLOW)
        self.assertIn("!github.event.pull_request.draft", WORKFLOW)
        self.assertIn("github.event.pull_request.head.repo.full_name == github.repository", WORKFLOW)
        self.assertIn("permissions:\n  contents: read", WORKFLOW)

    def test_no_privileged_or_paid_automation_paths(self):
        self.assertEqual(set(WORKFLOWS), {
            "test.yml",
            "stcvrc-network-lab.yml",
            "codeql.yml",
            "dependency-review.yml",
        })
        for name, workflow in WORKFLOWS.items():
            self.assertIn("pull_request:\n    branches: [main]", workflow, name)
            self.assertIn("permissions:\n  contents: read", workflow, name)
            self.assertIn("!github.event.repository.private", workflow, name)
            self.assertIn("!github.event.pull_request.draft", workflow, name)
            self.assertIn("github.event.pull_request.head.repo.full_name == github.repository", workflow, name)
            self.assertTrue(set(re.findall(r"runs-on: (.+)", workflow)) <= {"ubuntu-24.04", "windows-2022"})
        for name in ("test.yml", "stcvrc-network-lab.yml", "codeql.yml"):
            self.assertIn("push:\n    branches: [main]", WORKFLOWS[name], name)

        refs = re.findall(r"^\s*uses:\s*([^\s#]+)", "\n".join(WORKFLOWS.values()), re.MULTILINE)
        self.assertEqual({ref.split("@", 1)[0] for ref in refs}, {
            "actions/checkout",
            "github/codeql-action/init",
            "github/codeql-action/analyze",
            "actions/dependency-review-action",
        })
        self.assertTrue(all(re.fullmatch(r"[^@]+@[0-9a-f]{40}", ref) for ref in refs))
        self.assertIn("security-events: write", WORKFLOWS["codeql.yml"])
        self.assertIn("actions: read", WORKFLOWS["codeql.yml"])
        self.assertNotIn("security-events: write", WORKFLOWS["dependency-review.yml"])

        for forbidden in ("pull_request_target", "workflow_run:", "schedule:", "tags:",
                          "secrets.", "GITHUB_TOKEN", "GH_TOKEN", "write-all",
                          "upload-artifact", "download-artifact", "actions/cache", "sudo ",
                          "--privileged", "self-hosted", "docker ", "--force", "/dispatches"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, "\n".join(WORKFLOWS.values()) + SCRIPT)

    def test_weekly_grouped_dependabot_updates(self):
        self.assertTrue(DEPENDABOT, "missing .github/dependabot.yml")
        ecosystems = re.findall(r"^  - package-ecosystem: (.+)$", DEPENDABOT, re.MULTILINE)
        directories = re.findall(r"^    directory: (.+)$", DEPENDABOT, re.MULTILINE)
        self.assertEqual(ecosystems, ["gomod", "gomod", "github-actions"])
        self.assertEqual(directories, ["/", "/test", "/"])
        self.assertEqual(DEPENDABOT.count("interval: weekly"), 3)
        self.assertEqual(len(re.findall(r"^        - \"\*\"$", DEPENDABOT, re.MULTILINE)), 3)
        self.assertEqual(DEPENDABOT.count("update-types:"), 3)

    def test_dependabot_changes_run_the_contract_check(self):
        self.assertEqual(WORKFLOWS["test.yml"].count(".github/dependabot.yml"), 2)

    def test_templates_capture_downstream_evidence_and_privacy(self):
        bug = (ROOT / ".github/ISSUE_TEMPLATE/bug_report.yml").read_text()
        feature = (ROOT / ".github/ISSUE_TEMPLATE/feature_request.yml").read_text()
        pr = (ROOT / ".github/PULL_REQUEST_TEMPLATE.md").read_text()

        for required in ("STCVRC version", "Source commit", "Binary SHA-256",
                         "Expected result", "Observed result", "Redacted profile/config",
                         "Do not include credentials"):
            with self.subTest(required=required):
                self.assertIn(required, bug)
        self.assertNotIn("mihomo Alpha", bug)
        self.assertNotIn("log level set to `DEBUG`", bug)
        self.assertNotIn("log level 使用 DEBUG", bug)
        self.assertIn("https://github.com/smart-tinker/stcvrc/issues", bug)

        for required in ("Required scenario and upstream gap", "sanitized evidence",
                         "Definition of Done", "Upstream exit and stop conditions"):
            with self.subTest(required=required):
                self.assertIn(required, feature)
        for required in ("Exact tested revision / evidence", "RED must fail",
                         "Native Windows", "No secrets/private operational data"):
            with self.subTest(required=required):
                self.assertIn(required, pr)

        self.assertEqual(WORKFLOWS["test.yml"].count(".github/ISSUE_TEMPLATE/**"), 2)
        self.assertEqual(WORKFLOWS["test.yml"].count(".github/PULL_REQUEST_TEMPLATE.md"), 2)

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
