import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class DistributionAuditContractTests(unittest.TestCase):
    def test_manifest_pins_each_binary_to_fresh_source_and_build_inputs(self):
        path = ROOT / "docs" / "license-provenance.json"
        self.assertTrue(path.is_file(), "distribution provenance manifest is missing")
        manifest = json.loads(path.read_text(encoding="utf-8"))
        variants = {item["id"]: item for item in manifest["variants"]}
        expected = {
            "accepted-1.19.29": {
                "release_tag": "v1.19.29-stcvrc.1",
                "asset_sha256": "71195c943be67017c5646ea2021734bc122fa83c58a408ab6713a2b25cb6b62b",
                "source_commit": "7b93ba0e1439e7f27629743bed550d99e7f9c9a4",
                "upstream_commit": "e26714a181ac0e2fa803453c0a8e9a9ce94e31cb",
                "go_version": "1.26.5",
                "go_sha256": "5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053",
            },
            "candidate-1.19.33-rc.2": {
                "release_tag": "stcvrc-1.19.33-rc.2",
                "asset_sha256": "6a35ab8e2db4c0171f74563aded55949d10a3dcc5ad9c1c1b5e155ab2a2986c7",
                "source_commit": "d888dfad5e785217778bb7515c931840d5307dd4",
                "upstream_commit": "3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8",
                "go_version": "1.26.10",
                "go_sha256": "ccfe7ae822d2c2f41f4fe7c956199967a4dac22d0ee0d2b2bfdb440aab3b20c5",
            },
        }
        self.assertEqual(set(variants), set(expected))
        self.assertEqual(manifest["scope"], "core-binaries-only")
        for key, fields in expected.items():
            item = variants[key]
            for field, value in fields.items():
                self.assertEqual(item[field], value, f"{key}.{field}")
            self.assertEqual(item["build"]["source"], "fresh-checkout")
            self.assertEqual(item["build"]["target"], "windows/amd64")
            self.assertEqual(item["build"]["tags"], ["with_gvisor"])
            self.assertEqual(item["build"]["cgo_enabled"], 0)

    def test_ci_audits_manifest_without_release_binary_artifacts_or_cache(self):
        workflow = (ROOT / ".github" / "workflows" / "test.yml").read_text(encoding="utf-8")
        self.assertIn("license-audit:", workflow, "license audit job is missing")
        self.assertIn("permissions:\n  contents: read", workflow)
        job_lines = []
        in_job = False
        for line in workflow.splitlines():
            if line == "  license-audit:":
                in_job = True
                continue
            if in_job and line.startswith("  ") and not line.startswith("    "):
                break
            if in_job:
                job_lines.append(line)
        job = "\n".join(job_lines)
        for required in (
            "runs-on: ubuntu-24.04",
            '"$dir/go/bin/go"',
            "AUDIT_COMMIT:",
            "git -C \"$audit_root\" fetch",
            "python3 - \"$RUNNER_TEMP/audit-definition\"",
            "root = Path(audit_root)",
            "license_findings=0",
            "report_status=0",
            "save_status=0",
            "go-licenses-report.stderr",
            "go-licenses-save.stderr",
            "chmod -R u+w",
            "manual license review is required",
            "github.com/google/go-licenses/v2@v2.0.1",
            "report .",
            "save . --save_path=",
            "with_gvisor",
            "7b93ba0e1439e7f27629743bed550d99e7f9c9a4",
            "d888dfad5e785217778bb7515c931840d5307dd4",
        ):
            self.assertIn(required, job)
        self.assertIn("go-licenses", job)
        for forbidden in ("actions/upload-artifact", "actions/cache", "secrets.", "releases/download"):
            self.assertNotIn(forbidden, job.lower())
        self.assertIn("tools/license-audit/**", workflow)
        self.assertIn("tools/license-audit", workflow)

    def test_release_documentation_links_the_audit_record(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("docs/license-audit.md", readme)


if __name__ == "__main__":
    unittest.main()
