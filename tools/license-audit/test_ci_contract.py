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
            "candidate-1.19.33-mit-lzo": {
                "distribution_status": "unpublished-candidate",
                "release_tag": None,
                "asset_sha256": None,
                "source_commit": "92107a2605e19df0cb0d8b7bb08aa9ffb6b7ee93",
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

    def test_unpublished_mit_lzo_candidate_records_two_identical_fresh_builds(self):
        manifest = json.loads((ROOT / "docs" / "license-provenance.json").read_text(encoding="utf-8"))
        candidate = next(item for item in manifest["variants"] if item["id"] == "candidate-1.19.33-mit-lzo")
        self.assertEqual(
            candidate["fresh_build_evidence"],
            {
                "sha256": "c00707e061c91fd5bfa5b3a88653597b00ae1ffad39ba33221e5c8cad1eefcbf",
                "runs": [
                    "https://github.com/smart-tinker/stcvrc/actions/runs/42723333952",
                    "https://github.com/smart-tinker/stcvrc/actions/runs/42726584980",
                ],
            },
        )

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
            'mkdir -p "$gopath" "$modcache" "$gocache" "$gobin"',
            'test ! -e "$licenses"',
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
        self.assertNotIn('mkdir -p "$gopath" "$modcache" "$gocache" "$gobin" "$licenses"', job)
        self.assertLess(job.index('test ! -e "$licenses"'), job.index('"$gobin/go-licenses" save'))
        for forbidden in ("actions/upload-artifact", "actions/cache", "secrets.", "releases/download"):
            self.assertNotIn(forbidden, job.lower())
        self.assertIn("tools/license-audit/**", workflow)
        self.assertIn("tools/license-audit", workflow)

    def test_release_documentation_links_the_audit_record(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("docs/license-audit.md", readme)

    def test_license_audit_docs_trigger_source_checks(self):
        workflow = (ROOT / ".github" / "workflows" / "test.yml").read_text(encoding="utf-8")
        for path in ("README.md", "docs/license-audit.md", "docs/license-provenance.json", "docs/third-party-notices.md"):
            self.assertGreaterEqual(
                workflow.count(f"      - {path}"),
                2,
                f"{path} edits must trigger both push and pull_request checks",
            )

    def test_incomplete_and_unknown_report_status_survives_summary_pipeline(self):
        workflow = (ROOT / ".github" / "workflows" / "test.yml").read_text(encoding="utf-8")
        report_start = workflow.index("            local report_status=0")
        report_pipeline_end = workflow.index('            } | tee -a "$GITHUB_STEP_SUMMARY"', report_start)
        save_start = workflow.index("            local save_status=0", report_pipeline_end)
        report_section = workflow[report_start:save_start]
        finding = report_section.index("license_findings=1")
        self.assertGreater(
            finding,
            report_pipeline_end - report_start,
            "license finding state must be set after the piped summary group",
        )
        self.assertIn('tolower($3) == "unknown"', report_section, "unclassified license rows must require manual review")


    def test_unpublished_mit_lzo_candidate_pins_exact_source_and_build(self):
        manifest = json.loads((ROOT / "docs" / "license-provenance.json").read_text(encoding="utf-8"))
        candidate = {item["id"]: item for item in manifest["variants"]}["candidate-1.19.33-mit-lzo"]
        self.assertEqual(candidate["distribution_status"], "unpublished-candidate")
        self.assertEqual(candidate["source_commit"], "92107a2605e19df0cb0d8b7bb08aa9ffb6b7ee93")
        self.assertEqual(candidate["upstream_commit"], "3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8")
        self.assertEqual(candidate["go_version"], "1.26.10")
        self.assertEqual(candidate["go_sha256"], "ccfe7ae822d2c2f41f4fe7c956199967a4dac22d0ee0d2b2bfdb440aab3b20c5")
        self.assertEqual(candidate["build"]["source"], "fresh-checkout")
        self.assertEqual(candidate["build"]["target"], "windows/amd64")
        self.assertEqual(candidate["build"]["version"], "1.19.33-STCVRC-candidate-mit-lzo-20261109")
        self.assertEqual(candidate["build"]["build_time"], "2026-11-09T00:00:00Z")
        self.assertEqual(candidate["lzo_decoder"], {
            "module": "github.com/anchore/go-lzo",
            "version": "v0.1.1",
            "go_sum": "h1:IwL/fvkdtlIrYIXck6WxZ3nb8WjjHziYYmGxlooyOnM=",
            "license": "MIT",
            "license_url": "https://github.com/anchore/go-lzo/blob/v0.1.1/LICENSE",
        })
        self.assertIsNone(candidate["asset_sha256"])
        self.assertIsNone(candidate["release_tag"])

    def test_license_ci_builds_the_exact_unpublished_mit_lzo_source(self):
        workflow = (ROOT / ".github" / "workflows" / "test.yml").read_text(encoding="utf-8")
        for required in (
            "candidate-1.19.33-mit-lzo",
            "92107a2605e19df0cb0d8b7bb08aa9ffb6b7ee93",
            "github.com/anchore/go-lzo v0.1.1",
            "github.com/anchore/go-lzo v0.1.1 h1:IwL/fvkdtlIrYIXck6WxZ3nb8WjjHziYYmGxlooyOnM=",
            "github.com/rasky/go-lzo",
            '$1 == "github.com/anchore/go-lzo" && $3 == "MIT"',
            "No published reference asset; candidate SHA256 is recorded only",
        ):
            self.assertIn(required, workflow)


    def test_public_notice_includes_mit_lzo_and_flags_unresolved_chacha(self):
        path = ROOT / "docs" / "third-party-notices.md"
        self.assertTrue(path.is_file(), "public third-party notice file is missing")
        notices = path.read_text(encoding="utf-8")
        lzo_section = notices.split("## github.com/anchore/go-lzo v0.1.1", 1)[1]
        lzo_section = lzo_section.split("\n## github.com/metacubex/chacha", 1)[0]
        self.assertIn("https://github.com/anchore/go-lzo/blob/v0.1.1/LICENSE", lzo_section)
        fence = chr(96) * 3 + "text\n"
        license_text = lzo_section.split(fence, 1)[1].split("\n" + chr(96) * 3, 1)[0]
        self.assertEqual(
            license_text,
            """MIT License

Copyright (c) 2025 Anchore, Inc

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.""",
        )

        chacha_section = notices.split("## github.com/metacubex/chacha v0.1.5", 1)[1]
        self.assertIn("07294f500ca8384015f6cc21311de7b6f093607d", chacha_section)
        self.assertIn("7b981d42c3baca5a004e7b0ecfb9b67ee20e583a", chacha_section)
        self.assertIn("has the exact pinned v0.1.5 commit as its parent", chacha_section)
        self.assertIn("adds only the root `LICENSE` file", chacha_section)
        self.assertIn("scanner still reports `Unknown` for v0.1.5", chacha_section)
        self.assertIn("not a legal-compliance conclusion", chacha_section)
        self.assertIn("https://github.com/MetaCubeX/chacha/commit/7b981d42c3baca5a004e7b0ecfb9b67ee20e583a", chacha_section)
        self.assertIn("Copyright (c) 2016 Andreas Auernhammer", chacha_section)
        self.assertIn("Copyright (c) 2025 MetaCubex", chacha_section)
        self.assertIn("Permission is hereby granted, free of charge, to any person obtaining a copy", chacha_section)


if __name__ == "__main__":
    unittest.main()
