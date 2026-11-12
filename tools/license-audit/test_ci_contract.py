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
                "distribution_status": "draft-prerelease",
                "release_id": 442680453,
                "release_tag": "stcvrc-1.19.33-rc.7",
                "asset_sha256": "d72784d98a44b90e561c701589c50f53074958d7cef656607ee5be1143b36c87",
                "source_commit": "086a62c3ce9a77f650786ae2eae92b68909d49e1",
                "upstream_commit": "3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8",
                "go_version": "1.26.11",
                "go_sha256": "9849f4e04ee35303714e34fbc3ac8ab44ea3e448a95aa182f91e3b9b79c710ec",
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

    def test_mit_lzo_candidate_records_two_identical_fresh_builds(self):
        manifest = json.loads((ROOT / "docs" / "license-provenance.json").read_text(encoding="utf-8"))
        candidate = next(item for item in manifest["variants"] if item["id"] == "candidate-1.19.33-mit-lzo")
        self.assertEqual(
            candidate["fresh_build_evidence"],
            {
                "sha256": "d72784d98a44b90e561c701589c50f53074958d7cef656607ee5be1143b36c87",
                "runs": [
                    "https://github.com/smart-tinker/stcvrc/actions/runs/43016768459",
                    "https://github.com/smart-tinker/stcvrc/actions/runs/43057665817",
                ],
            },
        )

    def test_required_license_job_collects_the_actual_fresh_build_graph(self):
        workflow = (ROOT / ".github/workflows/test.yml").read_text(encoding="utf-8")
        job = workflow.split("\n  license-audit:\n", 1)[1]
        builder = (ROOT / "tools/source-build/ci.sh").read_text(encoding="utf-8")
        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertIn("runs-on: ubuntu-24.04", job)
        self.assertNotRegex(job, r"(?m)^    permissions:")
        self.assertIn('bash "$recipe/tools/source-build/ci.sh"', job)
        self.assertIn('python "$recipe/tools/license-audit/collect.py" --build-root "$root"', builder)
        self.assertIn('go test -tags=with_gvisor -count=1 -timeout=240s github.com/easytier/easytier/easytier-go/...', builder)
        self.assertIn('govulncheck -tags=with_gvisor ./...', builder)
        for forbidden in ("actions/upload-artifact", "actions/cache", "secrets.", "GH_TOKEN", "releases/download"):
            self.assertNotIn(forbidden, job)
        self.assertIn("tools/license-audit/**", workflow)

    def test_release_documentation_links_the_audit_record(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("docs/license-audit.md", readme)

    def test_license_audit_docs_trigger_source_checks(self):
        workflow = (ROOT / ".github" / "workflows" / "test.yml").read_text(encoding="utf-8")
        for path in ("README.md", "docs/license-audit.md", "docs/license-provenance.json", "docs/third-party-notices.md", "candidates/v1.19.33-20261022/**"):
            self.assertIn(
                f"      - {path}",
                workflow,
                f"{path} must remain in push filters; all pull requests run",
            )


    def test_draft_rc7_mit_lzo_candidate_pins_exact_source_and_build(self):
        manifest = json.loads((ROOT / "docs" / "license-provenance.json").read_text(encoding="utf-8"))
        candidate = {item["id"]: item for item in manifest["variants"]}["candidate-1.19.33-mit-lzo"]
        self.assertEqual(candidate["distribution_status"], "draft-prerelease")
        self.assertEqual(candidate["source_commit"], "086a62c3ce9a77f650786ae2eae92b68909d49e1")
        self.assertEqual(candidate["upstream_commit"], "3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8")
        self.assertEqual(candidate["go_version"], "1.26.11")
        self.assertEqual(candidate["go_sha256"], "9849f4e04ee35303714e34fbc3ac8ab44ea3e448a95aa182f91e3b9b79c710ec")
        self.assertEqual(candidate["build"]["source"], "fresh-checkout")
        self.assertEqual(candidate["build"]["target"], "windows/amd64")
        self.assertEqual(candidate["build"]["version"], "1.19.33-STCVRC-candidate-mit-lzo-20261111")
        self.assertEqual(candidate["build"]["build_time"], "2026-11-11T00:00:00Z")
        self.assertEqual(candidate["lzo_decoder"], {
            "module": "github.com/anchore/go-lzo",
            "version": "v0.1.1",
            "go_sum": "h1:IwL/fvkdtlIrYIXck6WxZ3nb8WjjHziYYmGxlooyOnM=",
            "license": "MIT",
            "license_url": "https://github.com/anchore/go-lzo/blob/v0.1.1/LICENSE",
        })
        self.assertEqual(candidate["asset_sha256"], "d72784d98a44b90e561c701589c50f53074958d7cef656607ee5be1143b36c87")
        self.assertEqual(candidate["release_id"], 442680453)
        self.assertEqual(candidate["release_assets"], [
            {"name": "RC-MANIFEST.json", "sha256": "ef81b3f7577ecb681dca400c633d27ca5901fba21d02fdc0548c8ae0c3e22d1f"},
            {"name": "verge-mihomo.exe", "sha256": "d72784d98a44b90e561c701589c50f53074958d7cef656607ee5be1143b36c87"},
        ])
        self.assertEqual(candidate["release_tag"], "stcvrc-1.19.33-rc.7")


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


    def test_codeql_disables_overlay_and_dependency_cache(self):
        codeql = (ROOT / ".github" / "workflows" / "codeql.yml").read_text(encoding="utf-8")
        self.assertIn("CODEQL_OVERLAY_DATABASE_MODE: none", codeql)
        self.assertIn("dependency-caching: false", codeql)
        self.assertNotIn("actions/cache", codeql)


    def test_rc7_mit_lzo_manifest_maps_exact_upstream_source_delta(self):
        manifest = json.loads((ROOT / "docs" / "license-provenance.json").read_text(encoding="utf-8"))
        candidate = {item["id"]: item for item in manifest["variants"]}["candidate-1.19.33-mit-lzo"]
        expected = {
            "adapter/outbound/openvpn.go",
            "adapter/outbound/openvpn_keepalive_test.go",
            "adapter/outboundgroup/urltest.go",
            "adapter/outboundgroup/urltest_test.go",
            "go.mod",
            "go.sum",
            "transport/openvpn/client.go",
            "transport/openvpn/control.go",
            "transport/openvpn/keepalive.go",
            "transport/openvpn/keepalive_lzo_test.go",
            "transport/openvpn/keepalive_test.go",
            "transport/openvpn/lzo.go",
            "transport/openvpn/lzo_test.go",
            "transport/openvpn/push.go",
            "transport/openvpn/push_keepalive_test.go",
            "transport/openvpn/push_retry_test.go",
            "transport/openvpn/rekey_test.go",
        }
        self.assertEqual(set(candidate["upstream_delta_blobs"]), expected)
        for path, blob_sha in candidate["upstream_delta_blobs"].items():
            self.assertRegex(blob_sha, r"^[0-9a-f]{40}$", path)



    def test_mit_lzo_provenance_tracks_current_rc7_draft_assets(self):
        manifest = json.loads((ROOT / "docs" / "license-provenance.json").read_text(encoding="utf-8"))
        candidate = {item["id"]: item for item in manifest["variants"]}["candidate-1.19.33-mit-lzo"]
        self.assertEqual(candidate["release_tag"], "stcvrc-1.19.33-rc.7")
        self.assertEqual(candidate["release_id"], 442680453)
        assets = {item["name"]: item["sha256"] for item in candidate["release_assets"]}
        self.assertEqual(
            assets,
            {
                "RC-MANIFEST.json": "ef81b3f7577ecb681dca400c633d27ca5901fba21d02fdc0548c8ae0c3e22d1f",
                "verge-mihomo.exe": "d72784d98a44b90e561c701589c50f53074958d7cef656607ee5be1143b36c87",
            },
        )

    def test_candidate_source_manifest_matches_the_pinned_binary_provenance(self):
        provenance = json.loads((ROOT / "docs" / "license-provenance.json").read_text(encoding="utf-8"))
        candidate = {item["id"]: item for item in provenance["variants"]}["candidate-1.19.33-mit-lzo"]
        path = ROOT / "candidates" / "v1.19.33-20261022" / "source.json"
        self.assertTrue(path.is_file(), "public candidate source manifest is missing")
        source = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(source["source"]["commit"], candidate["source_commit"])
        self.assertEqual(source["source"]["upstream_tag"], candidate["upstream_tag"])
        self.assertEqual(source["source"]["upstream_commit"], candidate["upstream_commit"])
        self.assertEqual(source["source"]["upstream_delta_blobs"], candidate["upstream_delta_blobs"])
        self.assertEqual(source["binary"]["sha256"], candidate["asset_sha256"])
        self.assertEqual(source["toolchain"]["go_version"], candidate["go_version"])
        self.assertEqual(source["toolchain"]["archive_sha256"], candidate["go_sha256"])
        self.assertEqual(source["binary"]["release_tag"], candidate["release_tag"])
        self.assertEqual(source["binary"]["release_id"], candidate["release_id"])
        self.assertEqual(source["binary"]["manifest_sha256"], candidate["release_assets"][0]["sha256"])


if __name__ == "__main__":
    unittest.main()
