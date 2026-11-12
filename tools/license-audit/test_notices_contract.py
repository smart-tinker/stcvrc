import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
EXPECTED = ROOT / "tools" / "license-audit" / "fixtures" / "expected-rc7-sources.json"
PROVENANCE = ROOT / "docs" / "license-provenance.json"
CANDIDATE_SOURCE = ROOT / "candidates" / "v1.19.33-20261022" / "source.json"


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


class NoticeEvidenceTests(unittest.TestCase):
    def test_manual_go_license_evidence_covers_the_eight_candidate_meta_roots(self):
        fixture = load_json(EXPECTED)
        overrides = fixture["meta_gpl_overrides"]
        self.assertEqual(len(overrides), 8)
        self.assertEqual(
            {item["module"] for item in overrides},
            {
                "github.com/metacubex/fswatch",
                "github.com/metacubex/sing",
                "github.com/metacubex/sing-mux",
                "github.com/metacubex/sing-quic",
                "github.com/metacubex/sing-shadowsocks",
                "github.com/metacubex/sing-shadowsocks2",
                "github.com/metacubex/sing-tun",
                "github.com/metacubex/sing-vmess",
            },
        )
        for item in overrides:
            self.assertEqual(item["license_spdx"], "GPL-3.0-or-later")
            self.assertEqual(item["license_path"], "LICENSE")
            self.assertEqual(item["license_git_blob"], "3e3e29e359d205307555aa41f19fb2a8415de885")
            self.assertRegex(item["source_revision"], r"^[0-9a-f]{40}$")
            self.assertEqual(
                item["source_url"],
                f'https://github.com/MetaCubeX/{item["module"].rsplit("/", 1)[1]}/tree/{item["source_revision"]}',
            )

    def test_chacha_license_exception_is_pinned_to_license_only_child(self):
        item = load_json(EXPECTED)["chacha_mit_evidence"]
        self.assertEqual(item["pinned_source_revision"], "07294f500ca8384015f6cc21311de7b6f093607d")
        self.assertEqual(item["license_source_revision"], "7b981d42c3baca5a004e7b0ecfb9b67ee20e583a")
        self.assertEqual(item["license_file_parent"], item["pinned_source_revision"])
        self.assertEqual(item["license_spdx"], "MIT")
        self.assertEqual(item["diff_files"], ["LICENSE"])
        self.assertEqual(len(item["copyrights"]), 2)
        self.assertIn("https://github.com/MetaCubeX/chacha/", item["license_source_url"])

    def test_historical_lzo_risk_is_recorded_without_a_legal_conclusion(self):
        item = load_json(EXPECTED)["historical_lzo_risk"]
        self.assertEqual(item["variants"], ["accepted-1.19.29", "candidate-1.19.33-rc.2"])
        self.assertEqual(item["module"], "github.com/rasky/go-lzo")
        self.assertEqual(item["license_spdx"], "GPL-2.0-only")
        self.assertIn("no infringement conclusion", item["disposition"])

    def test_source_manifest_claims_match_canonical_candidate_build_inputs(self):
        provenance = load_json(PROVENANCE)
        candidate = next(
            item for item in provenance["variants"]
            if item["id"] == "candidate-1.19.33-mit-lzo"
        )
        source = load_json(CANDIDATE_SOURCE)

        self.assertEqual(source["source"]["commit"], candidate["source_commit"])
        self.assertEqual(source["source"]["upstream_tag"], candidate["upstream_tag"])
        self.assertEqual(source["source"]["upstream_commit"], candidate["upstream_commit"])
        self.assertEqual(source["source"]["upstream_delta_blobs"], candidate["upstream_delta_blobs"])
        self.assertEqual(source["binary"]["sha256"], candidate["asset_sha256"])
        self.assertEqual(source["binary"]["release_tag"], candidate["release_tag"])
        self.assertEqual(source["binary"]["release_id"], candidate["release_id"])
        self.assertEqual(source["toolchain"]["go_version"], candidate["go_version"])
        self.assertEqual(source["toolchain"]["archive_sha256"], candidate["go_sha256"])
        for field in ("target", "goamd64", "cgo_enabled", "tags", "flags", "version", "build_time"):
            self.assertEqual(source["toolchain"][field], candidate["build"][field], field)
        self.assertEqual(source["lzo_decoder"], candidate["lzo_decoder"])

    def test_historical_patch_origin_remains_explicitly_unverified(self):
        source = load_json(CANDIDATE_SOURCE)
        manifest = load_json(PROVENANCE)
        candidate = next(
            item for item in manifest["variants"]
            if item["id"] == "candidate-1.19.33-rc.2"
        )
        self.assertIn("unverified", candidate["patch_source_claim"]["status"])
        self.assertNotEqual(
            candidate["patch_source_claim"]["base"],
            candidate["upstream_commit"],
        )


if __name__ == "__main__":
    unittest.main()
