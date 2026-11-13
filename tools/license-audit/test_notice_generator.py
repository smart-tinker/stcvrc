import copy
import hashlib
import json
import unittest
from pathlib import Path

from generate_notices import AuditIncomplete, generate_notices


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tools" / "license-audit" / "fixtures" / "notice-inventory.json"


def inventory_fixture():
    inventory = json.loads(FIXTURE.read_text(encoding="utf-8"))
    for component in [*inventory["components"], *inventory["build_tools"]]:
        for license_item in component["licenses"]:
            license_item["sha256"] = hashlib.sha256(
                license_item["text"].encode("utf-8")
            ).hexdigest()
    for component in inventory["components"]:
        for notice in component.get("supplemental_notices", []):
            notice["sha256"] = hashlib.sha256(notice["text"].encode("utf-8")).hexdigest()
    return inventory


class NoticeGeneratorBehaviorTests(unittest.TestCase):
    def test_generates_full_sorted_notices_and_source_directions_deterministically(self):
        inventory = inventory_fixture()
        notices, sources = generate_notices(inventory)

        self.assertIn("Fixture-only MIT license text.", notices)
        self.assertIn("Fixture-only Apache license text.", notices)
        self.assertIn("Fixture Rust standard library MIT license text.", notices)
        self.assertIn("Fixture Rust standard library Apache license text.", notices)
        self.assertIn("Fixture Wintun distribution terms.", notices)
        self.assertIn("Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.", notices)
        self.assertIn("Permission is hereby granted", notices)
        self.assertIn("Rust default features: disabled", notices)
        self.assertIn("Build-time tools (not included in the runtime dependency graph)", notices)
        self.assertEqual(
            {item["name"] for item in sources["components"]},
            {"example.invalid/go-widget", "example-rust-crate", "Rust standard library", "wintun.dll", "WireGuard Wintun Go bindings"},
        )
        self.assertTrue(sources["scope"]["rust_no_default_features"])
        self.assertEqual(sources["scope"]["core_size"], 123)
        self.assertEqual(
            {item["name"] for item in sources["build_tools"]},
            {"cargo-about"},
        )
        self.assertEqual(
            {item["source_url"] for item in sources["components"]},
            {
                "https://example.invalid/go-widget/tree/v1.2.3",
                "https://crates.io/crates/example-rust-crate/0.4.2",
                "https://github.com/rust-lang/rust/tree/59807616e1fa2540724bfbac14d7976d7e4a3860",
                "https://www.wintun.net/builds/wintun-0.14.1.zip",
                "https://github.com/MetaCubeX/sing-tun/tree/a128d0c3c8001e041725fa67ff3b521502298f17/internal/wintun",
            },
        )
        wintun = next(item for item in sources["components"] if item["name"] == "wintun.dll")
        self.assertEqual(wintun["licenses"], [])
        self.assertEqual(wintun["source_archive"]["path"], "wintun/bin/amd64/wintun.dll")
        self.assertEqual(
            generate_notices(inventory),
            (notices, sources),
            "same exact inventory must produce byte-stable notices and source records",
        )

    def test_renders_rust_distribution_copyright_as_a_separate_notice(self):
        inventory = inventory_fixture()
        rust_std = next(item for item in inventory["components"] if item["name"] == "Rust standard library")
        text = "<html>Fixture COPYRIGHT-library notice text.</html>\n"
        rust_std["supplemental_notices"] = [{
            "name": "COPYRIGHT-library.html",
            "text": text,
            "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "source_url": "https://github.com/rust-lang/rust/tree/59807616e1fa2540724bfbac14d7976d7e4a3860/src/tools/generate-copyright",
            "source_revision": "59807616e1fa2540724bfbac14d7976d7e4a3860",
            "source_path": "share/doc/rust/COPYRIGHT-library.html",
        }]

        notices, sources = generate_notices(inventory)

        self.assertIn("Fixture COPYRIGHT-library notice text.", notices)
        rust_source = next(item for item in sources["components"] if item["name"] == "Rust standard library")
        self.assertEqual(rust_source["supplemental_notices"][0]["name"], "COPYRIGHT-library.html")
        self.assertEqual(
            rust_source["supplemental_notices"][0]["sha256"],
            hashlib.sha256(text.encode("utf-8")).hexdigest(),
        )

    def test_rejects_missing_or_tampered_rust_copyright_notice(self):
        inventory = inventory_fixture()
        rust_std = next(item for item in inventory["components"] if item["name"] == "Rust standard library")
        rust_std["supplemental_notices"] = [{
            "name": "COPYRIGHT-library.html",
            "text": "tampered",
            "sha256": "0" * 64,
            "source_url": "https://github.com/rust-lang/rust/tree/59807616e1fa2540724bfbac14d7976d7e4a3860/src/tools/generate-copyright",
            "source_revision": "59807616e1fa2540724bfbac14d7976d7e4a3860",
            "source_path": "share/doc/rust/COPYRIGHT-library.html",
        }]

        with self.assertRaises(AuditIncomplete):
            generate_notices(inventory)

    def test_rejects_a_runtime_component_with_missing_license_text(self):
        inventory = inventory_fixture()
        inventory["components"][0]["licenses"][0]["text"] = ""

        with self.assertRaises(AuditIncomplete):
            generate_notices(inventory)

    def test_rejects_a_tampered_license_text_digest(self):
        inventory = inventory_fixture()
        inventory["components"][0]["licenses"][0]["text"] += "tampered\n"

        with self.assertRaises(AuditIncomplete):
            generate_notices(inventory)

    def test_rejects_a_component_without_reproducible_source_direction(self):
        inventory = inventory_fixture()
        del inventory["components"][1]["source_digest"]

        with self.assertRaises(AuditIncomplete):
            generate_notices(inventory)

    def test_rejects_a_missing_package_from_the_independent_dependency_graph(self):
        inventory = inventory_fixture()
        inventory["components"] = inventory["components"][:-1]

        with self.assertRaises(AuditIncomplete):
            generate_notices(inventory)

    def test_rejects_an_unresolved_spdx_result(self):
        inventory = inventory_fixture()
        inventory["components"][0]["licenses"][0]["spdx"] = "NOASSERTION"

        with self.assertRaises(AuditIncomplete):
            generate_notices(inventory)

    def test_rejects_unverifiable_source_digest_algorithm_or_value(self):
        inventory = inventory_fixture()
        inventory["components"][0]["source_digest"] = {
            "algorithm": "made-up-proof",
            "value": "opaque",
        }

        with self.assertRaises(AuditIncomplete):
            generate_notices(inventory)


if __name__ == "__main__":
    unittest.main()
