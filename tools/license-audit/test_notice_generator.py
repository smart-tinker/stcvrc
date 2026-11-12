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
    return inventory


class NoticeGeneratorBehaviorTests(unittest.TestCase):
    def test_generates_full_sorted_notices_and_source_directions_deterministically(self):
        inventory = inventory_fixture()
        notices, sources = generate_notices(inventory)

        self.assertIn("Fixture-only MIT license text.", notices)
        self.assertIn("Fixture-only Apache license text.", notices)
        self.assertIn("Fixture Rust standard library MIT license text.", notices)
        self.assertIn("Fixture Rust standard library Apache license text.", notices)
        self.assertIn("Rust default features: disabled", notices)
        self.assertIn("Build-time tools (not included in the runtime dependency graph)", notices)
        self.assertEqual(
            {item["name"] for item in sources["components"]},
            {"example.invalid/go-widget", "example-rust-crate", "Rust standard library"},
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
            },
        )
        self.assertEqual(
            generate_notices(inventory),
            (notices, sources),
            "same exact inventory must produce byte-stable notices and source records",
        )

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
