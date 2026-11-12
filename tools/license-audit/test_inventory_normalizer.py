import json
import unittest
from pathlib import Path

from generate_notices import AuditIncomplete
from normalize_inventory import normalize_inventory


FIXTURE = Path(__file__).resolve().parent / "fixtures" / "tool-output-bundle.json"


def load_bundle():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


class ToolOutputNormalizationTests(unittest.TestCase):
    def test_normalizes_selected_go_and_rust_runtime_graphs(self):
        inventory = normalize_inventory(load_bundle())
        names = {item["name"] for item in inventory["components"]}

        self.assertEqual(
            names,
            {"example.com/go-widget", "easytier-core", "example-rust-crate", "Go standard library", "github.com/easytier/easytier/easytier-go"},
        )
        self.assertEqual(
            set(inventory["required_components"]),
            {
                "go:example.com/go-widget@v1.2.3",
                "go:github.com/easytier/easytier/easytier-go@source-222222222222",
                "rust:easytier-core@1.0.0",
                "rust:example-rust-crate@0.4.2",
                "go-toolchain-runtime:Go standard library@1.26.11",
            },
        )
        rendered = json.dumps(inventory, sort_keys=True)
        self.assertNotIn("/tmp/easytier", rendered)
        self.assertNotIn("/cargo/registry", rendered)

    def test_rejects_a_runtime_crate_with_no_cargo_about_license_text(self):
        bundle = load_bundle()
        bundle["rust"]["about"]["licenses"] = []

        with self.assertRaisesRegex(AuditIncomplete, "license"):
            normalize_inventory(bundle)

    def test_rejects_a_runtime_crate_without_a_registry_source_checksum(self):
        bundle = load_bundle()
        bundle["rust"]["cargo_lock_text"] = (
            'version = 4\n\n'
            '[[package]]\nname = "example-rust-crate"\nversion = "0.4.2"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
        )

        with self.assertRaisesRegex(AuditIncomplete, "checksum"):
            normalize_inventory(bundle)


if __name__ == "__main__":
    unittest.main()
