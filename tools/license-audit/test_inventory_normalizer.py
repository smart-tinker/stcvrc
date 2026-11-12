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
            {"example.com/go-widget", "easytier-core", "example-rust-crate", "Go standard library", "Rust standard library", "google.golang.org/protobuf", "github.com/easytier/easytier/easytier-go"},
        )
        self.assertEqual(
            set(inventory["required_components"]),
            {
                "go:example.com/go-widget@v1.2.3",
                "go:github.com/easytier/easytier/easytier-go@source-222222222222",
                "rust:easytier-core@1.0.0",
                "rust:example-rust-crate@0.4.2",
                "go-toolchain-runtime:Go standard library@1.26.11",
                "rust-toolchain-runtime:Rust standard library@1.95.0",
                "go:google.golang.org/protobuf@v1.34.2",
            },
        )
        rendered = json.dumps(inventory, sort_keys=True)
        self.assertNotIn("/tmp/easytier", rendered)
        self.assertNotIn("/cargo/registry", rendered)

    def test_replaced_module_uses_replacement_source_and_checksum(self):
        inventory = normalize_inventory(load_bundle())
        component = next(item for item in inventory["components"] if item["name"] == "google.golang.org/protobuf")

        self.assertEqual(component["source_url"], "https://proxy.golang.org/github.com/metacubex/protobuf-go/@v/v0.0.0-20260306035419-7ceee0674686.zip")
        self.assertEqual(component["source_digest"], {"algorithm": "go.sum-h1", "value": "h1:" + ("I" * 43) + "="})
        self.assertEqual(component["upstream_module_version"], "v1.34.2")

    def test_rejects_a_runtime_crate_with_no_cargo_about_license_text(self):
        bundle = load_bundle()
        bundle["rust"]["about"]["licenses"] = []

        with self.assertRaises(AuditIncomplete):
            normalize_inventory(bundle)

    def test_rejects_a_runtime_crate_without_a_registry_source_checksum(self):
        bundle = load_bundle()
        bundle["rust"]["cargo_lock_text"] = (
            'version = 4\n\n'
            '[[package]]\nname = "example-rust-crate"\nversion = "0.4.2"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
        )

        with self.assertRaises(AuditIncomplete):
            normalize_inventory(bundle)


    def test_go_mod_checksum_is_not_accepted_as_source_checksum(self):
        bundle = load_bundle()
        modules = [json.loads(line) for line in bundle["go"]["modules_json"].splitlines()]
        packages = [json.loads(line) for line in bundle["go"]["packages_json"].splitlines()]
        for row in modules:
            if row.get("Path") == "example.com/go-widget":
                row.pop("Sum", None)
                row["GoModSum"] = "h1:" + ("K" * 43) + "="
        for row in packages:
            if row.get("Module", {}).get("Path") == "example.com/go-widget":
                row["Module"].pop("Sum", None)
                row["Module"]["GoModSum"] = "h1:" + ("K" * 43) + "="
        bundle["go"]["modules_json"] = "\n".join(json.dumps(row) for row in modules) + "\n"
        bundle["go"]["packages_json"] = "\n".join(json.dumps(row) for row in packages) + "\n"

        with self.assertRaises(AuditIncomplete):
            normalize_inventory(bundle)


    def test_preserves_rust_distribution_copyright_as_a_supplemental_notice(self):
        bundle = load_bundle()
        text = "<html>Fixture Rust library notice.</html>\\n"
        bundle["rust"]["standard_library"]["supplemental_notices"] = [{
            "name": "COPYRIGHT-library.html",
            "text": text,
            "sha256": "66d9c3344388f00327404d6c75d147e65369c98698e5354b2716a0db9dda3320",
            "source_url": "https://github.com/rust-lang/rust/blob/59807616e1fa2540724bfbac14d7976d7e4a3860/COPYRIGHT",
            "source_revision": "59807616e1fa2540724bfbac14d7976d7e4a3860",
            "source_path": "COPYRIGHT-library.html",
        }]

        inventory = normalize_inventory(bundle)
        rust_std = next(item for item in inventory["components"] if item["name"] == "Rust standard library")

        self.assertEqual(rust_std["supplemental_notices"][0]["name"], "COPYRIGHT-library.html")
        self.assertEqual(rust_std["supplemental_notices"][0]["text"], text)

    def test_rejects_rust_distribution_without_copyright_library_notice(self):
        bundle = load_bundle()
        bundle["rust"]["standard_library"].pop("supplemental_notices", None)

        with self.assertRaises(AuditIncomplete):
            normalize_inventory(bundle)


if __name__ == "__main__":
    unittest.main()
