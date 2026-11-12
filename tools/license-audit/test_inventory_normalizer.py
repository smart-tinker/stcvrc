import hashlib
import json
import unittest
from pathlib import Path

from generate_notices import AuditIncomplete
from normalize_inventory import normalize_inventory


FIXTURE = Path(__file__).resolve().parent / "fixtures" / "tool-output-bundle.json"


def load_bundle():
    bundle = json.loads(FIXTURE.read_text(encoding="utf-8"))
    for notice in bundle.get("go", {}).get("embedded_assets", []):
        text = notice.get("terms_text", "")
        notice["terms_sha256"] = hashlib.sha256(text.encode("utf-8")).hexdigest()
    for component in bundle.get("go", {}).get("additional_components", []):
        for license_item in component.get("licenses", []):
            text = license_item.get("text", "")
            license_item["sha256"] = hashlib.sha256(text.encode("utf-8")).hexdigest()
        for notice in component.get("supplemental_notices", []):
            text = notice.get("text", "")
            notice["sha256"] = hashlib.sha256(text.encode("utf-8")).hexdigest()
    for notice in bundle.get("rust", {}).get("standard_library", {}).get("supplemental_notices", []):
        notice["sha256"] = hashlib.sha256(notice["text"].encode("utf-8")).hexdigest()
    return bundle


class ToolOutputNormalizationTests(unittest.TestCase):
    def test_normalizes_selected_go_and_rust_runtime_graphs(self):
        inventory = normalize_inventory(load_bundle())
        names = {item["name"] for item in inventory["components"]}

        self.assertEqual(
            names,
            {"example.com/go-widget", "easytier-core", "example-rust-crate", "Go standard library", "Rust standard library", "google.golang.org/protobuf", "github.com/easytier/easytier/easytier-go", "github.com/metacubex/chacha", "github.com/metacubex/sing-tun", "wintun.dll", "WireGuard Wintun Go bindings"},
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
                "go:github.com/metacubex/chacha@v0.1.5",
                "go:github.com/metacubex/sing-tun@v0.4.28",
                "embedded-binary:wintun.dll@0.14.1",
                "go-source:WireGuard Wintun Go bindings@v0.4.28",
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

    def test_preserves_chacha_license_only_child_as_separate_source_evidence(self):
        inventory = normalize_inventory(load_bundle())
        component = next(item for item in inventory["components"] if item["name"] == "github.com/metacubex/chacha")

        self.assertEqual(component["source_digest"]["algorithm"], "go.sum-h1")
        self.assertEqual(component["licenses"][0]["spdx"], "MIT")
        self.assertEqual(component["licenses"][0]["source_url"], "https://github.com/MetaCubeX/chacha/blob/7b981d42c3baca5a004e7b0ecfb9b67ee20e583a/LICENSE")
        self.assertEqual(component["licenses"][0]["source_revision"], "7b981d42c3baca5a004e7b0ecfb9b67ee20e583a")
        self.assertEqual(component["licenses"][0]["source_git_blob"], "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")

    def test_preserves_mit_license_and_copyright_for_selected_wintun_bindings(self):
        inventory = normalize_inventory(load_bundle())
        component = next(item for item in inventory["components"] if item["name"] == "WireGuard Wintun Go bindings")

        self.assertEqual(component["licenses"][0]["spdx"], "MIT")
        self.assertIn("Permission is hereby granted", component["licenses"][0]["text"])
        self.assertIn("Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.", component["copyrights"])
        self.assertEqual(
            {item["source_path"] for item in component["supplemental_notices"]},
            {"internal/wintun/wintun_windows.go", "internal/wintun/memmod/memmod_windows.go"},
        )

    def test_rejects_missing_wintun_binding_license_component(self):
        bundle = load_bundle()
        bundle["go"]["additional_components"] = []
        with self.assertRaises(AuditIncomplete):
            normalize_inventory(bundle)

    def test_records_wintun_as_an_embedded_binary_with_distinct_archive_terms(self):
        inventory = normalize_inventory(load_bundle())
        component = next(item for item in inventory["components"] if item["name"] == "wintun.dll")

        self.assertEqual(component["licenses"], [])
        self.assertEqual(component["embedded_from"]["module"], "github.com/metacubex/sing-tun")
        self.assertEqual(component["source_archive"]["path"], "wintun/bin/amd64/wintun.dll")
        self.assertEqual(component["supplemental_notices"][0]["source_path"], "wintun/LICENSE.txt")

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
        library_notice = next(
            item for item in bundle["rust"]["standard_library"]["supplemental_notices"]
            if item["name"] == "COPYRIGHT-library.html"
        )
        library_notice.update({
            "text": text,
            "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "source_url": "https://github.com/rust-lang/rust/tree/59807616e1fa2540724bfbac14d7976d7e4a3860/src/tools/generate-copyright",
            "source_revision": "59807616e1fa2540724bfbac14d7976d7e4a3860",
            "source_path": "share/doc/rust/COPYRIGHT-library.html",
        })

        inventory = normalize_inventory(bundle)
        rust_std = next(item for item in inventory["components"] if item["name"] == "Rust standard library")

        library_notice = next(item for item in rust_std["supplemental_notices"] if item["name"] == "COPYRIGHT-library.html")
        self.assertEqual(library_notice["text"], text)
        self.assertIn("COPYRIGHT", {item["name"] for item in rust_std["supplemental_notices"]})

    def test_rejects_rust_distribution_without_copyright_library_notice(self):
        bundle = load_bundle()
        bundle["rust"]["standard_library"].pop("supplemental_notices", None)

        with self.assertRaises(AuditIncomplete):
            normalize_inventory(bundle)


if __name__ == "__main__":
    unittest.main()
