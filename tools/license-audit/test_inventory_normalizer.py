import hashlib
import io
import json
import sys
import tempfile
import tomllib
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from collect import (
    CARGO_ABOUT_ACCEPTED_LICENSES,
    _cargo_about_config,
    EASYTIER_LICENSE_PACKAGES,
    EASYTIER_LICENSE_SHA256,
    EASYTIER_LICENSE_SOURCE_COMMIT,
    EASYTIER_LICENSE_SPDX,
    EASYTIER_LICENSE_VERSION,
    _validate_easytier_license_scope,
)
from generate_notices import AuditIncomplete, generate_notices
from normalize_inventory import _cargo_tree_runtime_ids, main as normalize_inventory_cli, normalize_inventory


FIXTURE = Path(__file__).resolve().parent / "fixtures" / "tool-output-bundle.json"
EASYTIER_SOURCE_FIXTURE = FIXTURE.parent / "easytier-source"


def git_blob(text):
    data = text.encode("utf-8")
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def load_bundle():
    bundle = json.loads(FIXTURE.read_text(encoding="utf-8"))
    bundle["rust"]["source_root"] = str(EASYTIER_SOURCE_FIXTURE)
    metadata_by_id = {package["id"]: package for package in bundle["rust"]["metadata"]["packages"]}
    bundle["rust"]["runtime_tree"] = "\n".join(
        f'{metadata_by_id[entry["package"]["id"]]["name"]} v{metadata_by_id[entry["package"]["id"]]["version"]}'
        for entry in bundle["rust"]["about"]["crates"]
    )
    for package in bundle["rust"]["metadata"]["packages"]:
        if package.get("source") is None:
            package["manifest_path"] = str(EASYTIER_SOURCE_FIXTURE / "easytier-core" / "Cargo.toml")
            if package.get("license_file") is not None:
                package["license_file"] = str(EASYTIER_SOURCE_FIXTURE / "LICENSE")
    local_metadata = next(
        package for package in bundle["rust"]["metadata"]["packages"]
        if package.get("source") is None
    )
    local_metadata.pop("license", None)
    local_metadata["license_file"] = str(EASYTIER_SOURCE_FIXTURE / "LICENSE")
    bundle["rust"]["about"]["licenses"][0]["source_path"] = "../LICENSE"
    for crate in bundle["rust"]["about"]["crates"]:
        if crate["package"].get("source") is None:
            crate["package"]["manifest_path"] = str(EASYTIER_SOURCE_FIXTURE / "easytier-core" / "Cargo.toml")
            crate["package"].pop("license", None)
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
    return add_core_source_license_rows(bundle)


def add_core_source_license_rows(bundle):
    core = bundle["go"]["core_module_path"]
    commit = bundle["build"]["core_source_commit"]
    root_text = "Fixture GPL terms.\nCopyright (c) Mihomo Fixture\n"
    kcptun_text = "Fixture MIT terms.\nCopyright (c) kcptun Fixture\n"
    attribution = "Grabbed from https://github.com/xtaci/tcpraw with modifications\n"
    root_blob = git_blob(root_text)
    kcptun_blob = git_blob(kcptun_text)
    attribution_blob = git_blob(attribution)
    bundle["go"]["license_report"].extend([
        {
            "Name": core,
            "Version": "Unknown",
            "LicensePath": "LICENSE",
            "LicenseURL": "UNKNOWN",
            "LicenseName": "GPL-3.0",
            "LicenseText": root_text,
            "SourcePath": "LICENSE",
            "SourceRevision": commit,
            "SourceGitBlob": root_blob,
        },
        {
            "Name": core + "/transport/kcptun",
            "Version": "Unknown",
            "LicensePath": "transport/kcptun/LICENSE.md",
            "LicenseURL": "UNKNOWN",
            "LicenseName": "MIT",
            "LicenseText": kcptun_text,
            "SourcePath": "transport/kcptun/LICENSE.md",
            "SourceRevision": commit,
            "SourceGitBlob": kcptun_blob,
        },
        {
            "Name": core + "/transport/hysteria/conns/faketcp",
            "Version": "Unknown",
            "LicensePath": "transport/hysteria/conns/faketcp/LICENSE",
            "LicenseURL": "UNKNOWN",
            "LicenseName": "Unknown",
            "LicenseText": "",
            "SourcePath": "transport/hysteria/conns/faketcp/LICENSE",
            "SourceRevision": commit,
            "SourceGitBlob": attribution_blob,
        },
    ])
    bundle["go"]["core_source_notices"] = [
        {
            "name": "faketcp attribution; go-licenses reported Unknown (not a license)",
            "text": attribution,
            "sha256": hashlib.sha256(attribution.encode("utf-8")).hexdigest(),
            "source_path": "transport/hysteria/conns/faketcp/LICENSE",
            "source_revision": commit,
            "source_git_blob": attribution_blob,
        }
    ]
    return bundle


class ToolOutputNormalizationTests(unittest.TestCase):
    def test_local_rust_license_file_maps_to_exact_easy_tier_source_and_omits_declared_license(self):
        bundle = load_bundle()
        inventory = normalize_inventory(bundle)
        component = next(item for item in inventory["components"] if item["name"] == "easytier-core")
        license_record = component["licenses"][0]
        commit = bundle["build"]["easytier_source_commit"]

        self.assertNotIn("declared_license", component)
        self.assertEqual(license_record["source_url"], f"https://github.com/EasyTier/EasyTier/blob/{commit}/LICENSE")
        self.assertEqual(license_record["source_revision"], commit)
        self.assertEqual(license_record["source_path"], "LICENSE")
        self.assertEqual(
            license_record["source_git_blob"],
            git_blob("Fixture LGPL license text.\n"),
        )

    def test_rejects_local_rust_license_path_outside_pinned_source_tree(self):
        bundle = load_bundle()
        with tempfile.TemporaryDirectory() as outside:
            outside_license = Path(outside) / "LICENSE"
            outside_license.write_text("Fixture LGPL license text.\n", encoding="utf-8")
            bundle["rust"]["about"]["licenses"][0]["source_path"] = str(outside_license)
            with self.assertRaises(AuditIncomplete):
                normalize_inventory(bundle)

    def test_cargo_about_config_has_bounded_license_resolution_priority(self):
        config = tomllib.loads(_cargo_about_config("wasm32-wasip1"))
        accepted = config["accepted"]

        self.assertEqual(config["targets"], ["wasm32-wasip1"])
        self.assertEqual(accepted, list(CARGO_ABOUT_ACCEPTED_LICENSES))
        self.assertEqual(len(accepted), len(set(accepted)))
        self.assertTrue({"MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "Unicode-3.0", "LGPL-3.0-only", "LGPL-3.0-or-later", "CDLA-Permissive-2.0"}.issubset(accepted))
        self.assertNotIn("NOASSERTION", accepted)
        self.assertTrue(config["ignore-build-dependencies"])
        self.assertTrue(config["ignore-dev-dependencies"])

    def test_cargo_about_clarifies_exact_easytier_license_sources(self):
        config = tomllib.loads(_cargo_about_config("wasm32-wasip1"))
        expected = {
            "license": EASYTIER_LICENSE_SPDX,
            "files": [{
                "path": "../LICENSE",
                "checksum": EASYTIER_LICENSE_SHA256,
            }],
        }

        self.assertEqual(
            {name: config[name]["clarify"] for name in EASYTIER_LICENSE_PACKAGES},
            {name: expected for name in EASYTIER_LICENSE_PACKAGES},
        )
        self.assertNotIn("clarify", config)

    def test_easytier_license_clarification_is_bound_to_source_version_and_manifests(self):
        with tempfile.TemporaryDirectory() as temp:
            easytier = Path(temp)
            packages = []
            for name in EASYTIER_LICENSE_PACKAGES:
                manifest = easytier / name / "Cargo.toml"
                manifest.parent.mkdir()
                manifest.write_text("[package]\n", encoding="utf-8")
                packages.append({
                    "name": name,
                    "version": EASYTIER_LICENSE_VERSION,
                    "manifest_path": str(manifest.resolve()),
                })
            metadata = {"packages": packages}
            build = {"easytier_source_commit": EASYTIER_LICENSE_SOURCE_COMMIT}

            _validate_easytier_license_scope(easytier, build, metadata)

            wrong_version = json.loads(json.dumps(metadata))
            wrong_version["packages"][0]["version"] = "2.7.1"
            with self.assertRaises(AuditIncomplete):
                _validate_easytier_license_scope(easytier, build, wrong_version)

            wrong_manifest = json.loads(json.dumps(metadata))
            wrong_manifest["packages"][0]["manifest_path"] = str((easytier / "other/Cargo.toml").resolve())
            with self.assertRaises(AuditIncomplete):
                _validate_easytier_license_scope(easytier, build, wrong_manifest)

            wrong_commit = {"easytier_source_commit": "0" * 40}
            with self.assertRaises(AuditIncomplete):
                _validate_easytier_license_scope(easytier, wrong_commit, metadata)

    def test_external_git_crate_keeps_its_own_source_mapping(self):
        bundle = load_bundle()
        package = next(item for item in bundle["rust"]["metadata"]["packages"] if item["name"] == "example-rust-crate")
        commit = "3" * 40
        source = f"git+https://example.invalid/rust-crate#{commit}"
        package["source"] = source
        package["manifest_path"] = "/outside/easytier/example-rust-crate/Cargo.toml"
        bundle["rust"]["cargo_lock_text"] = (
            'version = 4\n\n[[package]]\n'
            f'name = "{package["name"]}"\nversion = "{package["version"]}"\nsource = "{source}"\n'
        )

        inventory = normalize_inventory(bundle)
        component = next(item for item in inventory["components"] if item["name"] == package["name"])

        self.assertEqual(component["source_digest"], {"algorithm": "git-commit", "value": commit})
        self.assertEqual(component["licenses"][0]["source_url"], f"https://example.invalid/rust-crate/tree/{commit}")
        self.assertEqual(component["licenses"][0]["source_revision"], commit)
        self.assertNotIn("source_path", component["licenses"][0])

    def test_cli_writes_mixed_newlines_byte_exact_and_reports_matching_sha256(self):
        bundle = load_bundle()
        mixed_license = "Fixture MIT terms first line\r\nsecond line\nthird line\r\n"
        widget = next(item for item in bundle["go"]["license_report"] if item["Name"] == "example.com/go-widget")
        widget["LicenseText"] = mixed_license
        inventory = normalize_inventory(bundle)
        notices, source_manifest = generate_notices(inventory)
        source_text = json.dumps(source_manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        notices_bytes = notices.encode("utf-8")
        sources_bytes = source_text.encode("utf-8")

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bundle_path = root / "bundle.json"
            notices_path = root / "notices.txt"
            sources_path = root / "sources.json"
            bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
            output = io.StringIO()
            previous_argv = sys.argv
            try:
                sys.argv = [
                    "normalize_inventory.py",
                    str(bundle_path),
                    "--notices",
                    str(notices_path),
                    "--sources",
                    str(sources_path),
                ]
                with redirect_stdout(output):
                    normalize_inventory_cli()
            finally:
                sys.argv = previous_argv

            self.assertEqual(notices_path.read_bytes(), notices_bytes)
            self.assertEqual(sources_path.read_bytes(), sources_bytes)
            self.assertIn(mixed_license, notices_path.read_bytes().decode("utf-8"))
            self.assertIn(hashlib.sha256(notices_bytes).hexdigest(), output.getvalue())
            self.assertIn(hashlib.sha256(sources_bytes).hexdigest(), output.getvalue())


    def test_cargo_tree_maps_duplicate_name_and_version_by_exact_source(self):
        registry = "registry+https://github.com/rust-lang/crates.io-index"
        git_source = "git+https://github.com/example/duplicate?rev=deadbeef#deadbeef"
        root = "path+file:///tmp/example#root@1.0.0"
        metadata = {
            "packages": [
                {"id": root, "name": "root", "version": "1.0.0", "source": None, "manifest_path": "/tmp/root/Cargo.toml"},
                {"id": registry + "#duplicate@1.0.0", "name": "duplicate", "version": "1.0.0", "source": registry},
                {"id": git_source + "#duplicate@1.0.0", "name": "duplicate", "version": "1.0.0", "source": git_source},
            ],
            "resolve": {"root": root},
        }

        packages, runtime_ids = _cargo_tree_runtime_ids(
            metadata,
            "root v1.0.0 (/tmp/root)\nduplicate v1.0.0 (git+https://github.com/example/duplicate?rev=deadbeef#deadbeef)",
        )

        self.assertEqual(set(packages), {root, registry + "#duplicate@1.0.0", git_source + "#duplicate@1.0.0"})
        self.assertEqual(runtime_ids, {root, git_source + "#duplicate@1.0.0"})

    def test_cargo_tree_rejects_an_ambiguous_unqualified_package(self):
        registry = "registry+https://github.com/rust-lang/crates.io-index"
        git_source = "git+https://github.com/example/duplicate?rev=deadbeef#deadbeef"
        root = "path+file:///tmp/example#root@1.0.0"
        metadata = {
            "packages": [
                {"id": root, "name": "root", "version": "1.0.0", "source": None, "manifest_path": "/tmp/root/Cargo.toml"},
                {"id": registry + "#duplicate@1.0.0", "name": "duplicate", "version": "1.0.0", "source": registry},
                {"id": git_source + "#duplicate@1.0.0", "name": "duplicate", "version": "1.0.0", "source": git_source},
            ],
            "resolve": {"root": root},
        }

        with self.assertRaises(AuditIncomplete):
            _cargo_tree_runtime_ids(metadata, "root v1.0.0 (/tmp/root)\nduplicate v1.0.0")

    def test_rust_inventory_uses_observed_build_graph_not_feature_unified_metadata_edges(self):
        bundle = load_bundle()
        rust = bundle["rust"]
        metadata = rust["metadata"]
        package_id = "registry+https://github.com/rust-lang/crates.io-index#dev-feature-only@0.1.0"
        metadata["packages"].append({
            "id": package_id,
            "name": "dev-feature-only",
            "version": "0.1.0",
            "source": "registry+https://github.com/rust-lang/crates.io-index",
            "manifest_path": "/cargo/registry/src/dev-feature-only-0.1.0/Cargo.toml",
            "license": "MIT",
        })
        root = metadata["resolve"]["root"]
        root_node = next(node for node in metadata["resolve"]["nodes"] if node["id"] == root)
        root_node["deps"].append({
            "name": "dev-feature-only",
            "pkg": package_id,
            "dep_kinds": [{"kind": None, "target": None}],
        })
        metadata["resolve"]["nodes"].append({"id": package_id, "deps": [], "features": []})
        inventory = normalize_inventory(bundle)

        self.assertNotIn("dev-feature-only", {item["name"] for item in inventory["components"]})


    def test_normalizes_selected_go_and_rust_runtime_graphs(self):
        inventory = normalize_inventory(load_bundle())
        names = {item["name"] for item in inventory["components"]}

        self.assertEqual(
            names,
            {"example.com/go-widget", "easytier-core", "example-rust-crate", "Go standard library", "Rust standard library", "google.golang.org/protobuf", "github.com/easytier/easytier/easytier-go", "github.com/metacubex/chacha", "github.com/metacubex/sing-tun", "wintun.dll", "WireGuard Wintun Go bindings", "github.com/metacubex/mihomo"},
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
                "go-source:github.com/metacubex/mihomo@source-111111111111",
            },
        )
        rendered = json.dumps(inventory, sort_keys=True)
        self.assertNotIn("/tmp/easytier", rendered)
        self.assertNotIn("/cargo/registry", rendered)

    def test_includes_exact_core_module_license_files_and_attribution(self):
        bundle = load_bundle()
        inventory = normalize_inventory(bundle)
        component = next(
            item for item in inventory["components"]
            if item["name"] == "github.com/metacubex/mihomo"
        )

        commit = bundle["build"]["core_source_commit"]
        self.assertEqual(component["ecosystem"], "go-source")
        self.assertEqual(component["source_digest"], {"algorithm": "git-commit", "value": commit})
        self.assertEqual(component["source_url"], f"https://github.com/smart-tinker/stcvrc/tree/{commit}")
        licenses = {item["spdx"]: item for item in component["licenses"]}
        self.assertEqual(set(licenses), {"GPL-3.0", "MIT"})
        self.assertEqual(licenses["GPL-3.0"]["source_path"], "LICENSE")
        self.assertEqual(licenses["GPL-3.0"]["source_revision"], commit)
        self.assertEqual(licenses["GPL-3.0"]["source_url"], f"https://github.com/smart-tinker/stcvrc/blob/{commit}/LICENSE")
        self.assertEqual(licenses["GPL-3.0"]["source_git_blob"], git_blob("Fixture GPL terms.\nCopyright (c) Mihomo Fixture\n"))
        attribution_notice = component["supplemental_notices"][0]
        self.assertIn("go-licenses reported Unknown", attribution_notice["name"])
        self.assertEqual(
            attribution_notice["source_url"],
            f"https://github.com/smart-tinker/stcvrc/blob/{commit}/transport/hysteria/conns/faketcp/LICENSE",
        )
        self.assertEqual(
            attribution_notice["source_git_blob"],
            git_blob("Grabbed from https://github.com/xtaci/tcpraw with modifications\n"),
        )
        self.assertEqual(licenses["MIT"]["source_path"], "transport/kcptun/LICENSE.md")
        self.assertEqual(
            component["supplemental_notices"][0]["source_path"],
            "transport/hysteria/conns/faketcp/LICENSE",
        )
        self.assertEqual(component["supplemental_notices"][0]["source_revision"], commit)
        self.assertIn("go-source:github.com/metacubex/mihomo@source-" + commit[:12], inventory["required_components"])

    def test_go_report_uses_effective_replacement_versions(self):
        bundle = load_bundle()
        rows = {item["Name"]: item for item in bundle["go"]["license_report"]}

        self.assertEqual(rows["github.com/easytier/easytier/easytier-go"]["Version"], "Unknown")
        self.assertEqual(rows["google.golang.org/protobuf"]["Version"], "v0.0.0-20260306035419-7ceee0674686")

    def test_replaced_module_uses_replacement_source_and_checksum(self):
        inventory = normalize_inventory(load_bundle())
        component = next(item for item in inventory["components"] if item["name"] == "google.golang.org/protobuf")

        self.assertEqual(component["source_url"], "https://proxy.golang.org/github.com/metacubex/protobuf-go/@v/v0.0.0-20260306035419-7ceee0674686.zip")
        self.assertEqual(component["source_digest"], {"algorithm": "go.sum-h1", "value": "h1:" + ("I" * 43) + "="})
        self.assertEqual(component["upstream_module_version"], "v1.34.2")

    def test_rejects_unknown_license_for_a_selected_runtime_module(self):
        bundle = load_bundle()
        row = next(item for item in bundle["go"]["license_report"] if item["Name"] == "example.com/go-widget")
        row["LicenseName"] = "Unknown"

        with self.assertRaises(AuditIncomplete):
            normalize_inventory(bundle)

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
