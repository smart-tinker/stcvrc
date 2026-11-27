#!/usr/bin/env python3
"""Build the externally pinned RC11 Windows acceptance stage."""
import argparse
import hashlib
import json
import re
import subprocess
import sys
import zipfile
from pathlib import Path

RELEASE_TAG = "stcvrc-1.19.33-rc.11"
CORE_VERSION = "1.19.33-STCVRC-rc.11"
CORE_SOURCE_COMMIT = "a884ad53a3999dd35acab979e0bb040c47f6dbc9"
DEPENDENCIES = {
    "github.com/gobwas/ws": "v1.5.0",
    "github.com/insomniacslk/dhcp": "v0.0.0-20260719225207-c76316d4aa82",
}
SOURCE_FILES = (
    "tools/network-lab/windows_idle_capture_operator.ps1",
    "tools/network-lab/windows_core_preimage_paths.ps1",
    "tools/network-lab/windows_idle_baseline_guard.ps1",
    "tools/network-lab/windows_idle_transaction.ps1",
    "tools/network-lab/windows_idle_preflight_package_writer.ps1",
    "tools/network-lab/windows_idle_preflight.ps1",
)
CORE_PATH = "payload/verge-mihomo.exe"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def file_record(path, archive_path):
    require(path.is_file() and not path.is_symlink(), "stage input is not a regular file")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
            size += len(block)
    return {"path": archive_path, "sha256": digest.hexdigest(), "size": size}


def check_source(source_root, source_sha):
    root = Path(source_root)
    require(COMMIT.fullmatch(source_sha) is not None, "source SHA is malformed")
    try:
        actual = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        raise ValueError("exact source checkout is unavailable") from None
    require(actual == source_sha, "source checkout does not match the reviewed SHA")
    missing = [name for name in SOURCE_FILES if not (root / name).is_file() or (root / name).is_symlink()]
    if "tools/network-lab/windows_idle_preflight.ps1" in missing:
        raise ValueError("RC11 stage packaging is blocked until #86 provides tools/network-lab/windows_idle_preflight.ps1")
    require(not missing, "required RC11 stage source is missing")
    for name in SOURCE_FILES:
        try:
            committed = subprocess.run(
                ["git", "-C", str(root), "show", f"{source_sha}:{name}"],
                check=True, capture_output=True,
            ).stdout
        except (OSError, subprocess.CalledProcessError):
            raise ValueError(f"required RC11 stage source is not present at the exact SHA: {name}") from None
        require((root / name).read_bytes() == committed, f"stage source differs from its exact Git blob: {name}")
    return root


def cvr_installers(inputs):
    require(inputs.get("repository") == "clash-verge-rev/clash-verge-rev", "unexpected CVR input repository")
    release_items = inputs.get("releases", [])
    require(isinstance(release_items, list) and len(release_items) == 2, "CVR stage must pin exactly two releases")
    releases = {item.get("version"): item for item in release_items if isinstance(item, dict)}
    require(len(releases) == 2 and set(releases) == {"2.5.8", "2.5.10"}, "CVR stage must pin exactly 2.5.8 recovery and 2.5.10 update")
    result = {}
    for version in ("2.5.8", "2.5.10"):
        release = releases[version]
        name = f"Clash.Verge_{version}_x64-setup.exe"
        expected_url = f"https://github.com/clash-verge-rev/clash-verge-rev/releases/download/v{version}/{name}"
        asset = release.get("assets", {}).get("installer", {})
        require(release.get("tag") == f"v{version}" and type(release.get("releaseId")) is int and release["releaseId"] > 0, "CVR release identity mismatch")
        require(asset.get("file") == name and asset.get("name") == name and type(asset.get("id")) is int and asset["id"] > 0, "CVR installer asset identity mismatch")
        require(asset.get("url") == expected_url, "CVR installer URL mismatch")
        require(type(asset.get("size")) is int and asset["size"] > 0, "CVR installer size pin is invalid")
        require(isinstance(asset.get("sha256"), str) and SHA256.fullmatch(asset["sha256"]) is not None, "CVR installer SHA256 pin is invalid")
        helper_sha = release.get("serviceInstallHelperSha256")
        require(isinstance(helper_sha, str) and SHA256.fullmatch(helper_sha) is not None, "CVR service helper pin is invalid")
        result[version] = {
            "releaseId": release["releaseId"],
            "tag": release["tag"],
            "assetId": asset["id"],
            "name": name,
            "size": asset["size"],
            "sha256": asset["sha256"],
            "serviceInstallHelperSha256": helper_sha,
        }
    return result


def build_stage(source_root, source_sha, build_path, inputs_path, core_path,
                native_core_sha256, recovery_installer_path, update_installer_path,
                output_path, record_path):
    root = check_source(source_root, source_sha)
    build = json.loads(Path(build_path).read_text(encoding="utf-8"))
    require(build.get("schema_version") == 1 and build.get("status") == "fresh-source-build" and build.get("build_host") == "windows/amd64", "source build identity mismatch")
    require(build.get("recipe_commit") == source_sha, "source build is not bound to the reviewed SHA")
    require(build.get("version") == CORE_VERSION and build.get("core_source_commit") == CORE_SOURCE_COMMIT, "source build is not the pinned RC11 candidate")
    require(build.get("selected_dependency_versions") == DEPENDENCIES, "source build dependency pins mismatch")
    artifacts = [
        item for item in build.get("artifacts", [])
        if item.get("name") == "verge-mihomo.exe" and item.get("target") == "windows/amd64"
    ]
    require(len(artifacts) == 1, "source build must contain one Windows RC11 core")
    core = Path(core_path)
    core_record = file_record(core, CORE_PATH)
    artifact = artifacts[0]
    require(
        isinstance(artifact.get("sha256"), str) and SHA256.fullmatch(artifact["sha256"]) is not None
        and artifact["sha256"] == core_record["sha256"] == native_core_sha256
        and artifact.get("size", 0) > 0 and artifact.get("size") == core_record["size"],
        "staged RC11 core does not match the source build and native Windows acceptance pins",
    )

    inputs_bytes = Path(inputs_path).read_bytes()
    installers = cvr_installers(json.loads(inputs_bytes))
    input_paths = {
        "2.5.8": Path(recovery_installer_path),
        "2.5.10": Path(update_installer_path),
    }
    staged = {}
    for version in ("2.5.8", "2.5.10"):
        pin = installers[version]
        record = file_record(input_paths[version], f"payload/{pin['name']}")
        require(record["sha256"] == pin["sha256"] and record["size"] == pin["size"], f"CVR {version} installer bytes do not match the release pin")
        staged[version] = record

    source_records = [file_record(root / name, name) for name in SOURCE_FILES]
    file_records = sorted(source_records + [core_record, staged["2.5.8"], staged["2.5.10"]], key=lambda item: item["path"])
    manifest_bytes = (
        json.dumps(
            {"schemaVersion": 1, "files": [{"path": item["path"], "sha256": item["sha256"]} for item in file_records]},
            ensure_ascii=False, separators=(",", ":"),
        ) + "\n"
    ).encode("utf-8")
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()

    output = Path(output_path)
    record_output = Path(record_path)
    require(output.name == "RC11-WINDOWS-STAGE.zip", "unexpected RC11 stage asset name")
    require(not output.exists() and not record_output.exists(), "refusing to overwrite RC11 stage output")
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
            manifest_info = zipfile.ZipInfo("source-manifest.json", (1980, 1, 1, 0, 0, 0))
            manifest_info.create_system = 0
            manifest_info.compress_type = zipfile.ZIP_STORED
            archive.writestr(manifest_info, manifest_bytes)
            for item in file_records:
                if item["path"] in SOURCE_FILES:
                    source = root / item["path"]
                elif item["path"] == CORE_PATH:
                    source = core
                elif item["path"] == staged["2.5.8"]["path"]:
                    source = input_paths["2.5.8"]
                else:
                    source = input_paths["2.5.10"]
                info = zipfile.ZipInfo(item["path"], (1980, 1, 1, 0, 0, 0))
                info.create_system = 0
                info.compress_type = zipfile.ZIP_STORED
                digest = hashlib.sha256()
                size = 0
                with source.open("rb") as src, archive.open(info, "w") as dst:
                    for block in iter(lambda: src.read(1024 * 1024), b""):
                        digest.update(block)
                        size += len(block)
                        dst.write(block)
                require(digest.hexdigest() == item["sha256"] and size == item["size"], "stage source changed while packaging")
        archive_record = file_record(output, output.name)
        require(archive_record["size"] <= 268435456, "RC11 stage exceeds the bounded release read-back size")
        input_sha256 = hashlib.sha256(inputs_bytes).hexdigest()
        record = {
            "schemaVersion": 1,
            "releaseTag": RELEASE_TAG,
            "sourceCommit": source_sha,
            "inputManifestSha256": input_sha256,
            "sourceManifest": {"path": "source-manifest.json", "sha256": manifest_sha256, "size": len(manifest_bytes)},
            "archive": archive_record,
            "core": {**core_record, "version": CORE_VERSION, "coreSourceCommit": CORE_SOURCE_COMMIT},
            "cvrInstallers": {
                "2.5.8": {**staged["2.5.8"], **installers["2.5.8"]},
                "2.5.10": {**staged["2.5.10"], **installers["2.5.10"]},
            },
            "sourceFiles": source_records,
        }
        record_output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return record
    except Exception:
        output.unlink(missing_ok=True)
        record_output.unlink(missing_ok=True)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    check = subparsers.add_parser("check-source")
    check.add_argument("--source-root", required=True)
    check.add_argument("--source-sha", required=True)
    pack = subparsers.add_parser("pack")
    pack.add_argument("--source-root", required=True)
    pack.add_argument("--source-sha", required=True)
    pack.add_argument("--build-report", required=True)
    pack.add_argument("--inputs", required=True)
    pack.add_argument("--core", required=True)
    pack.add_argument("--native-core-sha256", required=True)
    pack.add_argument("--recovery-installer", required=True)
    pack.add_argument("--update-installer", required=True)
    pack.add_argument("--output", required=True)
    pack.add_argument("--record", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "check-source":
            check_source(args.source_root, args.source_sha)
        else:
            require(SHA256.fullmatch(args.native_core_sha256) is not None, "native Windows core SHA256 is malformed")
            build_stage(
                args.source_root, args.source_sha, args.build_report, args.inputs,
                args.core, args.native_core_sha256, args.recovery_installer,
                args.update_installer, args.output, args.record,
            )
        return 0
    except (OSError, ValueError, KeyError, TypeError, AttributeError, json.JSONDecodeError, zipfile.BadZipFile) as error:
        print(f"RC11 stage packaging failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
