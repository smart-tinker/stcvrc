#!/usr/bin/env python3
"""Build the externally pinned RC11 Windows acceptance stage."""
import argparse
import hashlib
import json
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

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
    "tools/network-lab/windows_legacy_state_transaction.ps1",
    "tools/network-lab/windows_idle_preflight_package_writer.ps1",
    "tools/network-lab/windows_idle_preflight.ps1",
    "tools/network-lab/windows_idle_preflight_target_operator.ps1",
    "tools/network-lab/windows_idle_target_runtime.ps1",
    "tools/network-lab/idle-target-candidate-traffic.md",
    "tools/network-lab/windows_native_acceptance.ps1",
    "tools/network-lab/windows_native_port_plan.ps1",
    "tools/network-lab/windows_native_udp_ports.py",
    "tools/network-lab/windows_ssh_fixture_cleanup.ps1",
)
CORE_PATH = "payload/verge-mihomo.exe"
SERVICE_IPC_REPOSITORY = "clash-verge-rev/clash-verge-service-ipc"
SERVICE_HELPER_NAME = "clash-verge-service-install.exe"
SERVICE_HELPER_PATHS = {
    "2.5.8": "payload/cvr-2.5.8/clash-verge-service-install.exe",
    "2.5.10": "payload/cvr-2.5.10/clash-verge-service-install.exe",
}
SERVICE_IPC_LICENSE_PATH = "licenses/clash-verge-service-ipc/LICENSE"
SERVICE_IPC_PROVENANCE_PATH = "provenance/cvr-service-install-helpers.json"
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
    ipc_tags = {"2.5.8": "v2.7.6", "2.5.10": "v2.7.7"}
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
        provenance = release.get("serviceInstallHelperProvenance")
        require(isinstance(provenance, dict) and provenance.get("repository") == SERVICE_IPC_REPOSITORY, "CVR service helper provenance is missing")
        tag = ipc_tags[version]
        source_commit = provenance.get("sourceCommit")
        require(provenance.get("tag") == tag and isinstance(source_commit, str) and COMMIT.fullmatch(source_commit) is not None, "Service IPC source identity mismatch")
        ipc_asset = provenance.get("asset", {})
        ipc_name = f"clash-verge-service-ipc-{tag}-x86_64-pc-windows-msvc.zip"
        ipc_url = f"https://github.com/{SERVICE_IPC_REPOSITORY}/releases/download/{tag}/{ipc_name}"
        require(
            type(ipc_asset.get("id")) is int and ipc_asset["id"] > 0 and
            ipc_asset.get("name") == ipc_name and type(ipc_asset.get("size")) is int and ipc_asset["size"] > 0 and
            isinstance(ipc_asset.get("sha256"), str) and SHA256.fullmatch(ipc_asset["sha256"]) is not None and
            ipc_asset.get("url") == ipc_url,
            "Service IPC release asset pin is invalid",
        )
        helper = provenance.get("helper", {})
        require(
            helper.get("file") == SERVICE_HELPER_NAME and type(helper.get("size")) is int and helper["size"] > 0 and
            helper.get("sha256") == helper_sha,
            "Service IPC helper pin does not match the CVR installer pin",
        )
        license_sha = provenance.get("licenseSha256")
        require(isinstance(license_sha, str) and SHA256.fullmatch(license_sha) is not None, "Service IPC archive license pin is invalid")
        result[version] = {
            "releaseId": release["releaseId"], "tag": release["tag"],
            "assetId": asset["id"], "name": name, "size": asset["size"],
            "sha256": asset["sha256"], "serviceInstallHelperSha256": helper_sha,
            "serviceInstallHelperProvenance": provenance,
        }

    license_pin = inputs.get("serviceIpcLicense", {})
    update_source = result["2.5.10"]["serviceInstallHelperProvenance"]
    require(
        license_pin.get("repository") == SERVICE_IPC_REPOSITORY and
        license_pin.get("path") == SERVICE_IPC_LICENSE_PATH and
        license_pin.get("sourcePath") == "LICENSE" and
        license_pin.get("sourceCommit") == update_source["sourceCommit"] and
        isinstance(license_pin.get("sourceSha256"), str) and SHA256.fullmatch(license_pin["sourceSha256"]) is not None and
        license_pin.get("archiveSha256") == update_source["licenseSha256"] ==
        result["2.5.8"]["serviceInstallHelperProvenance"]["licenseSha256"],
        "shared Service IPC license source pin is invalid",
    )
    return result, license_pin


def bytes_record(data, archive_path):
    return {"path": archive_path, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


def read_service_ipc_archive(path, pin, provenance):
    record = file_record(path, str(pin["name"]))
    require(record["size"] == pin["size"] and record["sha256"] == pin["sha256"], "Service IPC archive does not match its release asset pin")
    try:
        with zipfile.ZipFile(path) as archive:
            helper_entries = [item for item in archive.infolist() if not item.is_dir() and PurePosixPath(item.filename).name == SERVICE_HELPER_NAME]
            license_entries = [item for item in archive.infolist() if not item.is_dir() and PurePosixPath(item.filename).name == "LICENSE"]
            require(len(helper_entries) == 1 and len(license_entries) == 1, "Service IPC archive helper or LICENSE entry is ambiguous")
            for item in helper_entries + license_entries:
                require(not stat.S_ISLNK(item.external_attr >> 16), "Service IPC archive contains a symlink input")
            helper_bytes = archive.read(helper_entries[0])
            license_bytes = archive.read(license_entries[0])
    except (OSError, zipfile.BadZipFile, RuntimeError):
        raise ValueError("Service IPC release archive is unreadable") from None
    helper = provenance["helper"]
    require(len(helper_bytes) == helper["size"] and hashlib.sha256(helper_bytes).hexdigest() == helper["sha256"], "Service IPC archive helper bytes do not match the pin")
    require(hashlib.sha256(license_bytes).hexdigest() == provenance["licenseSha256"], "Service IPC archive LICENSE bytes do not match the pin")
    return helper_bytes, license_bytes


def read_installer_helper(path, pin):
    seven_zip = shutil.which("7z.exe") or shutil.which("7z")
    require(seven_zip is not None, "7-Zip is required to verify the helper inside the pinned CVR installer")
    try:
        with tempfile.TemporaryDirectory(prefix="stcvrc-cvr-helper-") as directory:
            completed = subprocess.run(
                [seven_zip, "e", str(path), f"-o{directory}", SERVICE_HELPER_NAME, "-r", "-y", "-bso0", "-bsp0"],
                check=False, capture_output=True, text=True, timeout=180,
            )
            require(completed.returncode == 0, "pinned CVR installer helper extraction failed")
            matches = [item for item in Path(directory).rglob(SERVICE_HELPER_NAME) if item.is_file() and not item.is_symlink()]
            require(len(matches) == 1, "pinned CVR installer helper is missing or ambiguous")
            data = matches[0].read_bytes()
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError("pinned CVR installer helper extraction failed") from None
    require(len(data) == pin["size"] and hashlib.sha256(data).hexdigest() == pin["sha256"], "pinned CVR installer helper does not match its release pin")
    return data


def build_stage(source_root, source_sha, build_path, inputs_path, core_path,
                native_core_sha256, recovery_installer_path, update_installer_path,
                recovery_ipc_archive_path, update_ipc_archive_path, output_path, record_path):
    root = check_source(source_root, source_sha)
    build = json.loads(Path(build_path).read_text(encoding="utf-8"))
    require(build.get("schema_version") == 1 and build.get("status") == "fresh-source-build" and build.get("build_host") == "windows/amd64", "source build identity mismatch")
    require(build.get("recipe_commit") == source_sha, "source build is not bound to the reviewed SHA")
    require(build.get("version") == CORE_VERSION and build.get("core_source_commit") == CORE_SOURCE_COMMIT, "source build is not the pinned RC11 candidate")
    require(build.get("selected_dependency_versions") == DEPENDENCIES, "source build dependency pins mismatch")
    artifacts = [item for item in build.get("artifacts", []) if item.get("name") == "verge-mihomo.exe" and item.get("target") == "windows/amd64"]
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
    installers, license_pin = cvr_installers(json.loads(inputs_bytes))
    installer_paths = {"2.5.8": Path(recovery_installer_path), "2.5.10": Path(update_installer_path)}
    ipc_paths = {"2.5.8": Path(recovery_ipc_archive_path), "2.5.10": Path(update_ipc_archive_path)}
    installer_records = {}
    service_helpers = {}
    license_bytes = None
    for version in ("2.5.8", "2.5.10"):
        pin = installers[version]
        installer_record = file_record(installer_paths[version], f"payload/{pin['name']}")
        require(installer_record["sha256"] == pin["sha256"] and installer_record["size"] == pin["size"], f"CVR {version} installer bytes do not match the release pin")
        provenance = pin["serviceInstallHelperProvenance"]
        ipc_helper_bytes, current_license = read_service_ipc_archive(ipc_paths[version], provenance["asset"], provenance)
        installer_helper_bytes = read_installer_helper(installer_paths[version], provenance["helper"])
        require(installer_helper_bytes == ipc_helper_bytes, f"CVR {version} installer helper differs from its pinned Service IPC release")
        if license_bytes is None:
            license_bytes = current_license
        else:
            require(license_bytes == current_license, "Service IPC release archives contain different LICENSE bytes")
        installer_records[version] = installer_record
        service_helpers[version] = {
            "bytes": installer_helper_bytes,
            "record": bytes_record(installer_helper_bytes, SERVICE_HELPER_PATHS[version]),
            "installer": installer_record,
            "provenance": provenance,
        }

    require(license_bytes is not None, "pinned Service IPC license is missing")
    normalized_license = license_bytes.replace(b"\r\n", b"\n")
    require(hashlib.sha256(normalized_license).hexdigest() == license_pin["sourceSha256"], "Service IPC LICENSE differs from the pinned source")
    license_record = bytes_record(license_bytes, SERVICE_IPC_LICENSE_PATH)
    require(license_record["sha256"] == license_pin["archiveSha256"], "Service IPC LICENSE archive SHA256 mismatch")

    helper_records = []
    for version in ("2.5.8", "2.5.10"):
        item = service_helpers[version]
        provenance = item["provenance"]
        helper_records.append({
            "version": version,
            **item["record"],
            "installer": {
                "path": item["installer"]["path"], "size": item["installer"]["size"],
                "sha256": item["installer"]["sha256"], "tag": installers[version]["tag"],
                "releaseId": installers[version]["releaseId"], "assetId": installers[version]["assetId"],
            },
            "serviceIpc": {
                "repository": provenance["repository"], "tag": provenance["tag"],
                "sourceCommit": provenance["sourceCommit"], "asset": provenance["asset"],
                "helper": provenance["helper"],
            },
        })
    license_record_external = {
        **license_record,
        "repository": license_pin["repository"], "sourcePath": license_pin["sourcePath"],
        "sourceCommit": license_pin["sourceCommit"], "sourceSha256": license_pin["sourceSha256"],
        "archive": installers["2.5.10"]["serviceInstallHelperProvenance"]["asset"],
    }
    provenance_bytes = (
        json.dumps({"schemaVersion": 1, "cvrServiceInstallHelpers": helper_records, "serviceIpcLicense": license_record_external},
                   ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    provenance_record = bytes_record(provenance_bytes, SERVICE_IPC_PROVENANCE_PATH)

    source_records = [file_record(root / name, name) for name in SOURCE_FILES]
    file_records = sorted(
        source_records + [core_record, installer_records["2.5.8"], installer_records["2.5.10"]] +
        [service_helpers[v]["record"] for v in ("2.5.8", "2.5.10")] +
        [license_record, provenance_record],
        key=lambda item: item["path"],
    )
    manifest_bytes = (
        json.dumps({"schemaVersion": 1, "files": [{"path": item["path"], "sha256": item["sha256"]} for item in file_records]},
                   ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()

    output = Path(output_path)
    record_output = Path(record_path)
    require(output.name == "RC11-WINDOWS-STAGE.zip", "unexpected RC11 stage asset name")
    require(not output.exists() and not record_output.exists(), "refusing to overwrite RC11 stage output")
    output.parent.mkdir(parents=True, exist_ok=True)
    file_payloads = {service_helpers[v]["record"]["path"]: service_helpers[v]["bytes"] for v in ("2.5.8", "2.5.10")}
    file_payloads[SERVICE_IPC_LICENSE_PATH] = license_bytes
    file_payloads[SERVICE_IPC_PROVENANCE_PATH] = provenance_bytes
    source_paths = {name: root / name for name in SOURCE_FILES}
    source_paths[CORE_PATH] = core
    source_paths[installer_records["2.5.8"]["path"]] = installer_paths["2.5.8"]
    source_paths[installer_records["2.5.10"]["path"]] = installer_paths["2.5.10"]
    try:
        with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
            manifest_info = zipfile.ZipInfo("source-manifest.json", (1980, 1, 1, 0, 0, 0))
            manifest_info.create_system = 0
            manifest_info.compress_type = zipfile.ZIP_STORED
            archive.writestr(manifest_info, manifest_bytes)
            for item in file_records:
                info = zipfile.ZipInfo(item["path"], (1980, 1, 1, 0, 0, 0))
                info.create_system = 0
                info.compress_type = zipfile.ZIP_STORED
                digest = hashlib.sha256()
                size = 0
                if item["path"] in file_payloads:
                    with archive.open(info, "w") as target:
                        data = file_payloads[item["path"]]
                        for offset in range(0, len(data), 1024 * 1024):
                            block = data[offset:offset + 1024 * 1024]
                            digest.update(block)
                            size += len(block)
                            target.write(block)
                else:
                    with source_paths[item["path"]].open("rb") as src, archive.open(info, "w") as target:
                        for block in iter(lambda: src.read(1024 * 1024), b""):
                            digest.update(block)
                            size += len(block)
                            target.write(block)
                require(digest.hexdigest() == item["sha256"] and size == item["size"], "stage source changed while packaging")
        archive_record = file_record(output, output.name)
        require(archive_record["size"] <= 268435456, "RC11 stage exceeds the bounded release read-back size")
        record = {
            "schemaVersion": 1, "releaseTag": RELEASE_TAG, "sourceCommit": source_sha,
            "inputManifestSha256": hashlib.sha256(inputs_bytes).hexdigest(),
            "sourceManifest": {"path": "source-manifest.json", "sha256": manifest_sha256, "size": len(manifest_bytes)},
            "archive": archive_record,
            "core": {**core_record, "version": CORE_VERSION, "coreSourceCommit": CORE_SOURCE_COMMIT},
            "cvrInstallers": {
                version: {**installer_records[version], **installers[version]}
                for version in ("2.5.8", "2.5.10")
            },
            "cvrServiceInstallHelpers": helper_records,
            "serviceIpcLicense": license_record_external,
            "provenanceFile": provenance_record,
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
    pack.add_argument("--recovery-ipc-archive", required=True)
    pack.add_argument("--update-ipc-archive", required=True)
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
                args.update_installer, args.recovery_ipc_archive,
                args.update_ipc_archive, args.output, args.record,
            )
        return 0
    except (OSError, ValueError, KeyError, TypeError, AttributeError, json.JSONDecodeError, zipfile.BadZipFile) as error:
        print(f"RC11 stage packaging failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
