"""Deterministic renderer for reviewed, normalized third-party license inventory."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from urllib.parse import urlparse


class AuditIncomplete(ValueError):
    """The inventory cannot yet support a complete notice/source package."""


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_RELATIVE_PATH = re.compile(r"^(?!/)(?!.*(?:^|/)\.\.(?:/|$))[A-Za-z0-9._/-]+$")
_SPDX_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]*$")


def _required_text(value, label):
    if not isinstance(value, str) or not value.strip():
        raise AuditIncomplete(f"missing {label}")
    return value.strip()


def _source_digest(component):
    digest = component.get("source_digest")
    if not isinstance(digest, dict):
        raise AuditIncomplete(f"missing source digest for {component.get('name', 'component')}")
    algorithm = _required_text(digest.get("algorithm"), "source digest algorithm")
    value = _required_text(digest.get("value"), "source digest value")
    if value.upper() in {"UNKNOWN", "NOASSERTION", "UNAVAILABLE"}:
        raise AuditIncomplete(f"unresolved source digest for {component.get('name', 'component')}")
    if algorithm == "git-commit":
        valid = bool(_COMMIT.fullmatch(value))
    elif algorithm in {
        "sha256", "cargo-registry-sha256", "cargo-crate-sha256",
        "go-archive-sha256",
    }:
        valid = bool(_SHA256.fullmatch(value))
    elif algorithm == "go.sum-h1":
        encoded = value[3:] if value.startswith("h1:") else ""
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            decoded = b""
        valid = len(decoded) == 32 and base64.b64encode(decoded).decode("ascii") == encoded
    else:
        raise AuditIncomplete(f"unsupported source digest algorithm for {component.get('name', 'component')}: {algorithm}")
    if not valid:
        raise AuditIncomplete(f"invalid source digest for {component.get('name', 'component')}")
    return {"algorithm": algorithm, "value": value}


def _supplemental_notice(notice, component_name):
    if not isinstance(notice, dict):
        raise AuditIncomplete(f"invalid supplemental notice for {component_name}")
    name = _required_text(notice.get("name"), f"supplemental notice name for {component_name}")
    text = notice.get("text")
    if not isinstance(text, str) or not text.strip():
        raise AuditIncomplete(f"missing supplemental notice text for {component_name}: {name}")
    digest = _required_text(notice.get("sha256"), f"supplemental notice digest for {component_name}")
    actual = hashlib.sha256(text.encode("utf-8")).hexdigest()
    if not _SHA256.fullmatch(digest) or digest != actual:
        raise AuditIncomplete(f"supplemental notice digest mismatch for {component_name}: {name}")
    source_url = _required_text(notice.get("source_url"), f"supplemental notice source for {component_name}")
    parsed = urlparse(source_url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise AuditIncomplete(f"invalid public supplemental notice source for {component_name}: {name}")
    source_path = _required_text(notice.get("source_path"), f"supplemental notice source path for {component_name}")
    if not _RELATIVE_PATH.fullmatch(source_path):
        raise AuditIncomplete(f"invalid supplemental notice source path for {component_name}: {name}")
    normalized = {
        "name": name,
        "sha256": digest,
        "source_url": source_url,
        "source_path": source_path,
    }
    source_revision = notice.get("source_revision")
    archive_sha256 = notice.get("source_archive_sha256")
    if source_revision is not None:
        source_revision = _required_text(source_revision, f"supplemental notice source revision for {component_name}")
        if not _COMMIT.fullmatch(source_revision):
            raise AuditIncomplete(f"invalid supplemental notice source revision for {component_name}: {name}")
        normalized["source_revision"] = source_revision
    if archive_sha256 is not None:
        archive_sha256 = _required_text(archive_sha256, f"supplemental notice source archive digest for {component_name}")
        if not _SHA256.fullmatch(archive_sha256):
            raise AuditIncomplete(f"invalid supplemental notice source archive digest for {component_name}: {name}")
        normalized["source_archive_sha256"] = archive_sha256
    if ("source_revision" in normalized) == ("source_archive_sha256" in normalized):
        raise AuditIncomplete(f"supplemental notice requires one pinned source revision or archive for {component_name}: {name}")
    source_git_blob = notice.get("source_git_blob")
    if source_git_blob is not None:
        source_git_blob = _required_text(source_git_blob, f"supplemental notice Git blob for {component_name}")
        if not _COMMIT.fullmatch(source_git_blob):
            raise AuditIncomplete(f"invalid supplemental notice Git blob for {component_name}: {name}")
        normalized["source_git_blob"] = source_git_blob
    return normalized, text


def _embedded_source(value, component_name):
    if not isinstance(value, dict):
        raise AuditIncomplete(f"invalid embedded source mapping for {component_name}")
    module = _required_text(value.get("module"), f"embedded source module for {component_name}")
    version = _required_text(value.get("version"), f"embedded source version for {component_name}")
    revision = _required_text(value.get("source_revision"), f"embedded source revision for {component_name}")
    path = _required_text(value.get("source_path"), f"embedded source path for {component_name}")
    blob = _required_text(value.get("source_git_blob"), f"embedded source Git blob for {component_name}")
    sha256 = _required_text(value.get("source_sha256"), f"embedded source SHA256 for {component_name}")
    size = value.get("size")
    url = _required_text(value.get("source_url"), f"embedded source URL for {component_name}")
    parsed = urlparse(url)
    if not _COMMIT.fullmatch(revision) or not re.fullmatch(r"^[0-9a-f]{40}$", blob):
        raise AuditIncomplete(f"invalid embedded source revision or Git blob for {component_name}")
    if not _SHA256.fullmatch(sha256) or not isinstance(size, int) or isinstance(size, bool) or size < 1:
        raise AuditIncomplete(f"invalid embedded source bytes for {component_name}")
    if not _RELATIVE_PATH.fullmatch(path) or parsed.scheme != "https" or not parsed.netloc:
        raise AuditIncomplete(f"invalid embedded source location for {component_name}")
    return {
        "module": module,
        "version": version,
        "source_revision": revision,
        "source_path": path,
        "source_git_blob": blob,
        "source_sha256": sha256,
        "size": size,
        "source_url": url,
    }


def _source_archive(value, component_name):
    if not isinstance(value, dict):
        raise AuditIncomplete(f"invalid embedded asset archive for {component_name}")
    url = _required_text(value.get("url"), f"embedded asset archive URL for {component_name}")
    digest = _required_text(value.get("sha256"), f"embedded asset archive SHA256 for {component_name}")
    path = _required_text(value.get("path"), f"embedded asset archive path for {component_name}")
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc or not _SHA256.fullmatch(digest) or not _RELATIVE_PATH.fullmatch(path):
        raise AuditIncomplete(f"invalid embedded asset archive evidence for {component_name}")
    return {"url": url, "sha256": digest, "path": path}


def _license_id(value, component_name):
    license_id = _required_text(value, f"license identifier for {component_name}")
    if license_id.upper() in {"NOASSERTION", "UNKNOWN", "UNLICENSED"} or license_id.startswith("LicenseRef-"):
        raise AuditIncomplete(f"unresolved license for {component_name}: {license_id}")
    if not _SPDX_TOKEN.fullmatch(license_id):
        raise AuditIncomplete(f"invalid SPDX license identifier for {component_name}: {license_id}")
    return license_id
def _component(component, expected_role):
    if not isinstance(component, dict):
        raise AuditIncomplete("component record is not an object")
    ecosystem = _required_text(component.get("ecosystem"), "component ecosystem")
    role = _required_text(component.get("role"), "component role")
    if role != expected_role:
        raise AuditIncomplete(f"component role mismatch for {component.get('name', 'component')}")
    name = _required_text(component.get("name"), "component name")
    version = _required_text(component.get("version"), f"version for {name}")
    source_url = _required_text(component.get("source_url"), f"source URL for {name}")
    parsed = urlparse(source_url)
    if parsed.scheme not in {"https", "http"} or not parsed.netloc:
        raise AuditIncomplete(f"invalid source URL for {name}")
    source_digest = _source_digest(component)

    license_records = component.get("licenses")
    if not isinstance(license_records, list):
        raise AuditIncomplete(f"invalid license inventory for {name}")
    embedded = component.get("embedded_from")
    if not license_records and (role != "runtime" or not isinstance(embedded, dict)):
        raise AuditIncomplete(f"missing license text for {name}")
    licenses = []
    for license_record in license_records:
        if not isinstance(license_record, dict):
            raise AuditIncomplete(f"invalid license record for {name}")
        spdx = _license_id(license_record.get("spdx"), name)
        text = license_record.get("text")
        if not isinstance(text, str) or not text.strip():
            raise AuditIncomplete(f"missing license text for {name} ({spdx})")
        digest = _required_text(license_record.get("sha256"), f"license text digest for {name}")
        actual = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if not _SHA256.fullmatch(digest) or digest != actual:
            raise AuditIncomplete(f"license text digest mismatch for {name} ({spdx})")
        license_item = {"spdx": spdx, "sha256": digest}
        for field in ("source_url", "source_revision", "source_path", "source_git_blob"):
            if field in license_record:
                license_item[field] = _required_text(
                    license_record[field], f"license {field} for {name}"
                )
        licenses.append((license_item, text))
    licenses.sort(key=lambda item: (item[0]["spdx"], item[0]["sha256"]))

    supplemental_records = component.get("supplemental_notices", [])
    if not isinstance(supplemental_records, list):
        raise AuditIncomplete(f"invalid supplemental notice inventory for {name}")
    supplemental = [_supplemental_notice(item, name) for item in supplemental_records]
    supplemental.sort(key=lambda item: (item[0]["name"], item[0]["sha256"]))
    if embedded is not None and not supplemental:
        raise AuditIncomplete(f"embedded runtime asset has no redistribution terms: {name}")
    normalized_embedded = _embedded_source(embedded, name) if embedded is not None else None
    archive = component.get("source_archive")
    normalized_archive = _source_archive(archive, name) if archive is not None else None
    asset_size = component.get("asset_size")
    if asset_size is not None and (
        not isinstance(asset_size, int) or isinstance(asset_size, bool) or asset_size < 1
    ):
        raise AuditIncomplete(f"invalid embedded asset size for {name}")
    if normalized_embedded is not None:
        if source_digest != {"algorithm": "sha256", "value": normalized_embedded["source_sha256"]}:
            raise AuditIncomplete(f"embedded asset digest disagrees with its source for {name}")
        if asset_size != normalized_embedded["size"]:
            raise AuditIncomplete(f"embedded asset size disagrees with its source for {name}")
        if normalized_archive is None:
            raise AuditIncomplete(f"embedded asset has no archive source for {name}")

    copyrights = component.get("copyrights", [])
    if not isinstance(copyrights, list) or any(
        not isinstance(item, str) or not item.strip() for item in copyrights
    ):
        raise AuditIncomplete(f"invalid copyright metadata for {name}")
    copyrights = sorted({item.strip() for item in copyrights})

    record = {
        "ecosystem": ecosystem,
        "role": role,
        "name": name,
        "version": version,
        "source_url": source_url,
        "source_digest": source_digest,
        "licenses": [item[0] for item in licenses],
        "supplemental_notices": [item[0] for item in supplemental],
        "copyrights": copyrights,
    }
    if asset_size is not None:
        record["asset_size"] = asset_size
    if normalized_embedded is not None:
        record["embedded_from"] = normalized_embedded
    if normalized_archive is not None:
        record["source_archive"] = normalized_archive
    for field in ("declared_license", "selected_license", "upstream_module_version", "replacement_module"):
        if field in component:
            value = component[field]
            if value is not None and (not isinstance(value, str) or not value.strip()):
                raise AuditIncomplete(f"invalid {field} for {name}")
            record[field] = value.strip() if isinstance(value, str) else None
    key = f"{ecosystem}:{name}@{version}"
    return key, record, licenses, supplemental


def _render_component(record, licenses, supplemental):
    lines = [
        f"## {record['name']} {record['version']}",
        "",
        f"Ecosystem: {record['ecosystem']}",
        f"Source: {record['source_url']}",
        f"Source digest: {record['source_digest']['algorithm']} {record['source_digest']['value']}",
    ]
    if record.get("declared_license"):
        lines.append(f"Declared license expression: {record['declared_license']}")
    if record.get("selected_license"):
        lines.append(f"Selected license: {record['selected_license']}")
    if record.get("upstream_module_version"):
        lines.append(f"Upstream module version: {record['upstream_module_version']}")
    if record.get("replacement_module"):
        lines.append(f"Replacement source module: {record['replacement_module']}")
    if record.get("source_archive"):
        archive = record["source_archive"]
        lines.extend([
            f"Embedded binary archive: {archive['url']}",
            f"Embedded binary archive SHA256: {archive['sha256']}",
            f"Asset path in archive: {archive['path']}",
        ])
    if record.get("embedded_from"):
        embedded = record["embedded_from"]
        lines.extend([
            f"Embedded by: {embedded['module']} {embedded['version']}",
            f"Embedding source: {embedded['source_url']}",
            f"Embedded source commit: {embedded['source_revision']}",
            f"Embedded source path: {embedded['source_path']}",
            f"Embedded source Git blob: {embedded['source_git_blob']}",
            f"Embedded source SHA256: {embedded['source_sha256']}",
            f"Embedded source size: {embedded['size']} bytes",
        ])
    if record["copyrights"]:
        lines.extend(["Copyright:", *[f"- {item}" for item in record["copyrights"]]])
    for license_record, license_text in licenses:
        lines.extend(
            [
                "",
                f"License: {license_record['spdx']}",
                f"License text SHA256: {license_record['sha256']}",
            ]
        )
        if license_record.get("source_url"):
            lines.append(f"License source: {license_record['source_url']}")
        lines.extend(["", license_text.rstrip(), ""])
    if supplemental:
        lines.extend(["", "Additional required terms and notices (not SPDX license text):", ""])
        for notice_record, notice_text in supplemental:
            lines.extend([
                f"### {notice_record['name']}",
                f"Notice SHA256: {notice_record['sha256']}",
                f"Notice source: {notice_record['source_url']}",
                f"Notice source path: {notice_record['source_path']}",
            ])
            if notice_record.get("source_revision"):
                lines.append(f"Notice source revision: {notice_record['source_revision']}")
            if notice_record.get("source_archive_sha256"):
                lines.append(f"Notice source archive SHA256: {notice_record['source_archive_sha256']}")
            if notice_record.get("source_git_blob"):
                lines.append(f"Notice source Git blob: {notice_record['source_git_blob']}")
            lines.extend(["", notice_text.rstrip(), ""])
    return lines


def generate_notices(inventory):
    """Return deterministic full-text notices and exact source directions."""
    if not isinstance(inventory, dict) or inventory.get("schema_version") != 1:
        raise AuditIncomplete("unsupported notice inventory schema")
    scope = inventory.get("scope")
    if not isinstance(scope, dict):
        raise AuditIncomplete("missing candidate scope")
    candidate_id = _required_text(scope.get("candidate_id"), "candidate identifier")
    source_commit = _required_text(scope.get("core_source_commit"), "core source commit")
    core_sha = _required_text(scope.get("core_sha256"), "core binary SHA256")
    if not _COMMIT.fullmatch(source_commit) or not _SHA256.fullmatch(core_sha):
        raise AuditIncomplete("invalid core source commit or binary SHA256")
    target = _required_text(scope.get("target"), "build target")
    tags = scope.get("go_build_tags")
    if not isinstance(tags, list) or any(not isinstance(tag, str) or not tag for tag in tags):
        raise AuditIncomplete("invalid Go build tags")
    core_size = scope.get("core_size")
    if not isinstance(core_size, int) or isinstance(core_size, bool) or core_size < 1:
        raise AuditIncomplete("invalid core artifact size")
    rust_target = _required_text(scope.get("rust_target"), "Rust target")
    rust_no_default_features = scope.get("rust_no_default_features")
    if not isinstance(rust_no_default_features, bool):
        raise AuditIncomplete("missing Rust default-feature selection")
    rust_features = scope.get("rust_features")
    if not isinstance(rust_features, list) or any(not isinstance(item, str) or not item.strip() for item in rust_features):
        raise AuditIncomplete("invalid Rust features")
    embedded = scope.get("embedded_wasm")
    if not isinstance(embedded, dict):
        raise AuditIncomplete("missing embedded WASM provenance")
    wasm_commit = _required_text(embedded.get("source_commit"), "embedded WASM source commit")
    wasm_sha = _required_text(embedded.get("sha256"), "embedded WASM SHA256")
    if not _COMMIT.fullmatch(wasm_commit) or not _SHA256.fullmatch(wasm_sha):
        raise AuditIncomplete("invalid embedded WASM source commit or SHA256")

    runtime = inventory.get("components")
    build_tools = inventory.get("build_tools")
    if not isinstance(runtime, list) or not runtime:
        raise AuditIncomplete("missing runtime dependency inventory")
    if not isinstance(build_tools, list):
        raise AuditIncomplete("invalid build-tool inventory")

    normalized_runtime = [_component(item, "runtime") for item in runtime]
    normalized_build_tools = [_component(item, "build-tool") for item in build_tools]
    runtime_keys = [item[0] for item in normalized_runtime]
    build_tool_keys = [item[0] for item in normalized_build_tools]
    if len(runtime_keys) != len(set(runtime_keys)):
        raise AuditIncomplete("duplicate runtime component")
    if len(build_tool_keys) != len(set(build_tool_keys)):
        raise AuditIncomplete("duplicate build tool component")

    required = inventory.get("required_components")
    if not isinstance(required, list) or any(not isinstance(item, str) or not item for item in required):
        raise AuditIncomplete("missing independent runtime dependency graph")
    if len(required) != len(set(required)) or set(required) != set(runtime_keys):
        raise AuditIncomplete("runtime license coverage does not match the independent dependency graph")

    normalized_runtime.sort(key=lambda item: item[0])
    normalized_build_tools.sort(key=lambda item: item[0])
    source_manifest = {
        "schema_version": 1,
        "scope": {
            "candidate_id": candidate_id,
            "core_source_commit": source_commit,
            "core_sha256": core_sha,
            "core_size": core_size,
            "target": target,
            "go_build_tags": sorted(tags),
            "rust_target": rust_target,
            "rust_features": sorted(set(rust_features)),
            "rust_no_default_features": rust_no_default_features,
            "embedded_wasm": {"source_commit": wasm_commit, "sha256": wasm_sha},
        },
        "components": [item[1] for item in normalized_runtime],
        "build_tools": [item[1] for item in normalized_build_tools],
    }

    lines = [
        "Third-party notices and source directions",
        "",
        f"Candidate: {candidate_id}",
        f"Core source commit: {source_commit}",
        f"Core binary SHA256: {core_sha}",
        f"Core binary size: {core_size} bytes",
        f"Build target: {target}",
        f"Go build tags: {', '.join(sorted(tags))}",
        f"Rust target: {rust_target}",
        f"Rust features: {', '.join(sorted(set(rust_features)))}",
        f"Rust default features: {'disabled' if rust_no_default_features else 'enabled'}",
        f"Embedded EasyTier WASM source commit: {wasm_commit}",
        f"Embedded EasyTier WASM SHA256: {wasm_sha}",
        "",
        "Runtime components",
        "",
    ]
    for _, record, licenses, supplemental in normalized_runtime:
        lines.extend(_render_component(record, licenses, supplemental))
    lines.extend(
        [
            "## Build-time tools (not included in the runtime dependency graph)",
            "",
        ]
    )
    for _, record, licenses, supplemental in normalized_build_tools:
        lines.extend(_render_component(record, licenses, supplemental))
    notices = "\n".join(lines).rstrip() + "\n"
    return notices, source_manifest


def source_manifest_json(inventory):
    """Return canonical UTF-8 JSON bytes as text for source directions."""
    _, manifest = generate_notices(inventory)
    return json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
