"""Deterministic renderer for reviewed, normalized third-party license inventory."""

from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import urlparse


class AuditIncomplete(ValueError):
    """The inventory cannot yet support a complete notice/source package."""


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
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
    return {"algorithm": algorithm, "value": value}


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
    if not isinstance(license_records, list) or not license_records:
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
        "copyrights": copyrights,
    }
    key = f"{ecosystem}:{name}@{version}"
    return key, record, licenses


def _render_component(record, licenses):
    lines = [
        f"## {record['name']} {record['version']}",
        "",
        f"Ecosystem: {record['ecosystem']}",
        f"Source: {record['source_url']}",
        f"Source digest: {record['source_digest']['algorithm']} {record['source_digest']['value']}",
    ]
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
            "target": target,
            "go_build_tags": sorted(tags),
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
        f"Build target: {target}",
        f"Go build tags: {', '.join(sorted(tags))}",
        f"Embedded EasyTier WASM source commit: {wasm_commit}",
        f"Embedded EasyTier WASM SHA256: {wasm_sha}",
        "",
        "Runtime components",
        "",
    ]
    for _, record, licenses in normalized_runtime:
        lines.extend(_render_component(record, licenses))
    lines.extend(
        [
            "## Build-time tools (not included in the runtime dependency graph)",
            "",
        ]
    )
    for _, record, licenses in normalized_build_tools:
        lines.extend(_render_component(record, licenses))
    notices = "\n".join(lines).rstrip() + "\n"
    return notices, source_manifest


def source_manifest_json(inventory):
    """Return canonical UTF-8 JSON bytes as text for source directions."""
    _, manifest = generate_notices(inventory)
    return json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
