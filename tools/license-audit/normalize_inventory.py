"""Normalize actual Go and Rust tool output into the notice renderer contract."""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
from pathlib import Path
from urllib.parse import urlsplit

from generate_notices import AuditIncomplete, _component as _validate_component, _embedded_source, _source_archive, _supplemental_notice


_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GO_H1 = re.compile(r"^h1:[A-Za-z0-9+/]{43}=$")
_LICENSE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]*$")
_EASYTIER_MODULE = "github.com/easytier/easytier/easytier-go"
_EASYTIER_REPO = "https://github.com/EasyTier/EasyTier"
_CORE_LICENSE_IDS = {
    "LICENSE": {"GPL-3.0"},
    "transport/kcptun/LICENSE.md": {"MIT"},
}
_CORE_ATTRIBUTION_PATH = "transport/hysteria/conns/faketcp/LICENSE"
_CORE_ATTRIBUTION_TEXT = "Grabbed from https://github.com/xtaci/tcpraw with modifications"
_CORE_SOURCE_REPO = "https://github.com/smart-tinker/stcvrc"


def _required(value, label):
    if not isinstance(value, str) or not value.strip():
        raise AuditIncomplete(f"missing {label}")
    return value.strip()


def _json_stream(value, label):
    if isinstance(value, list):
        return value
    if not isinstance(value, str):
        raise AuditIncomplete(f"missing {label} JSON stream")
    decoder = json.JSONDecoder()
    rows = []
    offset = 0
    while offset < len(value):
        while offset < len(value) and value[offset].isspace():
            offset += 1
        if offset == len(value):
            break
        try:
            row, offset = decoder.raw_decode(value, offset)
        except json.JSONDecodeError as error:
            raise AuditIncomplete(f"invalid {label} JSON stream") from error
        if not isinstance(row, dict):
            raise AuditIncomplete(f"invalid object in {label} JSON stream")
        rows.append(row)
    if not rows:
        raise AuditIncomplete(f"empty {label} JSON stream")
    return rows


def _https(value, label):
    value = _required(value, label)
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise AuditIncomplete(f"invalid public HTTPS URL for {label}")
    return value


def _license_record(spdx, text, source_url, **extra):
    spdx = _required(spdx, "license identifier")
    if spdx.upper() in {"UNKNOWN", "NOASSERTION", "UNLICENSED", "IGNORE"} or spdx.startswith("LicenseRef-"):
        raise AuditIncomplete(f"unresolved license identifier: {spdx}")
    if not _LICENSE_ID.fullmatch(spdx):
        raise AuditIncomplete(f"invalid single license identifier: {spdx}")
    if not isinstance(text, str) or not text.strip():
        raise AuditIncomplete(f"missing full license text for {spdx}")
    record = {
        "spdx": spdx,
        "text": text,
        "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "source_url": _https(source_url, "license source"),
    }
    for key in ("source_revision", "source_path", "source_git_blob"):
        if key in extra and extra[key] is not None:
            record[key] = _required(extra[key], f"license {key}")
    return record


def _component_key(component):
    return f"{component['ecosystem']}:{component['name']}@{component['version']}"


def _copyright_lines(texts):
    if isinstance(texts, str):
        texts = [texts]
    result = set()
    for text in texts:
        if isinstance(text, str):
            result.update(line.strip() for line in text.splitlines() if re.search(r"\bcopyright\b", line, re.IGNORECASE))
    return sorted(result)


def _component(ecosystem, role, name, version, source_url, source_digest, licenses, **extra):
    record = {
        "ecosystem": ecosystem,
        "role": role,
        "name": name,
        "version": version,
        "source_url": source_url,
        "source_digest": source_digest,
        "licenses": licenses,
        "copyrights": [],
    }
    record.update(extra)
    return record


def _go_proxy_escape(value):
    return "".join(f"!{char.lower()}" if char.isupper() else char for char in value)


def _go_graph(bundle):
    go = bundle.get("go")
    if not isinstance(go, dict):
        raise AuditIncomplete("missing Go tool output")
    modules = _json_stream(go.get("modules_json"), "go list -m")
    packages = _json_stream(go.get("packages_json"), "go list -deps")
    core_path = _required(go.get("core_module_path"), "core Go module path")
    modules_by_path = {}
    for module in modules:
        path = _required(module.get("Path"), "Go module path")
        previous = modules_by_path.get(path)
        if previous is not None and previous.get("Version") != module.get("Version"):
            raise AuditIncomplete(f"multiple selected versions for Go module {path}")
        modules_by_path[path] = module

    graph = {}
    for package in packages:
        module = package.get("Module")
        if module is None:
            continue
        if not isinstance(module, dict):
            raise AuditIncomplete("invalid Go package module record")
        path = _required(module.get("Path"), "Go package module path")
        if path == core_path:
            continue
        listed = modules_by_path.get(path, {})
        version = module.get("Version") or listed.get("Version")
        version = _required(version, f"selected version for Go module {path}")
        if listed and listed.get("Version") and listed["Version"] != version:
            raise AuditIncomplete(f"Go package/module version mismatch for {path}")
        merged = dict(listed)
        merged.update(module)
        merged["Path"] = path
        merged["Version"] = version
        if path in graph and graph[path]["Version"] != version:
            raise AuditIncomplete(f"multiple package versions for Go module {path}")
        graph[path] = merged

    if _EASYTIER_MODULE not in graph:
        raise AuditIncomplete("EasyTier Go adapter is missing from the selected Windows build graph")
    return go, graph


def _go_report_version(module):
    replacement = module.get("Replace")
    if replacement is not None:
        if not isinstance(replacement, dict):
            raise AuditIncomplete("invalid selected Go module replacement")
        version = replacement.get("Version")
        if not version and str(replacement.get("Path", "")).startswith((".", "/")):
            return "Unknown"
    else:
        version = module.get("Version")
    if not isinstance(version, str) or not version:
        return "Unknown"
    return version.removesuffix("+incompatible")


def _go_license_overrides(go, graph):
    overrides = go.get("manual_overrides", [])
    if not isinstance(overrides, list):
        raise AuditIncomplete("invalid Go manual-license overrides")
    by_key = {}
    for item in overrides:
        if not isinstance(item, dict):
            raise AuditIncomplete("invalid Go manual-license override")
        key = (item.get("module"), item.get("version"))
        if not all(isinstance(part, str) and part for part in key):
            raise AuditIncomplete("manual license override lacks exact module/version")
        if key in by_key:
            raise AuditIncomplete(f"duplicate manual license override for {key[0]}")
        if key[0] not in graph or graph[key[0]]["Version"] != key[1]:
            raise AuditIncomplete(f"manual license override does not match selected source: {key[0]}@{key[1]}")
        by_key[key] = item

    required = go.get("required_manual_overrides")
    if required is not None:
        if not isinstance(required, list):
            raise AuditIncomplete("invalid required manual override list")
        expected = set()
        for entry in required:
            if not isinstance(entry, dict) or not entry.get("module") or not entry.get("version"):
                raise AuditIncomplete("invalid required manual override entry")
            expected.add((entry["module"], entry["version"]))
        if expected != set(by_key):
            raise AuditIncomplete("manual license overrides do not match pinned evidence set")
    return by_key



def _wintun_binding_component(go, graph):
    module_path = "github.com/metacubex/sing-tun"
    module = graph.get(module_path)
    if not isinstance(module, dict):
        raise AuditIncomplete("Wintun Go binding module is absent from the selected graph")
    version = _required(module.get("Version"), "selected Wintun Go binding module version")
    assets = go.get("embedded_assets")
    if not isinstance(assets, list):
        raise AuditIncomplete("missing embedded Wintun binary evidence")
    matching_assets = [
        item for item in assets
        if isinstance(item, dict) and item.get("module") == module_path and item.get("module_version") == version
    ]
    if len(matching_assets) != 1:
        raise AuditIncomplete("Wintun Go binding source is not uniquely tied to the selected embedded module")
    revision = _required(matching_assets[0].get("source_revision"), "Wintun Go binding source revision")
    if not _COMMIT.fullmatch(revision):
        raise AuditIncomplete("invalid Wintun Go binding source revision")
    package_paths = {
        f"{module_path}/internal/wintun",
        f"{module_path}/internal/wintun/memmod",
    }
    packages = _json_stream(go.get("packages_json"), "go list -deps")
    selected = {}
    for package in packages:
        import_path = package.get("ImportPath")
        if import_path in package_paths:
            selected.setdefault(import_path, []).append(package)
    if set(selected) != package_paths or any(len(items) != 1 for items in selected.values()):
        raise AuditIncomplete("selected Go runtime graph omits or duplicates a Wintun binding package")
    expected_files = set()
    for package_path in sorted(package_paths):
        package = selected[package_path][0]
        package_module = package.get("Module")
        if (
            not isinstance(package_module, dict)
            or package_module.get("Path") != module_path
            or package_module.get("Version") != version
        ):
            raise AuditIncomplete(f"selected Wintun Go package has the wrong module source: {package_path}")
        go_files = package.get("GoFiles", [])
        cgo_files = package.get("CgoFiles", [])
        if not isinstance(go_files, list) or not isinstance(cgo_files, list):
            raise AuditIncomplete(f"invalid selected Go source files for {package_path}")
        package_dir = package_path.removeprefix(module_path + "/")
        for filename in set(go_files + cgo_files):
            if not isinstance(filename, str) or not filename or Path(filename).name != filename:
                raise AuditIncomplete(f"invalid selected Wintun Go source filename: {filename}")
            expected_files.add(f"{package_dir}/{filename}")
    if not expected_files:
        raise AuditIncomplete("selected Wintun Go packages contain no source files")
    records = go.get("additional_components")
    if not isinstance(records, list) or len(records) != 1:
        raise AuditIncomplete("missing separate Wintun Go binding license component")
    _, component, licenses, supplemental = _validate_component(records[0], "runtime")
    if (
        component["ecosystem"] != "go-source"
        or component["name"] != "WireGuard Wintun Go bindings"
        or component["version"] != version
        or component["source_url"] != f"https://github.com/MetaCubeX/sing-tun/tree/{revision}/internal/wintun"
        or component["source_digest"] != {"algorithm": "git-commit", "value": revision}
    ):
        raise AuditIncomplete("Wintun Go binding component is not tied to the selected module source")
    if len(licenses) != 1 or licenses[0][0]["spdx"] != "MIT":
        raise AuditIncomplete("Wintun Go bindings require their separate full MIT license")
    license_record = licenses[0][0]
    if (
        not license_record.get("source_url", "").startswith("https://github.com/spdx/license-list-data/blob/")
        or license_record.get("source_path") != "text/MIT.txt"
        or not _COMMIT.fullmatch(license_record.get("source_revision", ""))
        or not _COMMIT.fullmatch(license_record.get("source_git_blob", ""))
        or "Permission is hereby granted" not in licenses[0][1]
        or "THE SOFTWARE IS PROVIDED" not in licenses[0][1]
    ):
        raise AuditIncomplete("Wintun Go binding MIT license lacks pinned full-text source evidence")
    if component["copyrights"] != ["Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved."]:
        raise AuditIncomplete("Wintun Go binding copyright header is missing")
    source_notices = component["supplemental_notices"]
    if {item["source_path"] for item in source_notices} != expected_files:
        raise AuditIncomplete("Wintun Go binding headers do not cover every selected source file")
    for item, text in supplemental:
        if (
            item.get("source_revision") != revision
            or "SPDX-License-Identifier: MIT" not in text
            or "Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved." not in text
        ):
            raise AuditIncomplete("Wintun Go binding source header evidence is incomplete")
    # Keep full texts for the renderer; validation returns a text-free source record.
    return records[0]


def _core_source_component(go, build, core_path, core_version, rows):
    if core_path != "github.com/metacubex/mihomo":
        raise AuditIncomplete("unexpected main Mihomo module path")
    commit = _required(build.get("core_source_commit"), "core source commit")
    if not _COMMIT.fullmatch(commit):
        raise AuditIncomplete("invalid exact core source commit")
    expected_version = core_version or "Unknown"
    licenses_by_path = {}
    fake_name = core_path + "/transport/hysteria/conns/faketcp"
    for row in rows:
        name = _required(row.get("Name"), "main-module go-licenses name")
        version = _required(row.get("Version"), "main-module go-licenses version")
        if version != expected_version:
            raise AuditIncomplete("go-licenses main-module version differs from the selected source")
        spdx = row.get("LicenseName")
        source_path = row.get("SourcePath")
        if isinstance(spdx, str) and spdx.lower() in {"unknown", "noassertion", "unlicensed"}:
            if name != fake_name or row.get("LicenseText") not in {"", _CORE_ATTRIBUTION_TEXT, _CORE_ATTRIBUTION_TEXT + "\n"}:
                raise AuditIncomplete(f"unresolved Go license for main Mihomo package: {name}")
            if source_path not in {None, "", _CORE_ATTRIBUTION_PATH}:
                raise AuditIncomplete("unresolved main-module row maps to an unexpected source file")
            if source_path == _CORE_ATTRIBUTION_PATH:
                if row.get("SourceRevision") != commit or not _COMMIT.fullmatch(row.get("SourceGitBlob", "")):
                    raise AuditIncomplete("faketcp Unknown row is not tied to exact source attribution")
            continue
        if source_path not in _CORE_LICENSE_IDS:
            raise AuditIncomplete(f"unmapped go-licenses row for main Mihomo module: {name}")
        if spdx not in _CORE_LICENSE_IDS[source_path]:
            raise AuditIncomplete(f"unexpected SPDX classification for core source file: {source_path}")
        if row.get("SourceRevision") != commit:
            raise AuditIncomplete(f"core license source revision mismatch: {source_path}")
        source_blob = _required(row.get("SourceGitBlob"), f"core source Git blob for {source_path}")
        if not _COMMIT.fullmatch(source_blob):
            raise AuditIncomplete(f"invalid core source Git blob: {source_path}")
        if source_path in licenses_by_path:
            raise AuditIncomplete(f"duplicate main-module license report row: {source_path}")
        source_url = f"{_CORE_SOURCE_REPO}/blob/{commit}/{source_path}"
        license_record = _license_record(
            spdx,
            row.get("LicenseText"),
            source_url,
            source_revision=commit,
            source_path=source_path,
            source_git_blob=source_blob,
        )
        licenses_by_path[source_path] = license_record

    if set(licenses_by_path) != set(_CORE_LICENSE_IDS):
        raise AuditIncomplete("go-licenses report does not cover every reviewed Mihomo license file")

    notice_rows = go.get("core_source_notices")
    if not isinstance(notice_rows, list) or len(notice_rows) != 1:
        raise AuditIncomplete("missing exact faketcp attribution source record")
    notice_row = notice_rows[0]
    if not isinstance(notice_row, dict):
        raise AuditIncomplete("invalid faketcp attribution source record")
    if (
        notice_row.get("source_path") != _CORE_ATTRIBUTION_PATH
        or notice_row.get("source_revision") != commit
        or not isinstance(notice_row.get("source_git_blob"), str)
        or not _COMMIT.fullmatch(notice_row["source_git_blob"])
        or not isinstance(notice_row.get("text"), str)
        or notice_row["text"].strip() != _CORE_ATTRIBUTION_TEXT
    ):
        raise AuditIncomplete("faketcp attribution is not bound to the exact core source")
    notice = {
        "name": notice_row.get("name"),
        "text": notice_row["text"],
        "sha256": notice_row.get("sha256"),
        "source_url": f"{_CORE_SOURCE_REPO}/blob/{commit}/{_CORE_ATTRIBUTION_PATH}",
        "source_path": _CORE_ATTRIBUTION_PATH,
        "source_revision": commit,
        "source_git_blob": notice_row["source_git_blob"],
    }
    if notice.get("name") != "faketcp attribution; go-licenses reported Unknown (not a license)":
        raise AuditIncomplete("faketcp Unknown result must remain visible as attribution, not license")
    normalized_notice, notice_text = _supplemental_notice(notice, "Mihomo core")
    if notice_text.strip() != _CORE_ATTRIBUTION_TEXT:
        raise AuditIncomplete("faketcp source record is not an attribution-only notice")

    return _component(
        "go-source",
        "runtime",
        core_path,
        f"source-{commit[:12]}",
        f"{_CORE_SOURCE_REPO}/tree/{commit}",
        {"algorithm": "git-commit", "value": commit},
        [licenses_by_path[path] for path in sorted(licenses_by_path)],
        copyrights=_copyright_lines([item["text"] for item in licenses_by_path.values()]),
        supplemental_notices=[dict(normalized_notice, text=notice_text)],
    )


def _go_components(bundle):
    go, graph = _go_graph(bundle)
    build = bundle["build"]
    overrides = _go_license_overrides(go, graph)
    rows = go.get("license_report")
    if not isinstance(rows, list):
        raise AuditIncomplete("missing go-licenses JSON report")
    core_path = _required(go.get("core_module_path"), "core Go module path")
    module_rows = _json_stream(go.get("modules_json"), "go list -m")
    main_modules = [item for item in module_rows if item.get("Path") == core_path]
    if len(main_modules) != 1:
        raise AuditIncomplete("main Mihomo module is missing or duplicated in go list -m")
    core_version = main_modules[0].get("Version") or "Unknown"

    by_module = {path: [] for path in graph}
    core_rows = []
    for row in rows:
        if not isinstance(row, dict):
            raise AuditIncomplete("invalid go-licenses record")
        name = _required(row.get("Name"), "go-licenses package/module name")
        if name == core_path or name.startswith(core_path + "/"):
            core_rows.append(row)
            continue
        candidates = [
            path for path in graph
            if name == path or name.startswith(path + "/")
        ]
        if not candidates:
            raise AuditIncomplete(f"Go license report entry is outside the selected module graph: {name}")
        module_path = max(candidates, key=len)
        expected_report_version = _go_report_version(graph[module_path])
        version = _required(row.get("Version"), f"go-licenses version for {module_path}")
        if version != expected_report_version:
            raise AuditIncomplete(f"go-licenses version mismatch for {module_path}")
        by_module[module_path].append(row)

    components = []
    for module_path in sorted(graph):
        module = graph[module_path]
        version = module["Version"]
        override = overrides.get((module_path, version))
        if override is not None:
            spdx = override.get("license_spdx")
            text = override.get("license_text")
            license_source = override.get("license_source_url") or override.get("source_url")
            license_meta = {}
            if override.get("license_text_source_revision") or override.get("license_source_revision"):
                license_meta["source_revision"] = override.get("license_text_source_revision") or override.get("license_source_revision")
            if override.get("license_text_path") or override.get("license_source_path"):
                license_meta["source_path"] = override.get("license_text_path") or override.get("license_source_path")
            if override.get("license_text_git_blob"):
                license_meta["source_git_blob"] = override["license_text_git_blob"]
            licenses = [_license_record(spdx, text, license_source, **license_meta)]
        else:
            licenses = []
            for row in by_module[module_path]:
                spdx = row.get("LicenseName")
                if not isinstance(spdx, str) or spdx.lower() in {"unknown", "noassertion", "unlicensed"}:
                    raise AuditIncomplete(f"unresolved Go license for {module_path}@{version}")
                source_url = row.get("LicenseURL")
                if module_path == _EASYTIER_MODULE and (not source_url or source_url.upper() == "UNKNOWN"):
                    source_url = f"{_EASYTIER_REPO}/blob/{build['easytier_source_commit']}/easytier-go/{Path(row.get('LicensePath') or 'LICENSE').name}"
                record = _license_record(spdx, row.get("LicenseText"), source_url)
                licenses.append(record)

        if not licenses:
            raise AuditIncomplete(f"missing license report coverage for Go module {module_path}@{version}")
        unique = {}
        for license_item in licenses:
            unique[(license_item["spdx"], license_item["sha256"])] = license_item
        licenses = [unique[key] for key in sorted(unique)]

        replacement_module = None
        replacement = module.get("Replace")
        if module_path == _EASYTIER_MODULE:
            if not isinstance(replacement, dict):
                raise AuditIncomplete("EasyTier Go adapter is not the source-built local replacement")
            replacement_path = _required(replacement.get("Path"), "EasyTier local replacement path")
            replacement_dir = _required(replacement.get("Dir"), "EasyTier local replacement directory")
            if not replacement_path.startswith(".") or not Path(replacement_dir).is_absolute():
                raise AuditIncomplete("EasyTier Go adapter replacement is not a local source checkout")
            commit = _required(build.get("easytier_source_commit"), "EasyTier source commit")
            if not _COMMIT.fullmatch(commit):
                raise AuditIncomplete("invalid EasyTier source commit")
            source_version = f"source-{commit[:12]}"
            source_url = f"{_EASYTIER_REPO}/tree/{commit}/easytier-go"
            source_digest = {"algorithm": "git-commit", "value": commit}
            upstream_version = version
        elif replacement is not None:
            if not isinstance(replacement, dict):
                raise AuditIncomplete(f"invalid Go module replacement for {module_path}")
            replacement_path = _required(replacement.get("Path"), f"replacement module path for {module_path}")
            if replacement_path.startswith((".", "/")):
                raise AuditIncomplete(f"unsupported local Go module replacement for {module_path}")
            replacement_version = _required(replacement.get("Version"), f"replacement module version for {module_path}")
            source_sum = _required(replacement.get("Sum"), f"replacement go.sum checksum for {module_path}")
            if not _GO_H1.fullmatch(source_sum):
                raise AuditIncomplete(f"invalid replacement go.sum h1 checksum for {module_path}")
            source_version = version
            source_url = (
                "https://proxy.golang.org/"
                + _go_proxy_escape(replacement_path)
                + "/@v/"
                + _go_proxy_escape(replacement_version)
                + ".zip"
            )
            source_digest = {"algorithm": "go.sum-h1", "value": source_sum}
            upstream_version = version
            replacement_module = f"{replacement_path}@{replacement_version}"
        else:
            source_sum = _required(module.get("Sum"), f"go.sum module checksum for {module_path}")
            if not _GO_H1.fullmatch(source_sum):
                raise AuditIncomplete(f"invalid go.sum h1 checksum for {module_path}")
            source_version = version
            source_url = (
                "https://proxy.golang.org/"
                + _go_proxy_escape(module_path)
                + "/@v/"
                + _go_proxy_escape(version)
                + ".zip"
            )
            source_digest = {"algorithm": "go.sum-h1", "value": source_sum}
            upstream_version = None

        component = _component(
            "go",
            "runtime",
            module_path,
            source_version,
            source_url,
            source_digest,
            licenses,
            copyrights=_copyright_lines([license_item["text"] for license_item in licenses]),
            **({"upstream_module_version": upstream_version} if upstream_version else {}),
            **({"replacement_module": replacement_module} if replacement_module else {}),
        )
        if override is not None:
            if override.get("copyrights"):
                component["copyrights"] = list(override["copyrights"])
            if override.get("supplemental_notices"):
                component["supplemental_notices"] = [
                    dict(_supplemental_notice(item, module_path)[0], text=item["text"])
                    for item in override["supplemental_notices"]
                ]
        components.append(component)

    components.append(_core_source_component(go, build, core_path, core_version, core_rows))
    components.append(_wintun_binding_component(go, graph))

    stdlib = go.get("stdlib_license")
    if not isinstance(stdlib, dict):
        raise AuditIncomplete("missing Go standard-library license text")
    go_version = _required(build.get("go_version"), "Go toolchain version")
    go_archive = build.get("go_archive")
    if not isinstance(go_archive, dict):
        raise AuditIncomplete("missing pinned Go toolchain archive")
    go_archive_sha = _required(go_archive.get("sha256"), "Go archive SHA256")
    if not _SHA256.fullmatch(go_archive_sha):
        raise AuditIncomplete("invalid Go archive SHA256")
    go_archive_url = _https(go_archive.get("url"), "Go toolchain archive")
    if _https(stdlib.get("source_url"), "Go standard-library source") != go_archive_url:
        raise AuditIncomplete("Go standard-library source does not match the pinned toolchain")
    stdlib_license = _license_record(
        stdlib.get("spdx"),
        stdlib.get("text"),
        go_archive_url,
    )
    go_copyrights = stdlib.get("copyrights") or _copyright_lines(stdlib.get("text"))
    go_supplemental = stdlib.get("supplemental_notices", [])
    if not isinstance(go_supplemental, list):
        raise AuditIncomplete("invalid Go standard-library supplemental notices")
    normalized_go_supplemental = []
    for item in go_supplemental:
        normalized, text = _supplemental_notice(item, "Go standard library")
        normalized_go_supplemental.append(dict(normalized, text=text))
    stdlib_component = _component(
        "go-toolchain-runtime",
        "runtime",
        "Go standard library",
        go_version,
        go_archive_url,
        {"algorithm": "go-archive-sha256", "value": go_archive_sha},
        [stdlib_license],
        copyrights=list(go_copyrights),
        supplemental_notices=normalized_go_supplemental,
    )
    components.append(stdlib_component)

    toolchain_component = _component(
        "toolchain",
        "build-tool",
        "Go compiler and toolchain",
        go_version,
        go_archive_url,
        {"algorithm": "go-archive-sha256", "value": go_archive_sha},
        [dict(stdlib_license)],
        copyrights=list(go_copyrights),
    )
    return components, [_component_key(item) for item in components], [toolchain_component]


def _go_embedded_assets(bundle, graph):
    go = bundle["go"]
    records = go.get("embedded_assets")
    if not isinstance(records, list):
        raise AuditIncomplete("missing embedded Go runtime asset inventory")
    components = []
    for item in records:
        if not isinstance(item, dict):
            raise AuditIncomplete("invalid embedded Go runtime asset record")
        module = _required(item.get("module"), "embedded asset Go module")
        module_version = _required(item.get("module_version"), f"embedded asset module version for {module}")
        if module not in graph or graph[module]["Version"] != module_version:
            raise AuditIncomplete(f"embedded asset source does not match selected Go module: {module}")
        name = _required(item.get("name"), "embedded runtime asset name")
        version = _required(item.get("version"), f"embedded runtime asset version for {name}")
        target = _required(item.get("target"), f"embedded runtime asset target for {name}")
        if target != "windows/amd64":
            raise AuditIncomplete(f"unexpected embedded runtime asset target for {name}: {target}")
        binary_sha = _required(item.get("sha256"), f"embedded runtime asset SHA256 for {name}")
        size = item.get("size")
        if not _SHA256.fullmatch(binary_sha) or not isinstance(size, int) or isinstance(size, bool) or size < 1:
            raise AuditIncomplete(f"invalid embedded runtime asset bytes for {name}")
        archive = _source_archive(
            {"url": item.get("archive_url"), "sha256": item.get("archive_sha256"), "path": item.get("archive_path")},
            name,
        )
        embedded = _embedded_source({
            "module": module,
            "version": module_version,
            "source_revision": item.get("source_revision"),
            "source_path": item.get("source_path"),
            "source_git_blob": item.get("source_git_blob"),
            "source_sha256": binary_sha,
            "size": size,
            "source_url": item.get("source_url"),
        }, name)
        if embedded["source_git_blob"] != _required(item.get("expected_source_git_blob"), f"expected embedded source Git blob for {name}"):
            raise AuditIncomplete(f"embedded runtime asset source Git blob mismatch for {name}")
        terms = {
            "name": _required(item.get("terms_name"), f"embedded asset terms name for {name}"),
            "text": item.get("terms_text"),
            "sha256": _required(item.get("terms_sha256"), f"embedded asset terms SHA256 for {name}"),
            "source_url": archive["url"],
            "source_archive_sha256": archive["sha256"],
            "source_path": _required(item.get("terms_path"), f"embedded asset terms path for {name}"),
        }
        normalized_terms, terms_text = _supplemental_notice(terms, name)
        component = _component(
            "embedded-binary",
            "runtime",
            name,
            version,
            archive["url"],
            {"algorithm": "sha256", "value": binary_sha},
            [],
            copyrights=list(item.get("copyrights", [])),
            supplemental_notices=[dict(normalized_terms, text=terms_text)],
            embedded_from=embedded,
            source_archive=archive,
            asset_size=size,
        )
        components.append(component)
    if not components:
        raise AuditIncomplete("embedded Go runtime asset inventory is empty")
    return components


def _rust_runtime_ids(metadata):
    if not isinstance(metadata, dict) or not isinstance(metadata.get("packages"), list):
        raise AuditIncomplete("missing cargo metadata package graph")
    resolve = metadata.get("resolve")
    if not isinstance(resolve, dict):
        raise AuditIncomplete("cargo metadata has no resolved graph")
    root = _required(resolve.get("root"), "Cargo runtime root package")
    packages = {item.get("id"): item for item in metadata["packages"] if isinstance(item, dict)}
    nodes = {item.get("id"): item for item in resolve.get("nodes", []) if isinstance(item, dict)}
    if root not in packages or root not in nodes:
        raise AuditIncomplete("Cargo runtime root is absent from resolved package graph")
    reachable = set()
    pending = [root]
    while pending:
        package_id = pending.pop()
        if package_id in reachable:
            continue
        if package_id not in packages or package_id not in nodes:
            raise AuditIncomplete(f"Cargo dependency graph references a missing package: {package_id}")
        reachable.add(package_id)
        for dependency in nodes[package_id].get("deps", []):
            if not isinstance(dependency, dict):
                raise AuditIncomplete("invalid Cargo dependency edge")
            kinds = dependency.get("dep_kinds") or [{"kind": None}]
            if any(kind.get("kind") is None for kind in kinds if isinstance(kind, dict)):
                pending.append(_required(dependency.get("pkg"), "Cargo dependency package id"))
    return packages, reachable


def _cargo_lock(lock_text):
    if not isinstance(lock_text, str) or not lock_text.strip():
        raise AuditIncomplete("missing Cargo.lock")
    try:
        lock = tomllib.loads(lock_text)
    except (tomllib.TOMLDecodeError, TypeError) as error:
        raise AuditIncomplete("invalid Cargo.lock") from error
    packages = lock.get("package")
    if not isinstance(packages, list):
        raise AuditIncomplete("Cargo.lock has no package table")
    return packages


def _cargo_source(package, lock_packages, build, source_root):
    name = _required(package.get("name"), "Cargo package name")
    version = _required(package.get("version"), f"Cargo package version for {name}")
    source = package.get("source")
    if source is None:
        commit = _required(build.get("easytier_source_commit"), "EasyTier source commit")
        if not _COMMIT.fullmatch(commit):
            raise AuditIncomplete("invalid EasyTier source commit")
        manifest_path = _required(package.get("manifest_path"), f"manifest path for local crate {name}")
        try:
            relative = Path(manifest_path).parent.relative_to(Path(source_root))
        except ValueError as error:
            raise AuditIncomplete(f"local Cargo source is outside pinned EasyTier checkout: {name}") from error
        subdir = relative.as_posix()
        source_url = f"{_EASYTIER_REPO}/tree/{commit}"
        if subdir not in {"", "."}:
            source_url += "/" + subdir
        return version, source_url, {"algorithm": "git-commit", "value": commit}, commit

    if not isinstance(source, str):
        raise AuditIncomplete(f"invalid Cargo package source for {name}")
    matches = [
        item for item in lock_packages
        if item.get("name") == name and item.get("version") == version and item.get("source") == source
    ]
    if len(matches) != 1:
        raise AuditIncomplete(f"Cargo.lock source mapping missing or ambiguous for {name}@{version}")
    lock_package = matches[0]
    if source.startswith("registry+"):
        checksum = lock_package.get("checksum")
        if not isinstance(checksum, str) or not _SHA256.fullmatch(checksum):
            raise AuditIncomplete(f"missing Cargo registry checksum for {name}@{version}")
        url = f"https://crates.io/api/v1/crates/{name}/{version}/download"
        return version, url, {"algorithm": "cargo-registry-sha256", "value": checksum}, None
    if source.startswith("git+"):
        git_source = source[4:]
        if "#" not in git_source:
            raise AuditIncomplete(f"Cargo git dependency lacks pinned commit for {name}@{version}")
        remote, commit = git_source.rsplit("#", 1)
        if not _COMMIT.fullmatch(commit):
            raise AuditIncomplete(f"Cargo git dependency has non-commit revision for {name}@{version}")
        parsed = urlsplit(remote.split("?", 1)[0])
        if parsed.scheme != "https" or not parsed.netloc:
            raise AuditIncomplete(f"Cargo git dependency has invalid public source URL for {name}")
        repo_url = f"https://{parsed.netloc}{parsed.path}".removesuffix(".git")
        return version, f"{repo_url}/tree/{commit}", {"algorithm": "git-commit", "value": commit}, commit
    raise AuditIncomplete(f"unsupported Cargo source kind for {name}@{version}: {source}")


def _local_license_source(source_path, package, source_root, commit, license_text):
    root = Path(source_root).resolve(strict=True)
    manifest_value = _required(package.get("manifest_path"), "local Cargo manifest path")
    manifest = Path(manifest_value).resolve(strict=True)
    try:
        manifest.relative_to(root)
    except ValueError as error:
        raise AuditIncomplete("local Cargo manifest is outside pinned EasyTier checkout") from error
    if not manifest.is_file():
        raise AuditIncomplete("local Cargo manifest is not a regular file")

    resolved_paths = []
    for value, label in (
        (source_path, "cargo-about license source"),
        (package.get("license_file"), "Cargo metadata license_file"),
    ):
        if value is None or value == "":
            continue
        if not isinstance(value, str):
            raise AuditIncomplete(f"invalid {label}")
        candidate = Path(value)
        if not candidate.is_absolute():
            candidate = manifest.parent / candidate
        try:
            resolved = candidate.resolve(strict=True)
            relative = resolved.relative_to(root)
        except (OSError, ValueError) as error:
            raise AuditIncomplete(f"{label} is outside or missing from pinned EasyTier checkout") from error
        if not resolved.is_file():
            raise AuditIncomplete(f"{label} is not a regular source file")
        resolved_paths.append((resolved, relative.as_posix()))

    if not resolved_paths:
        raise AuditIncomplete("local Cargo license has no source file mapping")
    selected = resolved_paths[0]
    if any(path != selected[0] for path, _ in resolved_paths[1:]):
        raise AuditIncomplete("cargo-about and Cargo metadata license paths disagree")
    data = selected[0].read_bytes()
    try:
        actual_text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise AuditIncomplete("local Cargo license source is not UTF-8") from error
    if actual_text != license_text:
        raise AuditIncomplete("cargo-about license text differs from exact local source file")
    relative_path = selected[1]
    blob = hashlib.sha1(
        b"blob " + str(len(data)).encode("ascii") + b"\0" + data
    ).hexdigest()
    return {
        "source_url": f"{_EASYTIER_REPO}/blob/{commit}/{relative_path}",
        "source_revision": commit,
        "source_path": relative_path,
        "source_git_blob": blob,
    }


def _rust_components(bundle):
    rust = bundle.get("rust")
    if not isinstance(rust, dict):
        raise AuditIncomplete("missing Rust tool output")
    metadata = rust.get("metadata")
    packages, required_ids = _rust_runtime_ids(metadata)
    lock_packages = _cargo_lock(rust.get("cargo_lock_text"))
    about = rust.get("about")
    if not isinstance(about, dict):
        raise AuditIncomplete("missing cargo-about JSON output")
    about_crates = about.get("crates")
    about_licenses = about.get("licenses")
    if not isinstance(about_crates, list) or not isinstance(about_licenses, list):
        raise AuditIncomplete("invalid cargo-about LicenseList output")
    about_by_id = {}
    for entry in about_crates:
        if not isinstance(entry, dict) or not isinstance(entry.get("package"), dict):
            raise AuditIncomplete("invalid cargo-about crate record")
        package_id = _required(entry["package"].get("id"), "cargo-about package ID")
        if package_id in about_by_id:
            raise AuditIncomplete(f"duplicate cargo-about crate record: {package_id}")
        about_by_id[package_id] = entry
    about_ids = set(about_by_id)
    if about_ids != required_ids:
        missing_ids = sorted(required_ids - about_ids)
        extra_ids = sorted(about_ids - required_ids)

        def package_samples(ids, lookup):
            return [
                {
                    "id": package_id,
                    "name": (lookup(package_id) or {}).get("name"),
                    "version": (lookup(package_id) or {}).get("version"),
                }
                for package_id in ids[:20]
            ]

        details = {
            "root_id": metadata["resolve"]["root"],
            "required_count": len(required_ids),
            "about_count": len(about_ids),
            "missing_count": len(missing_ids),
            "missing_sample": package_samples(missing_ids, packages.get),
            "extra_count": len(extra_ids),
            "extra_sample": package_samples(
                extra_ids,
                lambda package_id: about_by_id[package_id].get("package"),
            ),
        }
        raise AuditIncomplete(
            "cargo-about crates do not match the independent Cargo runtime graph: "
            + json.dumps(details, sort_keys=True)
        )

    licenses_by_crate = {}
    for license_entry in about_licenses:
        if not isinstance(license_entry, dict):
            raise AuditIncomplete("invalid cargo-about license record")
        license_id = _required(license_entry.get("id"), "cargo-about SPDX license ID")
        if license_id.upper() in {"UNKNOWN", "NOASSERTION", "UNLICENSED", "IGNORE"} or not _LICENSE_ID.fullmatch(license_id):
            raise AuditIncomplete(f"unresolved cargo-about license ID: {license_id}")
        text = license_entry.get("text")
        if not isinstance(text, str) or not text.strip():
            raise AuditIncomplete(f"cargo-about omitted full license text for {license_id}")
        used_by = license_entry.get("used_by")
        if not isinstance(used_by, list):
            raise AuditIncomplete(f"cargo-about omitted package coverage for {license_id}")
        for usage in used_by:
            package = usage.get("crate") if isinstance(usage, dict) else None
            package_id = package.get("id") if isinstance(package, dict) else None
            if package_id:
                licenses_by_crate.setdefault(package_id, []).append((license_entry, text))

    source_root = _required(rust.get("source_root"), "EasyTier source checkout path")
    build = bundle["build"]
    components = []
    required_keys = []
    for package_id in sorted(required_ids):
        package = packages[package_id]
        about_entry = about_by_id[package_id]
        selected = about_entry.get("license")
        if not isinstance(selected, str) or not selected.strip() or selected.strip().lower() in {"unknown", "ignore", "noassertion", "unlicensed"}:
            raise AuditIncomplete(f"cargo-about could not resolve selected license for {package.get('name', package_id)}")
        version, source_url, source_digest, source_commit = _cargo_source(
            package, lock_packages, build, source_root
        )
        source_url = _https(source_url, f"Cargo source for {package.get('name', package_id)}")
        license_records = []
        for license_entry, text in licenses_by_crate.get(package_id, []):
            lic_url = source_url
            license_meta = {}
            if source_commit and package.get("source") is None:
                license_meta = _local_license_source(
                    license_entry.get("source_path"),
                    package,
                    source_root,
                    source_commit,
                    text,
                )
                lic_url = license_meta.pop("source_url")
            elif source_commit:
                license_meta["source_revision"] = source_commit
            license_records.append(_license_record(
                license_entry.get("id"),
                text,
                lic_url,
                **license_meta,
            ))
        if not license_records:
            raise AuditIncomplete(f"missing cargo-about full license text for {package.get('name', package_id)}")
        unique = {}
        for item in license_records:
            unique[(item["spdx"], item["sha256"])] = item
        license_records = [unique[key] for key in sorted(unique)]
        name = _required(package.get("name"), "Cargo package name")
        component_metadata = {"selected_license": selected.strip()}
        declared_license = package.get("license")
        if declared_license is not None:
            component_metadata["declared_license"] = _required(
                declared_license, f"declared license for Cargo package {name}"
            )
        component = _component(
            "rust",
            "runtime",
            name,
            version,
            source_url,
            source_digest,
            license_records,
            copyrights=_copyright_lines([item["text"] for item in license_records]),
            **component_metadata,
        )
        components.append(component)
        required_keys.append(_component_key(component))

    standard_library = rust.get("standard_library")
    if not isinstance(standard_library, dict):
        raise AuditIncomplete("missing Rust standard-library license evidence")
    rust_version = _required(standard_library.get("version"), "Rust standard-library version")
    if rust_version != _required(build.get("rust_version"), "Rust toolchain version"):
        raise AuditIncomplete("Rust standard-library version does not match the selected toolchain")
    stdlib_commit = _required(standard_library.get("source_commit"), "Rust standard-library source commit")
    if not _COMMIT.fullmatch(stdlib_commit):
        raise AuditIncomplete("invalid Rust standard-library source commit")
    stdlib_licenses = standard_library.get("licenses")
    if not isinstance(stdlib_licenses, list):
        raise AuditIncomplete("missing Rust standard-library license texts")
    stdlib_by_id = {}
    for entry in stdlib_licenses:
        if not isinstance(entry, dict):
            raise AuditIncomplete("invalid Rust standard-library license record")
        spdx = _required(entry.get("spdx"), "Rust standard-library SPDX identifier")
        if spdx in stdlib_by_id:
            raise AuditIncomplete(f"duplicate Rust standard-library license: {spdx}")
        source_url = _https(entry.get("source_url"), f"Rust standard-library {spdx} license source")
        stdlib_by_id[spdx] = _license_record(
            spdx,
            entry.get("text"),
            source_url,
            source_revision=stdlib_commit,
        )
    if set(stdlib_by_id) != {"MIT", "Apache-2.0"}:
        raise AuditIncomplete("Rust standard library requires MIT and Apache-2.0 license texts")
    supplemental_records = standard_library.get("supplemental_notices")
    if not isinstance(supplemental_records, list):
        raise AuditIncomplete("missing Rust distribution copyright notices")
    expected_supplemental = {"COPYRIGHT", "COPYRIGHT-library.html"}
    if {item.get("name") for item in supplemental_records if isinstance(item, dict)} != expected_supplemental:
        raise AuditIncomplete("Rust standard library requires COPYRIGHT and COPYRIGHT-library.html")
    supplemental = []
    for item in supplemental_records:
        normalized, text = _supplemental_notice(item, "Rust standard library")
        if normalized.get("source_revision") != stdlib_commit:
            raise AuditIncomplete("Rust distribution copyright source does not match the selected rustc commit")
        supplemental.append(dict(normalized, text=text))

    stdlib_component = _component(
        "rust-toolchain-runtime",
        "runtime",
        "Rust standard library",
        rust_version,
        f"https://github.com/rust-lang/rust/tree/{stdlib_commit}",
        {"algorithm": "git-commit", "value": stdlib_commit},
        [stdlib_by_id[key] for key in sorted(stdlib_by_id)],
        copyrights=standard_library.get("copyrights") or _copyright_lines(
            [entry["text"] for entry in stdlib_licenses]
        ),
        supplemental_notices=supplemental,
    )
    components.append(stdlib_component)
    required_keys.append(_component_key(stdlib_component))

    toolchain_component = _component(
        "toolchain",
        "build-tool",
        "Rust compiler and toolchain",
        rust_version,
        f"https://github.com/rust-lang/rust/tree/{stdlib_commit}",
        {"algorithm": "git-commit", "value": stdlib_commit},
        [dict(stdlib_by_id[key]) for key in sorted(stdlib_by_id)],
        copyrights=standard_library.get("copyrights") or _copyright_lines(
            [entry["text"] for entry in stdlib_licenses]
        ),
    )
    return components, required_keys, [toolchain_component]


def normalize_inventory(bundle):
    """Normalize exact report outputs; reject gaps instead of inferring licenses."""
    if not isinstance(bundle, dict) or bundle.get("bundle_schema_version") != 1:
        raise AuditIncomplete("unsupported tool-output bundle schema")
    build = bundle.get("build")
    if not isinstance(build, dict):
        raise AuditIncomplete("missing source-build report")
    version = _required(build.get("version"), "source-built candidate version")
    core_commit = _required(build.get("core_source_commit"), "core source commit")
    if not _COMMIT.fullmatch(core_commit):
        raise AuditIncomplete("invalid core source commit")
    artifacts = build.get("artifacts")
    if not isinstance(artifacts, list):
        raise AuditIncomplete("missing source-built core assets")
    binaries = [item for item in artifacts if isinstance(item, dict) and item.get("name") == "verge-mihomo.exe"]
    if len(binaries) != 1 or not isinstance(binaries[0].get("sha256"), str) or not _SHA256.fullmatch(binaries[0]["sha256"]):
        raise AuditIncomplete("missing or invalid Windows core SHA256")
    target = _required(binaries[0].get("target"), "Windows core target")
    if target != "windows/amd64":
        raise AuditIncomplete(f"unexpected Windows core target: {target}")
    artifact_size = binaries[0].get("size")
    if not isinstance(artifact_size, int) or isinstance(artifact_size, bool) or artifact_size < 1:
        raise AuditIncomplete("missing or invalid Windows core size")
    go_tags = build.get("go_build_tags")
    rust_features = build.get("rust_features")
    if not isinstance(go_tags, list) or any(not isinstance(item, str) or not item for item in go_tags):
        raise AuditIncomplete("missing selected Go build tags")
    if not isinstance(rust_features, list) or any(not isinstance(item, str) or not item for item in rust_features):
        raise AuditIncomplete("missing selected Rust features")
    rust_target = _required(build.get("rust_target"), "selected Rust target")
    rust_no_default_features = build.get("rust_no_default_features")
    if not isinstance(rust_no_default_features, bool):
        raise AuditIncomplete("missing Rust default-feature selection")
    wasm_commit = _required(build.get("easytier_source_commit"), "EasyTier source commit")
    wasm_sha = _required(build.get("wasm_sha256"), "fresh WASM SHA256")
    if not _COMMIT.fullmatch(wasm_commit) or not _SHA256.fullmatch(wasm_sha):
        raise AuditIncomplete("invalid fresh EasyTier WASM provenance")

    scope = {
        "candidate_id": version,
        "core_source_commit": core_commit,
        "core_sha256": binaries[0]["sha256"],
        "core_size": artifact_size,
        "target": target,
        "go_build_tags": sorted(set(go_tags)),
        "rust_target": rust_target,
        "rust_features": sorted(set(rust_features)),
        "rust_no_default_features": rust_no_default_features,
        "embedded_wasm": {"source_commit": wasm_commit, "sha256": wasm_sha},
    }
    go_components, go_required, go_tools = _go_components(bundle)
    go, go_graph = _go_graph(bundle)
    embedded_components = _go_embedded_assets(bundle, go_graph)
    rust_components, rust_required, rust_tools = _rust_components(bundle)
    supplied_tools = bundle.get("build_tools", [])
    if not isinstance(supplied_tools, list):
        raise AuditIncomplete("invalid build-tool inventory")
    return {
        "schema_version": 1,
        "scope": scope,
        "components": go_components + embedded_components + rust_components,
        "build_tools": go_tools + rust_tools + supplied_tools,
        "required_components": sorted(set(go_required + [_component_key(item) for item in embedded_components] + rust_required)),
    }


def main():
    import argparse
    import hashlib

    from generate_notices import generate_notices, write_notice_outputs

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle")
    parser.add_argument("--notices", required=True)
    parser.add_argument("--sources", required=True)
    args = parser.parse_args()
    bundle = json.loads(Path(args.bundle).read_text(encoding="utf-8"))
    inventory = normalize_inventory(bundle)
    notices, sources = generate_notices(inventory)
    source_text = json.dumps(sources, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    notices_sha, sources_sha = write_notice_outputs(notices, source_text, args.notices, args.sources)
    print(f"THIRD-PARTY-NOTICES.txt sha256={notices_sha}")
    print(f"THIRD-PARTY-SOURCES.json sha256={sources_sha}")


if __name__ == "__main__":
    main()
