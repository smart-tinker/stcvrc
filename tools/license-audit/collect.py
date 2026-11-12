"""Collect a fresh source-built candidate's runtime notices and source directions."""

from __future__ import annotations

import ast
import hashlib
import io
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

from generate_notices import AuditIncomplete, generate_notices, write_notice_outputs
from normalize_inventory import _copyright_lines, _json_stream, normalize_inventory


GO_LICENSES_VERSION = "v2.0.1"
CARGO_ABOUT_VERSION = "0.9.2"

EASYTIER_LICENSE_SOURCE_COMMIT = "3463190838eb642ba8324c6a4011acdea52495a8"
EASYTIER_LICENSE_VERSION = "2.7.0"
EASYTIER_LICENSE_SPDX = "LGPL-3.0-only"
EASYTIER_LICENSE_SHA256 = "e3a994d82e644b03a792a930f574002658412f62407f5fee083f2555c5f23118"
EASYTIER_LICENSE_PACKAGES = ("easytier-core", "easytier-proto")
GO_LICENSES_MODULE = "github.com/google/go-licenses/v2"
GO_LICENSES_URL = f"https://proxy.golang.org/{GO_LICENSES_MODULE}/@v/{GO_LICENSES_VERSION}.zip"
GPL_TEXT_URL = "https://raw.githubusercontent.com/spdx/license-list-data/v3.29.0/text/GPL-3.0-or-later.txt"
WINTUN_ARCHIVE_URL = "https://www.wintun.net/builds/wintun-0.14.1.zip"
WINTUN_ARCHIVE_SHA256 = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
WINTUN_SOURCE_PATH = "internal/wintun/amd64/wintun.dll"
WINTUN_ARCHIVE_PATH = "wintun/bin/amd64/wintun.dll"
WINTUN_TERMS_PATH = "wintun/LICENSE.txt"
CHACHA_API = "https://api.github.com/repos/MetaCubeX/chacha"
_CORE_MODULE_PATH = "github.com/metacubex/mihomo"
_CORE_LICENSE_IDS = {
    "LICENSE": {"GPL-3.0"},
    "transport/kcptun/LICENSE.md": {"MIT"},
}
_CORE_ATTRIBUTION_PATH = "transport/hysteria/conns/faketcp/LICENSE"
_CORE_ATTRIBUTION_TEXT = "Grabbed from https://github.com/xtaci/tcpraw with modifications"


# cargo-about calls this list "accepted": it selects a license from SPDX OR expressions;
# it is a reporting-resolution policy, not a legal-compatibility approval. --fail still rejects
# expressions that cannot be resolved using this bounded list.
CARGO_ABOUT_ACCEPTED_LICENSES = (
    "MIT",
    "Apache-2.0",
    "BSD-3-Clause",
    "BSD-2-Clause",
    "ISC",
    "Zlib",
    "0BSD",
    "BSL-1.0",
    "CC0-1.0",
    "CDLA-Permissive-2.0",
    "Unlicense",
    "Unicode-3.0",
    "MPL-2.0",
    "LGPL-3.0-only",
    "LGPL-3.0-or-later",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
)


def _cargo_about_config(target):
    accepted = json.dumps(list(CARGO_ABOUT_ACCEPTED_LICENSES))
    targets = json.dumps([target])
    config = (
        f"targets = {targets}\n"
        f"accepted = {accepted}\n"
        "ignore-build-dependencies = true\n"
        "ignore-dev-dependencies = true\n"
    )
    clarifications = []
    for crate in EASYTIER_LICENSE_PACKAGES:
        clarifications.append(
            f"[{crate}.clarify]\n"
            f'license = "{EASYTIER_LICENSE_SPDX}"\n\n'
            f"[[{crate}.clarify.files]]\n"
            'path = "../LICENSE"\n'
            f'checksum = "{EASYTIER_LICENSE_SHA256}"\n'
        )
    return config + "\n" + "\n".join(clarifications)



def _validate_easytier_license_scope(easytier, build, metadata_json):
    if build.get("easytier_source_commit") != EASYTIER_LICENSE_SOURCE_COMMIT:
        raise AuditIncomplete("EasyTier license clarification does not match the pinned source commit")
    if not isinstance(metadata_json, dict):
        raise AuditIncomplete("invalid selected EasyTier package metadata")
    packages = metadata_json.get("packages")
    if not isinstance(packages, list):
        raise AuditIncomplete("missing selected EasyTier package metadata")
    matches = {name: [] for name in EASYTIER_LICENSE_PACKAGES}
    for package in packages:
        if not isinstance(package, dict):
            continue
        name = package.get("name")
        if isinstance(name, str) and name in matches:
            matches[name].append(package)
    if any(len(matches[name]) != 1 for name in EASYTIER_LICENSE_PACKAGES):
        raise AuditIncomplete("EasyTier license clarification package scope is ambiguous")
    for name in EASYTIER_LICENSE_PACKAGES:
        package = matches[name][0]
        if package.get("version") != EASYTIER_LICENSE_VERSION:
            raise AuditIncomplete(f"EasyTier license clarification version mismatch for {name}")
        manifest_path = package.get("manifest_path")
        expected_manifest = (Path(easytier) / name / "Cargo.toml").resolve()
        if not isinstance(manifest_path, str) or Path(manifest_path).resolve() != expected_manifest:
            raise AuditIncomplete(f"EasyTier license clarification source mismatch for {name}")


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _git_blob(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def _read(path, label):
    path = Path(path)
    if not path.is_file():
        raise AuditIncomplete(f"missing {label}: {path.name}")
    return path.read_bytes()


def _run(args, cwd, env, *, github_api=False):
    child_env = dict(env)
    child_env.pop("GH_TOKEN", None)
    if github_api:
        if len(args) != 5 or args[:2] != ["gh", "api"] or args[3:] != ["--hostname", "github.com"]:
            raise AuditIncomplete("GitHub API credentials are restricted to the metadata command")
        _github_api_endpoint("https://api.github.com/" + args[2])
        if env.get("GH_TOKEN"):
            child_env["GH_TOKEN"] = env["GH_TOKEN"]
    result = subprocess.run(
        [str(item) for item in args],
        cwd=str(cwd),
        env=child_env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        stderr = result.stderr[-8000:]
        raise AuditIncomplete(
            f"command failed ({result.returncode}): {Path(str(args[0])).name} "
            f"{' '.join(str(item) for item in args[1:])}\n{stderr}"
        )
    return result.stdout


def _fetch(url, maximum=16 * 1024 * 1024, github_api=False):
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "smart-tinker-stcvrc-license-audit",
            "Accept": "application/vnd.github+json" if github_api else "application/octet-stream",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            final = response.geturl()
            if not final.startswith("https://") or response.status != 200:
                raise AuditIncomplete(f"unexpected HTTPS response for pinned source: {url}")
            body = response.read(maximum + 1)
    except (urllib.error.URLError, TimeoutError) as error:
        raise AuditIncomplete(f"could not retrieve pinned public source: {url}") from error
    if len(body) > maximum:
        raise AuditIncomplete(f"pinned public source exceeds size limit: {url}")
    return body


def _read_json_stream(text, label):
    return _json_stream(text, label)


def _go_module_map(modules):
    result = {}
    for item in modules:
        path = item.get("Path")
        if isinstance(path, str) and path:
            result[path] = item
    return result


def _module_dir(module, label):
    directory = module.get("Dir")
    if not isinstance(directory, str) or not directory:
        raise AuditIncomplete(f"missing downloaded source directory for {label}")
    path = Path(directory)
    if not path.is_dir():
        raise AuditIncomplete(f"missing downloaded source directory for {label}")
    return path


def _source_url(module, revision, path):
    repository = module.removeprefix("github.com/metacubex/")
    return f"https://github.com/MetaCubeX/{repository}/blob/{revision}/{path}"


def _validate_checkout(path, expected, label):
    actual = _run(["git", "rev-parse", "HEAD"], path, os.environ).strip()
    if actual != expected:
        raise AuditIncomplete(f"{label} checkout does not match build report")


def _verified_artifact(build, output_dir, name, target):
    return verify_artifact(build, output_dir, name, target)


def verify_artifact(build, output_dir, name, target):
    """Verify the bytes and size of an artifact against the fresh build report."""
    if not isinstance(name, str) or not name or Path(name).name != name:
        raise AuditIncomplete("invalid build artifact name")
    artifacts = build.get("artifacts")
    if not isinstance(artifacts, list):
        raise AuditIncomplete("missing build artifacts")
    matches = [item for item in artifacts if isinstance(item, dict) and item.get("name") == name]
    if len(matches) != 1 or matches[0].get("target") != target:
        raise AuditIncomplete(f"missing or ambiguous build artifact: {name}")
    record = matches[0]
    expected_sha = record.get("sha256")
    expected_size = record.get("size")
    if not isinstance(expected_sha, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_sha):
        raise AuditIncomplete(f"invalid build artifact SHA256: {name}")
    if not isinstance(expected_size, int) or isinstance(expected_size, bool) or expected_size < 1:
        raise AuditIncomplete(f"invalid build artifact size: {name}")
    artifact_path = Path(output_dir) / name
    data = _read(artifact_path, f"fresh build artifact {name}")
    if _sha256(data) != expected_sha or len(data) != expected_size:
        raise AuditIncomplete(f"build artifact bytes disagree with source build report: {name}")
    return record


def _has_module_build_info(build_info, module, version):
    for line in build_info.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[:3] == ["mod", module, version]:
            return True
    return False


def _go_license_report_template():
    return (
        '{{range .}}'
        '{{printf "%q\\t%q\\t%q\\t%q\\t%q\\t" .Name .Version .LicenseURL .LicenseName .LicensePath}}'
        '{{if and .LicensePath (ne .LicensePath "Unknown")}}'
        '{{printf "%q" .LicenseText}}'
        '{{else}}{{printf "%q" ""}}{{end}}'
        '{{printf "\\n"}}'
        '{{end}}'
    )


def _parse_go_license_report(report):
    rows = []
    for line in report.splitlines():
        if not line:
            continue
        fields = line.split("\t")
        if len(fields) != 6:
            raise AuditIncomplete("go-licenses returned a malformed template row")
        try:
            values = [ast.literal_eval(field) for field in fields]
        except (SyntaxError, ValueError) as error:
            raise AuditIncomplete("go-licenses returned an invalid quoted field") from error
        rows.append(dict(zip(
            ("Name", "Version", "LicenseURL", "LicenseName", "LicensePath", "LicenseText"),
            values,
        )))
    return rows


def _core_report_path(core, value):
    if not isinstance(value, str) or not value or value == "Unknown":
        return None
    root = Path(core).resolve()
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        resolved = candidate.resolve(strict=True)
        relative = resolved.relative_to(root)
    except (OSError, ValueError) as error:
        raise AuditIncomplete("core license report path is outside the exact source checkout") from error
    if not resolved.is_file():
        raise AuditIncomplete("core license report path is not a regular source file")
    return relative.as_posix()


def _committed_source_blob(core, commit, path, data):
    expected = _run(["git", "rev-parse", f"{commit}:{path}"], core, os.environ).strip()
    actual = _git_blob(data)
    if expected != actual:
        raise AuditIncomplete(f"source bytes do not match the selected Git commit: {path}")
    return expected


def _core_source_notices(core, build, modules, rows):
    commit = build.get("core_source_commit")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise AuditIncomplete("missing exact core source commit for Go license rows")
    _validate_checkout(core, commit, "core source")
    module = modules.get(_CORE_MODULE_PATH)
    if not isinstance(module, dict):
        raise AuditIncomplete("main Mihomo module is missing from go list -m")
    expected_version = module.get("Version") or "Unknown"

    tree_paths = _run(
        ["git", "ls-tree", "-r", "--name-only", "HEAD"],
        core,
        os.environ,
    ).splitlines()
    license_like = {
        path for path in tree_paths
        if Path(path).name.upper().startswith(("LICENSE", "COPYING", "NOTICE"))
    }
    expected_paths = set(_CORE_LICENSE_IDS) | {_CORE_ATTRIBUTION_PATH}
    if license_like != expected_paths:
        raise AuditIncomplete("core source license/notice file set changed and needs review")

    core_rows = []
    fake_name = _CORE_MODULE_PATH + "/transport/hysteria/conns/faketcp"
    for row in rows:
        name = row.get("Name")
        if not isinstance(name, str) or not (name == _CORE_MODULE_PATH or name.startswith(_CORE_MODULE_PATH + "/")):
            continue
        if row.get("Version") != expected_version:
            raise AuditIncomplete("go-licenses main-module version differs from the selected source")
        path = _core_report_path(core, row.get("LicensePath"))
        if path in _CORE_LICENSE_IDS:
            source_bytes = _read(Path(core) / path, f"core license file {path}")
            source_text = source_bytes.decode("utf-8")
            if row.get("LicenseName") not in _CORE_LICENSE_IDS[path] or row.get("LicenseText") != source_text:
                raise AuditIncomplete(f"go-licenses row does not match exact core license source: {path}")
            row["SourcePath"] = path
            row["SourceRevision"] = commit
            row["SourceGitBlob"] = _committed_source_blob(core, commit, path, source_bytes)
            core_rows.append(row)
        elif path == _CORE_ATTRIBUTION_PATH:
            source_bytes = _read(Path(core) / path, "faketcp attribution")
            source_text = source_bytes.decode("utf-8")
            if source_text.strip() != _CORE_ATTRIBUTION_TEXT:
                raise AuditIncomplete("faketcp attribution text changed and needs review")
            if not isinstance(row.get("LicenseName"), str) or row["LicenseName"].lower() not in {"unknown", "noassertion", "unlicensed"}:
                raise AuditIncomplete("faketcp attribution was unexpectedly classified as a license")
            if row.get("LicenseText") not in {"", source_text}:
                raise AuditIncomplete("faketcp unknown-license row has unexpected text")
            row["SourcePath"] = path
            row["SourceRevision"] = commit
            row["SourceGitBlob"] = _committed_source_blob(core, commit, path, source_bytes)
        elif (
            path is None
            and name == fake_name
            and isinstance(row.get("LicenseName"), str)
            and row["LicenseName"].lower() in {"unknown", "noassertion", "unlicensed"}
            and row.get("LicenseText") == ""
        ):
            # go-licenses represents a package with no recognized license using Unknown;
            # the exact package's attribution file is independently included below.
            pass
        else:
            raise AuditIncomplete(f"unmapped go-licenses row for main Mihomo module: {name}")

    for path, allowed_spdx in _CORE_LICENSE_IDS.items():
        matches = [row for row in core_rows if row.get("SourcePath") == path]
        if len(matches) != 1 or matches[0].get("LicenseName") not in allowed_spdx:
            raise AuditIncomplete(f"missing or ambiguous go-licenses coverage for core source file: {path}")

    attribution_path = Path(core) / _CORE_ATTRIBUTION_PATH
    attribution_bytes = _read(attribution_path, "faketcp attribution")
    attribution_text = attribution_bytes.decode("utf-8")
    if attribution_text.strip() != _CORE_ATTRIBUTION_TEXT:
        raise AuditIncomplete("faketcp attribution text changed and needs review")
    attribution_blob = _committed_source_blob(
        core, commit, _CORE_ATTRIBUTION_PATH, attribution_bytes
    )
    return [{
        "name": "faketcp attribution; go-licenses reported Unknown (not a license)",
        "text": attribution_text,
        "sha256": _sha256(attribution_bytes),
        "source_path": _CORE_ATTRIBUTION_PATH,
        "source_revision": commit,
        "source_git_blob": attribution_blob,
    }]


def _download_go_license_tool(go, root, env, output_dir):
    host_goos = "windows" if os.name == "nt" else "linux"
    host_arch = "arm64" if platform.machine().lower() in {"aarch64", "arm64"} else "amd64"
    tool_env = dict(env)
    tool_env["GOOS"] = host_goos
    tool_env["GOARCH"] = host_arch
    tool_env["GOFLAGS"] = ""
    tool_env["GOBIN"] = str(Path(root) / "bin")
    Path(tool_env["GOBIN"]).mkdir(parents=True, exist_ok=True)
    _run([go, "install", f"{GO_LICENSES_MODULE}@{GO_LICENSES_VERSION}"], root, tool_env)
    binary = Path(tool_env["GOBIN"]) / ("go-licenses.exe" if host_goos == "windows" else "go-licenses")
    if not binary.is_file():
        raise AuditIncomplete("pinned go-licenses executable was not installed")
    build_info = _run([go, "version", "-m", binary], root, tool_env)
    if not _has_module_build_info(build_info, GO_LICENSES_MODULE, GO_LICENSES_VERSION):
        raise AuditIncomplete("go-licenses binary does not match its pinned version")
    cache = Path(env.get("GOMODCACHE", ""))
    module_dir = cache / "github.com/google/go-licenses/v2@v2.0.1"
    ziphash = cache / "cache/download/github.com/google/go-licenses/v2/@v/v2.0.1.ziphash"
    if not module_dir.is_dir():
        raise AuditIncomplete("go-licenses source module is missing from the isolated module cache")
    source_sum = ziphash.read_text(encoding="ascii").strip() if ziphash.is_file() else ""
    if not re.fullmatch(r"h1:[A-Za-z0-9+/]{43}=", source_sum):
        raise AuditIncomplete("go-licenses module archive checksum is missing")
    license_text = _read(module_dir / "LICENSE", "go-licenses license").decode("utf-8")
    tool_license = {
        "spdx": "Apache-2.0",
        "text": license_text,
        "sha256": _sha256(license_text.encode("utf-8")),
        "source_url": f"https://github.com/google/go-licenses/blob/{GO_LICENSES_VERSION}/LICENSE",
        "source_revision": GO_LICENSES_VERSION,
        "source_path": "LICENSE",
    }
    return binary, {
        "ecosystem": "go-tool",
        "role": "build-tool",
        "name": GO_LICENSES_MODULE,
        "version": GO_LICENSES_VERSION,
        "source_url": GO_LICENSES_URL,
        "source_digest": {"algorithm": "go.sum-h1", "value": source_sum},
        "licenses": [tool_license],
        "copyrights": _copyright_lines([license_text]),
    }


def _go_rows(core, go, build, root, env):
    goos = "windows"
    goarch = "amd64"
    selected = dict(env)
    selected["GOOS"] = goos
    selected["GOARCH"] = goarch
    selected["CGO_ENABLED"] = "0"
    selected["GOAMD64"] = "v1"
    tags = build.get("go_build_tags")
    if not isinstance(tags, list) or not tags or any(not isinstance(tag, str) or not tag for tag in tags):
        raise AuditIncomplete("missing selected Go build tags")
    modfile = Path(core) / ".ci-build.mod"
    if not modfile.is_file():
        raise AuditIncomplete("fresh source build has no isolated Go module file")
    goflags = f"-modfile={modfile.as_posix()} -mod=readonly -p=2 -tags={','.join(tags)}"
    selected["GOFLAGS"] = goflags
    modules = _run([go, "list", "-m", "-json", "all"], core, selected)
    packages = _run([go, "list", "-deps", "-json", "."], core, selected)
    module_rows = _read_json_stream(modules, "go list -m")
    package_rows = _read_json_stream(packages, "go list -deps")
    selected_modules = _go_module_map(module_rows)
    runtime_module_paths = set()
    for package in package_rows:
        module = package.get("Module")
        if isinstance(module, dict):
            path = module.get("Path")
            if isinstance(path, str) and path:
                runtime_module_paths.add(path)
    # Validate manual evidence only for modules in the built core's package graph.
    overrides = _manual_go_overrides(selected_modules, runtime_module_paths, build, root)
    license_tool, tool_record = _download_go_license_tool(go, root, selected, root)
    template = Path(root) / "output" / "license-report.tmpl"
    template.write_text(_go_license_report_template(), encoding="utf-8")
    report = _run(
        [license_tool, "report", ".", f"--template={template}"],
        core,
        selected,
    )
    rows = _parse_go_license_report(report)
    print(
        "go-licenses rows: "
        + json.dumps([
            {
                "Name": row.get("Name"),
                "Version": row.get("Version"),
                "LicenseName": row.get("LicenseName"),
            }
            for row in sorted(rows, key=lambda item: (item.get("Name", ""), item.get("LicenseName", "")))
        ], sort_keys=True),
        file=sys.stderr,
    )
    core_notices = _core_source_notices(core, build, selected_modules, rows)

    embedded = _wintun_record(selected_modules)
    wintun_bindings = _wintun_binding_component(selected_modules, package_rows)
    go_root = Path(_run([go, "env", "GOROOT"], core, selected).strip())
    go_license = _read(go_root / "LICENSE", "Go toolchain LICENSE").decode("utf-8")
    go_archive = build.get("go_archive")
    if not isinstance(go_archive, dict) or not isinstance(go_archive.get("url"), str):
        raise AuditIncomplete("missing exact Go toolchain archive in build report")
    stdlib = {
        "spdx": "BSD-3-Clause",
        "text": go_license,
        "source_url": go_archive["url"],
        "copyrights": _copyright_lines([go_license]),
    }
    patents = go_root / "PATENTS"
    if patents.is_file():
        patent_text = patents.read_text(encoding="utf-8")
        stdlib["supplemental_notices"] = [{
            "name": "Go distribution PATENTS",
            "text": patent_text,
            "sha256": _sha256(patent_text.encode("utf-8")),
            "source_url": go_archive["url"],
            "source_archive_sha256": go_archive.get("sha256"),
            "source_path": "PATENTS",
        }]
    return {
        "core_module_path": "github.com/metacubex/mihomo",
        "modules_json": modules,
        "packages_json": packages,
        "license_report": rows,
        "core_source_notices": core_notices,
        "manual_overrides": overrides,
        "required_manual_overrides": [
            {"module": item["module"], "version": item["version"]}
            for item in overrides
        ],
        "embedded_assets": [embedded],
        "additional_components": [wintun_bindings],
        "stdlib_license": stdlib,
    }, tool_record


def _github_api_endpoint(url):
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.netloc != "api.github.com"
        or parsed.query
        or parsed.fragment
        or not re.fullmatch(
            r"/repos/MetaCubeX/(?:chacha|sing-tun)/commits/[A-Za-z0-9][A-Za-z0-9._+-]{0,127}",
            parsed.path,
        )
    ):
        raise AuditIncomplete("refusing GitHub API URL outside pinned commit metadata")
    return parsed.path.lstrip("/")


def _github_json(url):
    endpoint = _github_api_endpoint(url)
    if not os.environ.get("GH_TOKEN"):
        raise AuditIncomplete("GitHub API metadata requires the workflow API token")
    raw = _run(
        ["gh", "api", endpoint, "--hostname", "github.com"],
        Path(__file__).resolve().parents[2],
        os.environ,
        github_api=True,
    )
    try:
        result = json.loads(raw)
    except json.JSONDecodeError as error:
        raise AuditIncomplete(f"invalid GitHub API JSON from {url}") from error
    if not isinstance(result, dict):
        raise AuditIncomplete(f"unexpected GitHub API response from {url}")
    return result


def _manual_go_overrides(modules, runtime_module_paths, build, root):
    evidence_path = Path(__file__).resolve().parent / "fixtures" / "expected-rc7-sources.json"
    evidence = json.loads(_read(evidence_path, "pinned license evidence").decode("utf-8"))
    result = []
    runtime_pins = [
        pin for pin in evidence.get("meta_gpl_overrides", [])
        if pin.get("module") in runtime_module_paths
    ]
    if runtime_pins:
        expected_text = evidence.get("canonical_license_texts", {}).get("GPL-3.0-or-later")
        if not isinstance(expected_text, dict):
            raise AuditIncomplete("missing pinned full GPL-3.0-or-later text evidence")
        gpl_text = _fetch(expected_text["url"]).decode("utf-8")
        if _sha256(gpl_text.encode("utf-8")) != expected_text.get("sha256"):
            raise AuditIncomplete("canonical GPL-3.0-or-later text checksum mismatch")
    for pin in runtime_pins:
        module = pin["module"]
        version = pin["version"]
        selected = modules.get(module)
        if not isinstance(selected, dict) or selected.get("Version") != version or selected.get("Replace"):
            raise AuditIncomplete(f"pinned MetaCubeX module is not selected unchanged: {module}@{version}")
        source_dir = _module_dir(selected, f"{module}@{version}")
        header_bytes = _read(source_dir / pin["license_path"], f"{module} license header")
        if _git_blob(header_bytes) != pin["license_git_blob"]:
            raise AuditIncomplete(f"MetaCubeX license header differs from pinned source: {module}@{version}")
        repo = module.removeprefix("github.com/metacubex/")
        raw_url = f"https://raw.githubusercontent.com/MetaCubeX/{repo}/{pin['source_revision']}/{pin['license_path']}"
        remote_header = _fetch(raw_url)
        if remote_header != header_bytes:
            raise AuditIncomplete(f"MetaCubeX module source does not match its pinned license revision: {module}")
        header_text = header_bytes.decode("utf-8")
        result.append({
            **pin,
            "license_text": gpl_text,
            "license_source_url": expected_text["url"],
            "license_text_source_revision": expected_text.get("source_revision"),
            "license_text_path": expected_text.get("source_path"),
            "copyrights": _copyright_lines([header_text, gpl_text]),
            "supplemental_notices": [{
                "name": "Upstream LICENSE header (supplemental to full GPL terms)",
                "text": header_text,
                "sha256": _sha256(header_bytes),
                "source_url": _source_url(module, pin["source_revision"], pin["license_path"]),
                "source_revision": pin["source_revision"],
                "source_path": pin["license_path"],
                "source_git_blob": pin["license_git_blob"],
            }],
        })

    chacha = evidence.get("chacha_mit_evidence")
    if not isinstance(chacha, dict):
        if any(path == "github.com/metacubex/chacha" for path in runtime_module_paths):
            raise AuditIncomplete("missing pinned chacha MIT child evidence")
        return result
    if chacha["module"] not in runtime_module_paths:
        return result
    selected = modules.get(chacha["module"])
    if not isinstance(selected, dict) or selected.get("Version") != chacha["version"] or selected.get("Replace"):
        raise AuditIncomplete("chacha source version does not match the reviewed license-only child")
    source_commit = _github_json(f"{CHACHA_API}/commits/{chacha['version']}")
    if source_commit.get("sha") != chacha["pinned_source_revision"]:
        raise AuditIncomplete("chacha module version does not resolve to the pinned source commit")
    source_dir = _module_dir(selected, "chacha@" + chacha["version"])
    pinned_source = _read(source_dir / "chacha" / "chacha.go", "pinned chacha source")
    source_url = f"https://raw.githubusercontent.com/MetaCubeX/chacha/{chacha['pinned_source_revision']}/chacha/chacha.go"
    if _fetch(source_url) != pinned_source:
        raise AuditIncomplete("selected chacha module source differs from its pinned public commit")
    commit = _github_json(f"{CHACHA_API}/commits/{chacha['license_source_revision']}")
    parents = commit.get("parents")
    files = commit.get("files")
    if (
        not isinstance(parents, list)
        or len(parents) != 1
        or parents[0].get("sha") != chacha["license_file_parent"]
        or not isinstance(files, list)
        or [item.get("filename") for item in files] != chacha.get("diff_files")
        or chacha.get("diff_files") != ["LICENSE"]
    ):
        raise AuditIncomplete("chacha license evidence is not an exact LICENSE-only child")
    raw_url = f"https://raw.githubusercontent.com/MetaCubeX/chacha/{chacha['license_source_revision']}/{chacha['license_path']}"
    license_bytes = _fetch(raw_url)
    license_text = license_bytes.decode("utf-8")
    for copyright in chacha.get("copyrights", []):
        if copyright not in license_text:
            raise AuditIncomplete("chacha MIT license text omits a pinned copyright notice")
    result.append({
        "module": chacha["module"],
        "version": chacha["version"],
        "source_revision": chacha["pinned_source_revision"],
        "license_spdx": chacha["license_spdx"],
        "license_text": license_text,
        "license_source_url": chacha["license_source_url"],
        "license_text_source_revision": chacha["license_source_revision"],
        "license_text_path": chacha["license_path"],
        "license_text_git_blob": _git_blob(license_bytes),
        "copyrights": chacha["copyrights"],
    })
    return result


def _wintun_record(modules):
    evidence_path = Path(__file__).resolve().parent / "fixtures" / "expected-rc7-sources.json"
    evidence = json.loads(_read(evidence_path, "pinned license evidence").decode("utf-8"))
    pin = evidence.get("wintun_embedded")
    if not isinstance(pin, dict):
        raise AuditIncomplete("missing Wintun embedded binary evidence")
    selected = modules.get(pin["module"])
    if not isinstance(selected, dict) or selected.get("Version") != pin["module_version"]:
        raise AuditIncomplete("Wintun embedding module does not match the selected Go graph")
    source_dir = _module_dir(selected, pin["module"])
    source_bytes = _read(source_dir / pin["source_path"], "embedded Wintun source bytes")
    raw_source_url = (
        f"https://raw.githubusercontent.com/MetaCubeX/sing-tun/"
        f"{pin['source_revision']}/{pin['source_path']}"
    )
    if _fetch(raw_source_url, maximum=2 * 1024 * 1024) != source_bytes:
        raise AuditIncomplete("embedded Wintun DLL differs from its pinned public Go source")
    if (
        _sha256(source_bytes) != pin["sha256"]
        or len(source_bytes) != pin["size"]
        or _git_blob(source_bytes) != pin["source_git_blob"]
    ):
        raise AuditIncomplete("embedded Wintun source bytes differ from the pinned module file")

    archive = _fetch(pin["archive_url"], maximum=16 * 1024 * 1024)
    archive_sha = _sha256(archive)
    if archive_sha != pin["archive_sha256"] or archive_sha != WINTUN_ARCHIVE_SHA256:
        raise AuditIncomplete("official Wintun archive checksum mismatch")
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
            embedded_bytes = zipped.read(pin["archive_path"])
            terms_bytes = zipped.read(pin["terms_path"])
    except (KeyError, zipfile.BadZipFile) as error:
        raise AuditIncomplete("official Wintun archive lacks the pinned binary or terms file") from error
    if embedded_bytes != source_bytes:
        raise AuditIncomplete("Go-embedded Wintun DLL differs from the official signed distribution")
    terms = terms_bytes.decode("utf-8")
    return {
        "module": pin["module"],
        "module_version": pin["module_version"],
        "name": "wintun.dll",
        "version": pin["binary_version"],
        "target": "windows/amd64",
        "source_revision": pin["source_revision"],
        "source_path": pin["source_path"],
        "source_git_blob": _git_blob(source_bytes),
        "expected_source_git_blob": pin["source_git_blob"],
        "sha256": _sha256(source_bytes),
        "size": len(source_bytes),
        "source_url": pin["source_url"],
        "archive_url": pin["archive_url"],
        "archive_sha256": archive_sha,
        "archive_path": pin["archive_path"],
        "terms_name": "Wintun signed-binary redistribution terms",
        "terms_text": terms,
        "terms_sha256": _sha256(terms_bytes),
        "terms_path": pin["terms_path"],
        "copyrights": _copyright_lines([terms]),
    }



def _wintun_binding_component(modules, package_rows):
    evidence_path = Path(__file__).resolve().parent / "fixtures" / "expected-rc7-sources.json"
    evidence = json.loads(_read(evidence_path, "pinned license evidence").decode("utf-8"))
    pin = evidence.get("wintun_go_bindings")
    if not isinstance(pin, dict):
        raise AuditIncomplete("missing Wintun Go binding license evidence")
    module = pin["module"]
    version = pin["module_version"]
    selected = modules.get(module)
    if not isinstance(selected, dict) or selected.get("Version") != version or selected.get("Replace"):
        raise AuditIncomplete("Wintun Go binding source does not match the selected Go module")

    resolved = _github_json(f"https://api.github.com/repos/MetaCubeX/sing-tun/commits/{version}")
    revision = pin["source_revision"]
    if resolved.get("sha") != revision:
        raise AuditIncomplete("Wintun Go binding version does not resolve to the pinned source commit")
    source_dir = _module_dir(selected, module)
    expected_packages = {
        f"{module}/internal/wintun",
        f"{module}/internal/wintun/memmod",
    }
    if set(pin.get("packages", [])) != expected_packages:
        raise AuditIncomplete("Wintun Go binding package scope differs from the reviewed evidence")
    selected_packages = {}
    for package in package_rows:
        if package.get("ImportPath") in expected_packages:
            selected_packages.setdefault(package["ImportPath"], []).append(package)
    if set(selected_packages) != expected_packages or any(len(items) != 1 for items in selected_packages.values()):
        raise AuditIncomplete("selected Windows build graph omits or duplicates a Wintun Go binding package")

    notices = []
    source_paths = set()
    header_pattern = re.compile(
        r"/\* SPDX-License-Identifier: MIT\s+\*\s+"
        r"\* Copyright \(C\) 2017-2021 WireGuard LLC\. All Rights Reserved\.\s+\*/"
    )
    for package_path in sorted(expected_packages):
        package = selected_packages[package_path][0]
        package_module = package.get("Module")
        if (
            not isinstance(package_module, dict)
            or package_module.get("Path") != module
            or package_module.get("Version") != version
        ):
            raise AuditIncomplete(f"Wintun Go binding package source mismatch: {package_path}")
        go_files = package.get("GoFiles", [])
        cgo_files = package.get("CgoFiles", [])
        if not isinstance(go_files, list) or not isinstance(cgo_files, list):
            raise AuditIncomplete(f"invalid selected Go source list for {package_path}")
        relative_package = package_path.removeprefix(module + "/")
        for filename in sorted(set(go_files + cgo_files)):
            if not isinstance(filename, str) or not filename or Path(filename).name != filename:
                raise AuditIncomplete(f"invalid selected Wintun Go source filename: {filename}")
            source_path = f"{relative_package}/{filename}"
            if source_path in source_paths:
                raise AuditIncomplete(f"duplicate selected Wintun Go source file: {source_path}")
            source_paths.add(source_path)
            source_bytes = _read(source_dir / source_path, f"Wintun Go binding source {source_path}")
            raw_url = f"https://raw.githubusercontent.com/MetaCubeX/sing-tun/{revision}/{source_path}"
            if _fetch(raw_url) != source_bytes:
                raise AuditIncomplete(f"Wintun Go binding source differs from its pinned public revision: {source_path}")
            source_text = source_bytes.decode("utf-8")
            header = header_pattern.search(source_text)
            if header is None or pin["copyright"] not in header.group(0):
                raise AuditIncomplete(f"Wintun Go source lacks the reviewed MIT copyright header: {source_path}")
            header_text = header.group(0)
            notices.append({
                "name": f"SPDX MIT header: {source_path}",
                "text": header_text,
                "sha256": _sha256(header_text.encode("utf-8")),
                "source_url": f"https://github.com/MetaCubeX/sing-tun/blob/{revision}/{source_path}",
                "source_revision": revision,
                "source_path": source_path,
                "source_git_blob": _git_blob(source_bytes),
            })
    if not source_paths:
        raise AuditIncomplete("selected Wintun Go binding packages contain no source files")

    license_bytes = _fetch(pin["license_text_url"])
    if _git_blob(license_bytes) != pin["license_git_blob"]:
        raise AuditIncomplete("canonical MIT license text differs from its pinned SPDX source blob")
    license_text = license_bytes.decode("utf-8")
    license_record = {
        "spdx": pin["license_spdx"],
        "text": license_text,
        "sha256": _sha256(license_bytes),
        "source_url": pin["license_source_url"],
        "source_revision": pin["license_source_revision"],
        "source_path": pin["license_path"],
        "source_git_blob": _git_blob(license_bytes),
    }
    return {
        "ecosystem": "go-source",
        "role": "runtime",
        "name": pin["name"],
        "version": version,
        "source_url": f"https://github.com/MetaCubeX/sing-tun/tree/{revision}/internal/wintun",
        "source_digest": {"algorithm": "git-commit", "value": revision},
        "licenses": [license_record],
        "copyrights": [pin["copyright"]],
        "supplemental_notices": notices,
    }


def _cargo_tool(cargo, root, env):
    tool_root = Path(root) / "output" / "cargo-about-tool"
    cargo_env = dict(env)
    cargo_env["CARGO_NET_OFFLINE"] = "false"
    cargo_env["CARGO_TARGET_DIR"] = str(Path(root) / "output" / "cargo-about-target")
    _run(
        [cargo, "install", "--locked", "--version", CARGO_ABOUT_VERSION, "--features", "cli", "--root", tool_root, "cargo-about"],
        root,
        cargo_env,
    )
    binary = tool_root / "bin" / ("cargo-about.exe" if os.name == "nt" else "cargo-about")
    if not binary.is_file():
        raise AuditIncomplete("pinned cargo-about executable was not installed")
    version = _run([binary, "--version"], root, cargo_env).strip()
    if version not in {f"cargo-about {CARGO_ABOUT_VERSION}", f"cargo-about v{CARGO_ABOUT_VERSION}"}:
        raise AuditIncomplete("cargo-about binary does not match its pinned version")

    cargo_home = Path(env.get("CARGO_HOME", ""))
    sources = list((cargo_home / "registry" / "src").glob(f"*/cargo-about-{CARGO_ABOUT_VERSION}"))
    archives = list((cargo_home / "registry" / "cache").glob(f"*/cargo-about-{CARGO_ABOUT_VERSION}.crate"))
    if len(sources) != 1 or len(archives) != 1:
        raise AuditIncomplete("cargo-about source crate or archive is missing/ambiguous")
    crate = sources[0]
    package = __import__("tomllib").loads((crate / "Cargo.toml").read_text(encoding="utf-8")).get("package", {})
    if package.get("version") != CARGO_ABOUT_VERSION or package.get("license") != "MIT OR Apache-2.0":
        raise AuditIncomplete("cargo-about source package metadata differs from the pinned crate")
    licenses = []
    for spdx, path, filename in (
        ("MIT", "LICENSE-MIT", "LICENSE-MIT"),
        ("Apache-2.0", "LICENSE-APACHE", "LICENSE-APACHE"),
    ):
        text = _read(crate / path, f"cargo-about {spdx} license").decode("utf-8")
        licenses.append({
            "spdx": spdx,
            "text": text,
            "sha256": _sha256(text.encode("utf-8")),
            "source_url": f"https://github.com/EmbarkStudios/cargo-about/blob/{CARGO_ABOUT_VERSION}/{filename}",
            "source_revision": CARGO_ABOUT_VERSION,
            "source_path": filename,
        })
    data = _read(archives[0], "cargo-about source crate")
    return binary, {
        "ecosystem": "rust-tool",
        "role": "build-tool",
        "name": "cargo-about",
        "version": CARGO_ABOUT_VERSION,
        "source_url": f"https://crates.io/crates/cargo-about/{CARGO_ABOUT_VERSION}",
        "source_digest": {"algorithm": "cargo-crate-sha256", "value": _sha256(data)},
        "licenses": licenses,
        "copyrights": _copyright_lines([item["text"] for item in licenses]),
    }


def _rust_rows(easytier, build, root, env, output_dir):
    rust_version = build.get("rust_version")
    if not isinstance(rust_version, str):
        raise AuditIncomplete("missing pinned Rust toolchain version")
    rustc = shutil.which("rustc")
    cargo = shutil.which("cargo")
    if not rustc or not cargo:
        raise AuditIncomplete("pinned Rust compiler tools are not on PATH")
    version_text = _run([rustc, "-vV"], easytier, env)
    parsed = {}
    for line in version_text.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            parsed[key.strip()] = value.strip()
    if parsed.get("release") != rust_version or not re.fullmatch(r"[0-9a-f]{40}", parsed.get("commit-hash", "")):
        raise AuditIncomplete("installed rustc version/commit does not match source-build record")
    source_commit = parsed["commit-hash"]
    lock_path = Path(easytier) / "Cargo.lock"
    lock = _read(lock_path, "EasyTier Cargo.lock")
    if _sha256(lock) != build.get("cargo_lock_sha256"):
        raise AuditIncomplete("EasyTier Cargo.lock differs from source-build record")
    target = build.get("rust_target")
    features = build.get("rust_features")
    if not isinstance(target, str) or not target or not isinstance(features, list) or not features:
        raise AuditIncomplete("missing selected EasyTier Rust target/features")
    manifest = Path(easytier) / "easytier-core" / "Cargo.toml"
    metadata = _run(
        [
            cargo, "metadata", "--format-version", "1", "--locked",
            "--manifest-path", manifest,
            "--filter-platform", target,
            "--features", ",".join(features),
            "--no-default-features",
        ],
        easytier,
        env,
    )
    metadata_json = json.loads(metadata)
    _validate_easytier_license_scope(easytier, build, metadata_json)
    runtime_tree = _run(
        [
            cargo, "tree", "--locked", "--manifest-path", manifest,
            "--target", target,
            "--features", ",".join(features),
            "--no-default-features",
            "--edges", "normal",
            "--format", "{p}",
            "--prefix", "none",
            "--no-dedupe",
        ],
        easytier,
        env,
    )
    about_config = Path(output_dir) / "cargo-about.toml"
    about_config.write_text(_cargo_about_config(target), encoding="utf-8")
    about_binary, cargo_about_record = _cargo_tool(cargo, root, env)
    about_env = dict(env)
    about_env["CARGO_NET_OFFLINE"] = "true"
    about = _run(
        [
            about_binary, "generate", "--format", "json", "--locked", "--fail",
            "--manifest-path", manifest,
            "--features", ",".join(features),
            "--no-default-features",
            "--config", about_config,
        ],
        easytier,
        about_env,
    )
    about_json = json.loads(about)

    sysroot = Path(_run([rustc, "--print", "sysroot"], easytier, env).strip())
    doc_root = sysroot / "share" / "doc" / "rust"
    # Rust's legal root overlay is not installed by rustup; use its exact compiler source.
    rust_source = f"https://raw.githubusercontent.com/rust-lang/rust/{source_commit}"
    license_mit = _fetch(f"{rust_source}/LICENSE-MIT").decode("utf-8")
    license_apache = _fetch(f"{rust_source}/LICENSE-APACHE").decode("utf-8")
    copyright = _fetch(f"{rust_source}/COPYRIGHT").decode("utf-8")
    library_copyright = _read(doc_root / "COPYRIGHT-library.html", "Rust standard-library third-party notices").decode("utf-8")
    rust_repo = "https://github.com/rust-lang/rust"
    standard = {
        "version": rust_version,
        "source_commit": source_commit,
        "licenses": [
            {"spdx": "MIT", "text": license_mit, "source_url": f"{rust_repo}/blob/{source_commit}/LICENSE-MIT"},
            {"spdx": "Apache-2.0", "text": license_apache, "source_url": f"{rust_repo}/blob/{source_commit}/LICENSE-APACHE"},
        ],
        "copyrights": _copyright_lines([copyright, library_copyright]),
        "supplemental_notices": [
            {
                "name": "COPYRIGHT",
                "text": copyright,
                "sha256": _sha256(copyright.encode("utf-8")),
                "source_url": f"{rust_repo}/blob/{source_commit}/COPYRIGHT",
                "source_revision": source_commit,
                "source_path": "COPYRIGHT",
            },
            {
                "name": "COPYRIGHT-library.html",
                "text": library_copyright,
                "sha256": _sha256(library_copyright.encode("utf-8")),
                "source_url": f"{rust_repo}/tree/{source_commit}/src/tools/generate-copyright",
                "source_revision": source_commit,
                "source_path": "share/doc/rust/COPYRIGHT-library.html",
            },
        ],
    }
    return {
        "metadata": metadata_json,
        "runtime_tree": runtime_tree,
        "about": about_json,
        "cargo_lock_text": lock.decode("utf-8"),
        "source_root": str(easytier),
        "standard_library": standard,
    }, cargo_about_record


def collect(build_root, output_dir=None):
    root = Path(build_root).resolve()
    output = Path(output_dir).resolve() if output_dir else root / "output"
    build_path = output / "build.json"
    try:
        build = json.loads(_read(build_path, "source-built build report").decode("utf-8"))
    except json.JSONDecodeError as error:
        raise AuditIncomplete("source-built build report is not valid JSON") from error
    core = root / "core"
    easytier = root / "easytier"
    core_commit = build.get("core_source_commit")
    easytier_commit = build.get("easytier_source_commit")
    if not isinstance(core_commit, str) or not isinstance(easytier_commit, str):
        raise AuditIncomplete("source build report omits exact source commits")
    _validate_checkout(core, core_commit, "STCVRC core")
    _validate_checkout(easytier, easytier_commit, "EasyTier")

    _verified_artifact(build, output, "verge-mihomo.exe", "windows/amd64")
    _verified_artifact(build, output, "core-linux", "linux/amd64")
    wasm = core / "third_party" / "easytier-go" / "internal" / "artifact" / "easytier_core.wasm"
    wasm_bytes = _read(wasm, "fresh EasyTier WASM copied into STCVRC")
    if _sha256(wasm_bytes) != build.get("wasm_sha256"):
        raise AuditIncomplete("copied EasyTier WASM bytes disagree with source-build report")
    generated_wasm = easytier / "easytier-go" / "internal" / "artifact" / "easytier_core.wasm"
    if _read(generated_wasm, "freshly generated EasyTier WASM") != wasm_bytes:
        raise AuditIncomplete("STCVRC local EasyTier module differs from freshly generated WASM source")
    cargo_lock = _read(easytier / "Cargo.lock", "EasyTier Cargo.lock")
    if _sha256(cargo_lock) != build.get("cargo_lock_sha256"):
        raise AuditIncomplete("EasyTier Cargo.lock differs from source-build report")

    go = shutil.which("go")
    if not go:
        raise AuditIncomplete("pinned Go compiler is not on PATH")
    go_version = _run([go, "version"], root, os.environ)
    if f"go{build.get('go_version')}" not in go_version:
        raise AuditIncomplete("installed Go version does not match source-build report")
    output.mkdir(parents=True, exist_ok=True)
    go_bundle, go_tool = _go_rows(core, go, build, root, os.environ)
    rust_bundle, cargo_tool = _rust_rows(easytier, build, root, os.environ, output)

    bundle = {
        "bundle_schema_version": 1,
        "build": build,
        "go": go_bundle,
        "rust": rust_bundle,
        "build_tools": [go_tool, cargo_tool],
    }
    inventory = normalize_inventory(bundle)
    notices, sources = generate_notices(inventory)
    sources_text = json.dumps(sources, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    notices_sha, sources_sha = write_notice_outputs(
        notices,
        sources_text,
        output / "THIRD-PARTY-NOTICES.txt",
        output / "THIRD-PARTY-SOURCES.json",
    )
    inventory_text = json.dumps(inventory, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    (output / "license-inventory.json").write_bytes(inventory_text.encode("utf-8"))
    print(f"Runtime components: {len(inventory['components'])}")
    print(f"Build tools: {len(inventory['build_tools'])}")
    print(f"THIRD-PARTY-NOTICES.txt SHA256: {notices_sha}")
    print(f"THIRD-PARTY-SOURCES.json SHA256: {sources_sha}")
    print("License inventory scope: fresh source-built candidate only")
    return inventory


def main():
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-root", required=True, help="disposable source-build root containing core/, easytier/, output/")
    parser.add_argument("--output-dir", help="defaults to <build-root>/output")
    args = parser.parse_args()
    collect(args.build_root, args.output_dir)


if __name__ == "__main__":
    main()
