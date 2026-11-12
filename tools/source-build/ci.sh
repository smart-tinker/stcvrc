#!/usr/bin/env bash
set -euo pipefail

test "${GITHUB_ACTIONS:-}" = true
test "${GITHUB_REPOSITORY:-}" = smart-tinker/stcvrc
test -n "${RUNNER_TEMP:-}"
recipe="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
case "${RUNNER_OS:-}" in
  Linux)
    host=linux
    go_archive=go1.26.11.linux-amd64.tar.gz
    go_archive_sha=9849f4e04ee35303714e34fbc3ac8ab44ea3e448a95aa182f91e3b9b79c710ec
    protoc_archive=protoc-35.1-linux-x86_64.zip
    protoc_archive_sha=6930ebf62bd4ea607b98fff052596c6ee564b9835b4ce172c75a3f53ae9d91b7
    root="$RUNNER_TEMP/stcvrc-source-built"
    ;;
  Windows)
    host=windows
    go_archive=go1.26.11.windows-amd64.zip
    go_archive_sha=71ae086f0137e665f855a811cc119152b6a783e0bbc1b906e709f46d80141eb0
    protoc_archive=protoc-35.1-win64.zip
    protoc_archive_sha=5d3ff218d7d91eea95f7569bcb5a98f3030f8996d44151279d9772edcff76082
    root="$(cygpath -u "$RUNNER_TEMP")/stcvrc-source-built"
    # GNU tar otherwise treats the native D: archive path as a remote host.
    export TAR_OPTIONS=--force-local
    ;;
  *) printf 'Unsupported standard runner OS.\n' >&2; exit 1 ;;
esac
native_path() {
  if [[ "$host" == windows ]]; then cygpath -m "$1"; else printf '%s\n' "$1"; fi
}
export PYTHONUTF8=1
export STCVRC_BUILD_HOST="$host/amd64"
export STCVRC_GO_ARCHIVE_URL="https://go.dev/dl/$go_archive" STCVRC_GO_ARCHIVE_SHA256="$go_archive_sha"
test ! -e "$root"
mkdir -p "$root/output"
core="$root/core"
easytier="$root/easytier"
fetch_source() {
  local path="$1" url="$2" commit="$3"
  git init --quiet "$path"
  git -C "$path" config core.autocrlf false
  git -C "$path" remote add origin "$url"
  git -C "$path" fetch --quiet --depth=1 --no-tags origin "$commit"
  git -C "$path" checkout --quiet --detach FETCH_HEAD
  test "$(git -C "$path" rev-parse HEAD)" = "$commit"
  test -z "$(git -C "$path" status --porcelain)"
}
fetch_source "$core" https://github.com/smart-tinker/stcvrc.git 086a62c3ce9a77f650786ae2eae92b68909d49e1
fetch_source "$easytier" https://github.com/EasyTier/EasyTier.git 3463190838eb642ba8324c6a4011acdea52495a8
awk '$1 == "github.com/easytier/easytier/easytier-go" { if ($2 != "v0.0.0-20260910071355-3d0c9c3ca5e2") exit 1; found++ } END { if (found != 1) exit 1 }' "$core/go.mod"
grep -Fqx 'channel = "1.95"' "$easytier/rust-toolchain.toml"
if ! grep -Fqx 'readonly core_features="management,proxy-smoltcp-stack,wasi-crypto-offload,aes-gcm,tcp-hole-punch"' "$easytier/script/build-wasi-core.sh"; then
  printf 'Unexpected upstream WASM feature profile.\n' >&2
  exit 1
fi
grep -Fq -- '--no-default-features' "$easytier/script/build-wasi-core.sh"

curl --fail --location --proto '=https' --proto-redir '=https' --retry 2 --max-time 180 --silent --show-error \
  "$STCVRC_GO_ARCHIVE_URL" -o "$root/$go_archive"
printf '%s  %s\n' "$go_archive_sha" "$root/$go_archive" | sha256sum --check --status
if [[ "$host" == windows ]]; then
  python -c 'import sys, zipfile; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])' "$root/$go_archive" "$root"
else
  tar -xzf "$root/$go_archive" -C "$root"
fi
export PATH="$root/go/bin:$PATH"
test "$(go version)" = "go version go1.26.11 $host/amd64"
export GOTOOLCHAIN=local GOENV=off GOWORK=off GOTELEMETRY=off
export CGO_ENABLED=0 GOAMD64=v1 GOMAXPROCS=2
GOPATH="$(native_path "$root/gopath")"
GOMODCACHE="$(native_path "$root/gomodcache")"
GOCACHE="$(native_path "$root/gocache")"
GOBIN="$(native_path "$root/bin")"
export GOPATH GOMODCACHE GOCACHE GOBIN
export GOFLAGS='-mod=readonly -p=2'
mkdir -p "$GOPATH" "$GOMODCACHE" "$GOCACHE" "$GOBIN"
export PATH="$root/bin:$PATH"
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11
printf 'Installed Go protoc plugin: %s\n' "$(protoc-gen-go --version)"
if [[ "$host" == windows ]]; then
  # Upstream shell checks use Unix display names; native tools retain their .exe suffix.
  mkdir -p "$root/shims"
  plugin_binary_sha="$(sha256sum "$root/bin/protoc-gen-go.exe" | awk '{print $1}')"
  cat > "$root/shims/protoc-gen-go" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$#" == 1 && "$1" == --version ]]; then
  "$(dirname -- "${BASH_SOURCE[0]}")/../bin/protoc-gen-go.exe" "$@" | tr -d '\r' | sed 's/^protoc-gen-go\.exe /protoc-gen-go /'
else
  exec "$(dirname -- "${BASH_SOURCE[0]}")/../bin/protoc-gen-go.exe" "$@"
fi
SH
  chmod +x "$root/shims/protoc-gen-go"
  bash -n "$root/shims/protoc-gen-go"
  test "$(sha256sum "$root/bin/protoc-gen-go.exe" | awk '{print $1}')" = "$plugin_binary_sha"
  export PATH="$root/shims:$PATH"
  hash -r
fi
test "$(protoc-gen-go --version)" = 'protoc-gen-go v1.36.11'
curl --fail --location --proto '=https' --proto-redir '=https' --retry 2 --max-time 180 --silent --show-error \
  "https://github.com/protocolbuffers/protobuf/releases/download/v35.1/$protoc_archive" -o "$root/protoc.zip"
printf '%s  %s\n' "$protoc_archive_sha" "$root/protoc.zip" | sha256sum --check --status
if [[ "$host" == windows ]]; then
  python -c 'import sys, zipfile; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])' "$root/protoc.zip" "$root/protoc"
else
  unzip -q "$root/protoc.zip" -d "$root/protoc"
fi
if [[ "$host" == windows ]]; then
  protoc_binary_sha="$(sha256sum "$root/protoc/bin/protoc.exe" | awk '{print $1}')"
  cat > "$root/shims/protoc" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$#" == 1 && "$1" == --version ]]; then
  "$(dirname -- "${BASH_SOURCE[0]}")/../protoc/bin/protoc.exe" "$@" | tr -d '\r'
else
  exec "$(dirname -- "${BASH_SOURCE[0]}")/../protoc/bin/protoc.exe" "$@"
fi
SH
  chmod +x "$root/shims/protoc"
  bash -n "$root/shims/protoc"
  test "$(sha256sum "$root/protoc/bin/protoc.exe" | awk '{print $1}')" = "$protoc_binary_sha"
  PATH="$root/shims:$root/protoc/bin:$PATH"
else
  PATH="$root/protoc/bin:$PATH"
fi
export PATH
if [[ "$host" == windows ]]; then
  PROTOC="$(native_path "$root/protoc/bin/protoc.exe")"
else
  PROTOC="$(native_path "$root/protoc/bin/protoc")"
fi
export PROTOC
test "$(protoc --version)" = 'libprotoc 35.1'
python - <<'PY'
import os, subprocess
protoc = os.environ["PROTOC"]
version = subprocess.check_output([protoc, "--version"], text=True).strip()
assert version == "libprotoc 35.1", (protoc, version)
print(f"Native PROTOC verified: {protoc} ({version})")
PY

export RUSTUP_TOOLCHAIN=1.95.0
RUSTUP_HOME="$(native_path "$root/rustup")"
CARGO_HOME="$(native_path "$root/cargo")"
CARGO_TARGET_DIR="$(native_path "$easytier/target")"
export RUSTUP_HOME CARGO_HOME CARGO_TARGET_DIR CARGO_BUILD_JOBS=2
rustup toolchain install 1.95.0 --profile minimal --target wasm32-wasip1
test "$(rustc --version | awk '{print $2}')" = 1.95.0
cd "$easytier"
cargo fetch --locked
export CARGO_NET_OFFLINE=true
git diff --exit-code
cd "$easytier/easytier-go"
go generate ./internal/artifact
wasm="$easytier/easytier-go/internal/artifact/easytier_core.wasm"
wasm_sha="$(sha256sum "$wasm" | awk '{print $1}')"
grep -Fq 'Commit = "3463190838eb642ba8324c6a4011acdea52495a8"' internal/artifact/provenance.go
grep -Fq "SHA256 = \"$wasm_sha\"" internal/artifact/provenance.go
go mod verify
if [[ "$host" == windows ]]; then
  # The upstream unit fixture uses a Unix-rooted path, which is not absolute on Windows.
  python - <<'PY'
from pathlib import Path
path = Path("cmd/update-wasm/main_test.go")
text = path.read_text(encoding="utf-8")
old_source = 'source := filepath.Join(string(filepath.Separator), "checkout")'
old_cache = 'filepath.Join(string(filepath.Separator), "cache")'
assert text.count(old_source) == 1 and text.count(old_cache) == 2
text = text.replace(old_source, 'source := filepath.Join(t.TempDir(), "checkout")')
text = text.replace(old_cache, 'filepath.Join(filepath.Dir(source), "cache")')
path.write_bytes(text.encode("utf-8"))
PY
fi
go test -count=1 -timeout=240s ./...
printf 'Fresh WASM SHA256: %s\n' "$wasm_sha"
git -C "$easytier" diff --name-only

mkdir -p "$core/third_party"
cp -a "$easytier/easytier-go" "$core/third_party/easytier-go"
cd "$core"
cp go.mod .ci-build.mod
cp go.sum .ci-build.sum
go mod edit -modfile=.ci-build.mod -replace=github.com/easytier/easytier/easytier-go=./third_party/easytier-go
GOFLAGS="-modfile=$(native_path "$core/.ci-build.mod") -mod=readonly -p=2"
export GOFLAGS
go mod verify
go list -m all > "$root/output/modules.txt"
grep -Fqx 'github.com/anchore/go-lzo v0.1.1' "$root/output/modules.txt"
if grep -q '^github.com/rasky/go-lzo ' "$root/output/modules.txt"; then
  printf 'Forbidden GPL-only LZO dependency in new candidate.\n' >&2
  exit 1
fi
go test -tags=with_gvisor -count=1 -timeout=240s ./transport/openvpn ./adapter/outbound ./adapter/outboundgroup
version=1.19.33-STCVRC-candidate-source-wasm-3463190-20261112
build_time=2026-11-12T00:00:00Z
ldflags="-s -w -buildid= -X github.com/metacubex/mihomo/constant.Version=$version -X github.com/metacubex/mihomo/constant.BuildTime=$build_time"
export STCVRC_BUILD_LDFLAGS="$ldflags"
GOOS=linux GOARCH=amd64 go build -tags=with_gvisor -trimpath -buildvcs=false -ldflags "$ldflags" -o "$root/output/core-linux" .
GOOS=windows GOARCH=amd64 go build -tags=with_gvisor -trimpath -buildvcs=false -ldflags "$ldflags" -o "$root/output/verge-mihomo.exe" .
git diff --exit-code
if [[ "$host" == windows ]]; then "$root/output/verge-mihomo.exe" -v; else "$root/output/core-linux" -v; fi
go version -m "$root/output/verge-mihomo.exe"

if [[ "$host" == linux ]]; then
mkdir "$root/xray"
curl --fail --location --proto '=https' --proto-redir '=https' --retry 2 --max-time 180 --silent --show-error \
  https://github.com/XTLS/Xray-core/releases/download/v26.10.31/Xray-linux-64.zip -o "$root/xray.zip"
printf '%s  %s\n' e4bd9119f50ae7c41658b1abd0679ae06f98bd864a2907ff33f2f2cf7081b214 "$root/xray.zip" | sha256sum --check --status
unzip -q "$root/xray.zip" -d "$root/xray"
printf '%s  %s\n' cc4b84d3069569f297a61f04b914f2bb37e9d202fd7b84cb50def1fc30fd40e1 "$root/xray/xray" | sha256sum --check --status
chmod +x "$root/xray/xray"
linux_sha="$(sha256sum "$root/output/core-linux" | awk '{print $1}')"
timeout 90s python3 "$recipe/tools/network-lab/lab.py" --core "$root/output/core-linux" --core-sha256 "$linux_sha" \
  --xray "$root/xray/xray" --xray-sha256 cc4b84d3069569f297a61f04b914f2bb37e9d202fd7b84cb50def1fc30fd40e1 | tee "$root/output/failover.json"
timeout 45s python3 "$recipe/tools/network-lab/lab.py" --core "$root/output/core-linux" --core-sha256 "$linux_sha" \
  --xray "$root/xray/xray" --xray-sha256 cc4b84d3069569f297a61f04b914f2bb37e9d202fd7b84cb50def1fc30fd40e1 --check-tls-rejection | tee "$root/output/tls.json"
else
  STCVRC_CORE_PATH="$(native_path "$root/output/verge-mihomo.exe")"
  STCVRC_CORE_SHA256="$(sha256sum "$root/output/verge-mihomo.exe" | awk '{print $1}')"
  export STCVRC_CORE_PATH STCVRC_CORE_SHA256
  python "$recipe/tools/network-lab/windows.py" | tee "$root/output/windows-loopback.txt"
fi

python - "$recipe" "$root/output" "$wasm" "$core/.ci-build.mod" "$easytier" <<'PY'
import hashlib, json, os, subprocess, sys
from pathlib import Path
recipe, output, wasm, modfile, easytier = map(Path, sys.argv[1:])
digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
changed = subprocess.check_output(["git", "-C", str(easytier), "ls-files", "--modified", "--others", "--exclude-standard"], text=True).splitlines()
fixture_patch = "easytier-go/cmd/update-wasm/main_test.go"
build_test_patches = [path for path in changed if path == fixture_patch]
assert not build_test_patches or os.environ["STCVRC_BUILD_HOST"] == "windows/amd64"
assert all(path.startswith(("easytier-go/internal/artifact/", "easytier-go/proto/")) or path == fixture_patch for path in changed), changed
report = {
    "schema_version": 1,
    "status": "fresh-source-candidate-experiment; no release",
    "recipe_commit": subprocess.check_output(["git", "-C", str(recipe), "rev-parse", "HEAD"], text=True).strip(),
    "core_source_commit": "086a62c3ce9a77f650786ae2eae92b68909d49e1",
    "easytier_source_commit": "3463190838eb642ba8324c6a4011acdea52495a8",
    "easytier_original_module_version": "v0.0.0-20260910071355-3d0c9c3ca5e2",
    "easytier_source_change_reason": "upstream PR2588 ABI4/wire3 alignment and PR2754 TCP FIN teardown",
    "build_host": os.environ["STCVRC_BUILD_HOST"],
    "go_archive": {"url": os.environ["STCVRC_GO_ARCHIVE_URL"], "sha256": os.environ["STCVRC_GO_ARCHIVE_SHA256"]},
    "go_build_tags": ["with_gvisor"],
    "go_build_flags": ["-tags=with_gvisor", "-trimpath", "-buildvcs=false"],
    "go_linker_flags": os.environ["STCVRC_BUILD_LDFLAGS"],
    "rust_target": "wasm32-wasip1",
    "rust_features": ["management", "proxy-smoltcp-stack", "wasi-crypto-offload", "aes-gcm", "tcp-hole-punch"],
    "rust_no_default_features": True,
    "cargo_lock_sha256": digest(easytier/"Cargo.lock"),
    "wasm_sha256": digest(wasm),
    "modfile_sha256": digest(modfile),
    "generated_easytier_files": {path: digest(easytier/path) for path in sorted(changed) if path != fixture_patch},
    "build_test_only_patches": {path: digest(easytier/path) for path in build_test_patches},
    "go_version": "1.26.11",
    "rust_version": "1.95.0",
    "protoc_version": "35.1",
    "protoc_gen_go_version": "1.36.11",
    "binaryen_version": "131",
    "version": "1.19.33-STCVRC-candidate-source-wasm-3463190-20261112",
    "build_time": "2026-11-12T00:00:00Z",
    "artifacts": [
        {"name": name, "target": "windows/amd64" if name.endswith(".exe") else "linux/amd64", "sha256": digest(output/name), "size": (output/name).stat().st_size}
        for name in ("core-linux", "verge-mihomo.exe")
    ],
    "license_review": "INCOMPLETE_ISSUE_7",
    "native_windows_acceptance": "UNRUN_FOR_THIS_NEW_BINARY",
}
text = json.dumps(report, indent=2, sort_keys=True) + "\n"
(output/"build.json").write_text(text, encoding="utf-8")
print(text)
PY
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    printf '## Fresh source-built dependency and core\n\n'
    printf '\140\140\140json\n'
    cat "$root/output/build.json"
    if [[ "$host" == linux ]]; then
      cat "$root/output/failover.json" "$root/output/tls.json"
    else
      cat "$root/output/windows-loopback.txt"
    fi
    printf '\n\140\140\140\n'
  } >> "$GITHUB_STEP_SUMMARY"
fi
