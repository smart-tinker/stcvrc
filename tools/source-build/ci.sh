#!/usr/bin/env bash
set -euo pipefail

test "${GITHUB_ACTIONS:-}" = true
test "${GITHUB_REPOSITORY:-}" = smart-tinker/stcvrc
test -n "${RUNNER_TEMP:-}"
recipe="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
root="$RUNNER_TEMP/stcvrc-source-built"
test ! -e "$root"
mkdir -p "$root/output"
core="$root/core"
easytier="$root/easytier"
fetch_source() {
  local path="$1" url="$2" commit="$3"
  git init --quiet "$path"
  git -C "$path" remote add origin "$url"
  git -C "$path" fetch --quiet --depth=1 --no-tags origin "$commit"
  git -C "$path" checkout --quiet --detach FETCH_HEAD
  test "$(git -C "$path" rev-parse HEAD)" = "$commit"
  test -z "$(git -C "$path" status --porcelain)"
}
fetch_source "$core" https://github.com/smart-tinker/stcvrc.git 086a62c3ce9a77f650786ae2eae92b68909d49e1
fetch_source "$easytier" https://github.com/EasyTier/EasyTier.git 3d0c9c3ca5e2c0b680383dedf5898f6c7eef9253
awk '$1 == "github.com/easytier/easytier/easytier-go" { if ($2 != "v0.0.0-20260910071355-3d0c9c3ca5e2") exit 1; found++ } END { if (found != 1) exit 1 }' "$core/go.mod"
grep -Fqx 'channel = "1.95"' "$easytier/rust-toolchain.toml"

curl --fail --location --proto '=https' --proto-redir '=https' --retry 2 --max-time 180 --silent --show-error \
  https://go.dev/dl/go1.26.11.linux-amd64.tar.gz -o "$root/go.tar.gz"
printf '%s  %s\n' 9849f4e04ee35303714e34fbc3ac8ab44ea3e448a95aa182f91e3b9b79c710ec "$root/go.tar.gz" | sha256sum --check --status
tar -xzf "$root/go.tar.gz" -C "$root"
export PATH="$root/go/bin:$PATH"
test "$(go version)" = 'go version go1.26.11 linux/amd64'
export GOTOOLCHAIN=local GOENV=off GOWORK=off GOTELEMETRY=off
export CGO_ENABLED=0 GOAMD64=v1 GOMAXPROCS=2
export GOPATH="$root/gopath" GOMODCACHE="$root/gomodcache" GOCACHE="$root/gocache" GOBIN="$root/bin"
export GOFLAGS='-mod=readonly -p=2'
mkdir -p "$GOPATH" "$GOMODCACHE" "$GOCACHE" "$GOBIN"
export PATH="$GOBIN:$PATH"
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11
test "$(protoc-gen-go --version)" = 'protoc-gen-go v1.36.11'
curl --fail --location --proto '=https' --proto-redir '=https' --retry 2 --max-time 180 --silent --show-error \
  https://github.com/protocolbuffers/protobuf/releases/download/v35.1/protoc-35.1-linux-x86_64.zip -o "$root/protoc.zip"
printf '%s  %s\n' 6930ebf62bd4ea607b98fff052596c6ee564b9835b4ce172c75a3f53ae9d91b7 "$root/protoc.zip" | sha256sum --check --status
unzip -q "$root/protoc.zip" -d "$root/protoc"
export PATH="$root/protoc/bin:$PATH"
export PROTOC="$root/protoc/bin/protoc"
test "$(protoc --version)" = 'libprotoc 35.1'

export RUSTUP_TOOLCHAIN=1.95.0
export RUSTUP_HOME="$root/rustup" CARGO_HOME="$root/cargo"
export CARGO_TARGET_DIR="$easytier/target" CARGO_BUILD_JOBS=2
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
grep -Fq 'Commit = "3d0c9c3ca5e2c0b680383dedf5898f6c7eef9253"' internal/artifact/provenance.go
grep -Fq "SHA256 = \"$wasm_sha\"" internal/artifact/provenance.go
go mod verify
go test -count=1 -timeout=240s ./...
printf 'Fresh WASM SHA256: %s\n' "$wasm_sha"
git -C "$easytier" diff --name-only

mkdir -p "$core/third_party"
cp -a "$easytier/easytier-go" "$core/third_party/easytier-go"
cd "$core"
cp go.mod .ci-build.mod
cp go.sum .ci-build.sum
go mod edit -modfile=.ci-build.mod -replace=github.com/easytier/easytier/easytier-go=./third_party/easytier-go
export GOFLAGS="-modfile=$core/.ci-build.mod -mod=readonly -p=2"
go mod verify
go list -m all > "$root/output/modules.txt"
grep -Fqx 'github.com/anchore/go-lzo v0.1.1' "$root/output/modules.txt"
if grep -q '^github.com/rasky/go-lzo ' "$root/output/modules.txt"; then
  printf 'Forbidden GPL-only LZO dependency in new candidate.\n' >&2
  exit 1
fi
go test -tags=with_gvisor -count=1 -timeout=240s ./transport/openvpn ./adapter/outbound ./adapter/outboundgroup
version=1.19.33-STCVRC-candidate-source-wasm-20261112
build_time=2026-11-12T00:00:00Z
ldflags="-s -w -buildid= -X github.com/metacubex/mihomo/constant.Version=$version -X github.com/metacubex/mihomo/constant.BuildTime=$build_time"
GOOS=linux GOARCH=amd64 go build -tags=with_gvisor -trimpath -buildvcs=false -ldflags "$ldflags" -o "$root/output/core-linux" .
GOOS=windows GOARCH=amd64 go build -tags=with_gvisor -trimpath -buildvcs=false -ldflags "$ldflags" -o "$root/output/verge-mihomo.exe" .
git diff --exit-code
"$root/output/core-linux" -v
go version -m "$root/output/verge-mihomo.exe"

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

python3 - "$recipe" "$root/output" "$wasm" "$core/.ci-build.mod" <<'PY'
import hashlib, json, subprocess, sys
from pathlib import Path
recipe, output, wasm, modfile = map(Path, sys.argv[1:])
digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
report = {
    "schema_version": 1,
    "status": "fresh-source-candidate-experiment; no release",
    "recipe_commit": subprocess.check_output(["git", "-C", str(recipe), "rev-parse", "HEAD"], text=True).strip(),
    "core_source_commit": "086a62c3ce9a77f650786ae2eae92b68909d49e1",
    "easytier_source_commit": "3d0c9c3ca5e2c0b680383dedf5898f6c7eef9253",
    "wasm_sha256": digest(wasm),
    "modfile_sha256": digest(modfile),
    "go_version": "1.26.11",
    "rust_version": "1.95.0",
    "protoc_version": "35.1",
    "protoc_gen_go_version": "1.36.11",
    "binaryen_version": "131",
    "version": "1.19.33-STCVRC-candidate-source-wasm-20261112",
    "build_time": "2026-11-12T00:00:00Z",
    "artifacts": [
        {"name": name, "sha256": digest(output/name), "size": (output/name).stat().st_size}
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
    cat "$root/output/build.json" "$root/output/failover.json" "$root/output/tls.json"
    printf '\n\140\140\140\n'
  } >> "$GITHUB_STEP_SUMMARY"
fi
