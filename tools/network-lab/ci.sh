#!/usr/bin/env bash
set -euo pipefail

readonly SOURCE_COMMIT=d888dfad5e785217778bb7515c931840d5307dd4
readonly GO_SHA256=ccfe7ae822d2c2f41f4fe7c956199967a4dac22d0ee0d2b2bfdb440aab3b20c5
readonly XRAY_ZIP_SHA256=e4bd9119f50ae7c41658b1abd0679ae06f98bd864a2907ff33f2f2cf7081b214
readonly XRAY_SHA256=cc4b84d3069569f297a61f04b914f2bb37e9d202fd7b84cb50def1fc30fd40e1
readonly CORE_SHA256=5c811c83dc2f8fae6dcb5933fde988f5d34bb3f87e6dbab6d130aeb30146809a
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly HERE

[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]]
work="$(mktemp -d "${RUNNER_TEMP:-$HERE}/stcvrc-ci.XXXXXXXX")"
cleanup() {
  status=$?
  trap - EXIT
  if [[ -x "$work/go/bin/go" && -d "$work/gopath/pkg/mod" ]]; then
    # Go module directories are read-only; its cleanup command handles them.
    GOTOOLCHAIN=local GOWORK=off GOMODCACHE="$work/gopath/pkg/mod" \
      "$work/go/bin/go" clean -modcache || status=1
  fi
  rm -rf -- "$work" || status=1
  exit "$status"
}
trap cleanup EXIT
available_kb="$(df -Pk "$work" | awk 'NR == 2 {print $4}')"
if (( available_kb < 6 * 1024 * 1024 )); then
  printf 'Need at least 6 GiB free on the temporary build filesystem\n' >&2
  exit 1
fi
mkdir "$work/tmp"
export TMPDIR="$work/tmp" GOTMPDIR="$work/tmp"

cd "$HERE"
python3 -m unittest discover -v -p 'test_*.py'

curl --fail --location --proto '=https' --retry 2 --max-time 120 --silent --show-error \
  https://go.dev/dl/go1.26.10.linux-amd64.tar.gz -o "$work/go.tar.gz"
printf '%s  %s\n' "$GO_SHA256" "$work/go.tar.gz" | sha256sum --check --status
tar -xzf "$work/go.tar.gz" -C "$work"

curl --fail --location --proto '=https' --retry 2 --max-time 120 --silent --show-error \
  https://github.com/XTLS/Xray-core/releases/download/v26.10.31/Xray-linux-64.zip \
  -o "$work/xray.zip"
printf '%s  %s\n' "$XRAY_ZIP_SHA256" "$work/xray.zip" | sha256sum --check --status
python3 - "$work" "$XRAY_SHA256" <<'PY'
import hashlib, pathlib, sys, zipfile
directory, expected = pathlib.Path(sys.argv[1]), sys.argv[2]
with zipfile.ZipFile(directory / "xray.zip") as archive:
    data = archive.read("xray")
if hashlib.sha256(data).hexdigest() != expected:
    raise SystemExit("Xray executable checksum mismatch")
(directory / "xray").write_bytes(data)
(directory / "xray").chmod(0o700)
PY

git init --quiet "$work/source"
git -C "$work/source" fetch --quiet --depth=1 \
  https://github.com/smart-tinker/stcvrc.git "$SOURCE_COMMIT"
git -C "$work/source" checkout --quiet --detach FETCH_HEAD
test "$(git -C "$work/source" rev-parse HEAD)" = "$SOURCE_COMMIT"

export GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1
export GOFLAGS='' GOEXPERIMENT='' GOTELEMETRY=off
export GOPATH="$work/gopath" GOCACHE="$work/gocache" GOMODCACHE="$work/gopath/pkg/mod"
export GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org
cd "$work/source"
"$work/go/bin/go" version
timeout 600s "$work/go/bin/go" build -p=2 -mod=readonly -tags=with_gvisor -trimpath -buildvcs=false \
  -ldflags='-s -w -buildid= -X github.com/metacubex/mihomo/constant.Version=1.19.33-STCVRC-lab-d888dfad -X github.com/metacubex/mihomo/constant.BuildTime=2026-10-22T00:00:00Z' \
  -o "$work/core" .
printf '%s  %s\n' "$CORE_SHA256" "$work/core" | sha256sum --check --status
timeout 90s "$work/go/bin/go" mod verify
test -z "$(git status --porcelain)"
"$work/core" -v
version_output="$("$work/xray" version)"
printf '%s\n' "$version_output"
if ! grep -Eq '^Xray 26\.10\.30 \(' <<<"$version_output"; then
  printf 'Expected Xray 26.10.31\n' >&2
  exit 1
fi

timeout 90s python3 "$HERE/lab.py" --core "$work/core" --core-sha256 "$CORE_SHA256" \
  --xray "$work/xray" --xray-sha256 "$XRAY_SHA256" | tee "$work/failover.json"
timeout 45s python3 "$HERE/lab.py" --core "$work/core" --core-sha256 "$CORE_SHA256" \
  --xray "$work/xray" --xray-sha256 "$XRAY_SHA256" --check-tls-rejection | tee "$work/tls.json"

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    printf '## STCVRC Linux loopback pilot\n\n'
    printf 'Source: %s\n\nLinux binary SHA256: %s\n\n' "$SOURCE_COMMIT" "$CORE_SHA256"
    printf 'Xray 26.10.31 SHA256: %s\n\n' "$XRAY_SHA256"
    printf '```json\n'
    cat "$work/failover.json" "$work/tls.json"
    printf '```\n\n'
    printf 'HTTP/TCP only. Not Windows, OpenVPN/rekey, UDP/DNS, OS TUN or production acceptance.\n'
  } >> "$GITHUB_STEP_SUMMARY"
fi
