#!/usr/bin/env bash
set -euo pipefail

test "${GITHUB_ACTIONS:-}" = true
test "${GITHUB_REPOSITORY:-}" = smart-tinker/stcvrc
test -n "${RUNNER_TEMP:-}"
test -n "${GH_TOKEN:-}"

recipe="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

case "${RUNNER_OS:-}" in
  Linux)
    host=linux
    root="$RUNNER_TEMP/stcvrc-source-built"
    ;;
  Windows)
    host=windows
    root="$(cygpath -u "$RUNNER_TEMP")/stcvrc-source-built"
    ;;
  *)
    printf 'Unsupported standard runner OS.\n' >&2
    exit 1
    ;;
esac

native_path() {
  if [[ "$host" == windows ]]; then
    cygpath -m "$1"
  else
    printf '%s\n' "$1"
  fi
}

test -f "$root/output/build.json"
export PYTHONUTF8=1
export GOTOOLCHAIN=local GOENV=off GOWORK=off GOTELEMETRY=off
export CGO_ENABLED=0 GOAMD64=v1 GOMAXPROCS=2
GOPATH="$(native_path "$root/gopath")"
GOMODCACHE="$(native_path "$root/gomodcache")"
GOCACHE="$(native_path "$root/gocache")"
GOBIN="$(native_path "$root/bin")"
export GOPATH GOMODCACHE GOCACHE GOBIN
export GOFLAGS='-mod=readonly -p=2'
export PATH="$root/go/bin:$root/bin:$PATH"
export RUSTUP_TOOLCHAIN=1.95.0
RUSTUP_HOME="$(native_path "$root/rustup")"
CARGO_HOME="$(native_path "$root/cargo")"
export RUSTUP_HOME CARGO_HOME CARGO_BUILD_JOBS=2 CARGO_NET_OFFLINE=true

test "$(go version | awk '{print $3}')" = go1.26.11
test "$(rustc --version | awk '{print $2}')" = 1.95.0
test "$(cargo --version | awk '{print $2}')" = 1.95.0
python "$recipe/tools/license-audit/collect.py" --build-root "$root"
