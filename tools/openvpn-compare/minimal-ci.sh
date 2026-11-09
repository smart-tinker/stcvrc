#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d "$RUNNER_TEMP/openvpn-minimal.XXXXXXXX")"
cleanup() {
  status=$?
  trap - EXIT
  if [[ -x "$work/go/bin/go" ]]; then
    GOPATH="$work/gopath" GOCACHE="$work/gocache-cleanup" "$work/go/bin/go" clean -modcache || status=1
  fi
  rm -rf -- "$work" || status=1
  exit "$status"
}
trap cleanup EXIT
export GOTOOLCHAIN=local GOWORK=off GOTELEMETRY=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1
export GOPATH="$work/gopath"
mkdir -p "$work/tmp"
export TMPDIR="$work/tmp" GOTMPDIR="$work/tmp"
curl --fail --location --proto '=https' --retry 2 --max-time 120 --silent --show-error \
  https://go.dev/dl/go1.26.10.linux-amd64.tar.gz -o "$work/go.tar.gz"
printf '%s  %s\n' ccfe7ae822d2c2f41f4fe7c956199967a4dac22d0ee0d2b2bfdb440aab3b20c5 "$work/go.tar.gz" | sha256sum --check --status
tar -xzf "$work/go.tar.gz" -C "$work"
export PATH="$work/go/bin:$PATH"
python3 -m unittest discover -s "$HERE" -p 'test_*.py' -v
go version
openvpn --version
scenarios=(idle idle-local idle-lzo lzo-data rekey deadline recovery)
for variant in full minimal upstream; do
  if [[ "$variant" == upstream ]]; then
    sha=3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8
    repo=https://github.com/MetaCubeX/mihomo.git
  else
    sha=400f18b4991f5f38c5418b0f3e4562c8dc3ea1d9
    repo=https://github.com/smart-tinker/stcvrc.git
  fi
  git init --quiet "$work/$variant"
  git -C "$work/$variant" fetch --quiet --depth=1 "$repo" "$sha"
  git -C "$work/$variant" checkout --quiet --detach FETCH_HEAD
  test "$(git -C "$work/$variant" rev-parse HEAD)" = "$sha"
  printf '%s source %s\n' "$variant" "$sha"
  if [[ "$variant" == "full" ]]; then
    (
      cd "$work/$variant"
      export GOCACHE="$work/gocache-lzo-regression"
      grep -Eq '^[[:space:]]*github\.com/anchore/go-lzo v0\.1\.1
      ! grep -Fq 'github.com/rasky/go-lzo ' go.mod
      ! grep -Fq 'github.com/rasky/go-lzo ' go.sum
      go list -m all > "$work/full-modules.txt"
      ! grep -Fq 'github.com/rasky/go-lzo ' "$work/full-modules.txt"
      go mod download github.com/anchore/go-lzo@v0.1.1
      module_dir="$(go list -m -f '{{.Dir}}' github.com/anchore/go-lzo)"
      test "$(head -n 1 "$module_dir/LICENSE")" = "MIT License"
      test "$(sha256sum "$module_dir/LICENSE" | cut -d' ' -f1)" = \
        56e580e89c7978e3ae946cc6c09db105895f112a
      printf 'LZO decoder: github.com/anchore/go-lzo v0.1.1 (MIT)\n' >> "$GITHUB_STEP_SUMMARY"
      timeout 90s go test -count=1 -mod=readonly \
        -run '^TestLzo1xDecompressRejectsOversizedPacket$' ./transport/openvpn
    )
  fi
  if [[ "$variant" == minimal ]]; then
    python3 "$HERE/minimalize.py" "$work/$variant"
    git -C "$work/$variant" add -A
    git -C "$work/$variant" diff --cached --stat
    git -C "$work/$variant" diff --cached | sha256sum
  fi
  python3 - "$work/$variant/transport/openvpn/lzo.go" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
source = path.read_text()
needle = chr(9) + "case lzoCompressLZO:" + chr(10)
if source.count(needle) != 1:
    raise SystemExit('INVALID: expected one LZO decoder branch')
path.write_text(source.replace(needle, needle + chr(9) * 2 + 'println("STCVRC_CI_LZO_COMPRESSED_FRAME")' + chr(10)))
PY
  export GOCACHE="$work/gocache-$variant"
  (
    cd "$work/$variant"
    timeout 600s go build -p=2 -mod=readonly -tags=with_gvisor -trimpath -buildvcs=false -o "$work/$variant-core" .
    go mod verify
    GOOS=windows GOARCH=amd64 timeout 600s go build -p=2 -mod=readonly -tags=with_gvisor -trimpath -buildvcs=false -o "$work/$variant-core.exe" .
  )
  sha256sum "$work/$variant-core" | tee "$work/$variant.sha256"
  sha256sum "$work/$variant-core.exe" | tee "$work/$variant-windows.sha256"
  printf 'Windows %s core SHA256: %s\n' "$variant" "$(cut -d' ' -f1 "$work/$variant-windows.sha256")" >> "$GITHUB_STEP_SUMMARY"
  (cd "$work/$variant"; timeout 300s go test -count=1 -p=2 -mod=readonly -tags=with_gvisor ./transport/openvpn ./adapter/outbound ./adapter/outboundgroup)
done
for variant in upstream full minimal; do
  for scenario in "${scenarios[@]}"; do
    sudo timeout 150s unshare --net -- python3 "$HERE/lab.py" \
      --namespace-parent "$(readlink /proc/self/ns/net)" --core "$work/$variant-core" \
      --scenario "$scenario" --output "$work/$variant-$scenario.json"
  done
done
PYTHONPATH="$HERE" python3 - "$work" <<'PY' | tee -a "$GITHUB_STEP_SUMMARY"
import hashlib
import json
import re
import sys
from pathlib import Path

from lab import assess

work = Path(sys.argv[1])
variants = ("upstream", "full", "minimal")
scenarios = ("idle", "idle-local", "idle-lzo", "lzo-data", "rekey", "deadline", "recovery")
results = {}
for variant in variants:
    expected_sha = (work / f"{variant}.sha256").read_text().split()[0]
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha):
        raise SystemExit(f"INVALID binary hash for {variant}")
    results[variant] = {}
    for scenario in scenarios:
        path = work / f"{variant}-{scenario}.json"
        data = json.loads(path.read_text())
        control_ok = data.get("control_ready") is True if scenario == "lzo-data" else data.get("baseline") is True
        if data.get("scenario") != scenario or not control_ok or data.get("direct_blocked") is not True:
            raise SystemExit(f"INVALID controls/evidence: {path.name}")
        if data.get("core_sha256") != expected_sha:
            raise SystemExit(f"INVALID source/binary binding: {path.name}")
        verdict = data.get("verdict")
        if verdict not in ("PASS", "FAIL") or assess(scenario, data) != verdict:
            raise SystemExit(f"INVALID verdict/evidence: {path.name}")
        results[variant][scenario] = data
for scenario in scenarios:
    if results["full"][scenario]["verdict"] != "PASS" or results["minimal"][scenario]["verdict"] != "PASS":
        raise SystemExit(f"FAIL: full/minimal did not pass {scenario}")
    if results["full"][scenario]["verdict"] != results["minimal"][scenario]["verdict"]:
        raise SystemExit(f"FAIL: full/minimal differ on {scenario}")
print("## Fresh-source integrated minimal candidate")
print("| Scenario | Upstream | Full .33 | Minimal .33 |")
print("|---|---|---|---|")
for scenario in scenarios:
    print("| " + scenario + " | " + " | ".join(results[v][scenario]["verdict"] for v in variants) + " |")
print("\nFull .33 and the counter-only minimal .33 passed all seven isolated Linux scenarios; upstream is the control.")
PY
 go.mod
      ! grep -Fq 'github.com/rasky/go-lzo ' go.mod
      ! grep -Fq 'github.com/rasky/go-lzo ' go.sum
      go list -m all > "$work/full-modules.txt"
      ! grep -Fq 'github.com/rasky/go-lzo ' "$work/full-modules.txt"
      go mod download github.com/anchore/go-lzo@v0.1.1
      module_dir="$(go list -m -f '{{.Dir}}' github.com/anchore/go-lzo)"
      test "$(head -n 1 "$module_dir/LICENSE")" = "MIT License"
      test "$(sha256sum "$module_dir/LICENSE" | cut -d' ' -f1)" = \
        56e580e89c7978e3ae946cc6c09db105895f112a
      printf 'LZO decoder: github.com/anchore/go-lzo v0.1.1 (MIT)\n' >> "$GITHUB_STEP_SUMMARY"
      timeout 90s go test -count=1 -mod=readonly \
        -run '^TestLzo1xDecompressRejectsOversizedPacket$' ./transport/openvpn
    )
  fi
  if [[ "$variant" == minimal ]]; then
    python3 "$HERE/minimalize.py" "$work/$variant"
    git -C "$work/$variant" add -A
    git -C "$work/$variant" diff --cached --stat
    git -C "$work/$variant" diff --cached | sha256sum
  fi
  python3 - "$work/$variant/transport/openvpn/lzo.go" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
source = path.read_text()
needle = chr(9) + "case lzoCompressLZO:" + chr(10)
if source.count(needle) != 1:
    raise SystemExit('INVALID: expected one LZO decoder branch')
path.write_text(source.replace(needle, needle + chr(9) * 2 + 'println("STCVRC_CI_LZO_COMPRESSED_FRAME")' + chr(10)))
PY
  export GOCACHE="$work/gocache-$variant"
  (
    cd "$work/$variant"
    timeout 600s go build -p=2 -mod=readonly -tags=with_gvisor -trimpath -buildvcs=false -o "$work/$variant-core" .
    go mod verify
    GOOS=windows GOARCH=amd64 timeout 600s go build -p=2 -mod=readonly -tags=with_gvisor -trimpath -buildvcs=false -o "$work/$variant-core.exe" .
  )
  sha256sum "$work/$variant-core" | tee "$work/$variant.sha256"
  sha256sum "$work/$variant-core.exe" | tee "$work/$variant-windows.sha256"
  printf 'Windows %s core SHA256: %s\n' "$variant" "$(cut -d' ' -f1 "$work/$variant-windows.sha256")" >> "$GITHUB_STEP_SUMMARY"
  (cd "$work/$variant"; timeout 300s go test -count=1 -p=2 -mod=readonly -tags=with_gvisor ./transport/openvpn ./adapter/outbound ./adapter/outboundgroup)
done
for variant in upstream full minimal; do
  for scenario in "${scenarios[@]}"; do
    sudo timeout 150s unshare --net -- python3 "$HERE/lab.py" \
      --namespace-parent "$(readlink /proc/self/ns/net)" --core "$work/$variant-core" \
      --scenario "$scenario" --output "$work/$variant-$scenario.json"
  done
done
PYTHONPATH="$HERE" python3 - "$work" <<'PY' | tee -a "$GITHUB_STEP_SUMMARY"
import hashlib
import json
import re
import sys
from pathlib import Path

from lab import assess

work = Path(sys.argv[1])
variants = ("upstream", "full", "minimal")
scenarios = ("idle", "idle-local", "idle-lzo", "lzo-data", "rekey", "deadline", "recovery")
results = {}
for variant in variants:
    expected_sha = (work / f"{variant}.sha256").read_text().split()[0]
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha):
        raise SystemExit(f"INVALID binary hash for {variant}")
    results[variant] = {}
    for scenario in scenarios:
        path = work / f"{variant}-{scenario}.json"
        data = json.loads(path.read_text())
        control_ok = data.get("control_ready") is True if scenario == "lzo-data" else data.get("baseline") is True
        if data.get("scenario") != scenario or not control_ok or data.get("direct_blocked") is not True:
            raise SystemExit(f"INVALID controls/evidence: {path.name}")
        if data.get("core_sha256") != expected_sha:
            raise SystemExit(f"INVALID source/binary binding: {path.name}")
        verdict = data.get("verdict")
        if verdict not in ("PASS", "FAIL") or assess(scenario, data) != verdict:
            raise SystemExit(f"INVALID verdict/evidence: {path.name}")
        results[variant][scenario] = data
for scenario in scenarios:
    if results["full"][scenario]["verdict"] != "PASS" or results["minimal"][scenario]["verdict"] != "PASS":
        raise SystemExit(f"FAIL: full/minimal did not pass {scenario}")
    if results["full"][scenario]["verdict"] != results["minimal"][scenario]["verdict"]:
        raise SystemExit(f"FAIL: full/minimal differ on {scenario}")
print("## Fresh-source integrated minimal candidate")
print("| Scenario | Upstream | Full .33 | Minimal .33 |")
print("|---|---|---|---|")
for scenario in scenarios:
    print("| " + scenario + " | " + " | ".join(results[v][scenario]["verdict"] for v in variants) + " |")
print("\nFull .33 and the counter-only minimal .33 passed all seven isolated Linux scenarios; upstream is the control.")
PY
