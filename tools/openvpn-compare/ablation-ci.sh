#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d "$RUNNER_TEMP/openvpn-compare.XXXXXXXX")"
cleanup() {
  status=$?
  trap - EXIT
  if [[ -x "$work/go/bin/go" ]]; then
    "$work/go/bin/go" clean -modcache || status=1
  fi
  rm -rf -- "$work" || status=1
  exit "$status"
}
trap cleanup EXIT
export GOTOOLCHAIN=local GOWORK=off GOTELEMETRY=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1
export GOPATH="$work/gopath" GOCACHE="$work/gocache"
mkdir "$work/tmp"
export TMPDIR="$work/tmp" GOTMPDIR="$work/tmp"
curl --fail --location --proto '=https' --retry 2 --max-time 120 --silent --show-error \
  https://go.dev/dl/go1.26.10.linux-amd64.tar.gz -o "$work/go.tar.gz"
printf '%s  %s\n' ccfe7ae822d2c2f41f4fe7c956199967a4dac22d0ee0d2b2bfdb440aab3b20c5 "$work/go.tar.gz" | sha256sum --check --status
tar -xzf "$work/go.tar.gz" -C "$work"
export PATH="$work/go/bin:$PATH"
python3 -m unittest discover -s "$HERE" -p 'test_*.py' -v
go version
openvpn --version
scenarios=(idle idle-local idle-lzo rekey deadline)
if [[ "$PATCH" == scheduler ]]; then scenarios=(deadline); fi
for variant in upstream stcvrc minus only; do
  if [[ "$variant" == upstream ]]; then
    sha=3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8
    repo=https://github.com/MetaCubeX/mihomo.git
  else
    sha=d888dfad5e785217778bb7515c931840d5307dd4
    repo=https://github.com/smart-tinker/stcvrc.git
  fi
  git init --quiet "$work/$variant"
  git -C "$work/$variant" fetch --quiet --depth=1 "$repo" "$sha"
  git -C "$work/$variant" checkout --quiet --detach FETCH_HEAD
  test "$(git -C "$work/$variant" rev-parse HEAD)" = "$sha"
  printf '%s source %s\n' "$variant" "$sha"
  if [[ "$variant" == minus || "$variant" == only ]]; then
    python3 "$HERE/ablate.py" "$work/$variant" "$variant" "$PATCH"
  fi
  git -C "$work/$variant" diff --stat
  git -C "$work/$variant" diff | sha256sum
  (cd "$work/$variant"; timeout 600s go build -p=2 -mod=readonly -tags=with_gvisor -trimpath -buildvcs=false -o "$work/$variant-core" .; go mod verify)
  sha256sum "$work/$variant-core"
done
# Same existing behavioral test, without altering production files in either tree.
cp "$work/stcvrc/adapter/outboundgroup/urltest_test.go" "$work/upstream/adapter/outboundgroup/urltest_test.go"
cp "$work/stcvrc/transport/openvpn/push_retry_test.go" "$work/upstream/transport/openvpn/push_retry_test.go"
for variant in upstream stcvrc minus only; do
  cp "$work/stcvrc/adapter/outboundgroup/urltest_test.go" "$work/$variant/adapter/outboundgroup/urltest_test.go" 2>/dev/null || test "$variant" = stcvrc
  cp "$work/stcvrc/transport/openvpn/push_retry_test.go" "$work/$variant/transport/openvpn/push_retry_test.go" 2>/dev/null || test "$variant" = stcvrc
  set +e
  (cd "$work/$variant"; timeout 180s go test -json -p=2 -mod=readonly -run '^TestURLTest(Tolerance|SelectionLifecycle)$' ./adapter/outboundgroup) > "$work/url-$variant.jsonl" 2> "$work/url-$variant.stderr"
  status=$?
  set -e
  if (( status > 1 )); then cat "$work/url-$variant.jsonl" "$work/url-$variant.stderr" >&2; exit "$status"; fi
  cat "$work/url-$variant.stderr" >&2
  printf '%s\n' "$status" > "$work/url-$variant.status"
  cat "$work/url-$variant.jsonl"
  set +e
  (cd "$work/$variant"; timeout 60s go test -json -p=2 -mod=readonly -run '^TestInitialHandshakeRetriesDeferredPush$' ./transport/openvpn) > "$work/push-$variant.jsonl" 2> "$work/push-$variant.stderr"
  status=$?
  set -e
  if (( status > 1 )); then cat "$work/push-$variant.jsonl" "$work/push-$variant.stderr" >&2; exit "$status"; fi
  cat "$work/push-$variant.stderr" >&2
  printf '%s\n' "$status" > "$work/push-$variant.status"
  cat "$work/push-$variant.jsonl"
  if [[ "$variant" == stcvrc || "$variant" == minus ]]; then
    set +e
    (cd "$work/$variant"; timeout 180s go test -json -count=1 -p=2 -mod=readonly -tags=with_gvisor ./transport/openvpn ./adapter/outbound ./adapter/outboundgroup) > "$work/all-$variant.jsonl" 2> "$work/all-$variant.stderr"
    suite_status=$?
    set -e
    if (( suite_status > 1 )); then cat "$work/all-$variant.jsonl" "$work/all-$variant.stderr" >&2; exit "$suite_status"; fi
    cat "$work/all-$variant.stderr" >&2
    printf '%s\n' "$suite_status" > "$work/all-$variant.status"
    cat "$work/all-$variant.jsonl"
    printf '\nFull suite %s: %s\n' "$variant" "$suite_status" >> "$GITHUB_STEP_SUMMARY"
  fi
  for scenario in "${scenarios[@]}"; do
    set +e
    sudo timeout 150s unshare --net -- python3 "$HERE/lab.py" \
      --namespace-parent "$(readlink /proc/self/ns/net)" --core "$work/$variant-core" \
      --scenario "$scenario" --output "$work/$variant-$scenario.json"
    status=$?
    set -e
    if (( status != 0 && status != 2 )); then exit "$status"; fi
  done
done
for variant in upstream stcvrc minus only; do
  printf '\n### Patch %s / variant %s\n' "$PATCH" "$variant" | tee -a "$GITHUB_STEP_SUMMARY"
  for scenario in "${scenarios[@]}"; do
    cat "$work/$variant-$scenario.json" | tee -a "$GITHUB_STEP_SUMMARY"
  done
  for group in url push; do
    printf '%s status: ' "$group" | tee -a "$GITHUB_STEP_SUMMARY"
    cat "$work/$group-$variant.status" | tee -a "$GITHUB_STEP_SUMMARY"
  done
done
python3 "$HERE/report.py" "$work" "${scenarios[@]}" | tee -a "$GITHUB_STEP_SUMMARY"
