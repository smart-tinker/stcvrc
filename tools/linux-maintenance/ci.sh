#!/usr/bin/env bash
set -euo pipefail
source_tree="$(realpath "$1")"
root="$2"
: "$RUNNER_TEMP"
runner_temp="$(realpath "$RUNNER_TEMP")"
case "$root/" in
  "$runner_temp/"*) ;;
  *) printf 'Refusing non-runner temp root\n' >&2; exit 2 ;;
esac
mkdir -m 700 -- "$root"
cleanup() { rm -rf -- "$root"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
export PYTHONDONTWRITEBYTECODE=1
unit_status=0
python3 -m unittest discover \
  -s "$source_tree/tools/linux-maintenance" \
  -p 'test_*.py' -v || unit_status=$?
probe_status=0
python3 "$source_tree/tools/linux-maintenance/systemd_counter_probe.py" "$root" \
  | tee -a "$GITHUB_STEP_SUMMARY" || probe_status=$?
if (( unit_status != 0 )); then exit "$unit_status"; fi
if (( probe_status != 0 )); then exit "$probe_status"; fi

fetch_xray() {
  local version="$1" expected_archive_sha="$2" destination="$3"
  local archive="$root/Xray-linux-64-$version.zip"
  curl --fail --location --proto '=https' --retry 2 --max-time 120 \
    --silent --show-error \
    "https://github.com/XTLS/Xray-core/releases/download/v$version/Xray-linux-64.zip" \
    -o "$archive"
  printf '%s  %s\n' "$expected_archive_sha" "$archive" | sha256sum --check --status
  [[ "$(unzip -Z1 "$archive" | grep -xc 'xray')" == 1 ]]
  unzip -p "$archive" xray > "$destination"
  chmod 755 "$destination"
  sha256sum "$destination" | awk '{print $1 "  xray"}'
}
baseline="$root/xray-26.10.21"
candidate="$root/xray-26.10.31"
fetch_xray 26.10.21 0eec3ed4163c273d8c8bf821f7d219e257921cf584aa3fb970715e458e631978 "$baseline"
fetch_xray 26.10.31 e4bd9119f50ae7c41658b1abd0679ae06f98bd864a2907ff33f2f2cf7081b214 "$candidate"
python3 "$source_tree/tools/linux-maintenance/native_scenario.py" \
  "$root" "$baseline" "$candidate" | tee -a "$GITHUB_STEP_SUMMARY"