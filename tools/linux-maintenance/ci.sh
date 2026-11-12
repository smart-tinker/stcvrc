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
cleanup() {
  rm -rf -- "$root"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
export PYTHONDONTWRITEBYTECODE=1
unit_status=0
python3 -m unittest discover \
  -s "$source_tree/tools/linux-maintenance" \
  -p 'test_*.py' -v || unit_status=$?
probe_status=0
python3 "$source_tree/tools/linux-maintenance/systemd_counter_probe.py" "$root" || probe_status=$?
if (( unit_status != 0 )); then
  exit "$unit_status"
fi
exit "$probe_status"
