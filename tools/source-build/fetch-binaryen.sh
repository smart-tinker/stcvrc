#!/usr/bin/env bash
set -euo pipefail

if (( $# != 3 )); then
  printf 'Usage: fetch-binaryen.sh HTTPS_URL SHA256 OUTPUT_ARCHIVE\n' >&2
  exit 2
fi
if [[ "$1" != https://* || ! "$2" =~ ^[0-9a-f]{64}$ ]]; then
  printf 'Invalid Binaryen download pin.\n' >&2
  exit 2
fi

url="$1"
expected_sha256="$2"
archive="$3"
temporary="${archive}.part.$$"
trap 'rm -f -- "$temporary"' EXIT

for attempt in 1 2 3 4; do
  rm -f -- "$temporary"
  if curl --fail --location --proto '=https' --proto-redir '=https' \
    --connect-timeout 30 --max-time 180 --silent --show-error \
    --output "$temporary" "$url"; then
    break
  fi
  if (( attempt == 4 )); then
    printf 'Binaryen download failed after 4 attempts.\n' >&2
    exit 1
  fi
  sleep 2
done
if [[ ! -f "$temporary" ]] || ! printf '%s  %s\n' "$expected_sha256" "$temporary" | sha256sum --check --status; then
  printf 'Binaryen archive SHA-256 mismatch.\n' >&2
  exit 1
fi
mv -- "$temporary" "$archive"
