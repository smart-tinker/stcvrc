import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
CI = ROOT / "tools" / "source-build" / "ci.sh"
HELPER = ROOT / "tools" / "source-build" / "fetch-binaryen.sh"
URL = "https://github.com/WebAssembly/binaryen/releases/download/version_131/binaryen-version_131-x86_64-windows.tar.gz"
SHA256 = "2f4edac1703a2f695254d6ff52ede03481e67db1f094915763d863158c17d9bc"


class BinaryenFetchTests(unittest.TestCase):
    def test_windows_recipe_pins_verified_optimizer_before_wasm_generation(self):
        recipe = CI.read_text(encoding="utf-8")
        helper = HELPER.read_text(encoding="utf-8")

        self.assertIn(f'binaryen_archive_url="{URL}"', recipe)
        self.assertIn(f'binaryen_archive_sha256="{SHA256}"', recipe)
        fetch = recipe.index('bash "$recipe/tools/source-build/fetch-binaryen.sh"')
        extract = recipe.index('tar -xzf "$binaryen_archive" -C "$root/binaryen"')
        optimizer = recipe.index('WASM_OPT="$root/binaryen/binaryen-version_131/bin/wasm-opt.exe"')
        generate = recipe.index("go generate ./internal/artifact")
        self.assertLess(fetch, extract)
        self.assertLess(extract, optimizer)
        self.assertLess(optimizer, generate)
        self.assertIn('export WASM_OPT STCVRC_BINARYEN_ARCHIVE_SHA256="$binaryen_archive_sha256"', recipe)
        self.assertIn('"binaryen_archive_sha256": os.environ.get("STCVRC_BINARYEN_ARCHIVE_SHA256")', recipe)
        self.assertIn("--proto '=https'", helper)
        self.assertIn("sha256sum --check --status", helper)
        self.assertLess(helper.index("sha256sum --check --status"), helper.index('mv -- "$temporary" "$archive"'))

    @unittest.skipIf(os.name == "nt", "synthetic curl fixture runs in the Ubuntu source job")
    def test_transient_504_then_success_keeps_only_the_verified_archive(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = b"synthetic pinned Binaryen archive"
            expected = hashlib.sha256(payload).hexdigest()
            result, archive, calls = self.run_fetch(root, "transient", payload, expected)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(int(calls.read_text(encoding="ascii")), 2)
            self.assertEqual(archive.read_bytes(), payload)
            self.assertEqual(list(root.glob("binaryen.tar.gz.part.*")), [])

    @unittest.skipIf(os.name == "nt", "synthetic curl fixture runs in the Ubuntu source job")
    def test_retry_exhaustion_fails_without_publishing_partial_download(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = b"partial response"
            expected = hashlib.sha256(b"expected pinned archive").hexdigest()
            result, archive, calls = self.run_fetch(root, "exhaust", payload, expected)

            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(int(calls.read_text(encoding="ascii")), 4)
            self.assertFalse(archive.exists())
            self.assertEqual(list(root.glob("binaryen.tar.gz.part.*")), [])
            self.assertIn("after 4 attempts", result.stderr)

    @unittest.skipIf(os.name == "nt", "synthetic curl fixture runs in the Ubuntu source job")
    def test_digest_mismatch_fails_before_publishing_archive(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result, archive, calls = self.run_fetch(
                root, "success", b"wrong archive bytes",
                hashlib.sha256(b"official pinned archive bytes").hexdigest(),
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(int(calls.read_text(encoding="ascii")), 1)
            self.assertFalse(archive.exists())
            self.assertEqual(list(root.glob("binaryen.tar.gz.part.*")), [])
            self.assertIn("SHA-256 mismatch", result.stderr)

    def run_fetch(self, root, mode, payload, expected_sha256):
        fake_bin = root / "fake-bin"
        fake_bin.mkdir()
        curl = fake_bin / "curl"
        curl.write_text("""#!/usr/bin/env bash
set -euo pipefail
output=
while (( $# )); do
  case "$1" in
    -o|--output) output="$2"; shift 2 ;;
    *) shift ;;
  esac
done
[[ -n "$output" ]]
count=0
if [[ -f "$CURL_STATE" ]]; then read -r count < "$CURL_STATE"; fi
count=$((count + 1))
printf '%s\\n' "$count" > "$CURL_STATE"
if [[ "$CURL_MODE" == exhaust || ( "$CURL_MODE" == transient && "$count" -eq 1 ) ]]; then
  printf partial > "$output"
  printf 'curl: (22) HTTP 504\\n' >&2
  exit 22
fi
cp "$CURL_PAYLOAD" "$output"
""", encoding="utf-8", newline="\n")
        curl.chmod(0o755)
        sleep = fake_bin / "sleep"
        sleep.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8", newline="\n")
        sleep.chmod(0o755)
        payload_path = root / "response.bin"
        payload_path.write_bytes(payload)
        calls = root / "curl.calls"
        archive = root / "binaryen.tar.gz"
        env = os.environ.copy()
        env.update({
            "PATH": str(fake_bin) + os.pathsep + env["PATH"],
            "CURL_MODE": mode,
            "CURL_STATE": str(calls),
            "CURL_PAYLOAD": str(payload_path),
        })
        result = subprocess.run(
            ["bash", str(HELPER), URL, expected_sha256, str(archive)],
            capture_output=True, text=True, env=env, timeout=15,
        )
        return result, archive, calls
