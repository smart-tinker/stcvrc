"""Check a freshly built Windows core using disposable loopback endpoints."""
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile

import lab

XRAY_URL = "https://github.com/XTLS/Xray-core/releases/download/v26.10.31/Xray-windows-64.zip"
XRAY_ZIP_SHA = "2e04a9995a6f2ad1b28c0bb25c708ecb2695e43a1c9c7889c4b6ac2b48cf7a6a"


def fresh_core():
    path = os.environ.get("STCVRC_CORE_PATH")
    expected = os.environ.get("STCVRC_CORE_SHA256")
    if not path or not expected:
        raise SystemExit("Fresh STCVRC build path and SHA are required")
    return pathlib.Path(lab.checked_binary(path, expected)), expected


def download(url, destination, expected):
    with urllib.request.urlopen(url, timeout=120) as response:
        if not response.url.startswith("https://"):
            raise ValueError("HTTPS download required")
        with destination.open("wb") as output:
            shutil.copyfileobj(response, output)
    lab.checked_binary(destination, expected)


def extract_xray(archive, destination):
    # Extract one known member, never archive-controlled paths.
    with zipfile.ZipFile(archive) as bundle:
        destination.write_bytes(bundle.read("xray.exe"))
    return hashlib.sha256(destination.read_bytes()).hexdigest()


def run_fixture(command, timeout=120):
    # Keep the parent alive until taskkill has identified its owned child tree.
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=None, text=True)
    try:
        try:
            stdout, _ = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            subprocess.run(["taskkill.exe", "/PID", str(process.pid), "/T", "/F"],
                           check=True, timeout=15)
            process.communicate(timeout=15)
            raise
        if process.returncode:
            print(stdout, file=sys.stderr, end="")
            raise subprocess.CalledProcessError(process.returncode, command, output=stdout)
        return stdout
    finally:
        # Popen's context manager can wait indefinitely if tree termination fails.
        if process.poll() is None:
            process.kill()
            process.wait(timeout=15)
        process.stdout.close()


def main():
    if sys.platform != "win32":
        raise SystemExit("This check requires native Windows")
    openssl = shutil.which("openssl")
    if not openssl:
        raise SystemExit("OpenSSL is required; no installation or trust-store change is performed")
    core, core_sha = fresh_core()
    here = pathlib.Path(__file__).resolve().parent
    with tempfile.TemporaryDirectory(prefix="stcvrc-windows-") as temporary:
        folder = pathlib.Path(temporary)
        archive, xray = folder / "xray.zip", folder / "xray.exe"
        download(XRAY_URL, archive, XRAY_ZIP_SHA)
        xray_sha = extract_xray(archive, xray)
        subprocess.run([str(core), "-v"], check=True, timeout=15)
        subprocess.run([str(xray), "version"], check=True, timeout=15)
        results = []
        for extra in ([], ["--check-tls-rejection"]):
            stdout = run_fixture([
                sys.executable, str(here / "lab.py"), "--core", str(core),
                "--core-sha256", core_sha, "--xray", str(xray),
                "--xray-sha256", xray_sha, "--openssl", openssl, *extra,
            ])
            results.append(json.loads(stdout))
        evidence = {"core_sha256": core_sha, "xray_zip_sha256": XRAY_ZIP_SHA,
                    "xray_sha256": xray_sha, "results": results}
        rendered = json.dumps(evidence, sort_keys=True)
        print(rendered)
        if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(summary, "a", encoding="utf-8") as output:
                output.write("## Fresh-source Windows loopback HTTP/TCP\n\n" + rendered +
                             "\n\nNo TUN, GUI/service, OpenVPN/rekey, UDP/DNS or user acceptance.\n")

if __name__ == "__main__":
    main()
