"""Check the published Windows core using disposable loopback endpoints."""
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

CORE_URL = "https://github.com/smart-tinker/stcvrc/releases/download/stcvrc-1.19.33-rc.1/verge-mihomo.exe"
CORE_SHA = "6a35ab8e2db4c0171f74563aded55949d10a3dcc5ad9c1c1b5e155ab2a2986c7"
XRAY_URL = "https://github.com/XTLS/Xray-core/releases/download/v26.10.31/Xray-windows-64.zip"
XRAY_ZIP_SHA = "2e04a9995a6f2ad1b28c0bb25c708ecb2695e43a1c9c7889c4b6ac2b48cf7a6a"


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


def main():
    if sys.platform != "win32":
        raise SystemExit("This check requires native Windows")
    openssl = shutil.which("openssl")
    if not openssl:
        raise SystemExit("OpenSSL is required; no installation or trust-store change is performed")
    here = pathlib.Path(__file__).resolve().parent
    with tempfile.TemporaryDirectory(prefix="stcvrc-windows-") as temporary:
        folder = pathlib.Path(temporary)
        core, archive, xray = folder / "core.exe", folder / "xray.zip", folder / "xray.exe"
        download(CORE_URL, core, CORE_SHA)
        download(XRAY_URL, archive, XRAY_ZIP_SHA)
        xray_sha = extract_xray(archive, xray)
        subprocess.run([str(core), "-v"], check=True, timeout=15)
        subprocess.run([str(xray), "version"], check=True, timeout=15)
        results = []
        for extra in ([], ["--check-tls-rejection"]):
            completed = subprocess.run([
                sys.executable, str(here / "lab.py"), "--core", str(core),
                "--core-sha256", CORE_SHA, "--xray", str(xray),
                "--xray-sha256", xray_sha, "--openssl", openssl, *extra,
            ], check=True, capture_output=True, text=True, timeout=120)
            results.append(json.loads(completed.stdout))
        evidence = {"core_sha256": CORE_SHA, "xray_zip_sha256": XRAY_ZIP_SHA,
                    "xray_sha256": xray_sha, "results": results}
        rendered = json.dumps(evidence, sort_keys=True)
        print(rendered)
        if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(summary, "a", encoding="utf-8") as output:
                output.write("## Published Windows EXE, loopback HTTP/TCP\n\n```json\n" + rendered +
                             "\n```\n\nNo TUN, GUI/service, OpenVPN/rekey, UDP/DNS or user acceptance.\n")


if __name__ == "__main__":
    main()
