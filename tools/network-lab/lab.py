"""Local-only VLESS/TLS failover fixture. Never downloads or installs binaries."""
import argparse
import contextlib
import hashlib
import http.client
import http.server
import json
import pathlib
import re
import socket
import subprocess
import tempfile
import threading
import time
import uuid

HOST = "127.0.0.1"
PORTS = {"core": 17890, "A": 18081, "B": 18082, "direct": 18083}
TARGET = f"http://{HOST}:{PORTS['direct']}"


def checked_binary(path, expected):
    path = pathlib.Path(path).resolve(strict=True)
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("Expected a reviewed lowercase SHA256")
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        raise ValueError(f"SHA256 mismatch for {path.name}")
    return str(path)


def configs(directory, certificate, identity, backends):
    directory = pathlib.Path(directory)
    core = {
        "mixed-port": PORTS["core"], "allow-lan": False,
        "bind-address": HOST, "mode": "rule", "log-level": "warning",
        "ipv6": False, "find-process-mode": "off",
        "tun": {"enable": False}, "dns": {"enable": False},
        "ntp": {"enable": False}, "geodata-mode": False,
        "geo-auto-update": False, "profile": {"store-selected": False},
        # This misspelling is the actual d888dfad config field, not a typo here.
        "tls": {"custom-certifactes": [certificate]},
        "proxies": [{
            "name": name, "type": "vless", "server": HOST,
            "port": PORTS[name], "uuid": identity, "tls": True,
            "servername": "stcvrc-lab.invalid", "skip-cert-verify": False,
            "network": "tcp", "udp": False,
        } for name in ("A", "B")],
        "proxy-groups": [{
            "name": "LAB", "type": "fallback", "proxies": ["A", "B"],
            "url": TARGET + "/generate_204", "interval": 2,
            "timeout": 1000, "lazy": False, "expected-status": 204,
        }],
        "rules": ["MATCH,LAB"],
    }
    result = {"core": core}
    for name in ("A", "B"):
        result[name] = {
            "log": {"loglevel": "warning"},
            "inbounds": [{
                "listen": HOST, "port": PORTS[name], "protocol": "vless",
                "settings": {"clients": [{"id": identity}], "decryption": "none"},
                "streamSettings": {
                    "network": "tcp", "security": "tls",
                    "tlsSettings": {"certificates": [{
                        "certificateFile": str(directory / "cert.pem"),
                        "keyFile": str(directory / "key.pem"),
                    }]},
                },
            }],
            "outbounds": [{"protocol": "freedom", "settings": {
                "redirect": f"{HOST}:{backends[name]}",
                "finalRules": [
                    {"action": "allow", "network": "tcp", "ip": [HOST + "/32"],
                     "port": f"{PORTS['direct']},{backends[name]}"},
                    {"action": "block"},
                ],
            }}],
        }
    return result


def request(port=PORTS["core"], proxy=True, timeout=1):
    connection = http.client.HTTPConnection(HOST, port, timeout=timeout)
    try:
        connection.request("GET", TARGET + "/probe" if proxy else "/probe",
                           headers={"Connection": "close"})
        response = connection.getresponse()
        body = response.read(128).decode("ascii", errors="replace")
        return response.status, body
    except (OSError, http.client.HTTPException):
        return None, None
    finally:
        connection.close()


def probe(port=PORTS["core"], proxy=True):
    status, body = request(port, proxy)
    return body if status == 200 else None


def wait_for(expected, timeout=15, start=None):
    start = time.monotonic() if start is None else start
    while time.monotonic() - start < timeout:
        actual = probe()
        if actual == expected:
            return round(time.monotonic() - start, 3)
        if actual not in (None, "A", "B"):
            raise AssertionError(f"Unexpected traffic path: {actual!r}")
        time.sleep(0.1)
    raise AssertionError(f"Did not reach {expected} within {timeout}s")


def check_both_down(client):
    for _ in range(3):
        if client.poll() is not None:
            raise AssertionError("Client exited during the both-down check")
        # Candidate retries failed upstream dials within a five-second TCP budget.
        status, _ = request(timeout=10)
        if client.poll() is not None:
            raise AssertionError("Client exited during the both-down check")
        # Candidate listener/http/proxy.go returns 502 when upstream dialing fails.
        if status != 502:
            raise AssertionError(f"Expected a live proxy's HTTP 502, got {status}")


def check_tls_rejection(log_path, client):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if client.poll() is not None:
            raise AssertionError("Client exited during TLS-negative startup")
        try:
            with socket.create_connection((HOST, PORTS["core"]), timeout=0.2):
                break
        except OSError:
            time.sleep(0.1)
    else:
        raise AssertionError("Client listener did not start for TLS-negative check")
    check_both_down(client)
    evidence = "certificate is valid for stcvrc-lab.invalid, not wrong-stcvrc-lab.invalid"
    if evidence not in log_path.read_text(errors="replace"):
        raise AssertionError("No explicit TLS hostname rejection found")
    return {"tls_hostname_mismatch_rejected": True}


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


@contextlib.contextmanager
def backend(identity, port=0):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.respond(send_body=True)

        def do_HEAD(self):
            self.respond(send_body=False)

        def respond(self, send_body):
            health = self.path == "/generate_204" and identity != "DIRECT"
            payload = b"" if health else identity.encode("ascii")
            self.send_response(204 if health else 200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if send_body:
                self.wfile.write(payload)

        def log_message(self, *_):
            pass

    server = http.server.ThreadingHTTPServer((HOST, port), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def run(core, xray, openssl, check_tls_hostname=False):
    # No TUN, Docker, controller, host routing, system trust-store or DNS changes.
    with contextlib.ExitStack() as stack:
        directory = pathlib.Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="stcvrc-lab-")))
        for port in PORTS.values():
            with socket.socket() as reservation:
                reservation.bind((HOST, port))
        endpoints = {name: stack.enter_context(backend(name)) for name in ("A", "B")}
        stack.enter_context(backend("DIRECT", PORTS["direct"]))
        if probe(PORTS["direct"], proxy=False) != "DIRECT":
            raise AssertionError("Direct-path negative control is not working")
        subprocess.run([
            openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=stcvrc-lab.invalid", "-addext", "subjectAltName=DNS:stcvrc-lab.invalid",
            "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "extendedKeyUsage=serverAuth",
            "-keyout", str(directory / "key.pem"), "-out", str(directory / "cert.pem"),
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
        generated = configs(directory, (directory / "cert.pem").read_text(), str(uuid.uuid4()), endpoints)
        if check_tls_hostname:
            for proxy in generated["core"]["proxies"]:
                proxy["servername"] = "wrong-stcvrc-lab.invalid"
        for name, config in generated.items():
            (directory / (name + ".json")).write_text(json.dumps(config), encoding="utf-8")
        state = directory / "state"
        state.mkdir()
        logs = stack.enter_context((directory / "process.log").open("wb"))
        for name in ("A", "B"):
            subprocess.run([xray, "run", "-test", "-c", str(directory / (name + ".json"))],
                           check=True, stdout=logs, stderr=logs, timeout=15)
        subprocess.run([core, "-t", "-d", str(state), "-f", str(directory / "core.json")],
                       check=True, stdout=logs, stderr=logs, timeout=15)

        def start(name):
            command = ([core, "-d", str(state), "-f", str(directory / "core.json")]
                       if name == "core" else [xray, "run", "-c", str(directory / (name + ".json"))])
            process = subprocess.Popen(command, stdout=logs, stderr=logs, cwd=directory)
            stack.callback(stop, process)
            return process

        initial_start = time.monotonic()
        a, b, client = start("A"), start("B"), start("core")
        if check_tls_hostname:
            print(json.dumps(check_tls_rejection(directory / "process.log", client)))
            return
        results = {"initial_A_seconds": wait_for("A", start=initial_start)}
        fault_start = time.monotonic()
        stop(a)
        results["failover_B_seconds"] = wait_for("B", start=fault_start)
        recovery_start = time.monotonic()
        a = start("A")
        results["failback_A_seconds"] = wait_for("A", start=recovery_start)
        stop(a)
        stop(b)
        check_both_down(client)
        results["both_down_requests_failed"] = 3
        print(json.dumps(results, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", required=True)
    parser.add_argument("--core-sha256", required=True)
    parser.add_argument("--xray", required=True)
    parser.add_argument("--xray-sha256", required=True)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--check-tls-rejection", action="store_true")
    args = parser.parse_args()
    run(checked_binary(args.core, args.core_sha256),
        checked_binary(args.xray, args.xray_sha256), args.openssl, args.check_tls_rejection)


if __name__ == "__main__":
    main()
