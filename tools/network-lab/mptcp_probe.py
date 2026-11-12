#!/usr/bin/env python3
"""Observe Xray 26.10.31 MPTCP behavior using loopback sockets only.

Linux IPPROTO_MPTCP is 262. SOL_MPTCP/MPTCP_INFO and its fallback flag are
defined by the Linux UAPI. The probe checks the kernel's negotiated socket
state at both ends; config snapshots and syscall intent are not acceptance.
"""
from __future__ import annotations

import argparse
import contextlib
import json
import os
import pathlib
import platform
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid


HOST = "127.0.0.1"
IPPROTO_MPTCP = 262
SOL_MPTCP = 284
MPTCP_INFO = 1
MPTCP_INFO_FLAG_FALLBACK = 1
SO_PROTOCOL = getattr(socket, "SO_PROTOCOL", 38)
MPTCP_INFO_FLAGS_OFFSET = 8  # six u8 fields, two bytes of ABI padding, then u32 flags
PAYLOAD_SIZE = 96


class ProbeError(RuntimeError):
    pass


class MptcpBlocked(ProbeError):
    pass


def effective_socket_state(sock: socket.socket) -> tuple[str, int, int | None]:
    """Return effective state, SO_PROTOCOL and MPTCP flags if available."""
    protocol = sock.getsockopt(socket.SOL_SOCKET, SO_PROTOCOL)
    if protocol == socket.IPPROTO_TCP:
        return "tcp", protocol, None
    if protocol != IPPROTO_MPTCP:
        raise ProbeError(f"unexpected SO_PROTOCOL={protocol}")
    try:
        info = sock.getsockopt(SOL_MPTCP, MPTCP_INFO, 128)
    except OSError as error:
        raise ProbeError(f"MPTCP_INFO failed on an MPTCP socket: {error}") from error
    end = MPTCP_INFO_FLAGS_OFFSET + 4
    if len(info) < end:
        raise ProbeError(f"MPTCP_INFO returned only {len(info)} bytes")
    flags = int.from_bytes(
        info[MPTCP_INFO_FLAGS_OFFSET:end], byteorder=sys.byteorder, signed=False
    )
    state = "tcp-fallback" if flags & MPTCP_INFO_FLAG_FALLBACK else "mptcp"
    return state, protocol, flags


class MptcpEcho:
    """One-shot loopback echo service whose accepted socket state is recorded."""

    def __init__(self, payload: bytes):
        self.payload = payload
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM, IPPROTO_MPTCP)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind((HOST, 0))
        self.listener.listen(8)
        self.listener.settimeout(0.2)
        self.address = self.listener.getsockname()
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.records: list[dict[str, object]] = []
        self.errors: list[str] = []
        self.handlers: list[threading.Thread] = []
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        while not self.stop_event.is_set():
            try:
                conn, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                if self.stop_event.is_set():
                    return
                with self.lock:
                    self.errors.append("MPTCP echo listener accept failed")
                return
            handler = threading.Thread(target=self._handle, args=(conn,), daemon=True)
            self.handlers.append(handler)
            handler.start()

    def _handle(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(5)
            received = bytearray()
            while len(received) < len(self.payload):
                chunk = conn.recv(len(self.payload) - len(received))
                if not chunk:
                    break
                received.extend(chunk)
            if not received:
                return  # readiness probes connect and close without sending payload
            if bytes(received) != self.payload:
                with self.lock:
                    self.errors.append("echo endpoint received unexpected payload")
                return
            state, protocol, flags = effective_socket_state(conn)
            with self.lock:
                self.records.append(
                    {"state": state, "protocol": protocol, "mptcp_flags": flags}
                )
            conn.sendall(self.payload)
        except (OSError, ProbeError) as error:
            with self.lock:
                self.errors.append(str(error))
        finally:
            conn.close()

    def wait_record(self, timeout: float = 5.0) -> dict[str, object]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self.lock:
                if self.errors:
                    raise ProbeError("; ".join(self.errors))
                if self.records:
                    return self.records[0]
            time.sleep(0.02)
        raise ProbeError("timed out waiting for the loopback echo transaction")

    def close(self) -> None:
        self.stop_event.set()
        self.listener.close()
        self.thread.join(timeout=1)
        for handler in self.handlers:
            handler.join(timeout=0.2)


@contextlib.contextmanager
def mptcp_echo(payload: bytes):
    server = MptcpEcho(payload)
    try:
        yield server
    finally:
        server.close()


def receive_exact(sock: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            break
        chunks.extend(chunk)
    return bytes(chunks)


def exchange_mptcp(server: MptcpEcho, payload: bytes) -> tuple[str, dict[str, object]]:
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM, IPPROTO_MPTCP)
    try:
        client.settimeout(5)
        client.connect(server.address)
        client.sendall(payload)
        echoed = receive_exact(client, len(payload))
        if echoed != payload:
            raise ProbeError("loopback MPTCP echo payload did not round-trip")
        client_state, client_protocol, client_flags = effective_socket_state(client)
        peer = server.wait_record()
        return client_state, {
            "client": {
                "state": client_state,
                "protocol": client_protocol,
                "mptcp_flags": client_flags,
            },
            "server": peer,
        }
    finally:
        client.close()


def random_port(exclude: set[int]) -> int:
    for _ in range(20):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind((HOST, 0))
            port = probe.getsockname()[1]
        if port not in exclude:
            return port
    raise ProbeError("could not reserve distinct loopback ports")


def check_kernel_support() -> dict[str, object]:
    enabled_path = pathlib.Path("/proc/sys/net/mptcp/enabled")
    try:
        enabled = enabled_path.read_text(encoding="ascii").strip()
    except OSError as error:
        raise MptcpBlocked(f"cannot read {enabled_path}: {error}") from error
    if enabled != "1":
        raise MptcpBlocked(f"net.mptcp.enabled={enabled}; this runner cannot prove MPTCP")
    payload = ("mptcp-capability-" + uuid.uuid4().hex).encode("ascii")
    with mptcp_echo(payload) as server:
        try:
            client_state, observed = exchange_mptcp(server, payload)
        except OSError as error:
            raise MptcpBlocked(f"IPPROTO_MPTCP loopback negotiation failed: {error}") from error
    if client_state != "mptcp" or observed["server"]["state"] != "mptcp":
        raise MptcpBlocked(
            "runner created MPTCP sockets but did not negotiate MPTCP on both loopback peers: "
            + json.dumps(observed, sort_keys=True)
        )
    return {
        "enabled_sysctl": enabled,
        "kernel": platform.release(),
        "loopback_negotiation": observed,
    }


def xray_config(inbound_port: int, backend_port: int, inbound_mptcp, outbound_mptcp):
    inbound = {
        "tag": "mptcp-probe-in",
        "listen": HOST,
        "port": inbound_port,
        "protocol": "dokodemo-door",
        "settings": {"network": "tcp", "address": HOST, "port": backend_port},
    }
    if inbound_mptcp is not None:
        inbound["streamSettings"] = {
            "sockopt": {"tcpMptcp": bool(inbound_mptcp)}
        }
    outbound = {
        "tag": "mptcp-probe-out",
        "protocol": "freedom",
        "settings": {},
    }
    if outbound_mptcp is not None:
        outbound["streamSettings"] = {
            "sockopt": {"tcpMptcp": bool(outbound_mptcp)}
        }
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [inbound],
        "outbounds": [outbound],
    }


def wait_until_listening(process: subprocess.Popen, port: int, log_path: pathlib.Path):
    deadline = time.monotonic() + 10
    last_error = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise ProbeError(
                f"Xray exited with {process.returncode}: "
                + log_path.read_text(encoding="utf-8", errors="replace")
            )
        try:
            with socket.create_connection((HOST, port), timeout=0.25):
                return
        except OSError as error:
            last_error = error
            time.sleep(0.05)
    raise ProbeError(
        f"Xray did not listen on loopback port {port}: {last_error}; "
        + log_path.read_text(encoding="utf-8", errors="replace")
    )


@contextlib.contextmanager
def run_xray(xray: pathlib.Path, config: dict[str, object], godebug: str, port: int):
    with tempfile.TemporaryDirectory(prefix="stcvrc-mptcp-") as temp:
        directory = pathlib.Path(temp)
        config_path = directory / "xray.json"
        log_path = directory / "xray.log"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        env = os.environ.copy()
        env["GODEBUG"] = f"multipathtcp={godebug}"
        checked = subprocess.run(
            [str(xray), "run", "-test", "-c", str(config_path)],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=15,
            check=False,
        )
        if checked.returncode:
            raise ProbeError(
                f"Xray rejected generated config: {checked.stdout[-4000:]}"
            )
        with log_path.open("w", encoding="utf-8") as log:
            process = subprocess.Popen(
                [str(xray), "run", "-c", str(config_path)],
                env=env,
                stdout=log,
                stderr=subprocess.STDOUT,
                text=True,
            )
            try:
                wait_until_listening(process, port, log_path)
                yield process
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)


def run_case(xray: pathlib.Path, case: dict[str, object]) -> dict[str, object]:
    payload = ("stcvrc-mptcp-" + str(case["name"]) + "-" + uuid.uuid4().hex).encode("ascii")
    with mptcp_echo(payload) as backend:
        inbound_port = random_port({backend.address[1]})
        config = xray_config(
            inbound_port,
            backend.address[1],
            case["inbound"],
            case["outbound"],
        )
        with run_xray(xray, config, str(case["godebug"]), inbound_port):
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM, IPPROTO_MPTCP)
            try:
                client.settimeout(8)
                client.connect((HOST, inbound_port))
                client.sendall(payload)
                echoed = receive_exact(client, len(payload))
                if echoed != payload:
                    raise ProbeError(f"{case['name']}: Xray loopback payload did not round-trip")
                client_state, client_protocol, client_flags = effective_socket_state(client)
                peer = backend.wait_record()
            finally:
                client.close()

    expected_inbound = bool(case["expected_inbound"])
    expected_outbound = bool(case["expected_outbound"])
    observed_inbound = client_state == "mptcp"
    observed_outbound = peer["state"] == "mptcp"
    if observed_inbound != expected_inbound or observed_outbound != expected_outbound:
        raise ProbeError(
            f"{case['name']}: expected inbound/outbound "
            f"{expected_inbound}/{expected_outbound}, observed "
            f"{observed_inbound}/{observed_outbound}; client="
            f"{client_state}, peer={peer['state']}"
        )
    return {
        "case": case["name"],
        "godebug_multipathtcp": case["godebug"],
        "config": {
            "inbound_tcpMptcp": case["inbound"],
            "outbound_tcpMptcp": case["outbound"],
        },
        "expected": {
            "inbound_mptcp": expected_inbound,
            "outbound_mptcp": expected_outbound,
        },
        "observed": {
            "inbound_client": {
                "state": client_state,
                "protocol": client_protocol,
                "mptcp_flags": client_flags,
            },
            "outbound_backend": peer,
        },
        "result": "PASS",
    }


CASES = (
    {
        "name": "default-godebug-0",
        "godebug": 0,
        "inbound": None,
        "outbound": None,
        "expected_inbound": False,
        "expected_outbound": False,
    },
    {
        "name": "inbound-explicit-true",
        "godebug": 0,
        "inbound": True,
        "outbound": None,
        "expected_inbound": True,
        "expected_outbound": False,
    },
    {
        "name": "outbound-explicit-true",
        "godebug": 0,
        "inbound": None,
        "outbound": True,
        "expected_inbound": False,
        "expected_outbound": True,
    },
    {
        "name": "explicit-false-godebug-0",
        "godebug": 0,
        "inbound": False,
        "outbound": False,
        "expected_inbound": False,
        "expected_outbound": False,
    },
    {
        "name": "explicit-false-godebug-1",
        "godebug": 1,
        "inbound": False,
        "outbound": False,
        "expected_inbound": False,
        "expected_outbound": True,
    },
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--xray", required=True, type=pathlib.Path)
    args = parser.parse_args()
    if not args.xray.is_file() or not os.access(args.xray, os.X_OK):
        raise ProbeError(f"not an executable Xray binary: {args.xray}")
    try:
        capability = check_kernel_support()
    except (MptcpBlocked, OSError, ProbeError) as error:
        print(f"MPTCP-BLOCKED: {error}", file=sys.stderr)
        return 2
    results = [run_case(args.xray.resolve(), case) for case in CASES]
    print(
        json.dumps(
            {
                "xray": "26.10.31",
                "runner_capability": capability,
                "cases": results,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ProbeError, OSError, subprocess.SubprocessError) as error:
        print(f"MPTCP-FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
