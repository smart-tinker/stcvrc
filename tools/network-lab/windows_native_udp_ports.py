import errno
import json
import os
import socket
import tempfile
from pathlib import Path


_PLAN_FIELDS = ("coreDnsPort", "profileDnsPort", "appDnsPort", "subscriptionDnsPort")
_FIXTURE_FIELDS = ("profileDnsPort", "appDnsPort", "subscriptionDnsPort")
_LOOPBACK = "127.0.0.1"


def _read_plan(path):
    try:
        plan = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("The native UDP port plan cannot be read.") from error
    if not isinstance(plan, dict) or type(plan.get("schemaVersion")) is not int or plan["schemaVersion"] != 1:
        raise ValueError("The native UDP port plan schema is invalid.")
    ports = {}
    for name in _PLAN_FIELDS:
        port = plan.get(name)
        if type(port) is not int or port < 1 or port > 65535:
            raise ValueError("The native UDP port plan contains an invalid endpoint.")
        ports[name] = port
    if len(set(ports.values())) != len(_PLAN_FIELDS):
        raise ValueError("The native UDP port plan contains duplicate endpoints.")
    return plan, ports


def _new_udp_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if os.name == "nt" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    return sock


def _bind_ephemeral(excluded):
    for _ in range(16):
        sock = _new_udp_socket()
        try:
            sock.bind((_LOOPBACK, 0))
            port = int(sock.getsockname()[1])
            if port not in excluded:
                return sock, port
        except BaseException:
            sock.close()
            raise
        sock.close()
    raise OSError(errno.EADDRINUSE, "No distinct loopback UDP fixture port became available.")


def _write_plan(path, plan):
    plan_path = Path(path)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=str(plan_path.parent),
            prefix=plan_path.name + ".",
            suffix=".tmp",
            delete=False,
        ) as output:
            temporary_path = Path(output.name)
            json.dump(plan, output, separators=(",", ":"))
            output.write("\n")
        os.replace(temporary_path, plan_path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass


def bind_dns_fixture_sockets(plan_path):
    plan, ports = _read_plan(plan_path)
    held_ports = {ports["coreDnsPort"]}
    unavailable = set(ports.values())
    sockets = {}
    collisions = []
    try:
        for name in _FIXTURE_FIELDS:
            requested = ports[name]
            sock = _new_udp_socket()
            try:
                sock.bind((_LOOPBACK, requested))
            except OSError as error:
                sock.close()
                if error.errno != errno.EADDRINUSE:
                    raise
                collisions.append(name)
                sock, actual = _bind_ephemeral(unavailable | held_ports)
            else:
                actual = int(sock.getsockname()[1])
                if actual in held_ports:
                    sock.close()
                    raise RuntimeError("A native UDP fixture endpoint overlaps another planned endpoint.")
            if actual in held_ports:
                sock.close()
                raise RuntimeError("A native UDP fixture endpoint overlaps another planned endpoint.")
            sockets[name] = sock
            plan[name] = actual
            held_ports.add(actual)
        if len({int(plan[name]) for name in _PLAN_FIELDS}) != len(_PLAN_FIELDS):
            raise RuntimeError("The bound native UDP fixture plan is not unique.")
        _write_plan(plan_path, plan)
        return sockets, tuple(collisions)
    except BaseException:
        for sock in sockets.values():
            sock.close()
        raise
