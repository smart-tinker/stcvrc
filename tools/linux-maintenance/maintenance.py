"""Reusable, fail-closed primitives for systemd maintenance transactions."""
import hashlib
import json
import os
import re
import tempfile
import time
from pathlib import Path


class AmbiguousOperation(RuntimeError):
    """A previous dispatch may have happened; reconcile it instead of replaying."""


class ReceiptMismatch(RuntimeError):
    pass


class ProcessIdentityError(RuntimeError):
    pass


def _atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix="." + path.name + ".", suffix=".tmp",
                                     dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def restart_once(receipt_path, operation_id, unit, method, invoke, observe):
    """Dispatch one DBus unit job, persisting intent/receipt before observation.

    An intent without a returned DBus job path is ambiguous and is never replayed.
    A dispatched receipt may be observed again after an observer failure, but the
    external operation itself is never dispatched twice for the same operation ID.
    """
    if not isinstance(operation_id, str) or not operation_id or "\n" in operation_id:
        raise ValueError("operation_id must be a non-empty single-line string")
    if not isinstance(unit, str) or not re.fullmatch(r"[A-Za-z0-9_.@:-]+", unit):
        raise ValueError("unit contains invalid characters")
    if method not in {"StartUnit", "RestartUnit", "StopUnit"}:
        raise ValueError("unsupported systemd method")
    path = Path(receipt_path)
    identity = {"operation_id": operation_id, "unit": unit, "method": method}
    if path.exists():
        receipt = json.loads(path.read_text(encoding="utf-8"))
        if any(receipt.get(key) != value for key, value in identity.items()):
            raise ReceiptMismatch("receipt belongs to a different operation")
        state = receipt.get("state")
        if state == "intent":
            raise AmbiguousOperation("dispatch outcome is unknown; refusing replay")
        if state == "observed":
            return receipt, None
        if state != "dispatched" or not receipt.get("job_id"):
            raise ReceiptMismatch("receipt state is invalid")
    else:
        receipt = {**identity, "state": "intent"}
        _atomic_json(path, receipt)
        job_id = invoke()
        if not isinstance(job_id, str) or not job_id:
            raise RuntimeError("systemd returned no job receipt")
        receipt = {**identity, "job_id": job_id, "state": "dispatched"}
        _atomic_json(path, receipt)

    result = observe(receipt)
    receipt["state"] = "observed"
    receipt["observed_at_unix"] = int(time.time())
    _atomic_json(path, receipt)
    return receipt, result


def _proc_start_ticks(stat_text):
    close = stat_text.rfind(")")
    if close < 0:
        raise ProcessIdentityError("invalid proc stat record")
    fields = stat_text[close + 1:].split()
    if len(fields) <= 19:
        raise ProcessIdentityError("proc stat record lacks start time")
    return int(fields[19])


def read_linux_process_identity(pid):
    """Return a PID-reuse-resistant identity and SHA256 of the running image."""
    if not isinstance(pid, int) or pid <= 1:
        raise ValueError("pid must be greater than 1")
    stat_path = Path("/proc") / str(pid) / "stat"
    before = _proc_start_ticks(stat_path.read_text(encoding="utf-8"))
    digest = hashlib.sha256()
    with (Path("/proc") / str(pid) / "exe").open("rb") as image:
        for chunk in iter(lambda: image.read(1024 * 1024), b""):
            digest.update(chunk)
    after = _proc_start_ticks(stat_path.read_text(encoding="utf-8"))
    if before != after:
        raise ProcessLookupError(pid)
    return {"pid": pid, "start_ticks": before, "exe_sha256": digest.hexdigest()}


def wait_for_main_process(read_unit, read_identity, expected_sha256,
                          timeout_seconds=30, poll_interval=0.1, stable_samples=2):
    """Wait for one active, stable MainPID whose live executable matches SHA256."""
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256 or ""):
        raise ValueError("expected_sha256 must be lowercase SHA256")
    deadline = time.monotonic() + timeout_seconds
    prior = None
    stable = 0
    while time.monotonic() < deadline:
        state = read_unit()
        pid = state.get("main_pid", 0)
        if state.get("active_state") == "active" and isinstance(pid, int) and pid > 1:
            try:
                identity = read_identity(pid)
            except (ProcessLookupError, FileNotFoundError):
                prior, stable = None, 0
            else:
                if identity.get("exe_sha256") != expected_sha256:
                    raise ProcessIdentityError("active process executable SHA256 mismatch")
                key = (identity.get("pid"), identity.get("start_ticks"),
                       identity.get("exe_sha256"))
                if key == prior:
                    stable += 1
                else:
                    prior, stable = key, 1
                if stable >= stable_samples:
                    return identity
        else:
            prior, stable = None, 0
        time.sleep(poll_interval)
    raise TimeoutError("no stable active MainPID with the expected executable")