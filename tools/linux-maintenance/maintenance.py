"""Small, generic Linux service-maintenance primitives.

This first revision intentionally mirrors the old observer ordering so the
contract tests can prove the lost-receipt and PID-race failures before fixes.
"""
import json
import os
import tempfile
import time
from pathlib import Path


def _atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".receipt-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def restart_once(receipt_path, operation_id, unit, method, invoke, observe):
    """Issue a unit job and return its observed result."""
    job_id = invoke()
    result = observe({"job_id": job_id})
    receipt = {
        "operation_id": operation_id,
        "unit": unit,
        "method": method,
        "job_id": job_id,
        "state": "observed",
    }
    _atomic_json(receipt_path, receipt)
    return receipt, result


def wait_for_main_process(read_unit, read_identity, expected_sha256=None,
                          timeout_seconds=1.0, poll_interval=0.01,
                          stable_samples=2):
    """Read the unit's main process identity (race handling is added after RED)."""
    state = read_unit()
    pid = int(state.get("main_pid", 0))
    if pid <= 1:
        raise RuntimeError("unit has no main process")
    return read_identity(pid)
