"""Observe Ubuntu systemd restart-counter semantics on owned transient units."""
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

from counter import UnknownRestartTransition, classify_restart_transition


class Blocked(RuntimeError):
    pass


def run(args, check=True):
    result = subprocess.run(args, text=True, capture_output=True)
    if check and result.returncode:
        command = " ".join(args)
        runner_temp = os.getenv("RUNNER_TEMP", "")
        if runner_temp:
            command = command.replace(runner_temp, "<RUNNER_TEMP>")
        stdout = result.stdout.strip().replace(runner_temp, "<RUNNER_TEMP>") if runner_temp else result.stdout.strip()
        stderr = result.stderr.strip().replace(runner_temp, "<RUNNER_TEMP>") if runner_temp else result.stderr.strip()
        raise Blocked(json.dumps({
            "command": command[:500], "exit_code": result.returncode,
            "stdout": stdout[:500], "stderr": stderr[:500],
        }, sort_keys=True))
    return result


def snapshot(unit, phase):
    result = run(["sudo", "-n", "systemctl", "show", unit,
                  "--property=ActiveState,MainPID,NRestarts,InvocationID",
                  "--no-pager"])
    fields = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    return {
        "unit": unit,
        "phase": phase,
        "active_state": fields.get("ActiveState", ""),
        "main_pid": int(fields.get("MainPID", "0") or "0"),
        "n_restarts": int(fields.get("NRestarts", "0") or "0"),
        "invocation_id": fields.get("InvocationID", ""),
    }


def wait_snapshot(unit, predicate, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        current = snapshot(unit, "wait")
        if predicate(current):
            return current
        time.sleep(0.1)
    raise Blocked("transient unit did not reach the expected state")


def dbus_job(unit, method):
    result = run([
        "sudo", "-n", "busctl", "call", "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager",
        method, "ss", unit, "replace",
    ])
    match = re.search(r'\bo\s+"([^"]+)"', result.stdout)
    if not match:
        raise Blocked("systemd did not return a DBus job path")
    return match.group(1)


def require_systemd():
    if Path("/proc/1/comm").read_text(encoding="utf-8").strip() != "systemd":
        raise Blocked("runner PID 1 is not systemd")
    version = run(["systemctl", "--version"]).stdout.splitlines()[0]
    if not version.startswith("systemd "):
        raise Blocked("systemd version could not be identified")
    for command in ("sudo", "systemctl", "systemd-run", "busctl"):
        if shutil.which(command) is None:
            raise Blocked("runner is missing required command: " + command)
    run(["sudo", "-n", "true"])
    return version


def start_transient(unit, script, marker):
    run([
        "sudo", "-n", "systemd-run", "--quiet", "--no-block",
        "--unit=" + unit,
        "--property=Type=simple",
        "--property=Restart=on-failure",
        "--property=RestartSec=100ms",
        "--property=StartLimitIntervalSec=10s",
        "--property=StartLimitBurst=4",
        "/bin/sh", "-c", script, "sh", str(marker),
    ])


def main():
    root = Path(sys.argv[1]).resolve()
    report = {"status": "BLOCKED", "scope": "transient-systemd-restart-counter-observation"}
    unit = "stcvrc-ci-counter-" + re.sub(r"[^a-z0-9-]", "", os.getenv("GITHUB_RUN_ID", "local"))[-20:] + ".service"
    marker = root / "restart-once.marker"
    try:
        report["systemd_version"] = require_systemd()
        script = 'if [ ! -e "$1" ]; then : > "$1"; exit 73; fi; exec sleep 45'
        start_transient(unit, script, marker)
        before = wait_snapshot(unit, lambda x: x["active_state"] == "active" and x["main_pid"] > 1)
        auto_retry = wait_snapshot(
            unit, lambda x: x["n_restarts"] >= 1 and x["invocation_id"] != before["invocation_id"]
        )
        auto_retry["phase"] = "after_auto_retry"
        auto_classification = classify_restart_transition(before, auto_retry)
        job_path = dbus_job(unit, "RestartUnit")
        manual = wait_snapshot(
            unit,
            lambda x: x["active_state"] == "active" and x["main_pid"] > 1
            and x["invocation_id"] != auto_retry["invocation_id"],
        )
        manual["phase"] = "after_manual_restart"
        receipt = {"unit": unit, "method": "RestartUnit", "job_id": job_path,
                   "state": "dispatched"}
        manual_classification = classify_restart_transition(auto_retry, manual, receipt)
        run(["sudo", "-n", "systemctl", "stop", unit])
        stopped = snapshot(unit, "after_stop")
        run(["sudo", "-n", "systemctl", "reset-failed", unit], check=False)
        start_transient(unit, script, marker)
        recreated = wait_snapshot(unit, lambda x: x["active_state"] == "active" and x["main_pid"] > 1)
        recreated["phase"] = "after_manual_start"
        report.update({
            "status": "PASS",
            "observations": [before, auto_retry, {"phase": "RestartUnit_job", "job_path": job_path},
                             manual, stopped, recreated],
            "classifications": [auto_classification, manual_classification],
            "counter_rule": "requested counter reset requires a matching durable job receipt",
        })
        print(json.dumps(report, sort_keys=True))
        return 0
    except (Blocked, UnknownRestartTransition) as error:
        report["blocked_reason"] = str(error)
        print(json.dumps(report, sort_keys=True))
        return 2
    finally:
        if shutil.which("sudo") and shutil.which("systemctl"):
            run(["sudo", "-n", "systemctl", "stop", unit], check=False)
            run(["sudo", "-n", "systemctl", "reset-failed", unit], check=False)


if __name__ == "__main__":
    raise SystemExit(main())