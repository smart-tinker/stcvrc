#!/usr/bin/env python3
"""Observe systemd restart-counter behavior on owned transient units only."""
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path


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
        payload = {
            "command": command[:500],
            "exit_code": result.returncode,
            "stdout": stdout[:500],
            "stderr": stderr[:500],
        }
        raise Blocked(json.dumps(payload, sort_keys=True))
    return result


def snapshot(unit, phase):
    result = run(["sudo", "-n", "systemctl", "show", unit,
                  "--property=ActiveState,MainPID,NRestarts,InvocationID",
                  "--no-pager"])
    fields = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    return {
        "phase": phase,
        "active_state": fields.get("ActiveState", ""),
        "main_pid": int(fields.get("MainPID", "0") or "0"),
        "n_restarts": int(fields.get("NRestarts", "0") or "0"),
        "invocation_id": fields.get("InvocationID", ""),
    }


def wait_active(unit, marker):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            current = snapshot(unit, "wait")
            if current["active_state"] == "active" and current["main_pid"] > 1 and marker.exists():
                return current
        except Blocked:
            pass
        time.sleep(0.1)
    raise Blocked("transient retry service did not reach active state")


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
    for command in ("systemctl", "systemd-run", "busctl", "nsenter", "ip", "curl"):
        if shutil.which(command) is None:
            raise Blocked("runner is missing required command: " + command)
    run(["sudo", "-n", "true"])
    run(["systemd-run", "--version"])
    run(["busctl", "--version"])
    return version


def main():
    root = Path(sys.argv[1]).resolve()
    report = {"status": "BLOCKED", "scope": "transient-systemd-restart-counter-observation"}
    unit = "stcvrc-ci-counter-" + re.sub(r"[^a-z0-9-]", "", os.getenv("GITHUB_RUN_ID", "local"))[-20:] + ".service"
    marker = root / "restart-once.marker"
    try:
        report["systemd_version"] = require_systemd()
        script = 'if [ ! -e "$1" ]; then : > "$1"; exit 73; fi; exec sleep 45'
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
        after_auto = wait_active(unit, marker)
        observations = [snapshot(unit, "after_auto_retry")]
        observations.append({"phase": "RestartUnit_job",
                             "job_path": dbus_job(unit, "RestartUnit")})
        observations.append(snapshot(unit, "after_manual_restart"))
        run(["sudo", "-n", "systemctl", "stop", unit])
        observations.append(snapshot(unit, "after_stop"))
        run(["sudo", "-n", "systemctl", "reset-failed", unit], check=False)
        observations.append({"phase": "StartUnit_job",
                             "job_path": dbus_job(unit, "StartUnit")})
        observations.append(snapshot(unit, "after_manual_start"))
        report.update({
            "status": "PASS",
            "auto_retry_main_pid": after_auto["main_pid"],
            "observations": observations,
            "counter_semantics": "observed-values-only; no monotonicity rule assumed",
        })
        print(json.dumps(report, sort_keys=True))
        return 0
    except Blocked as error:
        report["blocked_reason"] = str(error)
        print(json.dumps(report, sort_keys=True))
        return 2
    finally:
        run(["sudo", "-n", "systemctl", "stop", unit], check=False)
        run(["sudo", "-n", "systemctl", "reset-failed", unit], check=False)


if __name__ == "__main__":
    raise SystemExit(main())
