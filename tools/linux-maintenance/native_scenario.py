"""Native isolated Xray replacement and recovery through transient systemd units."""
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

from counter import classify_restart_transition
from maintenance import (
    ProcessIdentityError,
    restart_once,
    wait_for_main_process,
)


class Blocked(RuntimeError):
    pass


def safe_text(value):
    temp = os.getenv("RUNNER_TEMP", "")
    return str(value).replace(temp, "<RUNNER_TEMP>") if temp else str(value)


def run(args, check=True, timeout=15):
    try:
        result = subprocess.run(args, text=True, capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise Blocked(type(error).__name__ + ": " + safe_text(error)) from error
    if check and result.returncode:
        temp = os.getenv("RUNNER_TEMP", "")
        command = " ".join(args).replace(temp, "<RUNNER_TEMP>") if temp else " ".join(args)
        stdout = result.stdout.strip().replace(temp, "<RUNNER_TEMP>") if temp else result.stdout.strip()
        stderr = result.stderr.strip().replace(temp, "<RUNNER_TEMP>") if temp else result.stderr.strip()
        raise Blocked(json.dumps({
            "command": command[:500],
            "exit_code": result.returncode,
            "stdout": stdout[:500],
            "stderr": stderr[:500],
        }, sort_keys=True))
    return result


def port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def checksum(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def namespace_inode(pid):
    result = run([
        "sudo", "-n", "stat", "-L", "-c", "%i",
        "/proc/" + str(pid) + "/ns/net",
    ])
    try:
        return int(result.stdout.strip())
    except ValueError as error:
        raise Blocked("could not parse network namespace inode") from error


def xray_version(binary, expected):
    result = run([str(binary), "version"])
    output = (result.stdout + result.stderr).strip()
    if expected not in output:
        raise Blocked("Xray version output did not match the pinned release")
    return output.splitlines()[0][:240]


def atomic_symlink(target, link):
    link = Path(link)
    temporary = link.with_name("." + link.name + ".next")
    try:
        temporary.unlink()
    except FileNotFoundError:
        pass
    temporary.symlink_to(Path(target))
    os.replace(temporary, link)


def write_config(path, proxy_port):
    value = {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": proxy_port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False},
        }],
        "outbounds": [{"protocol": "freedom", "settings": {}}],
    }
    temporary = Path(str(path) + ".next")
    temporary.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def read_unit(unit):
    result = run([
        "sudo", "-n", "systemctl", "show", unit,
        "--property=ActiveState,MainPID,NRestarts,InvocationID,ExecMainStatus,User,Group",
        "--no-pager",
    ])
    fields = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    return {
        "unit": unit,
        "active_state": fields.get("ActiveState", ""),
        "main_pid": int(fields.get("MainPID", "0") or "0"),
        "n_restarts": int(fields.get("NRestarts", "0") or "0"),
        "invocation_id": fields.get("InvocationID", ""),
        "exec_main_status": int(fields.get("ExecMainStatus", "0") or "0"),
        "systemd_user": fields.get("User", ""),
        "systemd_group": fields.get("Group", ""),
    }


def read_process_identity_as_root(pid):
    """Use runner sudo only to read /proc identity for the owned MainPID."""
    if not isinstance(pid, int) or pid <= 1:
        raise ValueError("pid must be greater than 1")
    module_dir = str(Path(__file__).resolve().parent)
    code = (
        "import json,sys; from maintenance import read_linux_process_identity; "
        "print(json.dumps(read_linux_process_identity(int(sys.argv[1])), sort_keys=True))"
    )
    result = run([
        "sudo", "-n", "env", "PYTHONPATH=" + module_dir,
        sys.executable, "-B", "-c", code, str(pid),
    ], timeout=10)
    try:
        identity = json.loads(result.stdout)
    except (TypeError, json.JSONDecodeError) as error:
        raise ProcessIdentityError("privileged proc identity reader returned invalid JSON") from error
    required = {"pid", "start_ticks", "exe_sha256", "uid", "gid", "exe_path"}
    if not isinstance(identity, dict) or not required.issubset(identity):
        raise ProcessIdentityError("privileged proc identity is incomplete")
    return identity


def wait_state(unit, predicate, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = read_unit(unit)
        if predicate(state):
            return state
        time.sleep(0.1)
    raise TimeoutError("transient service did not reach expected state")


def observe_process(unit, expected_binary, expected_sha,
                    previous_invocation=None, timeout=12):
    expected_uid = os.getuid()
    expected_gid = os.getgid()
    expected_exe = os.path.realpath(str(expected_binary))

    def fresh_state():
        state = read_unit(unit)
        if previous_invocation and state["invocation_id"] == previous_invocation:
            return {**state, "active_state": "activating", "main_pid": 0}
        return state

    def read_stable_owned_process(pid):
        before = read_unit(unit)
        if before["active_state"] != "active" or before["main_pid"] != pid:
            raise ProcessLookupError(pid)
        identity = read_process_identity_as_root(pid)
        after = read_unit(unit)
        if (after["active_state"] != "active" or after["main_pid"] != pid
                or after["invocation_id"] != before["invocation_id"]):
            raise ProcessLookupError(pid)
        actual_exe = identity["exe_path"]
        if actual_exe.endswith(" (deleted)"):
            actual_exe = actual_exe[:-10]
        actual_exe = os.path.realpath(actual_exe)
        diagnostic = {
            "unit": unit,
            "active_state": after["active_state"],
            "main_pid": after["main_pid"],
            "systemd_user": after["systemd_user"],
            "systemd_group": after["systemd_group"],
            "invocation_id": after["invocation_id"],
            "n_restarts": after["n_restarts"],
            "exec_main_status": after["exec_main_status"],
            "proc_uid": identity["uid"],
            "proc_gid": identity["gid"],
            "start_ticks": identity["start_ticks"],
            "exe_name": Path(actual_exe).name,
            "exe_sha256": identity["exe_sha256"],
            "expected_uid": expected_uid,
            "expected_gid": expected_gid,
            "expected_exe_name": Path(expected_exe).name,
            "expected_exe_sha256": expected_sha,
        }
        if identity["uid"] != expected_uid or identity["gid"] != expected_gid:
            raise ProcessIdentityError(
                "MainPID credentials did not match the runner: "
                + json.dumps(diagnostic, sort_keys=True)
            )
        if actual_exe != expected_exe or identity["exe_sha256"] != expected_sha:
            raise ProcessIdentityError(
                "MainPID was not the exact expected Xray executable: "
                + json.dumps(diagnostic, sort_keys=True)
            )
        identity["invocation_id"] = after["invocation_id"]
        return identity

    identity = wait_for_main_process(
        fresh_state,
        read_stable_owned_process,
        expected_sha256=expected_sha,
        timeout_seconds=timeout,
        poll_interval=0.1,
        stable_samples=3,
    )
    state = read_unit(unit)
    if (state["main_pid"] != identity["pid"]
            or state["invocation_id"] != identity["invocation_id"]):
        raise ProcessIdentityError(
            "systemd MainPID or InvocationID changed after identity verification"
        )
    if previous_invocation and state["invocation_id"] == previous_invocation:
        raise RuntimeError("systemd invocation did not change")
    return {**state, **identity}


def dbus_job(unit, method):
    result = run([
        "sudo", "-n", "busctl", "call", "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager",
        method, "ss", unit, "replace",
    ])
    match = re.search(r'\bo\s+"([^"]+)"', result.stdout)
    if not match:
        raise Blocked("systemd returned no DBus job path")
    return match.group(1)


def request(unit, method):
    return lambda: dbus_job(unit, method)


def wait_http(anchor_pid, proxy_port, health_port):
    deadline = time.monotonic() + 12
    last = ""
    while time.monotonic() < deadline:
        result = run([
            "sudo", "-n", "nsenter", "-t", str(anchor_pid), "-n", "--",
            "curl", "--fail", "--silent", "--show-error", "--max-time", "3",
            "--socks5-hostname", "127.0.0.1:" + str(proxy_port),
            "http://127.0.0.1:" + str(health_port) + "/health",
        ], check=False, timeout=5)
        if result.returncode == 0 and result.stdout.strip() == "stcvrc-maintenance-ok":
            return
        last = (result.stderr or result.stdout).strip()[:180]
        time.sleep(0.2)
    raise RuntimeError("loopback HTTP through Xray failed: " + last)


def main():
    if len(sys.argv) != 5:
        raise SystemExit(
            "usage: native_scenario.py ROOT XRAY_BASELINE XRAY_CANDIDATE COUNTER_PROFILE"
        )
    root = Path(sys.argv[1]).resolve()
    baseline = Path(sys.argv[2]).resolve()
    candidate = Path(sys.argv[3]).resolve()
    profile_path = Path(sys.argv[4]).resolve()
    report = {
        "status": "BLOCKED",
        "scope": "owned-temp-xray-binary-replacement-and-recovery",
        "versions": {},
        "transitions": [],
        "cleanup_errors": [],
    }
    run_id = re.sub(r"[^a-z0-9-]", "", os.getenv("GITHUB_RUN_ID", "local").lower())
    attempt = re.sub(r"[^a-z0-9-]", "", os.getenv("GITHUB_RUN_ATTEMPT", "1").lower())
    suffix = (run_id + "-" + attempt)[-28:]
    core_unit = "stcvrc-ci-core-" + suffix + ".service"
    health_unit = "stcvrc-ci-health-" + suffix + ".service"
    anchor_launcher = None
    anchor_pid = None
    touched_units = set()
    try:
        for command in ("sudo", "unshare", "nsenter", "ip", "curl", "systemd-run", "systemctl", "busctl"):
            if shutil.which(command) is None:
                raise Blocked("runner is missing required command: " + command)
        if Path("/proc/1/comm").read_text(encoding="utf-8").strip() != "systemd":
            raise Blocked("runner PID 1 is not systemd")
        run(["sudo", "-n", "true"])
        baseline_sha = checksum(baseline)
        candidate_sha = checksum(candidate)
        if baseline_sha == candidate_sha:
            raise RuntimeError("pinned Xray baseline and candidate binaries are identical")
        counter_profile = json.loads(profile_path.read_text(encoding="utf-8"))
        if counter_profile.get("status") != "PASS":
            raise Blocked("native systemd counter profile is not PASS")
        if counter_profile.get("manual_restart_counter_resets") is not True:
            raise Blocked("native systemd probe did not confirm the manual-restart counter reset")
        report["systemd_version"] = counter_profile.get("systemd_version")
        report["versions"] = {
            "baseline": xray_version(baseline, "26.10.21"),
            "baseline_executable_sha256": baseline_sha,
            "candidate": xray_version(candidate, "26.10.31"),
            "candidate_executable_sha256": candidate_sha,
        }

        pid_file = root / "netns-anchor.pid"
        anchor_launcher = subprocess.Popen([
            "sudo", "-n", "unshare", "--net", "--fork", "--",
            "/bin/sh", "-c",
            'printf "%s\\n" "$$" > "$1"; exec /bin/sleep 600',
            "sh", str(pid_file),
        ], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not pid_file.exists():
            if anchor_launcher.poll() is not None:
                stdout, stderr = anchor_launcher.communicate(timeout=1)
                raise Blocked(json.dumps({
                    "command": "sudo -n unshare --net --fork ...",
                    "exit_code": anchor_launcher.returncode,
                    "stdout": safe_text(stdout.strip())[:300],
                    "stderr": safe_text(stderr.strip())[:300],
                }, sort_keys=True))
            time.sleep(0.05)
        if not pid_file.exists():
            raise Blocked("network namespace anchor did not publish a PID")
        anchor_pid = int(pid_file.read_text(encoding="utf-8").strip())
        host_netns = os.stat("/proc/self/ns/net").st_ino
        isolated_netns = namespace_inode(anchor_pid)
        if isolated_netns == host_netns:
            raise Blocked("unshare did not create a distinct network namespace")
        run(["sudo", "-n", "nsenter", "-t", str(anchor_pid), "-n", "--",
             "ip", "link", "set", "lo", "up"])
        default_v4 = run(["sudo", "-n", "nsenter", "-t", str(anchor_pid), "-n", "--",
                          "ip", "-4", "route", "show", "default"]).stdout.strip()
        default_v6 = run(["sudo", "-n", "nsenter", "-t", str(anchor_pid), "-n", "--",
                          "ip", "-6", "route", "show", "default"]).stdout.strip()
        if default_v4 or default_v6:
            raise RuntimeError("test network namespace unexpectedly has a default route")
        report["network_isolation"] = {
            "distinct_netns": True, "ipv4_default_route": default_v4,
            "ipv6_default_route": default_v6, "only_loopback_enabled": True,
        }

        health_port = port()
        proxy_port = port()
        while proxy_port == health_port:
            proxy_port = port()
        server = root / "health_server.py"
        server.write_text(
            "from http.server import BaseHTTPRequestHandler, HTTPServer\n"
            "class Handler(BaseHTTPRequestHandler):\n"
            "    def do_GET(self):\n"
            "        body = b'stcvrc-maintenance-ok\\n'\n"
            "        self.send_response(200)\n"
            "        self.send_header('Content-Length', str(len(body)))\n"
            "        self.end_headers()\n"
            "        self.wfile.write(body)\n"
            "    def log_message(self, *_args):\n"
            "        pass\n"
            "HTTPServer(('127.0.0.1', int(__import__('sys').argv[1])), Handler).serve_forever()\n",
            encoding="utf-8",
        )
        wrapper = root / "exec-current.sh"
        wrapper.write_text("#!/bin/sh\nexec \"$@\"\n", encoding="utf-8")
        wrapper.chmod(0o700)
        touched_units.add(health_unit)
        run([
            "sudo", "-n", "systemd-run", "--quiet", "--no-block",
            "--unit=" + health_unit,
            "--property=Type=simple", "--property=Restart=no",
            "--property=User=" + str(os.getuid()),
            "--property=Group=" + str(os.getgid()),
            "--property=NetworkNamespacePath=/proc/" + str(anchor_pid) + "/ns/net",
            sys.executable, str(server), str(health_port),
        ])
        wait_state(health_unit, lambda state: state["active_state"] == "active" and state["main_pid"] > 1)

        current_dir = root / "current"
        current_dir.mkdir(mode=0o700)
        current_binary = current_dir / "xray"
        current_config = current_dir / "config.json"
        valid_config = root / "valid-config.json"
        write_config(valid_config, proxy_port)
        atomic_symlink(baseline, current_binary)
        atomic_symlink(valid_config, current_config)

        def start_core():
            touched_units.add(core_unit)
            run([
                "sudo", "-n", "systemd-run", "--quiet", "--no-block",
                "--unit=" + core_unit,
                "--property=Type=simple", "--property=Restart=no",
                "--property=User=" + str(os.getuid()),
                "--property=Group=" + str(os.getgid()),
                "--property=NetworkNamespacePath=/proc/" + str(anchor_pid) + "/ns/net",
                "/bin/sh", str(wrapper), str(current_binary), "run", "-c", str(current_config),
            ])

        start_core()
        baseline_process = observe_process(core_unit, baseline, baseline_sha)
        if namespace_inode(baseline_process["pid"]) != isolated_netns:
            raise RuntimeError("baseline Xray process escaped its test network namespace")
        wait_http(anchor_pid, proxy_port, health_port)
        report["transitions"].append({
            "phase": "baseline-active",
            "version": report["versions"]["baseline"],
            "pid": baseline_process["pid"],
            "process_uid": baseline_process["uid"],
            "process_gid": baseline_process["gid"],
            "unit_user": baseline_process["systemd_user"],
            "unit_group": baseline_process["systemd_group"],
            "start_ticks": baseline_process["start_ticks"],
            "invocation_id": baseline_process["invocation_id"],
            "exe_name": Path(baseline_process["exe_path"]).name,
            "exe_sha256": baseline_sha,
            "loopback_http": "PASS",
        })

        atomic_symlink(candidate, current_binary)
        previous = read_unit(core_unit)
        receipt_path = root / "receipts" / "baseline-to-candidate.json"
        receipt, process = restart_once(
            receipt_path, "baseline-to-candidate", core_unit, "RestartUnit",
            request(core_unit, "RestartUnit"),
            lambda value: observe_process(core_unit, candidate, candidate_sha, previous["invocation_id"]),
        )
        restart_attribution = classify_restart_transition(
            previous, process, receipt, manual_restart_resets_counter=True
        )
        if restart_attribution != "requested-restart-counter-reset":
            raise RuntimeError("candidate restart had an unexpected attribution: " + restart_attribution)
        if process["start_ticks"] == baseline_process["start_ticks"] and process["pid"] == baseline_process["pid"]:
            raise RuntimeError("candidate did not replace the baseline process")
        if namespace_inode(process["pid"]) != isolated_netns:
            raise RuntimeError("candidate Xray process escaped its test network namespace")
        wait_http(anchor_pid, proxy_port, health_port)
        after_candidate_health = read_unit(core_unit)
        post_health_attribution = classify_restart_transition(
            process, after_candidate_health, receipt,
            manual_restart_resets_counter=True,
        )
        if post_health_attribution != "unchanged":
            raise RuntimeError("candidate auto-restarted during health check: " + post_health_attribution)
        report["transitions"].append({
            "phase": "candidate-active",
            "version": report["versions"]["candidate"],
            "pid": process["pid"],
            "process_uid": process["uid"],
            "process_gid": process["gid"],
            "unit_user": process["systemd_user"],
            "unit_group": process["systemd_group"],
            "start_ticks": process["start_ticks"],
            "invocation_id": process["invocation_id"],
            "exe_name": Path(process["exe_path"]).name,
            "exe_sha256": candidate_sha,
            "receipt_state": receipt["state"],
            "restart_attribution": restart_attribution,
            "post_health_attribution": post_health_attribution,
            "loopback_http": "PASS",
        })

        bad_config = root / "invalid-candidate-config.json"
        bad_config.write_text("{ invalid-json\n", encoding="utf-8")
        atomic_symlink(bad_config, current_config)
        previous_candidate = read_unit(core_unit)
        failed_receipt_path = root / "receipts" / "invalid-candidate.json"
        try:
            restart_once(
                failed_receipt_path, "invalid-candidate", core_unit, "RestartUnit",
                request(core_unit, "RestartUnit"),
                lambda _receipt: observe_process(
                    core_unit, candidate, candidate_sha, previous_candidate["invocation_id"], timeout=8
                ),
            )
            raise RuntimeError("invalid candidate unexpectedly started")
        except TimeoutError:
            failed_state = read_unit(core_unit)
            failed_receipt = json.loads(failed_receipt_path.read_text(encoding="utf-8"))
            if failed_state["active_state"] != "failed" or failed_state["exec_main_status"] == 0:
                raise RuntimeError("invalid config did not produce a failed Xray service")
            if failed_receipt.get("state") != "dispatched":
                raise RuntimeError("failed observation did not preserve the DBus receipt")
            report["transitions"].append({
                "phase": "invalid-candidate-rejected",
                "active_state": failed_state["active_state"],
                "exec_main_status": failed_state["exec_main_status"],
                "receipt_state": failed_receipt["state"],
                "redispatch": "not attempted",
            })

        atomic_symlink(baseline, current_binary)
        atomic_symlink(valid_config, current_config)
        previous_failed = read_unit(core_unit)
        rollback_path = root / "receipts" / "candidate-to-baseline.json"
        rollback_receipt, recovered = restart_once(
            rollback_path, "candidate-to-baseline", core_unit, "RestartUnit",
            request(core_unit, "RestartUnit"),
            lambda value: observe_process(
                core_unit, baseline, baseline_sha, previous_failed["invocation_id"]
            ),
        )
        rollback_attribution = classify_restart_transition(
            previous_failed, recovered, rollback_receipt,
            manual_restart_resets_counter=True,
        )
        if rollback_attribution != "requested-restart-counter-reset":
            raise RuntimeError(
                "baseline recovery had an unexpected attribution: " + rollback_attribution
            )
        if namespace_inode(recovered["pid"]) != isolated_netns:
            raise RuntimeError("recovered Xray process escaped its test network namespace")
        wait_http(anchor_pid, proxy_port, health_port)
        after_recovery_health = read_unit(core_unit)
        recovery_attribution = classify_restart_transition(recovered, after_recovery_health)
        if recovery_attribution != "unchanged":
            raise RuntimeError("baseline auto-restarted during health check: " + recovery_attribution)
        report["transitions"].append({
            "phase": "baseline-recovered",
            "version": report["versions"]["baseline"],
            "pid": recovered["pid"],
            "process_uid": recovered["uid"],
            "process_gid": recovered["gid"],
            "unit_user": recovered["systemd_user"],
            "unit_group": recovered["systemd_group"],
            "start_ticks": recovered["start_ticks"],
            "invocation_id": recovered["invocation_id"],
            "exe_name": Path(recovered["exe_path"]).name,
            "exe_sha256": baseline_sha,
            "receipt_state": rollback_receipt["state"],
            "restart_attribution": rollback_attribution,
            "post_health_attribution": recovery_attribution,
            "loopback_http": "PASS",
        })
        report["status"] = "PASS"
    except Blocked as error:
        report["status"] = "BLOCKED"
        report["reason"] = str(error)[:1200]
    except Exception as error:
        report["status"] = "FAIL"
        report["reason"] = (type(error).__name__ + ": " + safe_text(error))[:1200]
    finally:
        def cleanup_command(args):
            try:
                return subprocess.run(args, text=True, capture_output=True, timeout=10)
            except (OSError, subprocess.TimeoutExpired):
                return None

        def cleanup_snapshot(unit):
            result = cleanup_command([
                "sudo", "-n", "systemctl", "show", unit,
                "--property=LoadState,ActiveState,MainPID,NRestarts,InvocationID,ExecMainStatus,User,Group",
                "--no-pager",
            ])
            if result is None or result.returncode != 0:
                return result, None
            values = dict(
                line.split("=", 1) for line in result.stdout.splitlines() if "=" in line
            )
            try:
                state = {
                    "unit": unit,
                    "load_state": values.get("LoadState", ""),
                    "active_state": values.get("ActiveState", ""),
                    "main_pid": int(values.get("MainPID", "0") or "0"),
                    "n_restarts": int(values.get("NRestarts", "0") or "0"),
                    "invocation_id": values.get("InvocationID", ""),
                    "exec_main_status": int(values.get("ExecMainStatus", "0") or "0"),
                    "systemd_user": values.get("User", ""),
                    "systemd_group": values.get("Group", ""),
                }
            except ValueError:
                return result, None
            return result, state

        def cleanup_error(unit, step, result, state=None):
            report["cleanup_errors"].append({
                "unit": unit,
                "step": step,
                "exit_code": None if result is None else result.returncode,
                "stdout": "" if result is None else safe_text(result.stdout.strip())[:240],
                "stderr": "" if result is None else safe_text(result.stderr.strip())[:240],
                "unit_state": state,
            })

        if shutil.which("sudo") and shutil.which("systemctl"):
            for unit in sorted(touched_units):
                loaded_result, initial = cleanup_snapshot(unit)
                if loaded_result is None or loaded_result.returncode != 0 or initial is None:
                    cleanup_error(unit, "query-before-stop", loaded_result)
                    continue
                if initial["load_state"] == "not-found":
                    continue

                if initial["active_state"] in {
                    "active", "activating", "deactivating", "reloading",
                } or initial["main_pid"] > 1:
                    stop = cleanup_command(["sudo", "-n", "systemctl", "stop", unit])
                    if stop is None or stop.returncode != 0:
                        cleanup_error(unit, "stop", stop, initial)

                post_stop_result, post_stop = cleanup_snapshot(unit)
                if post_stop_result is None or post_stop_result.returncode != 0 or post_stop is None:
                    cleanup_error(unit, "query-after-stop", post_stop_result)
                    continue

                if post_stop["active_state"] in {
                    "active", "activating", "deactivating", "reloading",
                } or post_stop["main_pid"] > 1:
                    kill = cleanup_command([
                        "sudo", "-n", "systemctl", "kill", "--kill-who=all",
                        "--signal=KILL", unit,
                    ])
                    if kill is None or kill.returncode != 0:
                        cleanup_error(unit, "kill-owned-unit", kill, post_stop)
                    stop = cleanup_command(["sudo", "-n", "systemctl", "stop", unit])
                    if stop is None or stop.returncode != 0:
                        cleanup_error(unit, "stop-after-kill", stop, post_stop)
                    post_stop_result, post_stop = cleanup_snapshot(unit)
                    if post_stop_result is None or post_stop_result.returncode != 0 or post_stop is None:
                        cleanup_error(unit, "query-after-kill", post_stop_result)
                        continue

                if post_stop["active_state"] == "failed":
                    reset = cleanup_command([
                        "sudo", "-n", "systemctl", "reset-failed", unit,
                    ])
                    if reset is None or reset.returncode != 0:
                        cleanup_error(unit, "reset-failed", reset, post_stop)
                    final_result, final_state = cleanup_snapshot(unit)
                else:
                    final_result, final_state = post_stop_result, post_stop

                if final_result is None or final_result.returncode != 0 or final_state is None:
                    cleanup_error(unit, "query-final", final_result)
                elif (final_state["load_state"] != "not-found"
                        and (final_state["active_state"] != "inactive"
                             or final_state["main_pid"] > 1)):
                    cleanup_error(unit, "verify-inactive", final_result, final_state)
        elif touched_units:
            report["cleanup_errors"].append({
                "step": "preflight",
                "error": "sudo/systemctl unavailable for owned-unit cleanup",
            })

        if anchor_pid is not None:
            if not shutil.which("sudo"):
                report["cleanup_errors"].append("sudo unavailable for network namespace cleanup")
            else:
                cleanup_command(["sudo", "-n", "kill", "-TERM", str(anchor_pid)])
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline and Path("/proc/" + str(anchor_pid)).exists():
                    time.sleep(0.1)
                if Path("/proc/" + str(anchor_pid)).exists():
                    killed = cleanup_command(["sudo", "-n", "kill", "-KILL", str(anchor_pid)])
                    if killed is None or killed.returncode not in (0, 1):
                        report["cleanup_errors"].append("network namespace anchor kill failed")

        if anchor_launcher is not None:
            try:
                anchor_launcher.wait(timeout=3)
            except subprocess.TimeoutExpired:
                anchor_launcher.kill()
                try:
                    anchor_launcher.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    report["cleanup_errors"].append("unshare launcher did not terminate")
        if anchor_pid is not None and Path("/proc/" + str(anchor_pid)).exists():
            report["cleanup_errors"].append("network namespace anchor remains after cleanup")
        if report["cleanup_errors"] and report["status"] == "PASS":
            report["status"] = "FAIL"
            report["reason"] = "owned-resource cleanup was incomplete"
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "PASS" else (2 if report["status"] == "BLOCKED" else 1)


if __name__ == "__main__":
    raise SystemExit(main())