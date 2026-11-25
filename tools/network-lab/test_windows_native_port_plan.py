import errno
import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from windows_native_udp_ports import bind_dns_fixture_sockets


HERE = Path(__file__).resolve().parent
PORT_PLAN_SCRIPT = HERE / "windows_native_port_plan.ps1"
PLAN_FIELDS = ("coreDnsPort", "profileDnsPort", "appDnsPort", "subscriptionDnsPort")


def create_plan(path):
    env = os.environ.copy()
    env["STCVRC_PORT_PLAN_SCRIPT"] = str(PORT_PLAN_SCRIPT)
    env["STCVRC_PORT_PLAN_PATH"] = str(path)
    powershell = Path(os.environ["SystemRoot"]) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    command = (
        "$ErrorActionPreference='Stop'; "
        ". $env:STCVRC_PORT_PLAN_SCRIPT; "
        "Get-StcvrcNativePortPlan -Path $env:STCVRC_PORT_PLAN_PATH | Out-Null"
    )
    setup = subprocess.run(
        [str(powershell), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    if setup.returncode != 0:
        raise AssertionError(f"PowerShell port-plan setup failed (exit={setup.returncode}).")


class NativeUdpPortPlanCollisionTest(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "win32", "Requires the standard Windows runner.")
    def test_fixture_retries_and_persists_an_actually_bound_endpoint(self):
        with tempfile.TemporaryDirectory(prefix="stcvrc-port-plan-") as root:
            blocker = None
            plan_path = None
            plan = None
            requested_port = None
            for attempt in range(8):
                candidate_path = Path(root) / f"native-ports-{attempt}.json"
                create_plan(candidate_path)
                candidate_plan = json.loads(candidate_path.read_text(encoding="utf-8"))
                candidate_blocker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                candidate_blocker.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                try:
                    candidate_blocker.bind(("127.0.0.1", int(candidate_plan["profileDnsPort"])))
                except OSError as error:
                    candidate_blocker.close()
                    if error.errno != errno.EADDRINUSE:
                        raise
                    continue
                blocker = candidate_blocker
                plan_path = candidate_path
                plan = candidate_plan
                requested_port = int(candidate_plan["profileDnsPort"])
                break

            self.assertIsNotNone(blocker, "Could not claim a synthetic planned UDP endpoint.")
            sockets = {}
            probe = None
            try:
                sockets, collisions = bind_dns_fixture_sockets(plan_path)
                self.assertEqual(collisions, ("profileDnsPort",))
                persisted = json.loads(plan_path.read_text(encoding="utf-8"))
                actual = {}
                for name, fixture_socket in sockets.items():
                    actual[name] = int(fixture_socket.getsockname()[1])
                    self.assertEqual(int(persisted[name]), actual[name], f"{name} did not match its bound socket.")
                self.assertNotEqual(actual["profileDnsPort"], requested_port)
                all_ports = [int(persisted[name]) for name in PLAN_FIELDS]
                self.assertEqual(len(set(all_ports)), len(PLAN_FIELDS))
                self.assertTrue(all(0 < port <= 65535 for port in all_ports))

                probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                probe.settimeout(2)
                probe.sendto(b"udp-bind-collision", ("127.0.0.1", actual["profileDnsPort"]))
                payload, _ = sockets["profileDnsPort"].recvfrom(64)
                self.assertEqual(payload, b"udp-bind-collision")
            finally:
                if probe is not None:
                    probe.close()
                for fixture_socket in sockets.values():
                    fixture_socket.close()
                if blocker is not None:
                    blocker.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
