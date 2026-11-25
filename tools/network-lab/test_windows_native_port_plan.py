import errno
import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
PORT_PLAN_SCRIPT = HERE / "windows_native_port_plan.ps1"


class NativeUdpPortPlanCollisionTest(unittest.TestCase):
    def test_fixture_retries_and_persists_an_actually_bound_endpoint(self):
        if sys.platform != "win32":
            self.fail("This regression requires the standard Windows runner.")

        with tempfile.TemporaryDirectory(prefix="stcvrc-port-plan-") as root:
            plan_path = Path(root) / "native-ports.json"
            env = os.environ.copy()
            env["STCVRC_PORT_PLAN_SCRIPT"] = str(PORT_PLAN_SCRIPT)
            env["STCVRC_PORT_PLAN_PATH"] = str(plan_path)
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
            self.assertEqual(setup.returncode, 0, f"PowerShell port-plan setup failed (exit={setup.returncode}).")
            plan = json.loads(plan_path.read_text(encoding="utf-8"))
            requested_port = int(plan["profileDnsPort"])

            blocker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            blocker.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            blocker.bind(("127.0.0.1", requested_port))
            try:
                fixture = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                fixture.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                try:
                    fixture.bind(("127.0.0.1", requested_port))
                except OSError as error:
                    fixture.close()
                    if error.errno != errno.EADDRINUSE:
                        raise
                    self.fail(
                        "The native fixture could not bind the occupied profile DNS endpoint; "
                        "the persisted plan was not safely retried."
                    )
                actual_port = int(fixture.getsockname()[1])
                self.assertEqual(actual_port, requested_port)
                self.assertEqual(int(json.loads(plan_path.read_text(encoding="utf-8"))["profileDnsPort"]), actual_port)
                fixture.close()
            finally:
                blocker.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
