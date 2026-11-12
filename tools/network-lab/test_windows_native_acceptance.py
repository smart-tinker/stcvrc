"""Contract checks for the native Windows acceptance harness.

The end-to-end behavior is exercised by windows-2022 in test.yml. These checks
keep the disposable-runner, route-scope, service identity, and DNS assertions
wired into that native job.
"""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
INSTALLER_SMOKE = ROOT / "tools" / "network-lab" / "windows_install_update.ps1"
NATIVE_SMOKE = ROOT / "tools" / "network-lab" / "windows_native_acceptance.ps1"


class NativeWindowsAcceptanceContract(unittest.TestCase):
    def test_update_smoke_invokes_native_acceptance(self):
        source = INSTALLER_SMOKE.read_text(encoding="utf-8")
        self.assertIn("windows_native_acceptance.ps1", source)

    def test_native_acceptance_checks_safety_and_real_runtime(self):
        source = NATIVE_SMOKE.read_text(encoding="utf-8")
        required = (
            "198.18.0.0/16",
            "Get-NetRoute",
            "get_runtime_state",
            "clash_verge_service",
            "Get-FileHash",
            "Invoke-DnsQuery",
            "native-fixture",
        )
        for assertion in required:
            with self.subTest(assertion=assertion):
                self.assertIn(assertion, source)

    def test_reject_requires_fast_classified_socket_result_and_live_controls(self):
        source = NATIVE_SMOKE.read_text(encoding="utf-8")
        reject = source.split("function Test-RejectedFixture", 1)[1].split("\n}", 1)[0]
        for assertion in (
            "ConnectAsync",
            "Wait(2000)",
            "catch [System.AggregateException]",
            "catch [System.Net.Sockets.SocketException]",
            "SocketErrorCode",
            "ConnectionRefused",
            "ConnectionReset",
            "ConnectionAborted",
            "NetworkReset",
            "Assert-SelectedProfileReady",
            "Get-NetRoute",
            "Compare-Object",
        ):
            with self.subTest(assertion=assertion):
                self.assertIn(assertion, reject)
        self.assertNotIn("catch {", reject)
        controls = "Test-FixtureTraffic -FixtureName $AllowedControlName"
        self.assertEqual(reject.count(controls), 2)
        self.assertLess(reject.index(controls), reject.index("$connectTask ="))
        self.assertLess(reject.index("$connectTask ="), reject.rindex(controls))
        self.assertIn("-AllowedControlName 'native-fixture-b.invalid'", source)
        self.assertIn("-AllowedControlName 'native-fixture-a.invalid'", source)

    def test_tun_start_hands_off_to_service_before_fixture_traffic(self):
        source = NATIVE_SMOKE.read_text(encoding="utf-8")
        start = source.index("if ($uidA) {")
        end = source.index("if ($uidB) {", start)
        fixture_a = source[start:end]
        required = (
            "patch_verge_config",
            "Invoke-CvrCommand -Command 'restart_core'",
            "Assert-SelectedProfileReady",
            "Test-FixtureTraffic",
        )
        positions = []
        for assertion in required:
            with self.subTest(assertion=assertion):
                self.assertIn(assertion, fixture_a)
                positions.append(fixture_a.index(assertion))
        self.assertEqual(positions, sorted(positions))


    def test_live_core_is_direct_child_of_ready_service(self):
        source = NATIVE_SMOKE.read_text(encoding="utf-8")
        readiness = source.split("function Wait-ServiceReady", 1)[1].split("function Assert-LiveServiceIdentity", 1)[0]
        self.assertIn("([string]$lastState.mode).ToLowerInvariant() -eq 'service'", readiness)
        identity = source.split("function Assert-LiveServiceIdentity", 1)[1].split("function Get-RuntimeYaml", 1)[0]
        for assertion in (
            "Get-CimInstance Win32_Service",
            "$serviceRecord.ProcessId",
            "$processes[0].ParentProcessId",
            "$processes[0].ExecutablePath",
            "$serviceCore",
            "Get-FileHash",
            "$coreSha",
        ):
            with self.subTest(assertion=assertion):
                self.assertIn(assertion, identity)



if __name__ == "__main__":
    unittest.main()
