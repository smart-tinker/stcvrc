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
    def test_install_update_and_recovery_run_native_phases_in_order(self):
        source = INSTALLER_SMOKE.read_text(encoding="utf-8")
        phases = ("-Phase seed", "-Phase exercise", "-Phase recovery")
        positions = [source.index(phase) for phase in phases]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("Invoke-CvrInstaller -Version '2.5.8'", source)
        self.assertIn("Invoke-CvrInstaller -Version '2.5.10'", source)
        self.assertIn("Invoke-NativePhase", source)

    def test_native_acceptance_checks_safety_and_real_runtime(self):
        source = NATIVE_SMOKE.read_text(encoding="utf-8")
        required = (
            "198.18.0.0/16",
            "Get-NetRoute",
            "get_runtime_state",
            "clash_verge_service",
            "Get-FileHash",
            "Invoke-DnsQuery",
            "set_dns_override",
            "save_dns_config",
            "switch_proxy_node",
            "get_proxy_view",
            "Get-ProfileDnsState",
            "get_profiles",
            "native-fixture",
        )
        for assertion in required:
            with self.subTest(assertion=assertion):
                self.assertIn(assertion, source)

    def test_reject_requires_quick_application_close_and_live_controls(self):
        source = NATIVE_SMOKE.read_text(encoding="utf-8")
        reject = source.split("function Test-RejectedFixture", 1)[1].split("\n}", 1)[0]
        required = (
            "ConnectAsync",
            "$stream.Write($request",
            "$stream.Read($responseBuffer",
            "Host: $FixtureName",
            "SocketErrorCode",
            "ConnectionRefused",
            "ConnectionReset",
            "ConnectionAborted",
            "NetworkReset",
            "Assert-SelectedProfileReady",
            "Get-NetRoute",
            "Compare-Object",
        )
        for assertion in required:
            with self.subTest(assertion=assertion):
                self.assertIn(assertion, reject)

        controls = "Test-FixtureTraffic -FixtureName $AllowedControlName"
        self.assertEqual(reject.count(controls), 2)
        self.assertLess(reject.index(controls), reject.index("$connectTask ="))
        self.assertLess(reject.index("$connectTask ="), reject.index("$stream.Write($request"))
        self.assertLess(reject.index("$stream.Write($request"), reject.index("$stream.Read($responseBuffer"))
        self.assertLess(reject.index("$stream.Read($responseBuffer"), reject.rindex(controls))
        self.assertIn("-AllowedControlName 'native-fixture-b.invalid'", source)
        self.assertIn("-AllowedControlName 'native-fixture-a.invalid'", source)

    def test_native_phase_uses_real_service_and_recovery_paths(self):
        source = NATIVE_SMOKE.read_text(encoding="utf-8")
        service = source.index("Invoke-CvrCommand -Command 'install_service'")
        service_identity = source.index("Assert-LiveServiceIdentity", service)
        fixture = source.index("Assert-SelectedProfileReady", service_identity)
        self.assertLess(service, service_identity)
        self.assertLess(service_identity, fixture)
        self.assertIn("Assert-LiveCoreIdentity", source)
        self.assertIn("Assert-LiveSidecarCoreIdentity", source)
        self.assertIn("if ($Phase -eq 'seed')", source)
        self.assertIn("elseif ($Phase -eq 'recovery')", source)
        self.assertIn("DNS override on/off/confirmation", source)


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
