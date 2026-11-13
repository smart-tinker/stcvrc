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
            "plugin:mihomo|select_node_for_group",
            "record_selected_node",
            "get_proxy_view",
            "Get-ProfileDnsState",
            "get_profiles",
            "native-fixture",
        )
        for assertion in required:
            with self.subTest(assertion=assertion):
                self.assertIn(assertion, source)

    def test_runtime_dns_listener_requires_exact_loopback_and_core_owner(self):
        source = NATIVE_SMOKE.read_text(encoding="utf-8")
        listener = source.split("function Assert-VerifiedRuntimeDnsListener", 1)[1].split(
            "function Get-VerifiedRuntimeDnsEndpoint", 1
        )[0]
        self.assertIn("$allowedAddresses = @($Address)", listener)
        self.assertNotIn("'0.0.0.0'", listener)
        self.assertNotIn("'::'", listener)
        self.assertIn("Get-DnsReceiveDiagnostics", listener)
        self.assertIn("$ownerPids[0] -ne $expectedPid", listener)

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

        before_control = "Test-FixtureTraffic -FixtureName $beforeControlName"
        after_control = "Test-FixtureTraffic -FixtureName $afterControlName"
        self.assertEqual(reject.count(before_control), 1)
        self.assertEqual(reject.count(after_control), 1)
        self.assertIn("$beforeControlName = 'pre-' + [Guid]::NewGuid().ToString('N') + '.' + $AllowedControlName", reject)
        self.assertIn("$afterControlName = 'post-' + [Guid]::NewGuid().ToString('N') + '.' + $AllowedControlName", reject)
        self.assertLess(reject.index(before_control), reject.index("$connectTask ="))
        self.assertLess(reject.index("$connectTask ="), reject.index("$stream.Write($request"))
        self.assertLess(reject.index("$stream.Write($request"), reject.index("$stream.Read($responseBuffer"))
        self.assertLess(reject.index("$stream.Read($responseBuffer"), reject.index(after_control))
        self.assertIn("-AllowedControlName 'native-fixture-b.invalid'", source)
        self.assertIn("-AllowedControlName 'native-fixture-a.invalid'", source)

    def test_fake_ip_resolver_marker_follows_application_and_recovery_traffic(self):
        source = NATIVE_SMOKE.read_text(encoding="utf-8")
        fixture = source.split("function Test-FixtureTraffic", 1)[1].split("function Test-RejectedFixture", 1)[0]
        self.assertLess(fixture.index("Invoke-TunHttp"), fixture.index("Assert-DnsResolver"))
        self.assertIn("Get-DnsReceiveDiagnostics", source)
        recovery = source.split("elseif ($Phase -eq 'recovery')", 1)[1].split("\n    } else {", 1)[0]
        self.assertIn("Assert-SelectedProfileReady", recovery)
        self.assertIn("Start-CvrService", recovery)
        self.assertIn("Test-FixtureTraffic -FixtureName 'recovery.native-fixture-a.invalid'", recovery)

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


    def test_http_failure_reports_response_and_resolver_context(self):
        source = NATIVE_SMOKE.read_text(encoding="utf-8")
        http = source.split("function Invoke-TunHttp", 1)[1].split(
            "function Wait-ServiceReady", 1
        )[0]
        self.assertIn("$status = ($response -split", http)
        self.assertIn("body='$body'", http)

        traffic = source.split("function Test-FixtureTraffic", 1)[1].split(
            "function Test-RejectedFixture", 1
        )[0]
        self.assertIn("resolverLog=", traffic)
        self.assertIn("Get-NativeStateSnapshot", traffic)

    def test_http_failure_reports_dns_mapping_and_fixture_server_logs(self):
        source = NATIVE_SMOKE.read_text(encoding="utf-8")
        snapshot = source.split("function Get-NativeStateSnapshot", 1)[1].split(
            "function Wait-RuntimeRule", 1
        )[0]
        self.assertIn("$snapshot.dnsConfiguration = Get-SafeDnsConfigurationSnapshot", snapshot)
        self.assertIn("$snapshot.fixtureHttpServerStdoutTail = @(Get-BoundedLogTail -Path $script:serverStdoutPath -Count 12)", snapshot)
        self.assertIn("$snapshot.fixtureHttpServerStderrTail = @(Get-BoundedLogTail -Path $script:serverStderrPath -Count 12)", snapshot)

        traffic = source.split("function Test-FixtureTraffic", 1)[1].split(
            "function Test-RejectedFixture", 1
        )[0]
        self.assertIn("dnsEndpoint=$dnsEndpointText; fakeAddress=$fake", traffic)
        self.assertIn("fakeAddress=$fake", traffic)

    def test_core_restart_failure_reports_startup_and_process_state(self):
        source = NATIVE_SMOKE.read_text(encoding="utf-8")
        self.assertIn("function Invoke-CvrRestartCore", source)
        restart = source.split("function Invoke-CvrRestartCore", 1)[1].split(
            "\\n}", 1
        )[0]
        self.assertIn("get_core_startup_error", restart)
        self.assertIn("Get-NativeStateSnapshot", restart)
        self.assertEqual(source.count("Invoke-CvrCommand -Command 'restart_core'"), 1)
        self.assertEqual(source.count("Invoke-CvrRestartCore -Phase"), 5)


    def test_tun_cleanup_failure_preserves_primary_restart_failure(self):
        source = NATIVE_SMOKE.read_text(encoding="utf-8")
        seed = source.split("if ($Phase -eq 'seed')", 1)[1].split(
            "elseif ($Phase -eq 'recovery')", 1
        )[0]
        self.assertIn("$seedFailure", seed)
        self.assertIn("Add-Failure", seed)
        self.assertIn("2.5.8 pre-update TUN cleanup", seed)


    def test_seed_and_recovery_start_the_service_before_tun(self):
        source = NATIVE_SMOKE.read_text(encoding="utf-8")
        startup = source.split("function Start-CvrService", 1)
        self.assertEqual(len(startup), 2)
        startup_body = startup[1].split("function ", 1)[0]
        self.assertIn("Invoke-CvrCommand -Command 'install_service'", startup_body)
        self.assertIn("Assert-LiveServiceIdentity", startup_body)

        seed = source.split("if ($Phase -eq 'seed')", 1)[1].split(
            "elseif ($Phase -eq 'recovery')", 1
        )[0]
        recovery = source.split("elseif ($Phase -eq 'recovery')", 1)[1].split(
            "\\n    } else {", 1
        )[0]
        for phase in (seed, recovery):
            with self.subTest(phase="TUN phase"):
                self.assertIn("Start-CvrService", phase)
                self.assertIn("Assert-SelectedProfileReady", phase)
                self.assertLess(phase.index("Start-CvrService"), phase.index("enable_tun_mode=$true"))



    def test_258_service_identity_is_pinned_from_extracted_payload(self):
        workflow = (ROOT / ".github" / "workflows" / "test.yml").read_text(encoding="utf-8")
        self.assertIn("$serviceFiles = @($files | Where-Object { $_.Name -ieq 'clash-verge-service.exe' })", workflow)
        self.assertIn("if ($serviceFiles.Count -ne 1)", workflow)
        self.assertIn("CVR_258_SERVICE_SHA256=$serviceHash", workflow)


if __name__ == "__main__":
    unittest.main()
