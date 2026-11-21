"""Contract checks for the native Windows acceptance harness.

The end-to-end behavior is exercised by windows-2022 in test.yml. These checks
keep the disposable-runner, route-scope, service identity, and DNS assertions
wired into that native job.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
INSTALLER_SMOKE = ROOT / "tools" / "network-lab" / "windows_install_update.ps1"
NATIVE_SMOKE = ROOT / "tools" / "network-lab" / "windows_native_acceptance.ps1"
PORT_PLAN = ROOT / "tools" / "network-lab" / "windows_native_port_plan.ps1"


class NativeWindowsAcceptanceContract(unittest.TestCase):
    def test_fresh_windows_core_is_bound_to_exact_rc9_pin(self):
        manifest = json.loads((INSTALLER_SMOKE.parents[2] / "candidates" / "cvr-2.5.10" / "inputs.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["windowsNativeCandidate"], {
            "releaseId": 446278043,
            "tag": "stcvrc-1.19.33-rc.9",
            "candidate": "STCVRC 1.19.33 RC9",
            "assetId": 751963784,
            "assetName": "verge-mihomo.exe",
            "assetSize": 60833280,
            "sha256": "1e8648cf8a53a96697bfda5a53bbf3393a042430f5ec4e963c8f19dc83a5523e",
        })
        source = INSTALLER_SMOKE.read_text(encoding="utf-8")
        for pin in (
            "$nativeCandidate.releaseId -ne 446278043",
            "$nativeCandidate.tag -cne 'stcvrc-1.19.33-rc.9'",
            "$nativeCandidate.assetId -ne 751963784",
            "[long]$nativeCandidate.assetSize -ne 60833280",
            "$coreSha -cne [string]$nativeCandidate.sha256",
        ):
            self.assertIn(pin, source)

    def test_core_preimage_backups_keep_helper_filename_and_hash_contract(self):
        source = INSTALLER_SMOKE.read_text(encoding="utf-8")
        path_helper = (INSTALLER_SMOKE.parent / "windows_core_preimage_paths.ps1").read_text(encoding="utf-8")
        workflow = (ROOT / ".github" / "workflows" / "test.yml").read_text(encoding="utf-8")
        self.assertIn("New-CvrCorePreimageBackupPath", source)
        self.assertIn("Label $target.backupLabel", source)
        self.assertIn("Label '258-stock'", source)
        self.assertIn("GetFileName($backup) -cne 'verge-mihomo.exe'", source)
        self.assertIn("backup SHA256 expected=", source)
        self.assertIn("ACL SDDL SHA256 expected=", source)
        self.assertIn("Test-CvrCorePreimageBackupPathContract", path_helper)
        check = workflow.index("Test-CvrCorePreimageBackupPathContract -Root $env:RUNNER_TEMP")
        build = workflow.index("- name: Fresh native Windows core build")
        self.assertLess(check, build)

    def test_recovery_restores_original_split_core_pair_before_native_check(self):
        source = INSTALLER_SMOKE.read_text(encoding="utf-8")
        self.assertIn("$originalCorePair = $idleBaselineCapture.corePair", source)
        self.assertIn("Restore-CvrCorePairPreimage -Preimage $originalCorePair -HelperVersion '2.5.8'", source)
        self.assertIn("-ExpectedProgramFilesCoreSha $originalCorePair.programFiles.sha256", source)
        self.assertIn("-ExpectedServiceCoreSha $originalCorePair.service.sha256", source)
        self.assertIn("-RecoveryServiceCorePreimagePath $originalCorePair.service.backup", source)
        self.assertIn("-ExpectedProgramFilesCoreSha256 $ExpectedProgramFilesCoreSha", source)
        self.assertIn("-ExpectedServiceCoreSha256 $ExpectedServiceCoreSha", source)
        self.assertIn("if ($originalCorePair.programFiles.sha256 -cne $stockProgramFilesCore.sha256)", source)
        self.assertIn("if ($originalCorePair.programFiles.sha256 -ceq $coreSha)", source)
        self.assertIn("if ($originalCorePair.service.sha256 -cne $coreSha)", source)
        self.assertIn("GetFileName([string]$env:CUSTOM_CORE) -cne 'verge-mihomo.exe'", source)
        self.assertIn("$stockHelper.path --install-core $env:CUSTOM_CORE --sha256 $coreSha", source)
        native = NATIVE_SMOKE.read_text(encoding="utf-8")
        self.assertIn("$script:expectedProgramFilesCoreSha -cne $coreSha", native)
        self.assertIn("$script:expectedServiceCoreSha -cne $coreSha", native)
        service_identity = native.split("function Assert-LiveCoreIdentity", 1)[1].split(
            "function Assert-LiveSidecarCoreIdentity", 1
        )[0]
        sidecar_identity = native.split("function Assert-LiveSidecarCoreIdentity", 1)[1].split(
            "function Get-RuntimeDnsListen", 1
        )[0]
        self.assertIn("$script:expectedServiceCoreSha", service_identity)
        self.assertIn("$script:expectedProgramFilesCoreSha", sidecar_identity)
        self.assertIn("original pair after native recovery", source)


    def test_recovery_keeps_helper_service_running_and_checks_service_readiness(self):
        source = NATIVE_SMOKE.read_text(encoding="utf-8")
        recovery_install = source.split("function Install-CvrRecoveryService", 1)[1].split(
            "function Assert-LiveSidecarCoreIdentity", 1
        )[0]
        for assertion in (
            "CVR_258_SERVICE_INSTALL_HELPER_PATH",
            "CVR_258_SERVICE_INSTALL_HELPER_SHA256",
            "--install-service --install-core $preimagePath --sha256 $script:expectedServiceCoreSha",
            "GetFileName($preimagePath) -cne 'verge-mihomo.exe'",
            "Set-Acl -LiteralPath $serviceCore -AclObject $preimageAcl",
            "Assert-LiveServiceIdentity",
            "service-core ACL SDDL SHA256 expected=",
            "$script:expectedProgramFilesCoreSha",
            "$script:expectedServiceCoreSha",
        ):
            with self.subTest(assertion=assertion):
                self.assertIn(assertion, recovery_install)
        for forbidden in (
            "Stop-Service -Name $serviceName",
            "Start-Service -Name $serviceName",
            "Assert-LiveServiceIdentity -AllowStopped",
            "Assert-LiveCoreIdentity",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, recovery_install)
        helper = recovery_install.index("--install-service --install-core $preimagePath")
        running_identity = recovery_install.index("Assert-LiveServiceIdentity", helper)
        self.assertLess(helper, running_identity)

        startup = source.split("function Start-CvrService", 1)[1].split(
            "function Assert-LiveCoreIdentity", 1
        )[0]
        recovery_start = startup.split("if ($Phase -eq 'recovery')", 1)[1].split(
            "$outcome=Invoke-CvrCommand -Command 'install_service'", 1
        )[0]
        for assertion in (
            "$beforeStartSha",
            "$script:expectedServiceCoreSha",
            "if ($existingService.Status -ne 'Running')",
            "Assert-LiveServiceIdentity",
            "Wait-ServiceReady",
            "Assert-LiveCoreIdentity",
        ):
            with self.subTest(assertion=assertion):
                self.assertIn(assertion, recovery_start)
        for forbidden in ("Start-Service -Name $serviceName", "Assert-LiveServiceIdentity -AllowStopped"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, recovery_start)
        self.assertLess(recovery_start.index("$beforeStartSha"), recovery_start.index("Wait-ServiceReady"))
        self.assertLess(recovery_start.index("Wait-ServiceReady"), recovery_start.index("Assert-LiveCoreIdentity"))

        live_identity = source.split("function Assert-LiveCoreIdentity", 1)[1].split(
            "function Install-CvrRecoveryService", 1
        )[0]
        for assertion in ("$serviceCore", "ParentProcessId", "$serviceRecord.ProcessId",
                          "$script:expectedServiceCoreSha", "$script:verifiedCorePid"):
            with self.subTest(assertion=assertion):
                self.assertIn(assertion, live_identity)

        selected_ready = source.split("function Assert-SelectedProfileReady", 1)[1].split(
            "function Assert-SelectedSidecarProfileReady", 1
        )[0]
        self.assertLess(selected_ready.index("Wait-ServiceReady"), selected_ready.index("Assert-LiveCoreIdentity"))

        seed = source.split("if ($Phase -eq 'seed') {", 1)[1].split(
            "} elseif ($Phase -eq 'recovery') {", 1
        )[0]
        recovery = source.split("} elseif ($Phase -eq 'recovery') {", 1)[1].split(
            "} else {", 1
        )[0]
        self.assertIn("Assert-LiveSidecarCoreIdentity", seed)
        self.assertNotIn("Assert-LiveSidecarCoreIdentity", recovery)
        self.assertIn("[string]$profiles.current", recovery)
        self.assertIn("Assert-FixtureNodeSelection", recovery)
        self.assertIn("Assert-ProfileDnsState", recovery)
        self.assertIn("Test-FixtureTraffic -FixtureName 'recovery.native-fixture-a.invalid'", recovery)
        start_service = recovery.index("Start-CvrService")
        patch = recovery.index("Invoke-CvrCommand -Command 'patch_verge_config'")
        restart = recovery.index("Invoke-CvrRestartCore -Phase '2.5.8 functional recovery TUN'")
        ready = recovery.index("Assert-SelectedProfileReady")
        traffic = recovery.index("Test-FixtureTraffic -FixtureName 'recovery.native-fixture-a.invalid'")
        profile_read = recovery.index("$profiles = Invoke-CvrCommand -Command 'get_profiles'")
        global_check = recovery.index("Assert-GlobalUiModesOff")
        self.assertLess(start_service, global_check)
        self.assertLess(start_service, profile_read)
        self.assertLess(start_service, patch)
        self.assertLess(patch, restart)
        self.assertLess(restart, ready)
        self.assertLess(ready, traffic)
        self.assertLess(
            source.index("Install-CvrRecoveryService -CorePreimagePath $RecoveryServiceCorePreimagePath"),
            source.index("$gui=Start-Process -FilePath $guiPath"),
        )

    def test_synthetic_rollback_self_check_precedes_the_long_windows_build(self):
        workflow = (ROOT / ".github" / "workflows" / "test.yml").read_text(encoding="utf-8")
        helper = (INSTALLER_SMOKE.parent / "windows_legacy_state_transaction.ps1").read_text(encoding="utf-8")
        step = workflow.split("      - name: Check synthetic rollback before native build\n", 1)[1].split(
            "      - name: Fresh native Windows core build", 1
        )[0]
        check = step.index("Test-CvrInstallerActionFailureRollback")
        app_data_checks = [index for index in range(len(step)) if step.startswith("Test-Path -LiteralPath $normalAppDataPath", index)]
        build = workflow.index("- name: Fresh native Windows core build")
        self.assertEqual(len(app_data_checks), 2)
        self.assertLess(app_data_checks[0], check)
        self.assertLess(check, app_data_checks[1])
        self.assertIn("$env:APPDATA = $selfCheckAppDataRoot", step)
        self.assertIn("Remove-Item -LiteralPath $selfCheckAppDataRoot -Recurse -Force -ErrorAction Stop", step)
        self.assertLess(workflow.index("Test-CvrInstallerActionFailureRollback"), build)
        self.assertIn("function Test-CvrInstallerActionFailureRollback", helper)
        self.assertIn("Invoke-CvrStateTransaction -Phase 'intentional action-failure self-check'", helper)
        self.assertNotIn("CVR_258_INSTALLER", helper)
        self.assertNotIn("CUSTOM_CORE", helper)

    def test_install_update_and_recovery_run_native_phases_in_order(self):
        source = INSTALLER_SMOKE.read_text(encoding="utf-8")
        phases = ("-Phase seed", "-Phase exercise", "-Phase recovery")
        positions = [source.index(phase) for phase in phases]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("Invoke-CvrInstaller -Version '2.5.8'", source)
        self.assertIn("Invoke-CvrInstaller -Version '2.5.10'", source)
        self.assertIn("Invoke-NativePhase", source)

    def test_nsis_side_effects_and_split_core_preimages_are_restored(self):
        source = INSTALLER_SMOKE.read_text(encoding="utf-8")
        helper = (INSTALLER_SMOKE.parent / "windows_legacy_state_transaction.ps1").read_text(encoding="utf-8")
        self.assertIn("windows_legacy_state_transaction.ps1", source)
        self.assertIn("Invoke-CvrStateTransaction", helper)
        self.assertIn("Assert-CvrInstallerChangedLegacyPreimage", helper)
        self.assertIn("Restore-CvrLegacyState", helper)
        self.assertIn("if ((Get-Acl -LiteralPath $entry.path).Sddl -cne $entry.sddl)", helper)
        self.assertIn("Get-CvrCorePairPreimage", source)
        self.assertIn("Restore-CvrCorePairPreimage", source)
        self.assertIn("Set-CvrSyntheticSplitCorePreimage", source)
        self.assertIn("Assert-CvrCorePairPreimage", source)

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
        self.assertIn("[switch]$SkipResolverLogAssertion", fixture)
        self.assertIn("if ($ExpectedResolver -and -not $SkipResolverLogAssertion)", fixture)
        ssh_scenario = source.split("function Test-SshPrivateKeyInServiceMode", 1)[1].split("\nfunction ", 1)[0]
        self.assertIn("-SkipResolverLogAssertion", ssh_scenario)
        self.assertIn("Get-DnsReceiveDiagnostics", source)
        recovery = source.split("elseif ($Phase -eq 'recovery')", 1)[1].split("\n    } else {", 1)[0]
        self.assertIn("Assert-SelectedProfileReady", recovery)
        self.assertIn("Start-CvrService", recovery)
        self.assertIn("Test-FixtureTraffic -FixtureName 'recovery.native-fixture-a.invalid'", recovery)

    def test_recovery_preserves_and_uses_enabled_profile_dns_override(self):
        source = NATIVE_SMOKE.read_text(encoding="utf-8")
        recovery = source.split("elseif ($Phase -eq 'recovery')", 1)[1].split(
            "\n    } else {", 1
        )[0]
        self.assertIn(
            "Assert-ProfileDnsState -Uid ([string]$profileA.uid) -Enabled $true -Phase '2.5.8 recovery'",
            recovery,
        )
        self.assertIn(
            "Test-FixtureTraffic -FixtureName 'recovery.native-fixture-a.invalid' -DnsPort $dnsPort -HttpPort $httpPort -ExpectedResolver 'app'",
            recovery,
        )

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
            "$script:expectedServiceCoreSha",
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


    def test_dns_traffic_uses_service_owned_core_in_every_native_phase(self):
        source = NATIVE_SMOKE.read_text(encoding="utf-8")
        listener = source.split("function Assert-VerifiedRuntimeDnsListener", 1)[1].split(
            "function Get-VerifiedRuntimeDnsEndpoint", 1
        )[0]
        self.assertIn("Assert-LiveCoreIdentity", listener)
        self.assertNotIn("Assert-LiveSidecarCoreIdentity", listener)

    def test_dns_port_plan_is_reused_across_native_phases(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            plan_path = Path(temp_dir) / "native-ports.json"
            env = os.environ.copy()
            env["STCVRC_PORT_PLAN_SCRIPT"] = str(PORT_PLAN)
            env["STCVRC_PORT_PLAN_PATH"] = str(plan_path)
            command = r"""
                $ErrorActionPreference = 'Stop'
                if (-not (Test-Path -LiteralPath $env:STCVRC_PORT_PLAN_SCRIPT -PathType Leaf)) {
                    throw 'Native phase port-plan helper is missing.'
                }
                . $env:STCVRC_PORT_PLAN_SCRIPT
                $first = Get-StcvrcNativePortPlan -Path $env:STCVRC_PORT_PLAN_PATH
                $second = Get-StcvrcNativePortPlan -Path $env:STCVRC_PORT_PLAN_PATH
                $names = @('coreDnsPort', 'profileDnsPort', 'appDnsPort')
                $ports = @($names | ForEach-Object { [int]$first.$_ })
                if (@($ports | Sort-Object -Unique).Count -ne 3) {
                    throw 'The persistent DNS port plan must use three distinct ports.'
                }
                foreach ($name in $names) {
                    if ([int]$first.$name -ne [int]$second.$name) {
                        throw "DNS port plan changed between native phases: $name."
                    }
                }
            """
            result = subprocess.run(
                ["pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            plan = json.loads(plan_path.read_text(encoding="utf-8"))
            ports = [plan[name] for name in ("coreDnsPort", "profileDnsPort", "appDnsPort")]
            self.assertEqual(len(set(ports)), 3)
            self.assertTrue(all(0 < int(port) <= 65535 for port in ports))


    def test_subscription_dns_update_resets_override_and_uses_new_profile_resolver(self):
        source = NATIVE_SMOKE.read_text(encoding="utf-8")
        self.assertIn("function Test-SubscriptionDnsOverrideAfterUpdate", source)
        self.assertIn("Test-SubscriptionDnsOverrideAfterUpdate -DnsPort $dnsPort", source)
        scenario = source.split("function Test-SubscriptionDnsOverrideAfterUpdate", 1)[1].split(
            "function ", 1
        )[0]
        for assertion in (
            "Invoke-CvrCommand -Command 'import_profile'",
            "Invoke-CvrCommand -Command 'update_profile'",
            "Assert-ProfileDnsState -Uid $uid -Enabled $false",
            "Set-Content",
            "ExpectedResolver 'subscription'",
        ):
            with self.subTest(assertion=assertion):
                self.assertIn(assertion, scenario)
        self.assertIn("Test-SubscriptionDnsOverrideAfterUpdate", source)


    def test_cvr_2510_overlay_reinstall_starts_with_running_gui(self):
        source = INSTALLER_SMOKE.read_text(encoding="utf-8")
        self.assertIn("function Invoke-CvrOverlayReinstall", source)
        overlay = source.split("function Invoke-CvrOverlayReinstallAction", 1)[1].split(
            "\nfunction ", 1
        )[0]
        for assertion in (
            "Start-Process -FilePath $guiPath -PassThru",
            "Get-Process -Id $gui.Id",
            "$installerPaths['2.5.10']",
            "'/UPDATE'",
            "Expected the pinned CVR GUI process to exit during overlay",
            "if ($gui.HasExited -and $installerProcess.HasExited -and",
            "$gui.ExitTime.ToUniversalTime() -lt $installerProcess.ExitTime.ToUniversalTime()",
            "Get-InstalledCvrDirectory -ExpectedVersion '2.5.10'",
        ):
            with self.subTest(assertion=assertion):
                self.assertIn(assertion, overlay)
        exit_time_fallback = overlay.split(
            "if ($gui.HasExited -and $installerProcess.HasExited -and", 1
        )
        self.assertEqual(len(exit_time_fallback), 2)
        exit_time_fallback = exit_time_fallback[1].split(
            "if (-not $installerProcess.HasExited)", 1
        )[0]
        for assertion in (
            "$gui.ExitTime.ToUniversalTime() -ge $installerProcess.StartTime.ToUniversalTime()",
            "$gui.ExitTime.ToUniversalTime() -lt $installerProcess.ExitTime.ToUniversalTime()",
            "$guiExitedDuringOverlay = $true",
        ):
            with self.subTest(fallback_assertion=assertion):
                self.assertIn(assertion, exit_time_fallback)
        polling = overlay.split("while ([DateTime]::UtcNow -lt $deadline)", 1)[1].split(
            "if ($installerProcess.HasExited) { break }", 1
        )[0]
        self.assertIn("$gui.HasExited", polling)
        gui_exit_observation = polling.split("$gui.HasExited", 1)[1]
        for assertion in (
            "$guiExitTime = $gui.ExitTime.ToUniversalTime()",
            "$installerProcess.Refresh()",
            "$guiExitTime -ge $installerProcess.StartTime.ToUniversalTime() -and",
            "(-not $installerProcess.HasExited -or",
            "$guiExitTime -lt $installerProcess.ExitTime.ToUniversalTime())",
            "$guiExitedDuringOverlay = $true",
        ):
            with self.subTest(polling_assertion=assertion):
                self.assertIn(assertion, gui_exit_observation)
        if "$guiExitTime =" in gui_exit_observation and "$installerProcess.Refresh()" in gui_exit_observation:
            self.assertLess(
                gui_exit_observation.index("$guiExitTime ="),
                gui_exit_observation.index("$installerProcess.Refresh()"),
            )
        if "$installerProcess.Refresh()" in gui_exit_observation and "$guiExitTime -ge $installerProcess.StartTime.ToUniversalTime()" in gui_exit_observation:
            self.assertLess(
                gui_exit_observation.index("$installerProcess.Refresh()"),
                gui_exit_observation.index("$guiExitTime -ge $installerProcess.StartTime.ToUniversalTime()"),
            )
        self.assertIn(
            "if ($guiExitTime -ge $installerProcess.StartTime.ToUniversalTime() -and\n"
            "                    (-not $installerProcess.HasExited -or\n"
            "                    $guiExitTime -lt $installerProcess.ExitTime.ToUniversalTime())) {\n"
            "                    $guiExitedDuringOverlay = $true\n"
            "                }",
            gui_exit_observation,
        )
        overlay_call = "Invoke-CvrOverlayReinstall -InstallDirectory $install2510"
        self.assertIn(overlay_call, source)
        update_stage = source.index("Install-CandidateCore -InstallDirectory $install2510")
        overlay_position = source.index(overlay_call)
        exercise_position = source.index("Invoke-NativePhase -Phase exercise")
        self.assertLess(update_stage, overlay_position)
        self.assertLess(overlay_position, exercise_position)

    def test_service_ssh_key_file_is_used_by_authenticated_loopback_traffic(self):
        source = NATIVE_SMOKE.read_text(encoding="utf-8")
        self.assertIn("function Test-SshPrivateKeyInServiceMode", source)
        self.assertIn("Test-SshPrivateKeyInServiceMode -DnsPort $dnsPort -HttpPort $httpPort", source)
        scenario = source.split("function Test-SshPrivateKeyInServiceMode", 1)[1].split(
            "\nfunction ", 1
        )[0]
        for assertion in (
            "Start-SshFixtureServer",
            "Invoke-CvrCommand -Command 'get_app_dir'",
            "private-key:",
            "Assert-LiveCoreIdentity",
            "Test-FixtureTraffic",
            "-Route 'GLOBAL'",
            "$serviceConfigPath = Join-Path $runtimeDirectory 'config.yaml'",
            "$serviceRuntimeYaml = [IO.File]::ReadAllText($serviceConfigPath)",
            "[regex]::Matches($serviceRuntimeYaml, 'cvr-[0-9a-f]{64}')",
            "$runtimeConfigs = @(",
            "$runtimeMatch = $rewrittenConfigs[0]",
            "$stagedKeyPath = Join-Path $runtimeDirectory $assetAlias",
            "sshFixtureDiagnostics=",
            "Stop-Process -Id $fixture.Process.Id -Force -ErrorAction SilentlyContinue",
            "Wait-Process -Id $fixture.Process.Id -Timeout 5 -ErrorAction SilentlyContinue",
            "Get-Content -LiteralPath $fixture.StderrPath -Tail 8",
        ):
            with self.subTest(assertion=assertion):
                self.assertIn(assertion, scenario)
        self.assertNotIn("$runtimeYaml = Get-RuntimeYaml", scenario)
        self.assertNotIn("ssh-private-key-", scenario)
        self.assertNotIn("SSH_FIXTURE_AUTH_OK", scenario)
        self.assertNotIn("[IO.File]::ReadAllText($fixture.StdoutPath)", scenario)
        helper = ROOT / "tools" / "network-lab" / "ssh_fixture.go"
        self.assertTrue(helper.is_file())


        selector = source.split("function Select-FixtureProfile", 1)[1].split(
            "function Assert-SelectedProfileReady", 1
        )[0]
        self.assertIn("[string]$Route = 'DIRECT'", selector)
        self.assertIn("DOMAIN-SUFFIX,$AllowName,$Route", selector)


    def test_ssh_fixture_key_is_inside_profile_config_root(self):
        source = NATIVE_SMOKE.read_text(encoding="utf-8")
        scenario = source.split("function Test-SshPrivateKeyInServiceMode", 1)[1].split(
            "\nfunction ", 1
        )[0]
        self.assertIn("$profileDirectory = Join-Path $appHome 'profiles'", scenario)
        self.assertIn("$keyPath = Join-Path $profileDirectory", scenario)


    def test_ssh_key_lookup_avoids_locked_cache_db(self):
        source = NATIVE_SMOKE.read_text(encoding="utf-8")
        self.assertIn("function Get-ServiceRuntimeDirectories", source)
        scenario = source.split("function Test-SshPrivateKeyInServiceMode", 1)[1].split(
            "\nfunction ", 1
        )[0]
        self.assertIn("Get-ServiceRuntimeDirectories -ServiceUsersPath $serviceUsers", scenario)
        self.assertNotIn("Get-ChildItem -LiteralPath $serviceUsers -File -Recurse", scenario)
        self.assertNotIn("Get-ChildItem -LiteralPath $serviceUsers -Filter $assetAlias -File -Recurse", scenario)
        self.assertIn("Join-Path $runtimeDirectory $assetAlias", scenario)

        cleanup_start = source.rindex("} finally {\n    if ($script:cdp)")
        cleanup = source[cleanup_start:]
        process_stop = cleanup.index("foreach ($name in @('clash-verge'")
        staged_key_cleanup = cleanup.index("if ($script:fixtureSshKeyHash -and $script:fixtureSshKeyAlias)")
        self.assertLess(process_stop, staged_key_cleanup)
        self.assertIn("Get-ServiceRuntimeDirectories -ServiceUsersPath $serviceUsers", cleanup[staged_key_cleanup:])
        self.assertIn("Join-Path $runtimeDirectory $script:fixtureSshKeyAlias", cleanup[staged_key_cleanup:])
        self.assertIn("Hash.ToLowerInvariant() -ceq $script:fixtureSshKeyHash", cleanup[staged_key_cleanup:])

    def test_ssh_service_alias_is_independent_of_key_content_hash(self):
        source = NATIVE_SMOKE.read_text(encoding="utf-8")
        scenario = source.split("function Test-SshPrivateKeyInServiceMode", 1)[1].split(
            "\nfunction ", 1
        )[0]
        for assertion in (
            "$privateKeyAliasMatches = [regex]::Matches($privateKeyLines[0], 'cvr-[0-9a-f]{64}')",
            "$privateKeyAliasMatches.Count -ne 1",
            "$privateKeyAliasMatches[0].Value -cne $assetAlias",
            "Get-FileHash -LiteralPath $stagedKeyPath -Algorithm SHA256",
            "Hash.ToLowerInvariant() -ne $keyHash",
        ):
            with self.subTest(assertion=assertion):
                self.assertIn(assertion, scenario)
        self.assertNotIn("$assetAlias -cne $expectedAssetAlias", scenario)


    def test_ssh_alias_failure_reports_only_redacted_private_key_lines(self):
        source = NATIVE_SMOKE.read_text(encoding="utf-8")
        scenario = source.split("function Test-SshPrivateKeyInServiceMode", 1)[1].split(
            "\nfunction ", 1
        )[0]
        for assertion in (
            "[regex]::Escape($keyPath)",
            "[regex]::Escape($keyYamlPath)",
            "'<fixture-key>'",
            "$safePrivateKeyLines",
            "private-key-lines=$($safePrivateKeyLines -join ' | ')",
            "$privateKeyAliasMatches",
            "private-key-alias-count=$($privateKeyAliasMatches.Count)",
        ):
            with self.subTest(assertion=assertion):
                self.assertIn(assertion, scenario)


    def test_service_geo_update_is_synced_before_profile_validation(self):
        source = NATIVE_SMOKE.read_text(encoding="utf-8")
        self.assertIn("function Test-GeoDatabaseSyncThroughValidation", source)
        self.assertIn("Test-GeoDatabaseSyncThroughValidation -ProfileUid $uidA", source)
        scenario = source.split("function Test-GeoDatabaseSyncThroughValidation", 1)[1].split(
            "\nfunction ", 1
        )[0]
        for assertion in (
            "get_app_dir",
            "GeoSite.dat",
            "Join-Path $serviceData 'users'",
            "Select-FixtureProfile",
            "ReadAllBytes",
            "$originalAppBytes = [IO.File]::ReadAllBytes($appGeoPath)",
            "$originalAppWriteTime = [IO.File]::GetLastWriteTimeUtc($appGeoPath)",
            "$originalRuntimeBytes = [IO.File]::ReadAllBytes($runtimeGeoPath)",
            "$originalRuntimeWriteTime = [IO.File]::GetLastWriteTimeUtc($runtimeGeoPath)",
            "[IO.File]::WriteAllBytes($appGeoPath, $originalAppBytes)",
            "[IO.File]::WriteAllBytes($runtimeGeoPath, $originalRuntimeBytes)",
            "[IO.File]::SetLastWriteTimeUtc($appGeoPath, $originalAppWriteTime)",
            "[IO.File]::SetLastWriteTimeUtc($runtimeGeoPath, $originalRuntimeWriteTime)",
        ):
            with self.subTest(assertion=assertion):
                self.assertIn(assertion, scenario)
        self.assertNotIn("refusing to overwrite existing data", scenario)
        selector = source.split("function Select-FixtureProfile", 1)[1].split("\nfunction ", 1)[0]
        self.assertIn("Invoke-CvrCommand -Command 'patch_profiles_config'", selector)


    def test_ssh_fixture_is_loopback_only_and_forwards_only_synthetic_http(self):
        helper_path = ROOT / "tools" / "network-lab" / "ssh_fixture.go"
        self.assertTrue(helper_path.is_file())
        helper = helper_path.read_text(encoding="utf-8")
        for assertion in (
            'net.Listen("tcp", "127.0.0.1:0")',
            'case "direct-tcpip":',
            "syntheticAddress := ip != nil && ip[0] == 198 && ip[1] == 18",
            'if !syntheticAddress && req.DestAddr != "service-ssh-fixture.invalid" {',
            "req.Port != uint32(targetPort)",
            'net.JoinHostPort("127.0.0.1", strconv.Itoa(targetPort))',
            "PublicKeyCallback:",
            'bytes.Equal(key.Marshal(), clientSigner.PublicKey().Marshal())',
            "SSH_FIXTURE_AUTH_REJECTED",
            "SSH_FIXTURE_HANDSHAKE_REJECTED",
            "SSH_FIXTURE_UNSUPPORTED_CHANNEL",
            "SSH_FIXTURE_INVALID_CHANNEL",
            "SSH_FIXTURE_TARGET_ADDRESS_REJECTED",
            "SSH_FIXTURE_TARGET_PORT_REJECTED",
            "SSH_FIXTURE_HTTP_TARGET_UNAVAILABLE",
            "SSH_FIXTURE_CHANNEL_ACCEPT_FAILED",
        ):
            with self.subTest(assertion=assertion):
                self.assertIn(assertion, helper)


        self.assertNotIn("SSH_FIXTURE_AUTH_OK", helper)



    def test_public_installer_runs_candidate_from_captured_idle_baseline_and_restores_it(self):
        source = INSTALLER_SMOKE.read_text(encoding="utf-8")
        helper = (INSTALLER_SMOKE.parent / "windows_legacy_state_transaction.ps1").read_text(encoding="utf-8")
        guard = (INSTALLER_SMOKE.parent / "windows_idle_baseline_guard.ps1").read_text(encoding="utf-8")
        capture_call = source.index("$idleBaselineCapture = New-CvrIdleTransactionCapture")
        update = source.index("Invoke-CvrInstaller -Version '2.5.10'", capture_call)
        exercise = source.index("Invoke-NativePhase -Phase exercise", update)
        candidate_idle = source.index("Install-CvrIdleService -Version '2.5.10'", exercise)
        candidate_guard = source.index("Assert-CvrIdleBaseline @candidateIdleObservation", candidate_idle)
        recovery = source.index("Invoke-CvrInstaller -Version '2.5.8'", candidate_guard)
        restore_call = source.index("Restore-CvrIdleTransaction -Capture $idleBaselineCapture", recovery)
        self.assertLess(capture_call, update)
        self.assertLess(update, exercise)
        self.assertLess(exercise, candidate_idle)
        self.assertLess(candidate_idle, candidate_guard)
        self.assertLess(candidate_guard, recovery)
        self.assertLess(recovery, restore_call)
        self.assertIn("finally {", source[update:restore_call])
        candidate_program_files_guard = source.index(
            "$candidateProgramFilesCore = Join-Path $install2510 'verge-mihomo.exe'",
            exercise,
        )
        candidate_service_stage = source.index(
            "$candidateServiceHelper = Get-CvrServiceInstallHelper -Version '2.5.10'",
            candidate_program_files_guard,
        )
        candidate_pair = source.index("$candidateCorePair = Get-CvrCorePairPreimage", candidate_service_stage)
        self.assertLess(exercise, candidate_program_files_guard)
        self.assertLess(candidate_program_files_guard, candidate_service_stage)
        candidate_service_core_guard = source.index(
            "$candidateServiceCore = Join-Path $serviceData 'cores\\verge-mihomo.exe'",
            candidate_service_stage,
        )
        self.assertLess(candidate_service_stage, candidate_service_core_guard)
        self.assertLess(candidate_service_core_guard, candidate_pair)
        self.assertLess(exercise, candidate_program_files_guard)
        self.assertIn("Candidate service core SHA256 mismatch before idle preimage capture.", source)
        self.assertIn("Candidate Program Files core changed after the 2.5.10 native exercise.", source)
        self.assertIn("$candidateServiceHelper.path --install-core $env:CUSTOM_CORE --sha256 $coreSha", source)

        capture = source.split("function New-CvrIdleTransactionCapture", 1)[1].split(
            "function Restore-CvrIdleTransaction", 1
        )[0]
        for assertion in (
            "Get-CvrCorePairPreimage",
            "Get-CvrLegacyState",
            "ProgramFilesEntry $corePair.programFiles",
            "Install-CvrIdleService",
            "Assert-CvrIdleBaseline",
            "coreShouldBeRunning = [bool]$false",
        ):
            with self.subTest(assertion=assertion):
                self.assertIn(assertion, capture)

        restore = source.split("function Restore-CvrIdleTransaction", 1)[1].split(
            "function Invoke-NativePhase", 1
        )[0]
        for assertion in (
            "Restore-CvrCorePairPreimage",
            "Restore-CvrLegacyState",
            "ProgramFilesEntry $Capture.corePair.programFiles",
            "Assert-CvrCorePairPreimage",
            "Assert-CvrLegacyState",
            "Get-CvrIdleBaselineObservation",
            "Assert-CvrIdleBaseline",
        ):
            with self.subTest(assertion=assertion):
                self.assertIn(assertion, restore)

        transaction = helper.split("function Invoke-CvrStateTransaction", 1)[1].split(
            "function Test-CvrInstallerActionFailureRollback", 1
        )[0]
        self.assertNotIn("Synthetic NSIS preimage fixture was not prepared.", transaction)
        self.assertIn("if ($script:legacyStateFixture)", transaction)
        self.assertIn(
            "if ($CoreShouldBeRunning -isnot [bool] -or $ControllerListening -isnot [bool])",
            guard,
        )
        self.assertIn(
            "$idleBaselineGuardScript = Join-Path $PSScriptRoot 'windows_idle_baseline_guard.ps1'",
            source,
        )
        self.assertIn(". $idleBaselineGuardScript", source)
        self.assertIn(
            "Get-Command -Name Assert-CvrIdleBaseline -CommandType Function",
            source,
        )
        guard_import = source.index(". $idleBaselineGuardScript")
        capture_call = source.index("$idleBaselineCapture = New-CvrIdleTransactionCapture")
        self.assertLess(guard_import, capture_call)

if __name__ == "__main__":
    unittest.main()
