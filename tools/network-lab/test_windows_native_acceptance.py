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
    def test_fresh_windows_core_is_bound_to_rc11_build_report_and_preserves_rc9_pin(self):
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
        for identity in (
            "$build.version -cne '1.19.33-STCVRC-rc.11'",
            "$build.core_source_commit -cne 'a884ad53a3999dd35acab979e0bb040c47f6dbc9'",
            "$build.selected_dependency_versions.'github.com/gobwas/ws' -cne 'v1.5.0'",
            "$build.selected_dependency_versions.'github.com/insomniacslk/dhcp' -cne 'v0.0.0-20260719225207-c76316d4aa82'",
            "$coreEntries[0].size",
            "Get-FileHash -LiteralPath $env:CUSTOM_CORE -Algorithm SHA256",
            "windows_core_identity.ps1",
            "$expectedCoreVersion = Get-StcvrcWindowsCoreVersionIdentity -Build $build",
            "Test-StcvrcWindowsCoreVersionOutput -VersionLines",
            "Assert-StcvrcWindowsCoreVersionOutputVectors",
        ):
            with self.subTest(identity=identity):
                self.assertIn(identity, source)
        self.assertNotIn("$manifest.windowsNativeCandidate", source)
        self.assertNotIn("stcvrc-1.19.33-rc.9", source)
        identity = source.split("$coreSha = [string]$coreEntries[0].sha256", 1)[1].split("$installerPaths =", 1)[0]
        self.assertLess(identity.index("(Get-Item -LiteralPath $env:CUSTOM_CORE).Length"),
                        identity.index("$env:CUSTOM_CORE -v"))
        self.assertLess(identity.index("Get-FileHash -LiteralPath $env:CUSTOM_CORE"),
                        identity.index("$env:CUSTOM_CORE -v"))

    def test_core_preimage_backups_require_pinned_path_hash_and_acl(self):
        source = INSTALLER_SMOKE.read_text(encoding="utf-8")
        runtime = (INSTALLER_SMOKE.parent / "windows_idle_target_runtime.ps1").read_text(encoding="utf-8")
        path_helper = (INSTALLER_SMOKE.parent / "windows_core_preimage_paths.ps1").read_text(encoding="utf-8")
        idle_transaction = (INSTALLER_SMOKE.parent / "windows_idle_transaction.ps1").read_text(encoding="utf-8")
        workflow = (ROOT / ".github" / "workflows" / "test.yml").read_text(encoding="utf-8")

        self.assertIn("-Label $target.backupLabel", runtime)
        self.assertIn("-Label '258-stock'", source)
        self.assertIn("Save-CvrCorePreimageBackup", source + runtime)
        self.assertIn("Get-CvrCorePreimageBackupBytes", source + runtime)
        self.assertIn("backupPathPin = $backup.backupPathPin", source + runtime)
        self.assertIn("backupDirectorySddl = $backup.backupDirectorySddl", source + runtime)
        self.assertIn("[IO.Path]::GetFileName($backupPath) -cne 'verge-mihomo.exe'", path_helper)
        self.assertIn("$backupPath -ine $backupPathPin", path_helper)
        self.assertIn("backup SHA256 mismatch", path_helper)
        self.assertIn("Assert-CvrIdleCaptureAcl -Path $backupDirectory -Directory", path_helper)
        self.assertIn("Assert-CvrIdleCaptureAcl -Path $backupPath", path_helper)
        self.assertIn("directory SDDL SHA256 expected=", path_helper)
        self.assertIn("file SDDL SHA256 expected=", path_helper)
        self.assertIn("[IO.Path]::GetFullPath([string]$pinnedFiles[$entryInfo.pin])", idle_transaction)
        self.assertIn("Get-CvrCorePreimageBackupBytes -Entry $entry", idle_transaction)

        restore = runtime.split("function Restore-CvrCorePairPreimage", 1)[1].split(
            "function Invoke-CvrOverlayReinstall", 1
        )[0]
        pf_validation = restore.index("Get-CvrCorePreimageBackupBytes -Entry $Preimage.programFiles")
        service_validation = restore.index("Get-CvrCorePreimageBackupBytes -Entry $Preimage.service")
        first_live_write = restore.index("Restore-CvrCoreFilePreimage -Entry $Preimage.programFiles")
        self.assertLess(pf_validation, first_live_write)
        self.assertLess(service_validation, first_live_write)

        self.assertIn("Test-CvrCorePreimageBackupPathContract", path_helper)
        check = workflow.index("Test-CvrCorePreimageBackupPathContract -Root $env:RUNNER_TEMP")
        build = workflow.index("- name: Fresh native Windows core build")
        self.assertLess(check, build)

    def test_packaged_idle_candidate_operator_contains_guarded_action_and_is_called(self):
        smoke = INSTALLER_SMOKE.read_text(encoding="utf-8")
        operator = (INSTALLER_SMOKE.parent / "windows_idle_preflight_target_operator.ps1").read_text(encoding="utf-8")
        runtime = (INSTALLER_SMOKE.parent / "windows_idle_target_runtime.ps1").read_text(encoding="utf-8")
        packager = (INSTALLER_SMOKE.parent / "rc11_stage_package.py").read_text(encoding="utf-8")
        for staged in ("windows_idle_preflight_target_operator.ps1", "windows_idle_target_runtime.ps1", "idle-target-candidate-traffic.md"):
            with self.subTest(staged=staged):
                self.assertIn(staged, packager)
        self.assertNotIn("windows_install_update.ps1", packager)
        self.assertIn(". (Join-Path $script:idleStageRoot 'tools\\network-lab\\windows_idle_preflight_target_operator.ps1')", smoke)
        self.assertIn("Invoke-CvrIdlePreflightTargetAcceptance", smoke)
        self.assertIn("windows_idle_target_runtime.ps1", operator)
        self.assertIn("Get-CvrIdlePackageStageBinding", operator)
        self.assertIn("manifest.files", operator)
        for callback in ("ActionScript = {", "CandidateCheckScript = {", "RestoreScript = {", "VerifyScript = {"):
            with self.subTest(callback=callback):
                self.assertIn(callback, operator)
        self.assertIn("[Parameter(Mandatory)][scriptblock]$CandidateTrafficScript", operator)
        self.assertIn("Assert-CvrIdleCandidateTrafficVerification", operator)
        self.assertIn("& $candidateTrafficScript $callbackRequest", operator)
        self.assertNotIn("Invoke-CvrIdlePackagedNativePhase", operator)
        self.assertIn("Invoke-NativePhase -Phase exercise", smoke)
        self.assertIn("Invoke-NativePhase -Phase recovery", smoke)
    def test_recovery_restores_original_split_core_pair_before_native_check(self):
        smoke = INSTALLER_SMOKE.read_text(encoding="utf-8")
        operator = (INSTALLER_SMOKE.parent / "windows_idle_preflight_target_operator.ps1").read_text(encoding="utf-8")
        runtime = (INSTALLER_SMOKE.parent / "windows_idle_target_runtime.ps1").read_text(encoding="utf-8")
        native = NATIVE_SMOKE.read_text(encoding="utf-8")
        self.assertIn("Invoke-CvrIdlePreflightTargetAcceptance", smoke)
        self.assertIn("Restore-CvrCorePairPreimage -Preimage $capture.corePair -HelperVersion '2.5.8'", operator)
        self.assertIn("corePair.programFiles.sha256 -cne [string]$context.ExpectedPins.programFilesCore", operator)
        self.assertIn("corePair.service.sha256 -cne [string]$context.ExpectedPins.serviceCore", operator)
        self.assertNotIn("corePair.programFiles.sha256 -ceq $candidateCoreSha", operator)
        self.assertNotIn("corePair.service.sha256 -cne $candidateCoreSha", operator)
        self.assertIn("Invoke-CvrIdleStoppedMutation -StopScript", operator)
        self.assertEqual(operator.count("Invoke-CvrIdleStoppedMutation -StopScript"), 3)
        self.assertIn("Restore-CvrCorePairPreimage", runtime)
        self.assertIn("Install-CvrIdleService -Version '2.5.8'", operator)
        self.assertIn("recoveryServiceCorePreimagePath = [string]$capture.corePair.service.backup", operator)
        self.assertIn("Join-Path ([IO.Path]::GetFullPath($env:STCVRC_STAGE_ROOT)) 'local'", native)
        self.assertIn("-ExpectedProgramFilesCoreSha $request.expectedProgramFilesCoreSha256", smoke)
        self.assertIn("-ExpectedServiceCoreSha $request.expectedServiceCoreSha256", smoke)
        self.assertIn("--install-service --install-core $preimagePath --sha256 $script:expectedServiceCoreSha", native)
        self.assertIn("$script:expectedProgramFilesCoreSha -cne $coreSha", native)
        self.assertIn("$script:expectedServiceCoreSha -cne $coreSha", native)
        service_identity = native.split("function Assert-LiveCoreIdentity", 1)[1].split(
            "function Install-CvrRecoveryService", 1
        )[0]
        self.assertIn("$script:expectedServiceCoreSha", service_identity)
        self.assertIn("Assert-LiveCoreIdentity", native)
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
        smoke = INSTALLER_SMOKE.read_text(encoding="utf-8")
        operator = (INSTALLER_SMOKE.parent / "windows_idle_preflight_target_operator.ps1").read_text(encoding="utf-8")
        seed = smoke.index("Invoke-NativePhase -Phase seed")
        candidate_callback = smoke.index("$candidateTrafficScript = {")
        exercise = smoke.index("Invoke-NativePhase -Phase exercise", candidate_callback)
        recovery_callback = smoke.index("$recoveryVerificationScript = {", exercise)
        recovery = smoke.index("Invoke-NativePhase -Phase recovery", recovery_callback)
        invoke = smoke.index("Invoke-CvrIdlePreflightTargetAcceptance", recovery)
        self.assertLess(seed, candidate_callback)
        self.assertLess(candidate_callback, exercise)
        self.assertLess(exercise, recovery_callback)
        self.assertLess(recovery_callback, recovery)
        self.assertLess(recovery, invoke)

        action = operator.index("ActionScript = {")
        traffic = operator.index("& $candidateTrafficScript $callbackRequest", action)
        candidate = operator.index("CandidateCheckScript = {", traffic)
        restore = operator.index("RestoreScript = {", candidate)
        recovery_check = operator.index("& $recoveryVerificationScript $recoveryRequest", restore)
        verify = operator.index("VerifyScript = {", recovery_check)
        self.assertLess(action, traffic)
        self.assertLess(traffic, candidate)
        self.assertLess(candidate, restore)
        self.assertLess(restore, recovery_check)
        self.assertLess(recovery_check, verify)
        self.assertIn("Invoke-CvrInstaller -Version '2.5.10'", operator)
        self.assertIn("Invoke-CvrInstaller -Version '2.5.8'", operator)
    def test_nsis_side_effects_and_split_core_preimages_are_restored(self):
        source = INSTALLER_SMOKE.read_text(encoding="utf-8")
        helper = (INSTALLER_SMOKE.parent / "windows_legacy_state_transaction.ps1").read_text(encoding="utf-8")
        self.assertIn("windows_legacy_state_transaction.ps1", source)
        self.assertIn("Invoke-CvrStateTransaction", helper)
        self.assertIn("Assert-CvrInstallerChangedLegacyPreimage", helper)
        self.assertIn("Restore-CvrLegacyState", helper)
        self.assertIn("$acl.SetSecurityDescriptorSddlForm([string]$entry.sddl)", helper)
        self.assertIn("if ((Get-Acl -LiteralPath $path -ErrorAction Stop).Sddl -cne [string]$entry.sddl)", helper)
        self.assertIn("Set-Acl -LiteralPath $path -AclObject $acl -ErrorAction Stop", helper)
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
                $names = @('coreDnsPort', 'profileDnsPort', 'appDnsPort', 'subscriptionDnsPort')
                $ports = @($names | ForEach-Object { [int]$first.$_ })
                if (@($ports | Sort-Object -Unique).Count -ne 4) {
                    throw 'The persistent DNS port plan must use four distinct UDP ports.'
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
            self.assertIn(
                "subscriptionDnsPort",
                plan,
                "the shared UDP port plan must include the subscription DNS listener",
            )
            ports = [plan[name] for name in ("coreDnsPort", "profileDnsPort", "appDnsPort", "subscriptionDnsPort")]
            self.assertEqual(len(set(ports)), 4)
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
        smoke = INSTALLER_SMOKE.read_text(encoding="utf-8")
        operator = (INSTALLER_SMOKE.parent / "windows_idle_preflight_target_operator.ps1").read_text(encoding="utf-8")
        runtime = (INSTALLER_SMOKE.parent / "windows_idle_target_runtime.ps1").read_text(encoding="utf-8")
        self.assertIn("function Invoke-CvrOverlayReinstall", runtime)
        overlay = runtime.split("function Invoke-CvrOverlayReinstallAction", 1)[1].split(
            "\nfunction ", 1
        )[0]
        for assertion in (
            "Start-Process -FilePath $guiPath -PassThru",
            "$installerPaths['2.5.10']",
            "'/UPDATE'",
            "Expected the pinned CVR GUI process to exit during overlay",
            "Get-InstalledCvrDirectory -ExpectedVersion '2.5.10'",
        ):
            with self.subTest(assertion=assertion):
                self.assertIn(assertion, overlay)
        action = operator.split("ActionScript = {", 1)[1].split("CandidateCheckScript = {", 1)[0]
        first_core = action.index("Install-CandidateCore -InstallDirectory $install2510")
        overlay_call = action.index("Invoke-CvrOverlayReinstall -InstallDirectory $install2510")
        second_core = action.index("Install-CandidateCore -InstallDirectory $install2510", first_core + 1)
        self.assertLess(first_core, overlay_call)
        self.assertLess(overlay_call, second_core)
        self.assertIn("Invoke-NativePhase -Phase exercise", smoke)
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
            "Stop-StcvrcSshFixtureProcess -Fixture $fixture -TimeoutSeconds 5",
            "Remove-StcvrcSshFixture -Fixture $fixture -TimeoutSeconds 5",
            "SSH fixture cleanup verified: process_exited=true executable_removed=true directory_removed=true",
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


    def test_ssh_fixture_cleanup_behavior_runs_before_native_build(self):
        workflow = (ROOT / ".github" / "workflows" / "test.yml").read_text(encoding="utf-8")
        helper = ROOT / "tools" / "network-lab" / "windows_ssh_fixture_cleanup.ps1"
        behavior = ROOT / "tools" / "network-lab" / "test_windows_ssh_fixture_cleanup.ps1"
        self.assertTrue(helper.is_file())
        self.assertTrue(behavior.is_file())
        self.assertIn("Test SSH fixture cleanup before native build", workflow)
        self.assertIn("test_windows_ssh_fixture_cleanup.ps1", workflow)
        self.assertLess(workflow.index("Test SSH fixture cleanup before native build"), workflow.index("Fresh native Windows core build"))

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
        smoke = INSTALLER_SMOKE.read_text(encoding="utf-8")
        operator = (INSTALLER_SMOKE.parent / "windows_idle_preflight_target_operator.ps1").read_text(encoding="utf-8")
        runtime = (INSTALLER_SMOKE.parent / "windows_idle_target_runtime.ps1").read_text(encoding="utf-8")
        adapter = (INSTALLER_SMOKE.parent / "windows_idle_transaction.ps1").read_text(encoding="utf-8")
        packager = (INSTALLER_SMOKE.parent / "rc11_stage_package.py").read_text(encoding="utf-8")
        workflow = (ROOT / ".github" / "workflows" / "test.yml").read_text(encoding="utf-8")

        for assertion in (
            "windows_idle_capture_operator.ps1",
            "Invoke-CvrIdleOperatorChild",
            "STCVRC_STAGE_MANIFEST_SHA256",
            "Get-CvrIdlePackageStageBinding",
            "ExpectedPackageManifestSha256",
            "ExpectedPlanSha256 = $ExpectedPlanSha256",
            "ExpectedPins = $expectedPins",
            "RefreshObservationScript = {",
        ):
            with self.subTest(smoke_assertion=assertion):
                self.assertIn(assertion, smoke + operator)

        capture_seed = smoke[smoke.index("$captureSeed = [ordered]@{"):smoke.index("$captureChild = Invoke-CvrIdleOperatorChild")]
        for assertion in (
            "ExpectedOwnerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
            "ExpectedSessionId = [Diagnostics.Process]::GetCurrentProcess().SessionId",
            "ExpectedServiceAccountSid =",
            "corePair = $script:idleCorePair",
            "legacyState = $script:idleLegacyState",
            "pinnedFiles = $script:idlePinnedFiles",
        ):
            with self.subTest(capture_assertion=assertion):
                self.assertIn(assertion, capture_seed)

        action = operator.index("ActionScript = {")
        candidate = operator.index("CandidateCheckScript = {", action)
        restore = operator.index("RestoreScript = {", candidate)
        verify = operator.index("VerifyScript = {", restore)
        invoke = operator.index("Invoke-CvrIdlePreflightTargetTransaction @targetTransactionArguments", verify)
        self.assertLess(action, candidate)
        self.assertLess(candidate, restore)
        self.assertLess(restore, verify)
        self.assertLess(verify, invoke)

        for assertion in (
            "CandidateTrafficScript",
            "Assert-CvrIdleCandidateTrafficVerification",
            "capture.corePair.programFiles.sha256 -cne [string]$context.ExpectedPins.programFilesCore",
            "capture.corePair.service.sha256 -cne [string]$context.ExpectedPins.serviceCore",
            "Invoke-CvrInstaller -Version '2.5.10'",
            "Invoke-CvrOverlayReinstall -InstallDirectory $install2510",
            "Restore-CvrIdleFilePreimage -Entry $capture.rollbackState.gui",
            "Restore-CvrIdleFilePreimage -Entry $capture.rollbackState.serviceExe",
            "Restore-CvrCorePairPreimage -Preimage $capture.corePair -HelperVersion '2.5.8'",
            "Restore-CvrLegacyState -State $capture.legacyState",
            "Install-CvrIdleService -Version '2.5.8'",
            "Assert-CvrIdleRollbackState",
        ):
            with self.subTest(operator_assertion=assertion):
                self.assertIn(assertion, operator)

        for assertion in (
            "[string]$Context.ExpectedPins[$name]",
            "CVR 2.5.10",
            "Get-CvrServiceInstallHelper",
            "Restore-CvrCorePairPreimage",
            "Assert-CvrCorePairPreimage",
            "Get-CvrIdleBaselineObservation",
            "Stop-CvrRunnerRuntime",
        ):
            with self.subTest(runtime_assertion=assertion):
                self.assertIn(assertion, runtime)

        self.assertNotIn("windows_install_update.ps1", packager)
        self.assertIn("windows_idle_target_runtime.ps1", packager)
        self.assertIn("idle-target-candidate-traffic.md", packager)
        self.assertIn("Invoke-NativePhase -Phase exercise", smoke)
        self.assertIn("TrafficChallenge", smoke)
        self.assertIn("TrafficReceiptPath", smoke)
        self.assertIn("Invoke-NativePhase -Phase recovery", smoke)
        for assertion in ("Assert-CvrLegacyStatePath", "Get-CvrIdleFilePreimageBackupBytes", "ActionFailure = $actionFailure", "RestoreFailure = $restoreFailure"):
            with self.subTest(transaction_guard=assertion):
                self.assertIn(assertion, adapter)

        stage = workflow.split("- name: Package protected stage for native idle transaction", 1)[1].split(
            "\n      - name:", 1
        )[0]
        self.assertIn("'pack','--source-root'", stage)
        self.assertIn("& python $packager @packArguments", stage)
        self.assertIn("Get-CvrIdlePackageStageBinding", stage)
        self.assertIn("Set-CvrIdleCaptureAcl", stage)
        self.assertIn("STCVRC_STAGE_ROOT=", stage)
        self.assertLess(
            workflow.index("- name: Package protected stage for native idle transaction"),
            workflow.index("- name: Install, native acceptance, then recover to 2.5.8"),
        )
    def test_packaged_target_requires_candidate_traffic_evidence(self):
        operator = (INSTALLER_SMOKE.parent / "windows_idle_preflight_target_operator.ps1").read_text(encoding="utf-8")
        native = NATIVE_SMOKE.read_text(encoding="utf-8")
        smoke = INSTALLER_SMOKE.read_text(encoding="utf-8")
        self.assertIn("[Parameter(Mandatory)][scriptblock]$CandidateTrafficScript", operator)
        self.assertIn("[Parameter(Mandatory)][scriptblock]$RecoveryVerificationScript", operator)
        self.assertIn("Assert-CvrIdleCandidateTrafficVerification", operator)
        self.assertIn("observedAtUtcMs", operator)
        self.assertIn("& $recoveryVerificationScript $recoveryRequest", operator)
        self.assertIn("CandidateTrafficScript", smoke)
        self.assertIn("-RecoveryVerificationScript $recoveryVerificationScript", smoke)
        self.assertIn("candidateServiceExeSha256 -cne [string]$nativeCallbackContext.CandidateServiceExeSha256", smoke)
        self.assertIn("-NativeFailures $nativeCallbackContext.NativeFailures", smoke)
        self.assertIn("candidateGuiSha256 -cne [string]$nativeCallbackContext.CandidateGuiSha256", smoke)
        self.assertIn("candidateGuiSha256 = $expectedGuiSha", native)
        self.assertIn("candidateServiceExeSha256 = $script:expectedServiceSha", native)
        self.assertIn("candidateGuiSha256", operator)
        self.assertIn("candidateServiceExeSha256", operator)
        self.assertIn("TrafficReceiptPath", smoke)
        self.assertIn("Add-CandidateTrafficProbeEvidence -Protocol dns", native)
        self.assertIn("Add-CandidateTrafficProbeEvidence -Protocol http", native)
        self.assertIn("Candidate traffic receipt did not cover exactly the approved probes.", native)
        self.assertIn("verifiedPid", native)
if __name__ == "__main__":
    unittest.main()
