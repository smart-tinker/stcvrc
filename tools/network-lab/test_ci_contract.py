import json
import pathlib
import re
import unittest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
WORKFLOW = (ROOT / ".github/workflows/stcvrc-network-lab.yml").read_text()
WORKFLOWS = {path.name: path.read_text() for path in
             (ROOT / ".github/workflows").glob("*.y*ml")}
SCRIPT = (HERE / "ci.sh").read_text()
WINDOWS = (HERE / "windows.py").read_text(encoding="utf-8")
SS_TESTS = (ROOT / "test/ss_test.go").read_text()
CLASH_TESTS = (ROOT / "test/clash_test.go").read_text()
HYSTERIA_TESTS = (ROOT / "test/hysteria_test.go").read_text()
SINGBOX_CONFIG_PATH = ROOT / "test/config/sing-box-shadowsocks.json"
SINGBOX_CONFIG = SINGBOX_CONFIG_PATH.read_text(encoding="utf-8") if SINGBOX_CONFIG_PATH.is_file() else ""
DEPENDABOT_PATH = ROOT / ".github/dependabot.yml"
DEPENDABOT = DEPENDABOT_PATH.read_text() if DEPENDABOT_PATH.is_file() else ""


class CIContractTests(unittest.TestCase):
    def test_runner_and_review_gates(self):
        self.assertEqual(re.findall(r"runs-on: (.+)", WORKFLOW), ["ubuntu-24.04"])
        self.assertIn("timeout-minutes: 20", WORKFLOW)
        self.assertIn("!github.event.repository.private", WORKFLOW)
        self.assertIn("!github.event.pull_request.draft", WORKFLOW)
        self.assertIn("github.event.pull_request.head.repo.full_name == github.repository", WORKFLOW)
        self.assertIn("permissions:\n  contents: read", WORKFLOW)

    def test_no_privileged_or_paid_automation_paths(self):
        self.assertEqual(set(WORKFLOWS), {
            "test.yml",
            "stcvrc-network-lab.yml",
            "codeql.yml",
            "dependency-review.yml",
        })
        release_workflow = WORKFLOWS["test.yml"]
        release_job = release_workflow.split("\n  assemble-draft-rc:\n", 1)[1]
        self.assertIn("github.event_name == 'workflow_dispatch'", release_job)
        self.assertIn("github.repository == 'smart-tinker/stcvrc'", release_job)
        self.assertIn("github.ref == 'refs/heads/codex/cvr-2.5.9-release-cycle-20261102'", release_job)
        self.assertIn("runs-on: ubuntu-24.04", release_job)
        self.assertIn("permissions:\n      contents: write", release_job)
        self.assertIn("!github.event.repository.private", release_job)
        self.assertEqual(release_job.count("GH_TOKEN: ${{ github.token }}"), 1)
        self.assertEqual(release_workflow.count("GH_TOKEN: ${{ github.token }}"), 1)
        self.assertIn('gh api "repos/$repo/releases" --paginate', release_job)
        self.assertIn("releases/assets/$asset_id", release_job)
        self.assertNotIn("releases/tags/$tag", release_job)
        self.assertIn("cmp --silent", release_job)
        self.assertNotIn("GH_TOKEN:", release_workflow.split("\n  assemble-draft-rc:\n", 1)[0])
        for name, workflow in WORKFLOWS.items():
            self.assertIn("pull_request:\n    branches: [main]", workflow, name)
            self.assertIn("permissions:\n  contents: read", workflow, name)
            self.assertIn("!github.event.repository.private", workflow, name)
            self.assertIn("!github.event.pull_request.draft", workflow, name)
            self.assertIn("github.event.pull_request.head.repo.full_name == github.repository", workflow, name)
            self.assertTrue(set(re.findall(r"runs-on: (.+)", workflow)) <= {"ubuntu-24.04", "windows-2022"})
        for name in ("test.yml", "stcvrc-network-lab.yml", "codeql.yml"):
            self.assertIn("push:\n    branches: [main]", WORKFLOWS[name], name)

        refs = re.findall(r"^\s*uses:\s*([^\s#]+)", "\n".join(WORKFLOWS.values()), re.MULTILINE)
        self.assertEqual({ref.split("@", 1)[0] for ref in refs}, {
            "actions/checkout",
            "github/codeql-action/init",
            "github/codeql-action/analyze",
            "actions/dependency-review-action",
        })
        self.assertTrue(all(re.fullmatch(r"[^@]+@[0-9a-f]{40}", ref) for ref in refs))
        self.assertIn("security-events: write", WORKFLOWS["codeql.yml"])
        self.assertIn("actions: read", WORKFLOWS["codeql.yml"])
        self.assertNotIn("security-events: write", WORKFLOWS["dependency-review.yml"])

        # GH_TOKEN remains confined to the existing gated draft-RC assembly job above.
        for forbidden in ("pull_request_target", "workflow_run:", "schedule:", "tags:",
                          "secrets.", "GITHUB_TOKEN", "write-all",
                          "upload-artifact", "download-artifact", "actions/cache", "sudo ",
                          "--privileged", "self-hosted", "docker ", "--force", "/dispatches"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, "\n".join(WORKFLOWS.values()) + SCRIPT)

    def test_draft_rc_waits_for_profile_contract(self):
        release_workflow = WORKFLOWS["test.yml"]
        release_job = release_workflow.split("\n  assemble-draft-rc:\n", 1)[1]
        self.assertIn("needs:\n      - source\n      - profile-contract\n      - cvr-2-5-10-package\n      - cvr-windows-payload", release_job)

    def test_nested_module_tidy_preserves_committed_manifests(self):
        job = WORKFLOWS["test.yml"].split("\n  test-module:\n", 1)[1]
        drift_check = 'git -C "$GITHUB_WORKSPACE/source" diff --exit-code -- test/go.mod test/go.sum'
        self.assertIn("go mod tidy", job)
        self.assertIn(drift_check, job)
        self.assertLess(job.index("go mod tidy"), job.index(drift_check))

    def test_weekly_grouped_dependabot_updates(self):
        self.assertTrue(DEPENDABOT, "missing .github/dependabot.yml")
        ecosystems = re.findall(r"^  - package-ecosystem: (.+)$", DEPENDABOT, re.MULTILINE)
        directories = re.findall(r"^    directory: (.+)$", DEPENDABOT, re.MULTILINE)
        self.assertEqual(ecosystems, ["gomod", "gomod", "github-actions"])
        self.assertEqual(directories, ["/", "/test", "/"])
        self.assertEqual(DEPENDABOT.count("interval: weekly"), 3)
        self.assertEqual(len(re.findall(r"^        - \"\*\"$", DEPENDABOT, re.MULTILINE)), 3)
        self.assertEqual(DEPENDABOT.count("update-types:"), 3)

    def test_dependabot_changes_run_the_contract_check(self):
        self.assertEqual(WORKFLOWS["test.yml"].count(".github/dependabot.yml"), 2)

    def test_templates_capture_downstream_evidence_and_privacy(self):
        bug = (ROOT / ".github/ISSUE_TEMPLATE/bug_report.yml").read_text()
        feature = (ROOT / ".github/ISSUE_TEMPLATE/feature_request.yml").read_text()
        pr = (ROOT / ".github/PULL_REQUEST_TEMPLATE.md").read_text()

        for required in ("STCVRC version", "Source commit", "Binary SHA-256",
                         "Expected result", "Observed result", "Redacted profile/config",
                         "Do not include credentials"):
            with self.subTest(required=required):
                self.assertIn(required, bug)
        self.assertNotIn("mihomo Alpha", bug)
        self.assertNotIn("log level set to `DEBUG`", bug)
        self.assertNotIn("log level 使用 DEBUG", bug)
        self.assertIn("https://github.com/smart-tinker/stcvrc/issues", bug)

        for required in ("Required scenario and upstream gap", "sanitized evidence",
                         "Definition of Done", "Upstream exit and stop conditions"):
            with self.subTest(required=required):
                self.assertIn(required, feature)
        for required in ("Exact tested revision / evidence", "RED must fail",
                         "Native Windows", "No secrets/private operational data"):
            with self.subTest(required=required):
                self.assertIn(required, pr)

        self.assertEqual(WORKFLOWS["test.yml"].count(".github/ISSUE_TEMPLATE/**"), 2)
        self.assertEqual(WORKFLOWS["test.yml"].count(".github/PULL_REQUEST_TEMPLATE.md"), 2)

    def test_exact_inputs_and_separate_candidate_checkout(self):
        pins = dict(re.findall(r"readonly (\w+)=([0-9a-f]+)\n", SCRIPT))
        self.assertEqual(pins, {
            "SOURCE_COMMIT": "086a62c3ce9a77f650786ae2eae92b68909d49e1",
            "CORE_SHA256": "d40adc330243b201d4bf060ad23f9fb9fbbd90aba846d295be842663bed5aa99",
            "GO_SHA256": "9849f4e04ee35303714e34fbc3ac8ab44ea3e448a95aa182f91e3b9b79c710ec",
            "XRAY_ZIP_SHA256": "e4bd9119f50ae7c41658b1abd0679ae06f98bd864a2907ff33f2f2cf7081b214",
            "XRAY_SHA256": "cc4b84d3069569f297a61f04b914f2bb37e9d202fd7b84cb50def1fc30fd40e1",
        })
        self.assertIn('cd "$work/source"', SCRIPT)
        self.assertIn('-mod=readonly', SCRIPT)
        self.assertIn('--check-tls-rejection', SCRIPT)
        self.assertNotIn('build-windows.ps1', SCRIPT)

    def test_candidate_go_toolchain_matches_fresh_rebuilds(self):
        manifest = json.loads((ROOT / "candidates/cvr-2.5.10/inputs.json").read_text(encoding="utf-8"))
        version = manifest["core"]["goVersion"]
        go_pins = dict(re.findall(r"readonly (\w+)=([0-9a-f]+)\n", SCRIPT))
        package_job = WORKFLOWS["test.yml"].split("\n  cvr-2-5-10-package:\n", 1)[1].split("\n  cvr-windows-payload:\n", 1)[0]
        windows_job = WORKFLOWS["test.yml"].split("\n  cvr-windows-payload:\n", 1)[1].split("\n  assemble-draft-rc:\n", 1)[0]
        linux_archive = re.search(r"https://go\.dev/dl/go([0-9.]+)\.linux-amd64\.tar\.gz", package_job)
        windows_archive = re.search(r"https://go\.dev/dl/go([0-9.]+)\.windows-amd64\.zip", windows_job)
        self.assertIsNotNone(linux_archive)
        self.assertIsNotNone(windows_archive)
        self.assertEqual(version, linux_archive.group(1))
        self.assertEqual(version, windows_archive.group(1))
        self.assertEqual(manifest["core"]["goArchiveSha256"], go_pins["GO_SHA256"])
        self.assertIn(re.escape("go" + version), windows_job)


    def test_build_temporaries_and_cleanup_are_scoped(self):
        self.assertIn('${RUNNER_TEMP:-$HERE}/stcvrc-ci.XXXXXXXX', SCRIPT)
        self.assertIn('export TMPDIR="$work/tmp" GOTMPDIR="$work/tmp"', SCRIPT)
        self.assertIn('"$work/go/bin/go" clean -modcache', SCRIPT)
        self.assertIn('available_kb < 6 * 1024 * 1024', SCRIPT)
        self.assertNotIn('rm -rf /tmp', SCRIPT)


    def test_windows_installer_update_hash_matches_candidate_manifest(self):
        script = (HERE / "windows_install_update.ps1").read_text(encoding="utf-8")
        manifest = json.loads((ROOT / "candidates/cvr-2.5.10/inputs.json").read_text(encoding="utf-8"))
        pinned = re.search(r"\$coreSha -ne '([0-9a-f]{64})'", script)
        self.assertIsNotNone(pinned)
        self.assertEqual(pinned.group(1), manifest["core"]["sha256"])


    def test_windows_installer_update_gate_is_wired_into_existing_runner(self):
        workflow = WORKFLOWS["test.yml"]
        job = workflow.split("\n  cvr-windows-payload:\n", 1)[1].split("\n  assemble-draft-rc:\n", 1)[0]
        self.assertIn("windows_install_update.ps1", job,
                      "pinned Windows install/update smoke is not wired into the existing job")
        self.assertIn("Install 2.5.8, update to 2.5.10, then recover to 2.5.8", job)
        script = (HERE / "windows_install_update.ps1").read_text(encoding="utf-8")
        for required in ("GITHUB_ACTIONS", "2.5.8", "2.5.10", "'/UPDATE'", "clash_verge_service", "ci-update-preserve.yaml"):
            with self.subTest(required=required):
                self.assertIn(required, script)


    def test_synthetic_profile_clean_path_is_checked_before_creation(self):
        script = (HERE / "windows_install_update.ps1").read_text(encoding="utf-8")
        check = script.index("if (Test-Path -LiteralPath (Split-Path -Parent $profileDirectory))")
        create = script.index("[IO.Directory]::CreateDirectory($profileDirectory)")
        self.assertLess(check, create, "preflight must run before creating the synthetic profile")
        self.assertNotIn("$profileRoot = Split-Path -Parent $profileDirectory", script)


    def test_install_smoke_traces_forbidden_process_starts(self):
        script = (HERE / "windows_install_update.ps1").read_text(encoding="utf-8")
        for required in (
            "Register-CimIndicationEvent",
            "Win32_ProcessStartTrace",
            "clash-verge.exe",
            "clash-verge-service.exe",
            "verge-mihomo.exe",
            "verge-mihomo-alpha.exe",
            "Forbidden CVR process started during install smoke:",
        ):
            with self.subTest(required=required):
                self.assertIn(required, script)


    def test_windows_install_smoke_recovers_to_the_pinned_baseline(self):
        script = (HERE / "windows_install_update.ps1").read_text(encoding="utf-8")
        workflow = WORKFLOWS["test.yml"]
        recovery = "$installRecovered = Invoke-CvrInstaller -Version '2.5.8'"
        self.assertIn(recovery, script, "the updated 2.5.10 install is not rolled back to the pinned recovery version")
        recovery_script = script[script.index(recovery):]
        for required in (
            "Assert-ProfilePreserved -Phase 'recovery'",
            "Install-CandidateCore -InstallDirectory $installRecovered -Phase 'recovery'",
        ):
            with self.subTest(required=required):
                self.assertIn(required, recovery_script)
        self.assertIn('throw "CVR $Phase did not preserve the synthetic profile marker."', script)
        self.assertIn('throw "Fresh candidate core was not restored after $Phase."', script)
        self.assertIn("Install 2.5.8, update to 2.5.10, then recover to 2.5.8", workflow)


    def test_rc5_manifest_records_bounded_windows_smoke_without_claiming_acceptance(self):
        assembly = WORKFLOWS["test.yml"].split(chr(10) + "  assemble-draft-rc:" + chr(10), 1)[1]
        self.assertIn("tag=stcvrc-1.19.33-rc.5", assembly)
        self.assertIn("STCVRC 1.19.33 RC5", assembly)
        self.assertIn('test "$release_target" = "$HEAD_SHA"', assembly)
        for status in (
            '"disposableWindowsInstallUpdateRecovery": "PASS"',
            '"authenticodeSignerAcceptance": "NOT_REVIEWED"',
            '"nativeGuiServiceTunDns": "NOT_RUN"',
            '"licenseAudit": "INCOMPLETE_ISSUE_7"',
            '"userAcceptance": "NOT_RUN"',
            '"productionDeployment": "NOT_AUTHORIZED"',
        ):
            with self.subTest(status=status):
                self.assertEqual(assembly.count(status), 2)


    def test_installed_gui_matches_exact_extracted_release_payload(self):
        workflow = WORKFLOWS["test.yml"]
        script = (HERE / "windows_install_update.ps1").read_text(encoding="utf-8")
        for required in (
            "CVR_258_GUI_SHA256",
            "CVR_2510_GUI_SHA256",
            "$guiPath = Join-Path $fullPath 'clash-verge.exe'",
            "Get-FileHash -LiteralPath $guiPath -Algorithm SHA256",
            "Installed CVR GUI SHA256 mismatch",
        ):
            with self.subTest(required=required):
                self.assertIn(required, workflow + script)


    def test_rc5_manifest_schema_version_is_read_back(self):
        assembly = WORKFLOWS["test.yml"].split(chr(10) + "  assemble-draft-rc:" + chr(10), 1)[1]
        self.assertIn('"schemaVersion": 2,', assembly)
        self.assertIn('manifest.get("schemaVersion") != 2', assembly)


    def test_failover_labs_use_fresh_mit_lzo_source_on_linux_and_windows(self):
        source_sha = "086a62c3ce9a77f650786ae2eae92b68909d49e1"
        manifest = json.loads((HERE.parents[1] / "candidates/cvr-2.5.10/inputs.json").read_text())
        self.assertEqual(manifest["core"]["sourceCommit"], source_sha)
        self.assertIn(f"readonly SOURCE_COMMIT={source_sha}", SCRIPT)

        self.assertIn("STCVRC_CORE_PATH", WINDOWS)
        self.assertIn("STCVRC_CORE_SHA256", WINDOWS)
        self.assertNotIn("stcvrc-1.19.33-rc.1", WINDOWS)
        self.assertNotIn("CORE_URL", WINDOWS)
        self.assertIn("Fresh STCVRC build path and SHA are required", WINDOWS)

        source_workflow = WORKFLOWS["test.yml"]
        job = source_workflow.split(chr(10) + "  cvr-windows-payload:" + chr(10), 1)[1].split(
            chr(10) + "  assemble-draft-rc:" + chr(10), 1
        )[0]
        self.assertIn("Fresh native Windows core build", job)
        self.assertIn("$sourceSha = '086a62c3ce9a77f650786ae2eae92b68909d49e1'", job)
        self.assertIn("Test fresh Windows candidate over loopback", job)
        self.assertLess(job.index("Fresh native Windows core build"),
                        job.index("Test fresh Windows candidate over loopback"))
        self.assertIn("STCVRC_CORE_PATH", job)
        self.assertIn("python windows.py", job)
        self.assertNotIn("  windows-exe-lab:", WORKFLOW)
        self.assertIn("readonly VERSION=1.19.33-STCVRC-candidate-mit-lzo-20261111", SCRIPT)
        self.assertIn("readonly BUILD_TIME=2026-11-11T00:00:00Z", SCRIPT)
        self.assertIn("github.com/anchore/go-lzo v0.1.1", SCRIPT)
        self.assertIn("github.com/rasky/go-lzo", SCRIPT)
        self.assertIn("core_sha256=", SCRIPT)
        self.assertIn('--core-sha256 "$core_sha256"', SCRIPT)


    def test_test_module_dependency_changes_run_protocol_suite(self):
        workflow = WORKFLOWS["test.yml"]
        self.assertEqual(workflow.count("      - test/**"), 2,
                         "test module changes must trigger on both push and pull_request")
        self.assertIn("  test-module:" + chr(10), workflow,
                      "the test module needs its own fresh hosted-runner job")
        job = workflow.split(chr(10) + "  test-module:" + chr(10), 1)[1]
        self.assertIn("runs-on: ubuntu-24.04", job)
        self.assertIn("timeout-minutes: 30", job)
        self.assertIn("working-directory: source/test", job)
        self.assertIn("go mod tidy", job)
        expected = "go test -p=1 -v -mod=readonly -count=1 -timeout=25m ./..."
        self.assertIn(expected, job)
        self.assertNotIn("-skip=", job)
        self.assertIn("Full nested test-module suite completed from clean Go caches.", job)
        self.assertNotIn("This is not a full-suite pass", job)
        self.assertIn("go mod verify", job)



    def test_vulnerability_scan_covers_exact_root_candidate_and_test_modules(self):
        workflow = WORKFLOWS["test.yml"]
        self.assertIn("  vulnerability-scan:\n", workflow)
        self.assertIn("golang.org/x/vuln/cmd/govulncheck@v1.1.4", workflow)
        self.assertGreaterEqual(workflow.count("govulncheck"), 3)
        self.assertIn("SOURCE_SHA", workflow)
        self.assertIn("CANDIDATE_SOURCE_SHA", workflow)
        self.assertIn("working-directory: source/test", workflow)
        self.assertIn("086a62c3ce9a77f650786ae2eae92b68909d49e1", workflow)
        scan_job = workflow.split("\n  vulnerability-scan:\n", 1)[1].split("\n  source:\n", 1)[0]
        self.assertNotIn(r"\\n", scan_job)
        self.assertNotIn("runner.temp", scan_job)
        self.assertIn("RUNNER_TEMP", scan_job)
        self.assertEqual(scan_job.count("continue-on-error: true"), 4)
        self.assertIn("Enforce all three vulnerability scans", scan_job)
        source_job = workflow.split("\n  source:\n", 1)[1].split("\n  profile-contract:\n", 1)[0]
        self.assertIn("    needs: vulnerability-scan", source_job)


    def test_issue25_unresolved_protocol_cases_run_individually(self):
        job = WORKFLOWS["test.yml"].split(chr(10) + "  test-module:" + chr(10), 1)[1]
        self.assertIn("Run each issue-25 protocol case independently", job)
        step = job.split("      - name: Run each issue-25 protocol case independently", 1)[1]
        self.assertIn("        working-directory: source/test", step)
        for name in (
            "TestMihomo_Hysteria",
            "TestMihomo_ShadowsocksUoT",
            "TestMihomo_TrojanGrpc",
            "TestMihomo_VlessXTLS",
            "TestMihomo_VmessPacketAddr",
            "TestMihomo_VmessWebsocketXray0RTT",
        ):
            with self.subTest(name=name):
                self.assertIn(name, job)
        self.assertIn('go test -p=1 -v -mod=readonly -count=1 -timeout=25m -run="^${case_name}$" .', job)
        candidate_cases = (
            "TestMihomo_Hysteria",
            "TestMihomo_ShadowsocksUoT",
            "TestMihomo_TrojanGrpc",
            "TestMihomo_VlessXTLS",
            "TestMihomo_VmessPacketAddr",
            "TestMihomo_VmessWebsocketXray0RTT",
        )
        for name in candidate_cases:
            with self.subTest(candidate=name):
                self.assertIn(name, job)
        self.assertIn("candidate_sha=086a62c3ce9a77f650786ae2eae92b68909d49e1", job)
        self.assertIn('go test -p=1 -v -mod=readonly -count=1 -timeout=10m -run="^${candidate_case}$" .', job)

    def test_issue25_compares_the_same_cases_on_exact_33_sources(self):
        job = WORKFLOWS["test.yml"].split(chr(10) + "  test-module:" + chr(10), 1)[1]
        step = job.split("      - name: Run each issue-25 protocol case independently", 1)[1]
        self.assertIn("upstream_sha=3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8", step)
        self.assertIn("candidate_sha=086a62c3ce9a77f650786ae2eae92b68909d49e1", step)
        self.assertIn("https://github.com/MetaCubeX/mihomo.git", step)
        self.assertIn("SOURCE_SHA: ${{ github.event.pull_request.head.sha || github.sha }}", step)
        self.assertIn('test "$(git -C "$upstream" rev-parse HEAD)" = "$upstream_sha"', step)
        self.assertIn('test "$(git -C "$candidate" rev-parse HEAD)" = "$candidate_sha"', step)
        for name in (
            "TestMihomo_Hysteria",
            "TestMihomo_ShadowsocksUoT",
            "TestMihomo_TrojanGrpc",
            "TestMihomo_VmessWebsocketXray0RTT",
            "TestMihomo_VlessXTLS",
            "TestMihomo_VmessPacketAddr",
        ):
            with self.subTest(name=name):
                self.assertIn(name, step)
        baseline_cases = step.split("for baseline_case in \\\n", 1)[1].split("; do", 1)[0]
        candidate_cases = step.split("for candidate_case in \\\n", 1)[1].split("; do", 1)[0]
        self.assertIn("TestMihomo_VlessXTLS", baseline_cases)
        self.assertIn("TestMihomo_VmessPacketAddr", baseline_cases)
        self.assertIn("TestMihomo_VlessXTLS", candidate_cases)
        self.assertIn("TestMihomo_VmessPacketAddr", candidate_cases)
        self.assertIn('go test -p=1 -v -mod=readonly -count=1 -timeout=10m -run="^${baseline_case}$" .', step)
        self.assertIn('go test -p=1 -v -mod=readonly -count=1 -timeout=10m -run="^${candidate_case}$" .', step)
        self.assertIn('GOCACHE="$RUNNER_TEMP/issue-25-upstream-go-cache"', step)
        self.assertIn('GOCACHE="$RUNNER_TEMP/issue-25-candidate-go-cache"', step)
        self.assertIn('cp -a "$GITHUB_WORKSPACE/source/test" "$upstream/test"', step)
        self.assertIn('cp -a "$GITHUB_WORKSPACE/source/test" "$candidate/test"', step)

    def test_issue25_selected_xray_fixtures_use_digest_pinned_image(self):
        uot = SS_TESTS.split("func TestMihomo_ShadowsocksUoT", 1)[1].split("\nfunc ", 1)[0]
        self.assertIn("Image:        ImageSingBox", uot)
        self.assertNotIn("ImageXray", uot)
        self.assertIn('sing-box-shadowsocks.json', uot)
        self.assertIn('ImageSingBox        = "ghcr.io/sagernet/sing-box:v1.12.0@sha256:d7403cae8ffa17529b8676402346f2ca185a56dae8d90b73822d51421a850541"', CLASH_TESTS)
        self.assertTrue(SINGBOX_CONFIG, "missing pinned sing-box UoT server fixture")

    def test_issue25_xray_fixtures_allow_only_loopback_probe_endpoint(self):
        expected = [{
            "action": "allow",
            "network": "tcp,udp",
            "port": "10001",
            "ip": ["127.0.0.1/32"],
        }]
        for name in ("trojan-grpc.json", "vmess-ws-xray-0rtt.json"):
            with self.subTest(config=name):
                config = json.loads((ROOT / "test/config" / name).read_text(encoding="utf-8"))
                settings = config["outbounds"][0].get("settings", {})
                self.assertEqual(settings.get("finalRules"), expected)


    def test_hysteria_uses_bounded_tcp_and_udp_echo_smokes(self):
        case = HYSTERIA_TESTS.split("func TestMihomo_Hysteria", 1)[1].split(chr(10) + "}", 1)[0]
        self.assertIn("shortcut: bound Hysteria to TCP/UDP echo; restore bulk stress after repeatable hosted-runner evidence", case)
        self.assertIn("testPingPongWithConn", case)
        self.assertIn("testPingPongWithPacketConn", case)
        self.assertNotIn("testSuit", case)
        self.assertNotIn("testLargeData", case)

    def test_issue25_uot_fixture_blocks_external_egress(self):
        self.assertTrue(SINGBOX_CONFIG, "missing pinned sing-box UoT server fixture")
        if not SINGBOX_CONFIG:
            return
        config = json.loads(SINGBOX_CONFIG)
        self.assertEqual(config["inbounds"][0]["type"], "shadowsocks")
        self.assertEqual(config["inbounds"][0]["listen_port"], 10002)
        self.assertEqual(config["inbounds"][0]["method"], "aes-128-gcm")
        self.assertEqual(config["route"]["rules"], [{
            "network": ["tcp", "udp"],
            "ip_cidr": ["127.0.0.1/32"],
            "port": 10001,
            "outbound": "direct",
        }])
        self.assertEqual(config["route"]["final"], "block")

    def test_issue25_exact_upstream_failures_fail_the_job(self):
        job = WORKFLOWS["test.yml"].split(chr(10) + "  test-module:" + chr(10), 1)[1]
        step = job.split("      - name: Run each issue-25 protocol case independently", 1)[1]
        self.assertIn(
            "if (( case_status != 0 || upstream_status != 0 || candidate_status != 0 )); then exit 1; fi",
            step,
        )

    def test_issue25_legacy_vless_xtls_is_an_explicit_unsupported_assertion(self):
        source = (ROOT / "test/vless_test.go").read_text(encoding="utf-8")
        case = source.split("func TestMihomo_VlessXTLS", 1)[1].split("\nfunc ", 1)[0]
        self.assertIn('Flow:           "xtls-rprx-direct"', case)
        self.assertIn('assert.ErrorContains(t, err, "unsupported xtls flow type: xtls-rprx-direct")', case)
        self.assertNotIn("startContainer(", case)


if __name__ == "__main__":
    unittest.main()
