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
            "SOURCE_COMMIT": "92107a2605e19df0cb0d8b7bb08aa9ffb6b7ee93",
            "CORE_SHA256": "dce11f5ad306e80d4ac768daf744a88a412be06162ed228059b6b084842c2e56",
            "GO_SHA256": "ccfe7ae822d2c2f41f4fe7c956199967a4dac22d0ee0d2b2bfdb440aab3b20c5",
            "XRAY_ZIP_SHA256": "e4bd9119f50ae7c41658b1abd0679ae06f98bd864a2907ff33f2f2cf7081b214",
            "XRAY_SHA256": "cc4b84d3069569f297a61f04b914f2bb37e9d202fd7b84cb50def1fc30fd40e1",
        })
        self.assertIn('cd "$work/source"', SCRIPT)
        self.assertIn('-mod=readonly', SCRIPT)
        self.assertIn('--check-tls-rejection', SCRIPT)
        self.assertNotIn('build-windows.ps1', SCRIPT)

    def test_build_temporaries_and_cleanup_are_scoped(self):
        self.assertIn('${RUNNER_TEMP:-$HERE}/stcvrc-ci.XXXXXXXX', SCRIPT)
        self.assertIn('export TMPDIR="$work/tmp" GOTMPDIR="$work/tmp"', SCRIPT)
        self.assertIn('"$work/go/bin/go" clean -modcache', SCRIPT)
        self.assertIn('available_kb < 6 * 1024 * 1024', SCRIPT)
        self.assertNotIn('rm -rf /tmp', SCRIPT)


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
        source_sha = "92107a2605e19df0cb0d8b7bb08aa9ffb6b7ee93"
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
        self.assertIn("$sourceSha = '92107a2605e19df0cb0d8b7bb08aa9ffb6b7ee93'", job)
        self.assertIn("Test fresh Windows candidate over loopback", job)
        self.assertLess(job.index("Fresh native Windows core build"),
                        job.index("Test fresh Windows candidate over loopback"))
        self.assertIn("STCVRC_CORE_PATH", job)
        self.assertIn("python windows.py", job)
        self.assertNotIn("  windows-exe-lab:", WORKFLOW)
        self.assertIn("readonly VERSION=1.19.33-STCVRC-candidate-mit-lzo-20261109", SCRIPT)
        self.assertIn("readonly BUILD_TIME=2026-11-09T00:00:00Z", SCRIPT)
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
        self.assertIn("go test -p=1 -v -mod=readonly -count=1 -timeout=25m ./...", job)


if __name__ == "__main__":
    unittest.main()
