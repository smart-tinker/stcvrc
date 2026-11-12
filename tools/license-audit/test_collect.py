import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from collect import (
    CHACHA_API,
    _github_json,
    _go_license_report_template,
    _has_module_build_info,
    _manual_go_overrides,
    _parse_go_license_report,
    verify_artifact,
)
from generate_notices import AuditIncomplete


class GoLicenseToolBuildInfoTests(unittest.TestCase):
    def test_matches_the_pinned_module_in_go_version_m_tabular_output(self):
        build_info = (
            "go-licenses: go1.26.11\n"
            "\tpath\tgithub.com/google/go-licenses/v2\n"
            "\tmod\tgithub.com/google/go-licenses/v2\tv2.0.1\th1:example=\n"
        )

        self.assertTrue(_has_module_build_info(build_info, "github.com/google/go-licenses/v2", "v2.0.1"))

    def test_does_not_accept_a_dependency_row_or_different_module_version(self):
        build_info = (
            "\tdep\tgithub.com/google/go-licenses/v2\tv2.0.1\th1:example=\n"
            "\tmod\tgithub.com/google/go-licenses/v2\tv2.0.2\th1:example=\n"
        )

        self.assertFalse(_has_module_build_info(build_info, "github.com/google/go-licenses/v2", "v2.0.1"))


class GithubApiMetadataTests(unittest.TestCase):
    def test_uses_only_pinned_github_api_commit_routes(self):
        url = f"{CHACHA_API}/commits/v1.2.3"
        with patch.dict("os.environ", {"GH_TOKEN": "fixture-token"}):
            with patch("collect._run", return_value='{"sha":"fixture"}') as run:
                self.assertEqual(_github_json(url), {"sha": "fixture"})
            args = run.call_args.args[0]
            self.assertEqual(args[:2], ["gh", "api"])
            self.assertEqual(args[2], url.split("://", 1)[1].split("/", 1)[1])
            self.assertEqual(args[3:], ["--hostname", "github.com"])
            self.assertNotIn("fixture-token", args)

            rejected = (
                url.replace("api.github.com", "raw.githubusercontent.com"),
                url.replace("api.github.com", "api.github.com.example.invalid"),
                url.replace("/commits/", "/releases/download/"),
                url + "?redirect=https://example.invalid",
            )
            for candidate in rejected:
                with self.subTest(candidate=candidate):
                    with patch("collect._run") as blocked_run:
                        with self.assertRaises(AuditIncomplete):
                            _github_json(candidate)
                    blocked_run.assert_not_called()

    def test_requires_the_workflow_read_token(self):
        url = f"{CHACHA_API}/commits/v1.2.3"
        with patch.dict("os.environ", {}, clear=True):
            with patch("collect._run") as run:
                with self.assertRaises(AuditIncomplete):
                    _github_json(url)
        run.assert_not_called()


class ManualGoOverrideRuntimeScopeTests(unittest.TestCase):
    def test_does_not_fetch_manual_proofs_for_declared_but_uncompiled_modules(self):
        evidence_path = Path(__file__).resolve().parent / "fixtures" / "expected-rc7-sources.json"
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        declared_modules = {
            item["module"]: {"Version": item["version"]}
            for item in evidence["meta_gpl_overrides"]
        }
        chacha = evidence["chacha_mit_evidence"]
        declared_modules[chacha["module"]] = {"Version": chacha["version"]}

        with patch("collect._fetch") as fetch:
            overrides = _manual_go_overrides(
                declared_modules,
                set(),
                {},
                Path(__file__).resolve().parents[2],
            )

        self.assertEqual(overrides, [])
        fetch.assert_not_called()


class GoLicenseReportTemplateTests(unittest.TestCase):
    def test_unknown_license_path_skips_file_read_and_keeps_sibling_row(self):
        go = shutil.which("go")
        if go is None:
            self.skipTest("Go is required to exercise the production text/template")

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            template_path = root / "license-report.tmpl"
            template_path.write_text(_go_license_report_template(), encoding="utf-8")
            probe_path = root / "template_probe.go"
            probe_path.write_text(
                """package main
import (
    "fmt"
    "os"
    "text/template"
)
type licenseRow struct {
    Name, Version, LicenseURL, LicenseName, LicensePath, text string
}
func (r licenseRow) LicenseText() (string, error) {
    if r.LicensePath == "" || r.LicensePath == "Unknown" {
        return "", fmt.Errorf("LicenseText must not read an unknown path")
    }
    return r.text, nil
}
func main() {
    t, err := template.ParseFiles(os.Args[1])
    if err != nil { panic(err) }
    rows := []licenseRow{
        {Name: "unknown-module", Version: "v1", LicenseURL: "Unknown", LicenseName: "Unknown", LicensePath: "Unknown"},
        {Name: "unreviewed-sibling", Version: "v2", LicenseURL: "https://example.invalid/LICENSE", LicenseName: "MIT", LicensePath: "LICENSE", text: "sibling license text"},
    }
    if err := t.Execute(os.Stdout, rows); err != nil { panic(err) }
}
""",
                encoding="utf-8",
            )
            result = subprocess.run(
                [go, "run", str(probe_path), str(template_path)],
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        rows = _parse_go_license_report(result.stdout)
        self.assertEqual([row["Name"] for row in rows], ["unknown-module", "unreviewed-sibling"])
        self.assertEqual(rows[0]["LicenseText"], "")
        self.assertEqual(rows[1]["LicenseText"], "sibling license text")


class ArtifactEvidenceTests(unittest.TestCase):
    def test_accepts_binary_bytes_matching_source_build_report(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            data = b"fresh candidate"
            (output / "verge-mihomo.exe").write_bytes(data)
            build = {
                "artifacts": [{
                    "name": "verge-mihomo.exe",
                    "target": "windows/amd64",
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "size": len(data),
                }]
            }

            record = verify_artifact(build, output, "verge-mihomo.exe", "windows/amd64")

            self.assertEqual(record["sha256"], hashlib.sha256(data).hexdigest())
            self.assertEqual(record["size"], len(data))

    def test_rejects_binary_bytes_that_disagree_with_the_source_build_record(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            (output / "verge-mihomo.exe").write_bytes(b"tampered candidate")
            build = {
                "artifacts": [{
                    "name": "verge-mihomo.exe",
                    "target": "windows/amd64",
                    "sha256": hashlib.sha256(b"recorded candidate").hexdigest(),
                    "size": len(b"recorded candidate"),
                }]
            }

            with self.assertRaises(AuditIncomplete):
                verify_artifact(build, output, "verge-mihomo.exe", "windows/amd64")


if __name__ == "__main__":
    unittest.main()
