import hashlib
import tempfile
import unittest
from pathlib import Path

from collect import _has_module_build_info, verify_artifact
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
