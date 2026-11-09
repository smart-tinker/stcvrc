import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
REPORT = HERE / "report.py"
VARIANTS = ("upstream", "stcvrc", "minus", "only")
SCENARIOS = ("idle", "idle-local", "idle-lzo", "rekey", "deadline")


def write_fixture(root):
    for variant in VARIANTS:
        for scenario in SCENARIOS:
            failed_behavior = variant == "upstream" and scenario in ("idle", "idle-lzo")
            evidence = {
                "baseline": True,
                "direct_blocked": True,
                "live": True,
                "inactivity": 1 if failed_behavior else 0,
                "verdict": "FAIL" if failed_behavior else "PASS",
            }
            if scenario.startswith("idle"):
                evidence["resumed"] = not failed_behavior
            elif scenario == "deadline":
                evidence["timeout_observed"] = True
            else:
                evidence.update(samples=200, expected=200, rekeys=2, epochs=2,
                                post_epoch_samples=20)
            (root / f"{variant}-{scenario}.json").write_text(json.dumps(evidence))

        (root / f"url-{variant}.status").write_text("0")
        (root / f"push-{variant}.status").write_text("0")
        url_events = [
            {"Test": "TestURLTestTolerance", "Action": "pass"},
            {"Test": "TestURLTestSelectionLifecycle", "Action": "pass"},
            {"Action": "pass"},
        ]
        push_events = [
            {"Test": "TestInitialHandshakeRetriesDeferredPush", "Action": "pass"},
            {"Action": "pass"},
        ]
        (root / f"url-{variant}.jsonl").write_text(
            "\n".join(json.dumps(event) for event in url_events) + "\n")
        (root / f"push-{variant}.jsonl").write_text(
            "\n".join(json.dumps(event) for event in push_events) + "\n")


def run_report(root):
    return subprocess.run(
        [sys.executable, str(REPORT), str(root), *SCENARIOS],
        text=True, capture_output=True, timeout=10,
    )


class InvalidEvidenceGateTests(unittest.TestCase):
    def test_valid_behavioral_failures_are_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_fixture(root)
            result = run_report(root)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_invalid_in_any_variant_or_scenario_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for variant in VARIANTS:
                for scenario in SCENARIOS:
                    with self.subTest(variant=variant, scenario=scenario):
                        write_fixture(root)
                        path = root / f"{variant}-{scenario}.json"
                        evidence = json.loads(path.read_text())
                        evidence.update(verdict="INVALID", baseline=False)
                        path.write_text(json.dumps(evidence))
                        result = run_report(root)
                        self.assertNotEqual(result.returncode, 0,
                                            f"accepted INVALID {variant}/{scenario}")

    def test_missing_malformed_or_uncontrolled_evidence_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for defect in ("missing", "malformed", "baseline", "direct_blocked"):
                with self.subTest(defect=defect):
                    write_fixture(root)
                    path = root / "minus-deadline.json"
                    if defect == "missing":
                        path.unlink()
                    elif defect == "malformed":
                        path.write_text("{")
                    else:
                        evidence = json.loads(path.read_text())
                        evidence[defect] = False
                        path.write_text(json.dumps(evidence))
                    result = run_report(root)
                    self.assertNotEqual(result.returncode, 0,
                                        f"accepted defective evidence: {defect}")


if __name__ == "__main__":
    unittest.main()
