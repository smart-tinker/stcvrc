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
                "baseline": True, "direct_blocked": True, "live": True,
                "inactivity": 1 if failed_behavior else 0,
                "verdict": "FAIL" if failed_behavior else "PASS",
                "scenario": scenario, "core_sha256": "a" * 64,
            }
            if scenario.startswith("idle"):
                evidence["resumed"] = not failed_behavior
            elif scenario == "deadline":
                evidence.update(stream_before_stop=True, timeout_observed=True)
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

        if variant in ("stcvrc", "minus"):
            outcomes = ["pass", "pass", "pass"]
            if variant == "minus":
                outcomes[0] = "fail"
            elif variant == "only":
                outcomes[1] = "fail"
            packages = (
                "github.com/metacubex/mihomo/transport/openvpn",
                "github.com/metacubex/mihomo/adapter/outbound",
                "github.com/metacubex/mihomo/adapter/outboundgroup",
            )
            suite_events = []
            for package, action in zip(packages, outcomes):
                if action == "fail":
                    suite_events.append({"Action": "fail", "Package": package,
                                         "Test": "TestExpectedBehaviorFailure"})
                suite_events.append({"Action": action, "Package": package})
            (root / f"all-{variant}.status").write_text(
                "1" if "fail" in outcomes else "0")
            (root / f"all-{variant}.jsonl").write_text(
                "\n".join(json.dumps(event) for event in suite_events) + "\n")


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
            self.assertIn("| idle | FAIL |", result.stdout)

    def test_only_variant_does_not_require_unrelated_full_suite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_fixture(root)
            self.assertFalse((root / "all-only.jsonl").exists())
            result = run_report(root)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_package_failure_without_failed_test_is_invalid(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_fixture(root)
            packages = (
                "github.com/metacubex/mihomo/transport/openvpn",
                "github.com/metacubex/mihomo/adapter/outbound",
                "github.com/metacubex/mihomo/adapter/outboundgroup",
            )
            events = [{"Action": "fail", "Package": packages[0]}]
            events.extend({"Action": "pass", "Package": package}
                          for package in packages[1:])
            (root / "all-minus.status").write_text("1")
            (root / "all-minus.jsonl").write_text(
                "\n".join(json.dumps(event) for event in events) + "\n")
            result = run_report(root)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("no failed test", result.stdout)

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
            for defect in ("missing", "malformed", "baseline", "direct_blocked",
                           "target_test", "candidate_suite"):
                with self.subTest(defect=defect):
                    write_fixture(root)
                    path = root / "minus-deadline.json"
                    if defect == "missing":
                        path.unlink()
                    elif defect == "malformed":
                        path.write_text("{")
                    elif defect == "target_test":
                        (root / "url-only.jsonl").write_text('{"Action":"pass"}\n')
                    elif defect == "candidate_suite":
                        (root / "all-stcvrc.status").write_text("1")
                    else:
                        evidence = json.loads(path.read_text())
                        evidence[defect] = False
                        path.write_text(json.dumps(evidence))
                    result = run_report(root)
                    self.assertNotEqual(result.returncode, 0,
                                        f"accepted defective evidence: {defect}")


if __name__ == "__main__":
    unittest.main()
