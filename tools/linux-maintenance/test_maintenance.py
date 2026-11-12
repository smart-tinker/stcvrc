import json
import tempfile
import unittest
from pathlib import Path

from maintenance import restart_once, wait_for_main_process


class ReceiptTests(unittest.TestCase):
    def test_receipt_is_durable_before_observer_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt_path = Path(directory) / "restart.json"
            calls = []

            def invoke():
                calls.append("dispatch")
                return "/org/freedesktop/systemd1/job/41"

            def observe(_receipt):
                raise RuntimeError("observer failed")

            with self.assertRaisesRegex(RuntimeError, "observer failed"):
                restart_once(receipt_path, "op-1", "stcvrc-ci-a.service",
                             "RestartUnit", invoke, observe)

            self.assertTrue(
                receipt_path.exists(),
                "DBus receipt must be durable before post-dispatch observation",
            )
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertEqual(receipt["job_id"], "/org/freedesktop/systemd1/job/41")
            self.assertEqual(calls, ["dispatch"])

    def test_existing_receipt_prevents_redispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt_path = Path(directory) / "restart.json"
            receipt_path.write_text(json.dumps({
                "operation_id": "op-2",
                "unit": "stcvrc-ci-b.service",
                "method": "RestartUnit",
                "job_id": "/org/freedesktop/systemd1/job/52",
                "state": "dispatched",
            }), encoding="utf-8")
            calls = []

            receipt, observed = restart_once(
                receipt_path, "op-2", "stcvrc-ci-b.service", "RestartUnit",
                lambda: calls.append("dispatch") or "/job/unexpected",
                lambda value: value["job_id"],
            )

            self.assertEqual(calls, [], "a persisted DBus receipt must never be replayed")
            self.assertEqual(receipt["job_id"], "/org/freedesktop/systemd1/job/52")
            self.assertEqual(observed, "/org/freedesktop/systemd1/job/52")


class ProcessTransitionTests(unittest.TestCase):
    def test_disappearing_pid_is_reacquired_as_a_stable_new_process(self):
        expected = "a" * 64
        states = iter([
            {"active_state": "activating", "main_pid": 0},
            {"active_state": "active", "main_pid": 313},
            {"active_state": "active", "main_pid": 314},
            {"active_state": "active", "main_pid": 314},
        ])

        def read_unit():
            return next(states)

        def read_identity(pid):
            if pid == 313:
                raise ProcessLookupError(pid)
            return {
                "pid": pid,
                "start_ticks": 9001,
                "exe_sha256": expected,
            }

        identity = wait_for_main_process(
            read_unit, read_identity, expected_sha256=expected,
            timeout_seconds=1, poll_interval=0, stable_samples=2,
        )
        self.assertEqual(identity["pid"], 314)
        self.assertEqual(identity["exe_sha256"], expected)


if __name__ == "__main__":
    unittest.main(verbosity=2)
