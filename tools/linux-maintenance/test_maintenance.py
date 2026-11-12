import json
import tempfile
import unittest
from pathlib import Path

from counter import UnknownRestartTransition, classify_restart_transition
from maintenance import (
    AmbiguousOperation,
    ProcessIdentityError,
    ReceiptMismatch,
    _proc_start_ticks,
    restart_once,
    wait_for_main_process,
)


class ReceiptTests(unittest.TestCase):
    def test_receipt_is_durable_before_observer_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "restart.json"
            calls = []

            def invoke():
                calls.append("dispatch")
                return "/org/freedesktop/systemd1/job/41"

            def observe(_receipt):
                raise RuntimeError("observer failed")

            with self.assertRaisesRegex(RuntimeError, "observer failed"):
                restart_once(path, "op-1", "stcvrc-ci-a.service",
                             "RestartUnit", invoke, observe)
            receipt = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(receipt["state"], "dispatched")
            self.assertEqual(receipt["job_id"], "/org/freedesktop/systemd1/job/41")
            self.assertEqual(calls, ["dispatch"])

    def test_dispatched_receipt_reobserves_without_redispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "restart.json"
            path.write_text(json.dumps({
                "operation_id": "op-2", "unit": "stcvrc-ci-b.service",
                "method": "RestartUnit", "job_id": "/org/freedesktop/systemd1/job/52",
                "state": "dispatched",
            }), encoding="utf-8")
            calls = []
            receipt, result = restart_once(
                path, "op-2", "stcvrc-ci-b.service", "RestartUnit",
                lambda: calls.append("dispatch") or "/job/unexpected",
                lambda value: value["job_id"],
            )
            self.assertEqual(calls, [])
            self.assertEqual(result, "/org/freedesktop/systemd1/job/52")
            self.assertEqual(receipt["state"], "observed")

    def test_observed_receipt_is_terminal_and_never_replayed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "restart.json"
            path.write_text(json.dumps({
                "operation_id": "op-3", "unit": "stcvrc-ci-c.service",
                "method": "RestartUnit", "job_id": "/org/freedesktop/systemd1/job/53",
                "state": "observed",
            }), encoding="utf-8")
            calls = []
            receipt, result = restart_once(
                path, "op-3", "stcvrc-ci-c.service", "RestartUnit",
                lambda: calls.append("dispatch") or "/job/unexpected",
                lambda _value: calls.append("observe"),
            )
            self.assertEqual(calls, [])
            self.assertIsNone(result)
            self.assertEqual(receipt["state"], "observed")

    def test_ambiguous_intent_refuses_redispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "restart.json"
            calls = []
            with self.assertRaises(AmbiguousOperation):
                restart_once(path, "op-4", "stcvrc-ci-d.service",
                             "RestartUnit",
                             lambda: calls.append("dispatch"),
                             lambda _receipt: None)
            with self.assertRaises(AmbiguousOperation):
                restart_once(path, "op-4", "stcvrc-ci-d.service",
                             "RestartUnit",
                             lambda: calls.append("dispatch"),
                             lambda _receipt: None)
            self.assertEqual(calls, [])

    def test_receipt_identity_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "restart.json"
            path.write_text(json.dumps({
                "operation_id": "other", "unit": "stcvrc-ci-e.service",
                "method": "RestartUnit", "job_id": "/org/freedesktop/systemd1/job/4",
                "state": "dispatched",
            }), encoding="utf-8")
            with self.assertRaises(ReceiptMismatch):
                restart_once(path, "op-5", "stcvrc-ci-e.service", "RestartUnit",
                             lambda: None, lambda _receipt: None)


class ProcessTransitionTests(unittest.TestCase):
    def test_proc_start_ticks_handles_parenthesized_comm(self):
        # After the final ')', fields begin at Linux stat field 3; starttime is 22.
        stat_text = "91 (worker name ) with parens) S " + " ".join(str(i) for i in range(4, 24))
        self.assertEqual(_proc_start_ticks(stat_text), 22)

    def test_disappearing_pid_is_reacquired_as_a_stable_new_process(self):
        expected = "a" * 64
        states = iter([
            {"active_state": "activating", "main_pid": 0},
            {"active_state": "active", "main_pid": 313},
            {"active_state": "active", "main_pid": 314},
            {"active_state": "active", "main_pid": 314},
        ])

        def read_identity(pid):
            if pid == 313:
                raise ProcessLookupError(pid)
            return {"pid": pid, "start_ticks": 9001, "exe_sha256": expected}

        identity = wait_for_main_process(
            lambda: next(states), read_identity, expected_sha256=expected,
            timeout_seconds=1, poll_interval=0, stable_samples=2,
        )
        self.assertEqual(identity["pid"], 314)

    def test_wrong_executable_is_not_accepted(self):
        with self.assertRaises(ProcessIdentityError):
            wait_for_main_process(
                lambda: {"active_state": "active", "main_pid": 315},
                lambda pid: {"pid": pid, "start_ticks": 7, "exe_sha256": "b" * 64},
                expected_sha256="a" * 64, timeout_seconds=1, poll_interval=0,
            )


class RestartCounterTests(unittest.TestCase):
    def test_autorestart_uses_real_counter_increase(self):
        self.assertEqual(classify_restart_transition(
            {"unit": "stcvrc-ci-a.service", "invocation_id": "old", "n_restarts": 0},
            {"unit": "stcvrc-ci-a.service", "invocation_id": "new", "n_restarts": 1},
        ), "systemd-automatic-restart")

    def test_manual_restart_counter_reset_requires_matching_receipt(self):
        previous = {"unit": "stcvrc-ci-b.service", "invocation_id": "old", "n_restarts": 1}
        current = {"unit": "stcvrc-ci-b.service", "invocation_id": "new", "n_restarts": 0}
        receipt = {"unit": "stcvrc-ci-b.service", "method": "RestartUnit",
                   "job_id": "/org/freedesktop/systemd1/job/52", "state": "dispatched"}
        self.assertEqual(classify_restart_transition(previous, current, receipt),
                         "requested-restart-counter-reset")
        with self.assertRaises(UnknownRestartTransition):
            classify_restart_transition(previous, current)

    def test_same_counter_across_new_invocation_requires_receipt(self):
        previous = {"unit": "stcvrc-ci-c.service", "invocation_id": "old", "n_restarts": 0}
        current = {"unit": "stcvrc-ci-c.service", "invocation_id": "new", "n_restarts": 0}
        receipt = {"unit": "stcvrc-ci-c.service", "method": "RestartUnit",
                   "job_id": "/org/freedesktop/systemd1/job/53", "state": "observed"}
        self.assertEqual(classify_restart_transition(previous, current, receipt),
                         "requested-restart")
        with self.assertRaises(UnknownRestartTransition):
            classify_restart_transition(previous, current)


if __name__ == "__main__":
    unittest.main(verbosity=2)