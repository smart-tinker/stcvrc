"""Fail-closed interpretation of systemd invocation and restart counters."""
import re


class UnknownRestartTransition(RuntimeError):
    pass


def classify_restart_transition(previous, current, receipt=None,
                                manual_restart_resets_counter=False):
    """Classify one invocation transition without assuming a global counter delta.

    A receipt identifies an explicitly requested transition. The native probe may
    establish that this systemd version resets NRestarts for that operation; when
    so, any nonzero count in the new invocation reveals an automatic retry.
    """
    unit = current.get("unit")
    if not isinstance(unit, str) or not unit:
        raise UnknownRestartTransition("current unit identity is missing")
    try:
        old_count = int(previous["n_restarts"])
        new_count = int(current["n_restarts"])
        old_invocation = previous["invocation_id"]
        new_invocation = current["invocation_id"]
    except (KeyError, TypeError, ValueError) as error:
        raise UnknownRestartTransition("restart observation is incomplete") from error
    if old_count < 0 or new_count < 0 or not old_invocation or not new_invocation:
        raise UnknownRestartTransition("restart observation is invalid")
    if old_invocation == new_invocation:
        if old_count == new_count:
            return "unchanged"
        raise UnknownRestartTransition("counter changed without a new invocation")

    receipt_ok = (
        isinstance(receipt, dict)
        and receipt.get("unit") == unit
        and receipt.get("method") in {"RestartUnit", "StartUnit"}
        and receipt.get("state") in {"dispatched", "observed"}
        and isinstance(receipt.get("job_id"), str)
        and re.fullmatch(r"/org/freedesktop/systemd1/job/[0-9]+",
                         receipt["job_id"]) is not None
    )
    if receipt_ok:
        if manual_restart_resets_counter:
            if new_count == 0:
                return "requested-restart-counter-reset"
            return "requested-restart-followed-by-automatic-retry"
        if new_count > old_count:
            return "requested-restart-counter-increased"
        if new_count < old_count:
            return "requested-restart-counter-reset"
        return "requested-restart"
    if new_count > old_count:
        return "systemd-automatic-restart"
    raise UnknownRestartTransition(
        "counter did not increase across invocation without a matching job receipt"
    )