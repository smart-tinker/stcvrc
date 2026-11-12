"""Fail-closed interpretation of systemd invocation and restart counters."""
import re


class UnknownRestartTransition(RuntimeError):
    pass


def classify_restart_transition(previous, current, receipt=None):
    """Classify observed values without assuming NRestarts is monotonic.

    systemd may reset NRestarts when an explicit RestartUnit begins a new
    InvocationID. A decrease/equal count is accepted only with the durable
    receipt for that exact unit. An increase with a new invocation is a native
    systemd automatic restart observation.
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
    if new_count > old_count and not receipt_ok:
        return "systemd-automatic-restart"
    if not receipt_ok:
        raise UnknownRestartTransition(
            "counter did not increase across invocation without a matching job receipt"
        )
    if new_count > old_count:
        return "requested-restart-counter-increased"
    if new_count < old_count:
        return "requested-restart-counter-reset"
    return "requested-restart"