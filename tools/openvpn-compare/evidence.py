import json
import re
from pathlib import Path

from lab import assess

VARIANTS = ("upstream", "stcvrc", "minus", "only")
KNOWN_SCENARIOS = {"idle", "idle-local", "idle-lzo", "rekey", "deadline"}
TESTS = {
    "url": ("TestURLTestTolerance", "TestURLTestSelectionLifecycle"),
    "push": ("TestInitialHandshakeRetriesDeferredPush",),
}
PACKAGES = ("transport/openvpn", "adapter/outbound", "adapter/outboundgroup")


def _read_json(path, errors):
    try:
        value = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        errors.append(f"{path.name}: missing or malformed JSON ({exc})")
        return None
    if not isinstance(value, dict):
        errors.append(f"{path.name}: evidence must be a JSON object")
        return None
    return value


def _read_jsonl(path, errors):
    try:
        lines = path.read_text().splitlines()
    except OSError as exc:
        errors.append(f"{path.name}: missing JSONL evidence ({exc})")
        return []
    if not lines:
        errors.append(f"{path.name}: empty JSONL evidence")
        return []
    events = []
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except ValueError as exc:
            errors.append(f"{path.name}:{number}: malformed JSON ({exc})")
            continue
        if not isinstance(event, dict):
            errors.append(f"{path.name}:{number}: event must be a JSON object")
            continue
        events.append(event)
    if not events:
        errors.append(f"{path.name}: no parsed events")
    return events


def _status(path, errors):
    try:
        value = path.read_text().strip()
    except OSError as exc:
        errors.append(f"{path.name}: missing exit status ({exc})")
        return None
    if value not in {"0", "1"}:
        errors.append(f"{path.name}: invalid exit status {value!r}")
        return None
    return int(value)


def _is_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _valid_runtime(work, variant, scenario, errors):
    path = work / f"{variant}-{scenario}.json"
    data = _read_json(path, errors)
    if data is None:
        return "INVALID"
    fields = {
        "baseline": bool, "direct_blocked": bool, "live": bool,
        "inactivity": (int, float), "verdict": str, "scenario": str,
        "core_sha256": str,
    }
    if scenario.startswith("idle"):
        fields["resumed"] = bool
    elif scenario == "deadline":
        fields.update(stream_before_stop=bool, timeout_observed=bool)
    elif scenario == "rekey":
        fields.update(samples=(int, float), expected=(int, float),
                      rekeys=(int, float), epochs=(int, float),
                      post_epoch_samples=(int, float))
    valid = True
    for field, kinds in fields.items():
        if field not in data:
            errors.append(f"{path.name}: missing required field {field}")
            valid = False
        elif isinstance(data[field], bool) and kinds != bool:
            errors.append(f"{path.name}: field {field} has invalid type")
            valid = False
        elif not isinstance(data[field], kinds):
            errors.append(f"{path.name}: field {field} has invalid type")
            valid = False
    for field in ("baseline", "direct_blocked"):
        if data.get(field) is not True:
            errors.append(f"{path.name}: required control {field} is not true")
            valid = False
    if data.get("scenario") != scenario:
        errors.append(f"{path.name}: scenario does not match scheduled scenario {scenario}")
        valid = False
    if not re.fullmatch(r"[0-9a-f]{64}", data.get("core_sha256", "")):
        errors.append(f"{path.name}: missing or invalid freshly built core SHA256")
        valid = False
    if scenario == "deadline" and data.get("stream_before_stop") is not True:
        errors.append(f"{path.name}: deadline stream precondition was not observed")
        valid = False
    if scenario == "rekey" and _is_number(data.get("expected")) and data["expected"] <= 0:
        errors.append(f"{path.name}: invalid expected sample count")
        valid = False
    verdict = data.get("verdict")
    if not isinstance(verdict, str) or verdict not in ("PASS", "FAIL"):
        errors.append(f"{path.name}: verdict {verdict!r} is INVALID or unknown")
        valid = False
    elif valid and assess(scenario, data) != verdict:
        errors.append(f"{path.name}: verdict disagrees with recorded evidence")
        valid = False
    return verdict if valid else "INVALID"


def _valid_test_run(work, group, variant, required, errors):
    stem = f"{group}-{variant}"
    events = _read_jsonl(work / f"{stem}.jsonl", errors)
    status = _status(work / f"{stem}.status", errors)
    terminals = {name: [] for name in required}
    packages = []
    for event in events:
        action = event.get("Action")
        test = event.get("Test")
        if isinstance(test, str) and test in terminals and action in ("pass", "fail"):
            terminals[test].append(action)
        if not test and action in ("pass", "fail"):
            packages.append(action)
    valid = status is not None
    for name, actions in terminals.items():
        if len(actions) != 1:
            errors.append(f"{stem}: expected one terminal result for {name}, got {actions}")
            valid = False
    if len(packages) != 1:
        errors.append(f"{stem}: expected one terminal package result, got {packages}")
        valid = False
    elif status == 0 and packages[0] != "pass":
        errors.append(f"{stem}: package result disagrees with exit status")
        valid = False
    elif status == 1 and packages[0] != "fail":
        errors.append(f"{stem}: package result disagrees with exit status")
        valid = False
    if status == 0 and any(actions != ["pass"] for actions in terminals.values()):
        errors.append(f"{stem}: passing exit status has missing or failed required tests")
        valid = False
    if status == 1 and not any("fail" in actions for actions in terminals.values()):
        errors.append(f"{stem}: failing exit status has no required behavioral failure")
        valid = False
    if status == 0:
        return "PASS" if valid else "INVALID"
    return "FAIL" if valid and status == 1 else "INVALID"


def _valid_full_suite(work, variant, errors):
    stem = f"all-{variant}"
    events = _read_jsonl(work / f"{stem}.jsonl", errors)
    status = _status(work / f"{stem}.status", errors)
    terminals = {}
    for event in events:
        package, action = event.get("Package"), event.get("Action")
        if isinstance(package, str) and not event.get("Test") and action in ("pass", "fail"):
            terminals.setdefault(package, []).append(action)
    valid = status is not None
    for suffix in PACKAGES:
        matches = {name: actions for name, actions in terminals.items() if name.endswith(suffix)}
        if len(matches) != 1 or len(next(iter(matches.values()), [])) != 1:
            errors.append(f"{stem}: missing or duplicate terminal result for {suffix}")
            valid = False
    outcomes = [actions[0] for actions in terminals.values() if len(actions) == 1]
    failed_packages = {
        package for package, actions in terminals.items() if actions == ["fail"]
    }
    failed_test_packages = {
        event["Package"] for event in events
        if event.get("Action") == "fail" and event.get("Test")
        and isinstance(event.get("Package"), str)
    }
    unexplained_failures = failed_packages - failed_test_packages
    if unexplained_failures:
        errors.append(
            f"{stem}: failed package has no failed test result: "
            f"{sorted(unexplained_failures)}")
        valid = False
    if status == 0 and outcomes and any(value != "pass" for value in outcomes):
        errors.append(f"{stem}: passing exit status contains failed package")
        valid = False
    if status == 1 and outcomes and not any(value == "fail" for value in outcomes):
        errors.append(f"{stem}: failing exit status contains no failed package")
        valid = False
    if variant == "stcvrc" and status != 0:
        errors.append(f"{stem}: full candidate package suites must pass")
        valid = False
    if status == 0:
        return "PASS" if valid else "INVALID"
    return "FAIL" if valid and status == 1 else "INVALID"


def validate_experiment(work, scenarios):
    errors, runtime, tests, suites = [], {}, {}, {}
    if not scenarios or len(set(scenarios)) != len(scenarios):
        errors.append("scheduled scenarios are empty or duplicated")
        return errors, runtime, tests, suites
    unknown = set(scenarios) - KNOWN_SCENARIOS
    if unknown:
        errors.append(f"unknown scheduled scenarios: {sorted(unknown)}")
        return errors, runtime, tests, suites
    for variant in VARIANTS:
        runtime[variant] = {
            scenario: _valid_runtime(work, variant, scenario, errors)
            for scenario in scenarios
        }
        for group, required in TESTS.items():
            tests.setdefault(group, {})[variant] = _valid_test_run(
                work, group, variant, required, errors)
        if variant != "upstream":
            suites[variant] = _valid_full_suite(work, variant, errors)
    return errors, runtime, tests, suites
