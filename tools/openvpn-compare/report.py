import sys
from pathlib import Path

from evidence import validate_experiment

work = Path(sys.argv[1])
scenarios = sys.argv[2:]
errors, runtime, tests, suites = validate_experiment(work, scenarios)
print("## Fresh-source OpenVPN comparison\n")
if errors:
    print("INVALID evidence; this run cannot be used as a comparison:")
    for error in errors:
        print(f"- {error}")
    raise SystemExit(1)

variants = ("upstream", "stcvrc", "minus", "only")
print("| Scenario | Upstream .33 | STCVRC .33 | Minus patch | Only patch |")
print("|---|---|---|---|---|")
for scenario in scenarios:
    values = [runtime[variant][scenario] for variant in variants]
    print(f"| {scenario} | " + " | ".join(values) + " |")
for group, label in (("url", "URLTest tolerance/lifecycle"),
                     ("push", "Deferred PUSH_REQUEST test server")):
    values = [tests[group][variant] for variant in variants]
    print(f"| {label} | " + " | ".join(values) + " |")
print("\n| Full package suites | STCVRC | Minus patch |")
print("|---|---|---|")
print("| result | " + " | ".join(suites[v] for v in ("stcvrc", "minus")) + " |")
print("\nThe only-patch variant is evaluated by its scheduled runtime and targeted URL/PUSH tests; its full package suite is not run because that suite also includes tests for omitted patches.")
print("\nA green run means every scheduled observation and control is valid. Behavioral FAIL is retained as a result; "
      "it does not fail the comparison by itself. The restart scenario is a disposable local-server test, "
      "not corporate-server recovery acceptance. Real-server deferred auth, token refresh and Windows/TUN remain NOT TESTED.")
