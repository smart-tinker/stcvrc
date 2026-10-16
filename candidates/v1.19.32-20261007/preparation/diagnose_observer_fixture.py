"""Reproduce unisolated host I/O with synthetic app/API/body-probe fixtures only."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--work-dir', type=Path, required=True)
parser.add_argument('--output', type=Path, default=HERE / 'evidence/observer-fixture-diagnostic.json')
args = parser.parse_args()
args.work_dir.mkdir(parents=True, exist_ok=True)
tempfile.tempdir = str(args.work_dir.resolve())
os.environ['TEMP'] = os.environ['TMP'] = tempfile.tempdir
sys.path.insert(0, str(HERE / 'scripts'))
import test_stcvrc_observer as tests
o = tests.o
original_host = o.host_view
host_seconds = []


def timed_host(label):
    started = time.monotonic()
    try:
        return original_host(label)
    finally:
        host_seconds.append(round(time.monotonic() - started, 3))


case = tests.ObserverTests('test_active_checks_do_not_run_each_minute')
case.setUp()
try:
    app = case.active_fixture()
    with patch.object(o, 'host_view', side_effect=timed_host), patch.object(o, 'body_probe', return_value={'success': True}) as probe:
        first = o.observe(app, case.root, 'lab', True)
        second = o.observe(app, case.root, 'lab', True)
    def summary(record):
        return {key: record.get(key) for key in ('durationMs', 'components', 'stageDurationMs', 'applicationMode', 'application', 'traffic')}
    report = {'checkedUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'sourceSha256': hashlib.sha256(Path(o.__file__).read_bytes()).hexdigest(),
              'workBudgetSeconds': o.WORK_BUDGET_SECONDS, 'finalizeReserveSeconds': o.FINALIZE_RESERVE_SECONDS,
              'hostViewSeconds': host_seconds, 'bodyProbeCallCount': probe.call_count,
              'expectedBodyProbeCallCount': len(o.TARGETS) * len(o.LISTENERS),
              'first': summary(first), 'second': summary(second),
              'scope': 'Read-only local host enumeration; synthetic app/API/body probes; no deployment or remote commands'}
    args.output.write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(report))
finally:
    case.doCleanups()
