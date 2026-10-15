"""Run published unit/fixture/AST tests only; never invoke a deployment entry point."""
import argparse
import contextlib
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import time
import unittest

HERE = Path(__file__).resolve().parent
MODULES = ['test_stcvrc_candidate_gate', 'test_stcvrc_lab_stack', 'test_stcvrc_safe_rollout',
           'test_stcvrc_ui_candidate_rollout', 'test_stcvrc_observer_installer']


class Results(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.outcomes = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.outcomes.append({'test': test.id(), 'outcome': 'PASS'})

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.outcomes.append({'test': test.id(), 'outcome': 'SKIP', 'reason': reason})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts-root', type=Path, help='External root containing local/artifacts paths; never execute binaries')
    parser.add_argument('--work-dir', type=Path, required=True, help='Caller-owned scratch directory for temporary fixtures')
    parser.add_argument('--output-dir', type=Path, default=HERE / 'evidence')
    parser.add_argument('--suite', choices=['preparation', 'observer'], default='preparation')
    args = parser.parse_args()
    if os.name != 'nt':
        parser.error('Windows is required: do not present skipped PowerShell checks as full reproduction')
    args.work_dir.mkdir(parents=True, exist_ok=True)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    tempfile.tempdir = str(args.work_dir.resolve())
    os.environ['TEMP'] = os.environ['TMP'] = str(args.work_dir.resolve())
    if args.artifacts_root:
        os.environ['STCVRC_PREPARATION_ARTIFACTS_ROOT'] = str(args.artifacts_root.resolve())
    else:
        os.environ.pop('STCVRC_PREPARATION_ARTIFACTS_ROOT', None)
    inputs = json.loads((HERE / 'provenance.json').read_text(encoding='utf-8'))
    source_hashes = {}
    for row in inputs['records']:
        path = HERE / row['publicPath']
        sha = hashlib.sha256(path.read_bytes()).hexdigest()
        if sha != row['publicSha256']:
            raise SystemExit('Published source hash mismatch: ' + row['publicPath'])
        source_hashes[row['publicPath']] = sha
    # A mistaken Python network call must fail instead of contacting any host.
    def no_network(event, arguments):
        if event in ('socket.connect', 'socket.getaddrinfo', 'socket.bind'):
            raise RuntimeError('Offline test runner rejected network I/O')
    sys.addaudithook(no_network)
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(HERE / 'scripts'))
    # Tests spawn Python solely for rejected CLI input; it must resolve public copies.
    os.environ['PYTHONPATH'] = os.pathsep.join(str(path) for path in sys.path if path)
    (HERE / 'local/labs').mkdir(parents=True, exist_ok=True)
    modules = MODULES if args.suite == 'preparation' else ['test_stcvrc_observer']
    log = io.StringIO()
    started = time.monotonic()
    with contextlib.redirect_stdout(log), contextlib.redirect_stderr(log):
        suite = unittest.defaultTestLoader.loadTestsFromNames(modules)
        result = unittest.TextTestRunner(stream=log, verbosity=2, resultclass=Results).run(suite)
    content = log.getvalue()
    # Failure traces are review evidence, not a source of workstation identity.
    for path in (HERE, args.work_dir.resolve(), args.artifacts_root.resolve() if args.artifacts_root else None):
        if path:
            for spelling in (str(path).replace('\\', '\\\\'), str(path), path.as_posix()):
                content = content.replace(spelling, '<review-root>')
    report = {'schema': 1, 'checkedUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'pythonVersion': sys.version.split()[0], 'platform': sys.platform, 'suite': args.suite,
              'modules': modules, 'testsRun': result.testsRun, 'passed': len([row for row in result.outcomes if row['outcome'] == 'PASS']),
              'failures': len(result.failures), 'errors': len(result.errors), 'skipped': len(result.skipped),
              'pass': result.wasSuccessful(), 'seconds': round(time.monotonic() - started, 3),
              'fullOriginal55ReproducedAgainstSanitizedCopies': args.suite == 'preparation' and result.testsRun == 55 and result.wasSuccessful() and not result.skipped,
              'artifactInput': 'explicit-external-root' if args.artifacts_root else 'not-supplied',
              'sourceSha256': source_hashes, 'outcomes': result.outcomes,
              'scope': 'local Python unit/fixture and extracted PowerShell AST checks; artifacts read only for SHA-256',
              'remoteCommands': 0, 'vmGate': 'NOT_RUN', 'homeReady': False,
              'notAccepted': inputs['notAccepted']}
    name = args.suite + '-tests'
    (args.output_dir / (name + '.txt')).write_text(content, encoding='utf-8')
    (args.output_dir / (name + '.json')).write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({key: report[key] for key in ('testsRun', 'passed', 'failures', 'errors', 'skipped', 'pass', 'seconds', 'fullOriginal55ReproducedAgainstSanitizedCopies')}))
    return 0 if report['pass'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
