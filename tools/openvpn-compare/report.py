import json
from pathlib import Path
import sys

work = Path(sys.argv[1])
print('## Fresh-source OpenVPN comparison\n')
print('| Scenario | Upstream .33 | STCVRC .33 |\n|---|---|---|')
invalid = False
for scenario in ('idle', 'idle-local', 'idle-lzo', 'rekey'):
    values = []
    for variant in ('upstream', 'stcvrc'):
        data = json.loads((work/f'{variant}-{scenario}.json').read_text())
        invalid |= data['verdict'] == 'INVALID'
        values.append(data['verdict'])
    print(f'| {scenario} | {values[0]} | {values[1]} |')
for group, label, required in (
    ('url', 'URLTest tolerance/lifecycle', {'TestURLTestTolerance', 'TestURLTestSelectionLifecycle'}),
    ('push', 'Deferred PUSH_REQUEST (test TLS server)', {'TestInitialHandshakeRetriesDeferredPush'}),
):
    values = []
    for variant in ('upstream', 'stcvrc'):
        events = []
        for line in (work/f'{group}-{variant}.jsonl').read_text().splitlines():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        terminal = {e['Test']:e['Action'] for e in events if e.get('Test') in required and e.get('Action') in ('pass','fail')}
        packages = [e['Action'] for e in events if not e.get('Test') and e.get('Action') in ('pass','fail')]
        status = int((work/f'{group}-{variant}.status').read_text())
        valid = set(terminal) == required and bool(packages)
        invalid |= not valid
        passed = valid and status == 0 and packages[-1] == 'pass' and set(terminal.values()) == {'pass'}
        values.append('INVALID' if not valid else 'PASS' if passed else 'FAIL')
    print(f'| {label} | {values[0]} | {values[1]} |')
print('\nA completed comparison is not product acceptance. FAIL is an observed scenario failure, not a build error. '
      'Real-server deferred auth, server-loss recovery, token refresh and Windows remain NOT TESTED. '
      'Inspect per-scenario JSON/logs for epoch counts, stream integrity and freshly built core hashes.')
raise SystemExit(1 if invalid else 0)
