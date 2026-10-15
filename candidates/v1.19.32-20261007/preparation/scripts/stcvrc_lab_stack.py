"""Pinned binaries and result checks for the disposable desktop gate."""
from pathlib import Path
from datetime import datetime


STACKS = {
    "accepted": {
        "uiVersion": "2.5.2",
        "coreVersionToken": "1.19.29-STCVRC-urltest-candidate-20260905",
        "installer": "local/artifacts/stcvrc-v1.19.29/Clash.Verge_2.5.2_x64-setup.exe",
        "core": "local/artifacts/stcvrc-provider-repair-20260921/verge-mihomo.exe",
        "installerSha256": "ba42f00b1082e352352080170fe86ae411bcc854cb13f1b8bebc9025e8a7cbf4",
        "coreSha256": "40828a0f84c2c18fa917fa23246c7b87fc2c7d798c6a7c13a3db1dc997d94540",
    },
    "next": {
        "uiVersion": "2.5.5",
        "coreVersionToken": "1.19.31-STCVRC-lab-20260924g",
        "installer": "local/artifacts/stcvrc-next-20260922/cvr-2.5.5/Clash.Verge_2.5.5_x64-setup.exe",
        "core": "local/artifacts/stcvrc-next-20260922/mihomo-v1.19.31-stcvrc-lab-20260924g.exe",
        "installerSha256": "b00cefd93f4abaaf41f0dc62b9f441ae40f4e47d68590e58cb54e2eb5a11a4f3",
        "coreSha256": "5eef492d112a6ee9e81bce2298369f9feb5b63fbae9efc7e5a5dd9fc7441b439",
    },
    "candidate": {
        "uiVersion": "2.5.8",
        "coreVersionToken": "1.19.32-STCVRC-candidate-20261007",
        "installer": "local/artifacts/stcvrc-next-20261015/Clash.Verge_2.5.8_x64-setup.exe",
        "core": "local/artifacts/stcvrc-next-20261007/mihomo-v1.19.32-stcvrc-20261007.exe",
        "installerSha256": "821c0f5957f84c8f7d14532044840e8280d708af24a6a143db360b49bd1e7302",
        "coreSha256": "b072d09f0754b92cbe737757d2c63111d20ecf00e5d90b534ce2f9492feb9986",
    },
}

# Same new UI, accepted old core: isolates corporate regressions from UI changes.
STACKS['next-baseline']={**STACKS['next'],**{key:STACKS['accepted'][key]
    for key in ('coreVersionToken','core','coreSha256')}}


def stack_inputs(project, name):
    stack = STACKS[name]
    manifest = {k: v for k, v in stack.items() if k not in ("installer", "core")}
    manifest.update(schema=1, stack=name, installerName=Path(stack["installer"]).name,
                    coreName="gate-core.exe")
    inputs = {manifest["installerName"]: project / stack["installer"],
              manifest["coreName"]: project / stack["core"]}
    return manifest, inputs


def native_identity_check(rows):
    repeated = set()
    violations = []
    same_core_pairs = 0
    def core_key(row):
        cores = [p for p in row.get('host', {}).get('processes', [])
                 if p.get('role') == 'verge-mihomo.exe']
        if len(cores) != 1 or not cores[0].get('startUtc'):
            return None
        return tuple(cores[0].get(k) for k in ('pid', 'parent', 'startUtc', 'session'))
    for before, after in zip(rows, rows[1:]):
        key = core_key(before)
        if key is None or key != core_key(after):
            continue
        same_core_pairs += 1
        if not before.get('coreEpoch') or before['coreEpoch'] != after.get('coreEpoch'):
            violations.append('epoch-changed-with-same-process')
        for leaf in ('4VPS', 'GC'):
            first = before.get('native', {}).get('leaves', {}).get(leaf, {})
            second = after.get('native', {}).get('leaves', {}).get(leaf, {})
            if first.get('sourceUtc') and first['sourceUtc'] == second.get('sourceUtc'):
                repeated.add(leaf)
                if second.get('newSample') is not False:
                    violations.append('repeated-native-sample:' + leaf)
    return {'pass': repeated == {'4VPS', 'GC'} and not violations,
            'sameCorePairs': same_core_pairs, 'repeatedLeaves': sorted(repeated),
            'violations': violations}


def prelogin_observer_check(rows, boot_time, interactive_count):
    boot = datetime.fromisoformat(boot_time.replace('Z', '+00:00'))
    current = [row for row in rows
               if datetime.fromisoformat(row['observedUtc'].replace('Z', '+00:00')) >= boot]
    boot_trigger = any(event.get('id') == 118
                       for row in current for event in row.get('scheduler', {}).get('events', []))
    good = [row for row in current if row.get('checkpoint') == 'ok'
            and row.get('components', {}).get('host') == 'ok']
    return {'pass': interactive_count == 0 and bool(good) and boot_trigger,
            'records': len(current), 'completedRecords': len(good),
            'bootTrigger': boot_trigger, 'interactiveCount': interactive_count}


def desktop_acceptance(report):
    required = ('pass', 'cleanupPass', 'baselineMatch', 'stagingRemoved', 'homeUnchanged')
    return all(report.get(key) is True for key in required) and not any(
        report.get(key) for key in ('error', 'cleanupError'))


def inventory_comparison(before, after):
    keys = ('principalHash', 'elevated', 'processBits', 'appDataHash', 'hkcuRootHash')
    contexts = [sample.get('context', {}) for sample in (before, after)]
    known = all(c.get('schema') == 1 and all(c.get(key) is not None for key in keys) for c in contexts)
    comparable = known and all(contexts[0][key] == contexts[1][key] for key in keys)
    components = ('routes', 'dns', 'services', 'tasks', 'firewall', 'hiddify', 'proxy', 'winhttp')
    hashes = [sample.get('componentHashes', {}) for sample in (before, after)]
    matches = {key: bool(hashes[0].get(key)) and hashes[0].get(key) == hashes[1].get(key)
               for key in components}
    return {'contextComparable': comparable,
            'contextReason': 'same' if comparable else ('different' if known else 'unknown'),
            'componentMatch': matches,
            'baselineMatch': all(matches.values()) if comparable else None}
