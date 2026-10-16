"""Prepare a private single-policy profile without modifying a running client."""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import shutil
from datetime import datetime

import stmc_yaml


PUBLIC = 'FOREIGN-EGRESS'
POOL = 'VPS-POOL'
RETIRED = {'VPS-DEFAULT', 'VPS-AUTO', 'VPS-ONLY'}
MANAGED = RETIRED | {PUBLIC, POOL}
LEAVES = ['VPS-GREEN', '4VPS']
LATENCY = 'VPS-LATENCY'
FOUR_CHOICES = [POOL, '4VPS', 'GC', 'DIRECT']
BUILTINS = {'DIRECT', 'REJECT', 'REJECT-DROP', 'COMPATIBLE', 'PASS', 'PASS-RULE', 'GLOBAL'}


def retarget_rule_providers(result, *, rename_green=False):
    """Retarget only provider proxy fields, then reject dangling references."""
    names = [item['name'] for key in ('proxies', 'proxy-groups')
             for item in result.get(key, [])]
    if len(names) != len(set(names)):
        raise ValueError('Duplicate proxy/group names')
    targets = set(names) | BUILTINS
    replacements = {name: PUBLIC for name in RETIRED}
    if rename_green:
        replacements['VPS-GREEN'] = 'GC'
    for provider in result.get('rule-providers', {}).values():
        target = provider.get('proxy')
        if target is None or target == '':
            continue
        if not isinstance(target, str):
            raise ValueError('Invalid rule-provider proxy reference')
        target = replacements.get(target, target)
        if target not in targets:
            raise ValueError('Rule-provider proxy target is missing')
        provider['proxy'] = target
    return result


def build_provider_repair(source):
    """Repair provider references without changing routing or group policy."""
    if any(group['name'] in RETIRED for group in source['proxy-groups']):
        raise ValueError('Legacy groups require a policy migration first')
    return retarget_rule_providers(copy.deepcopy(source))


def four_choice_groups(*, interval=60, timeout=5000,
                       url='https://www.gstatic.com/generate_204'):
    health = dict(url=url, interval=interval, timeout=timeout, lazy=False,
                  **{'expected-status': '204'})
    return [
        dict(name=PUBLIC, type='select', proxies=list(FOUR_CHOICES)),
        dict(name=POOL, type='fallback', proxies=[LATENCY, 'DIRECT'], hidden=True, **health),
        dict(name=LATENCY, type='url-test', proxies=['GC', '4VPS'],
             tolerance=150, hidden=True, **health),
    ]


def build_four_choices(source):
    """Migrate the two-choice policy and GC label, including provider references."""
    result = copy.deepcopy(source)
    groups = source['proxy-groups']
    proxies = source['proxies']
    names = [g['name'] for g in groups]
    leaves = [p['name'] for p in proxies]
    if len(names) != len(set(names)) or len(leaves) != len(set(leaves)):
        raise ValueError('Duplicate proxy/group names')
    if set(names) & set(leaves):
        raise ValueError('Proxy/group name collision')
    managed = {PUBLIC, POOL, LATENCY}
    existing = [g for g in groups if g['name'] in managed]
    for rule in source.get('rules', []):
        fields = rule.split(',')
        action = fields[-2] if fields[-1] == 'no-resolve' else fields[-1]
        if action in {POOL, LATENCY, 'VPS-GREEN'}:
            raise ValueError('Rule depends directly on an internal group or renamed leaf')
    def check_dns(value):
        if isinstance(value, dict):
            for item in value.values():
                check_dns(item)
        elif isinstance(value, list):
            for item in value:
                check_dns(item)
        elif isinstance(value, str) and any('#' + n in value for n in (POOL, LATENCY, 'VPS-GREEN')):
            raise ValueError('DNS depends directly on an internal group or renamed leaf')
    check_dns(source.get('dns', {}))
    if 'GC' in leaves:
        if '4VPS' not in leaves or 'VPS-GREEN' in leaves or existing != four_choice_groups():
            raise ValueError('Unrecognized four-choice policy')
        return retarget_rule_providers(result, rename_green=True)
    if existing != egress_groups() or not set(LEAVES) <= set(leaves):
        raise ValueError('Expected accepted two-choice policy')
    if set(names + leaves) & RETIRED or 'GC' in names:
        raise ValueError('Legacy policy or GC collision requires separate migration')
    for group in groups:
        if group['name'] not in managed and set(group.get('proxies', [])) & (managed | {'VPS-GREEN'}):
            raise ValueError('Unrelated group dependency')
    for proxy in proxies:
        if proxy.get('dialer-proxy') in managed | {'VPS-GREEN'}:
            raise ValueError('Unrelated proxy dependency')
    for proxy in result['proxies']:
        if proxy['name'] == 'VPS-GREEN':
            proxy['name'] = 'GC'
    result['proxy-groups'] = four_choice_groups() + [
        copy.deepcopy(g) for g in groups if g['name'] not in managed]
    return retarget_rule_providers(result, rename_green=True)


def egress_groups(names=LEAVES, *, interval=60, timeout=5000,
                  url='https://www.gstatic.com/generate_204'):
    health = dict(url=url, interval=interval, timeout=timeout, lazy=False,
                  **{'expected-status': '204'})
    return [
        dict(name=PUBLIC, type='fallback', proxies=[POOL, 'DIRECT'], **health),
        dict(name=POOL, type='url-test', proxies=list(names), tolerance=150,
             hidden=True, **health),
    ]


def retarget_rule(rule):
    suffix = ',no-resolve' if rule.endswith(',no-resolve') else ''
    body = rule[:-len(suffix)] if suffix else rule
    prefix, comma, action = body.rpartition(',')
    if not comma:
        raise ValueError('Malformed rule; manual review required')
    return prefix + comma + (PUBLIC if action in RETIRED else action) + suffix


def retarget_dns(value):
    if isinstance(value, dict):
        return {key: retarget_dns(item) for key, item in value.items()}
    if isinstance(value, list):
        return [retarget_dns(item) for item in value]
    if isinstance(value, str):
        prefix, marker, group = value.rpartition('#')
        if marker and group in RETIRED:
            return prefix + marker + PUBLIC
        if any('#' + name in value for name in RETIRED):
            raise ValueError('Unexpected DNS group reference; manual review required')
    return value


def build_profile(source):
    result = copy.deepcopy(source)
    groups = source['proxy-groups']
    names = [group['name'] for group in groups]
    if len(names) != len(set(names)) or PUBLIC not in names:
        raise ValueError('Duplicate groups or missing foreign policy')
    proxies = [proxy['name'] for proxy in source['proxies']]
    if len(proxies) != len(set(proxies)) or not set(LEAVES) <= set(proxies):
        raise ValueError('Missing or duplicate VPS leaves')
    if set(proxies) & MANAGED:
        raise ValueError('Proxy/group name collision')
    for group in groups:
        if group['name'] not in MANAGED and set(group.get('proxies', [])) & MANAGED:
            raise ValueError('Unrelated selector refers to managed groups')
    for proxy in source['proxies']:
        if proxy.get('dialer-proxy') in MANAGED:
            raise ValueError('Proxy depends on managed policy')
    result['proxy-groups'] = egress_groups() + [
        copy.deepcopy(group) for group in groups if group['name'] not in MANAGED]
    result['rules'] = [retarget_rule(rule) for rule in source['rules']]
    result['dns'] = retarget_dns(source['dns'])
    return retarget_rule_providers(result)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', required=True, type=Path)
    parser.add_argument('--runtime', required=True, type=Path)
    parser.add_argument('--core', required=True, type=Path)
    parser.add_argument('--expected-core-sha256', required=True)
    parser.add_argument('--output', required=True, type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--four-choices', action='store_true')
    mode.add_argument('--provider-repair', action='store_true')
    args = parser.parse_args()
    local = (Path(__file__).resolve().parents[1] / 'local').resolve()
    output = args.output.resolve()
    if not output.is_relative_to(local) or output == local or output.exists():
        raise ValueError('Output must be a new directory inside project local root')
    inputs = {name: path.read_bytes() for name, path in
              [('profile', args.profile), ('runtime', args.runtime), ('core', args.core)]}
    if digest(inputs['core']).lower() != args.expected_core_sha256.lower():
        raise ValueError('Unexpected candidate core')
    profile, runtime = [stmc_yaml.load(inputs[name]) for name in ('profile', 'runtime')]
    for key in ('proxies', 'proxy-groups', 'rules', 'rule-providers'):
        if profile[key] != runtime[key]:
            raise ValueError('Active profile/runtime policy drift')
    transform = (build_provider_repair if args.provider_repair else
                 build_four_choices if args.four_choices else build_profile)
    profile_name = 'STCVRC-provider-repair.yaml' if args.provider_repair else 'STCVRC-single-egress.yaml'
    candidates = {name: transform(value) for name, value in
                  [(profile_name, profile), ('candidate-runtime.yaml', runtime)]}
    serialized = {name: stmc_yaml.dump(value) for name, value in candidates.items()}
    if any(stmc_yaml.load(serialized[name]) != value for name, value in candidates.items()):
        raise ValueError('YAML roundtrip changed profile semantics')
    output.mkdir(parents=True)
    for name, data in serialized.items():
        (output / name).write_bytes(data)
    shutil.copyfile(args.core, output / 'verge-mihomo.exe')
    manifest = {
        'createdAt': datetime.now().astimezone().isoformat(),
        'scope': 'private candidate; not installed or published',
        'inputHashes': {name: digest(data) for name, data in inputs.items()},
        'files': {name: digest(data) for name, data in serialized.items()} |
                 {'verge-mihomo.exe': digest(inputs['core'])},
        'policy': {'visible': PUBLIC, 'hidden': POOL, 'intervalSeconds': 60,
                   'timeoutMs': 5000, 'toleranceMs': 150, 'directLastResort': True,
                   'variant': 'four-choices' if args.four_choices else 'single-egress',
                   'choices': FOUR_CHOICES if args.four_choices else [POOL, 'DIRECT']},
        'rolloutGate': 'separate approval, backup, cache/pin readback and rollback required',
    }
    if args.provider_repair:
        manifest['policy'] = {'variant': 'provider-repair', 'routingUnchanged': True,
                              'change': 'retired rule-provider proxy references only'}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    print(json.dumps({'output': str(output), **manifest}, indent=2))


if __name__ == '__main__':
    main()
