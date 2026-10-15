"""Stage a host-bound core/profile transaction; never change a running client."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import urllib.request

import stmc_yaml
from stcvrc_lab_stack import STACKS
from stcvrc_observer import observer_profile
from stcvrc_single_egress import (build_profile, build_four_choices, build_provider_repair,
                                four_choice_groups, MANAGED, LATENCY)

PROJECT = Path(__file__).resolve().parents[1]
OLD_CORE = '71195c943be67017c5646ea2021734bc122fa83c58a408ab6713a2b25cb6b62b'
NEW_CORE = '40828a0f84c2c18fa917fa23246c7b87fc2c7d798c6a7c13a3db1dc997d94540'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def registry_candidate(registry, uid):
    result = copy.deepcopy(registry)
    matches = [item for item in result['items'] if item.get('uid') == uid]
    if len(matches) != 1 or matches[0].get('type') != 'local':
        raise ValueError('Expected one active local profile')
    selected = matches[0].get('selected') or []
    matches[0]['selected'] = [item for item in selected if item['name'] not in MANAGED | {LATENCY}]
    return result


def provider_repair_names(profile):
    groups = [g for g in profile['proxy-groups']
              if g['name'] in {'FOREIGN-EGRESS', 'VPS-POOL', LATENCY}]
    if groups != four_choice_groups():
        raise ValueError('Provider repair requires the accepted four-choice policy')
    repaired = build_provider_repair(profile)
    names = sorted(name for name, value in profile['rule-providers'].items()
                   if value != repaired['rule-providers'][name])
    if names != ['ru-service-domains', 'tspu-foreign-domains']:
        raise ValueError('Expected exactly the two reviewed provider repairs')
    return names


def selector_groups(profile, provider_repair=False):
    excluded = {'GLOBAL'} if provider_repair else MANAGED | {LATENCY, 'GLOBAL'}
    return {g['name']: g for g in profile['proxy-groups']
            if g['type'] == 'select' and g['name'] not in excluded}


def ui_migration_expectations(settings, runtime, uid, sid, profile=None):
    # CVR 2.5.5 persists per-profile DNS settings; do not change DNS semantics.
    if settings.get('enable_dns_settings') is not False or settings.get('profile_dns_settings'):
        raise ValueError('UI migration requires reviewed disabled DNS override')
    new_settings = copy.deepcopy(settings)
    new_settings['profile_dns_settings'] = {uid: {'enabled': False}}
    if new_settings.get('start_page') == '/home':
        new_settings['start_page'] = '/'
    new_runtime = copy.deepcopy(runtime)
    new_runtime['external-controller-pipe'] = r'\\.\pipe\verge-mihomo-sidecar-release-' + sha(sid.encode('ascii'))
    dns = new_runtime.get('dns', {})
    # CVR 2.5.5 changes only the implicit IPv6 fake-IP default in TUN mode.
    if (profile is not None and 'fake-ip-range6' not in profile.get('dns', {})
            and runtime.get('tun', {}).get('enable') is True
            and runtime.get('ipv6') is True
            and dns.get('enhanced-mode') == 'fake-ip'
            and dns.get('fake-ip-range6') == 'fdfe:dcba:9876::1/64'):
        dns['fake-ip-range6'] = '2001:2::0/64'
    return stmc_yaml.dump(new_settings), stmc_yaml.dump(new_runtime)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--app-root', type=Path, required=True)
    p.add_argument('--old-core', type=Path, required=True)
    p.add_argument('--bundle', type=Path)
    p.add_argument('--candidate-core', type=Path)
    p.add_argument('--source-stack', choices=['accepted', 'next'], help='Exact reviewed UI-update baseline; default accepted')
    p.add_argument('--target-stack', choices=['next', 'candidate'], help='Exact reviewed UI-update target; default next')
    p.add_argument('--service-owner-sid')
    p.add_argument('--ui-task', default='Clash Verge', choices=['Clash Verge', 'ClashVergeInteractiveLimited'])
    p.add_argument('--runtime-config', type=Path, help='Read-only actual owner-runtime snapshot for core-update or approved-layout UI source')
    p.add_argument('--yaml-validator', type=Path, default=PROJECT / 'local/artifacts/stcvrc-rollout-validator-20260906/yaml-equivalence.exe')
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--host', choices=['FIXTURE-HOME', 'LABHOST'], required=True)
    p.add_argument('--target-app-root', required=True)
    p.add_argument('--target-transaction-root', required=True)
    p.add_argument('--selectors-json', type=Path)
    p.add_argument('--service-owner-directory', help='Exact reviewed CVR service-owner log root, when applicable')
    p.add_argument('--lab', action='store_true')
    p.add_argument('--observer-config', action='store_true',
                   help='With core-update, keep the pinned core and only add observer listeners/log settings')
    mode = p.add_mutually_exclusive_group()
    mode.add_argument('--four-choices', action='store_true')
    mode.add_argument('--provider-repair', action='store_true')
    mode.add_argument('--core-update', action='store_true', help='Pinned core-only update on already installed CVR2.5.5')
    mode.add_argument('--ui-update', action='store_true', help='Exact pinned UI/core pair; historical default accepted to next')
    args = p.parse_args()
    if (args.source_stack or args.target_stack) and not args.ui_update:
        p.error('Explicit source/target stacks require ui-update')
    source_name, target_name = args.source_stack or 'accepted', args.target_stack or 'next'
    source_stack, target_stack = STACKS[source_name], STACKS[target_name]
    if args.ui_update and (source_name, target_name) not in {
            ('accepted', 'next'), ('accepted', 'candidate'), ('next', 'candidate')}:
        raise ValueError('Unreviewed UI version pair')
    if args.ui_update and (source_stack['uiVersion'], target_stack['uiVersion']) not in {
            ('2.5.2', '2.5.5'), ('2.5.2', '2.5.8'), ('2.5.5', '2.5.8')}:
        raise ValueError('Unreviewed UI version pair')
    source_approved = args.ui_update and source_stack['uiVersion'] != '2.5.2'
    if args.observer_config and not args.core_update:
        p.error('Observer configuration requires the already approved core-update layout')
    binary_update = args.core_update or args.ui_update
    if binary_update:
        if args.bundle or not args.candidate_core or (args.core_update and not args.runtime_config) or not re.fullmatch(r'S-1-5-21-\d+-\d+-\d+-\d+', args.service_owner_sid or ''):
            p.error('Core update requires candidate-core, runtime-config and service-owner-sid, without bundle')
        if args.ui_update and bool(args.runtime_config) != source_approved:
            p.error('UI migration requires the actual owner runtime only for an approved source layout')
    elif not args.bundle or args.candidate_core or args.service_owner_sid or args.runtime_config:
        p.error('Profile migration requires bundle; owner-scoped core options require core-update')
    if args.lab != (args.host == 'LABHOST'):
        raise ValueError('Lab/host scope mismatch')
    if args.service_owner_directory:
        if not re.fullmatch(r'C:\\ProgramData\\clash-verge-service\\users\\[0-9a-f]{64}',
                            args.service_owner_directory):
            raise ValueError('Exact service-owner directory required')
    owner = None
    if binary_update:
        owner = 'C:\\ProgramData\\clash-verge-service\\users\\' + sha(args.service_owner_sid.encode('ascii'))
        if args.service_owner_directory and args.service_owner_directory != owner:
            raise ValueError('Service owner directory differs from owner SID')
    output = args.output.resolve()
    if not output.is_relative_to((PROJECT / 'local').resolve()) or output.exists():
        raise ValueError('A new project-private output directory is required')
    raw = {name: (args.app_root / name).read_bytes() for name in ['profiles.yaml', 'verge.yaml']}
    raw['clash-verge.yaml'] = (args.runtime_config if args.core_update or source_approved else args.app_root / 'clash-verge.yaml').read_bytes()
    if source_approved:
        raw['app-runtime.yaml'] = (args.app_root / 'clash-verge.yaml').read_bytes()
    registry, runtime = [stmc_yaml.load(raw[n]) for n in ['profiles.yaml', 'clash-verge.yaml']]
    uid = registry['current']
    active = [i for i in registry['items'] if i.get('uid') == uid]
    if len(active) != 1 or active[0].get('type') != 'local':
        raise ValueError('Unexpected active registry')
    filename = active[0]['file']
    if Path(filename).name != filename or not filename.endswith('.yaml'):
        raise ValueError('Profile path must be a single YAML filename')
    raw['profile.yaml'] = (args.app_root / 'profiles' / filename).read_bytes()
    profile = stmc_yaml.load(raw['profile.yaml'])
    for key in ['proxies', 'proxy-groups', 'rules', 'rule-providers']:
        if profile[key] != runtime[key]:
            raise ValueError('Active profile/runtime policy drift')
    old_core = args.old_core.read_bytes()
    new_core = (args.candidate_core if binary_update else args.bundle / 'verge-mihomo.exe').read_bytes()
    validator = args.yaml_validator.read_bytes()
    expected_new = target_stack['coreSha256'] if args.ui_update else STACKS['next']['coreSha256'] if binary_update else NEW_CORE
    old_hashes = ({source_stack['coreSha256']} if args.source_stack or args.target_stack else {NEW_CORE}) if args.ui_update else {NEW_CORE, expected_new} if binary_update else {OLD_CORE, NEW_CORE}
    if sha(old_core) not in old_hashes or sha(new_core) != expected_new:
        raise ValueError('Unexpected core generation')
    if args.observer_config and sha(old_core) != sha(new_core):
        raise ValueError('Observer configuration must not change the core')
    if binary_update and sha(old_core) == sha(new_core) and not args.observer_config:
        raise ValueError('Candidate core is already installed')
    if (args.four_choices or args.provider_repair) and sha(old_core) != NEW_CORE:
        raise ValueError('Profile-only migration must not change the core')
    repaired_providers = provider_repair_names(profile) if args.provider_repair else []
    transform = (copy.deepcopy if binary_update else build_provider_repair if args.provider_repair else
                 build_four_choices if args.four_choices else build_profile)
    candidate_profile = (raw['profile.yaml'] if binary_update else
        (args.bundle / ('STCVRC-provider-repair.yaml' if args.provider_repair
                       else 'STCVRC-single-egress.yaml')).read_bytes())
    if stmc_yaml.load(candidate_profile) != transform(profile):
        raise ValueError('Bundle profile does not match the active policy transformation')
    candidate_runtime = raw['clash-verge.yaml'] if binary_update else stmc_yaml.dump(transform(runtime))
    if not args.lab and not binary_update:
        manifest = json.loads((args.bundle / 'manifest.json').read_text())
        if sha(raw['clash-verge.yaml']) != manifest['inputHashes']['runtime']:
            raise ValueError('Home runtime changed since the accepted candidate')
        if sha(candidate_runtime) != manifest['files']['candidate-runtime.yaml']:
            raise ValueError('Home runtime candidate differs from accepted artifact')
    if runtime.get('external-controller') != '127.0.0.1:9097' or runtime.get('mixed-port') != 7897:
        raise ValueError('Unexpected controller/listener boundary')
    if bool(runtime.get('tun', {}).get('enable')) == args.lab:
        raise ValueError('Unexpected TUN mode for this host scope')
    expected = selector_groups(profile, args.provider_repair or binary_update)
    if args.selectors_json:
        selectors = json.loads(args.selectors_json.read_text())
    else:
        req = urllib.request.Request('http://127.0.0.1:9097/proxies',
                headers={'Authorization': 'Bearer ' + runtime['secret']})
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=5) as r:
            groups = json.load(r)['proxies']
        selectors = {name: value['now'] for name, value in groups.items()
                     if value.get('type') == 'Selector' and name in expected}
    if set(selectors) != set(expected) or any(v not in expected[n]['proxies'] for n, v in selectors.items()):
        raise ValueError('Unrelated manual selectors must be captured exactly')
    staged = {'core': new_core, 'profile': candidate_profile, 'runtime': candidate_runtime,
              'registry': (raw['profiles.yaml'] if args.provider_repair or binary_update else
                           stmc_yaml.dump(registry_candidate(registry, uid)))}
    if binary_update:
        staged = {'core': new_core}
    if args.observer_config:
        observed = observer_profile(profile)
        if observed == profile:
            raise ValueError('Observer listeners are already configured')
        settings = stmc_yaml.load(raw['verge.yaml'])
        settings.update(app_log_max_size=4096, app_log_max_count=32, auto_log_clean=3)
        staged = {'profile': stmc_yaml.dump(observed), 'settings': stmc_yaml.dump(settings)}
    installers = {}
    if args.ui_update:
        settings = stmc_yaml.load(raw['verge.yaml'])
        if source_approved:
            if settings.get('enable_dns_settings') is not False or settings.get('profile_dns_settings', {}).get(uid, {}).get('enabled') is True:
                raise ValueError('UI migration requires reviewed disabled DNS override')
            expected_settings, expected_runtime = raw['verge.yaml'], raw['clash-verge.yaml']
        else:
            expected_settings, expected_runtime = ui_migration_expectations(
                settings, runtime, uid, args.service_owner_sid, profile)
        for label, stack in [('old', source_stack), ('new', target_stack)]:
            data = (PROJECT / stack['installer']).read_bytes()
            if sha(data) != stack['installerSha256']:
                raise ValueError('Pinned UI installer mismatch')
            installers[label] = data
    target = args.target_app_root.rstrip('\\/')
    entries = [
        ('core', r'C:\Program Files\Clash Verge\verge-mihomo.exe', old_core),
        ('profile', target + '\\profiles\\' + filename, raw['profile.yaml']),
        ('runtime', target + '\\clash-verge.yaml', raw.get('app-runtime.yaml', raw['clash-verge.yaml'])),
        ('registry', target + '\\profiles.yaml', raw['profiles.yaml']),
        ('settings', target + '\\verge.yaml', raw['verge.yaml']),
    ]
    if args.core_update:
        entries = [entry for entry in entries if entry[0] != 'runtime']
    output.mkdir(parents=True)
    for name, data in staged.items():
        (output / (name + '.new')).write_bytes(data)
    shutil.copyfile(PROJECT / 'scripts/stcvrc-safe-rollout.ps1', output / 'transaction.ps1')
    shutil.copyfile(PROJECT / 'scripts/preserve-stcvrc-evidence.ps1', output / 'preserve-evidence.ps1')
    (output / 'yaml-equivalence.exe').write_bytes(validator)
    plan = {'schema': 1, 'host': args.host, 'lab': args.lab, 'root': args.target_transaction_root,
            'appRoot': target, 'profileFile': filename, 'controllerSecret': runtime['secret'],
            'selectors': selectors, 'tunEnabled': bool(runtime.get('tun', {}).get('enable')),
            'oldVersion': (source_stack['coreVersionToken'] if args.ui_update else
                           STACKS['next']['coreVersionToken'] if args.core_update and sha(old_core) == expected_new else
                           '1.19.29-STCVRC-openvpn-rekey-9e235082' if sha(old_core) == OLD_CORE
                           else '1.19.29-STCVRC-urltest-candidate-20260905'),
            'newVersion': target_stack['coreVersionToken'] if args.ui_update else STACKS['next']['coreVersionToken'] if binary_update else '1.19.29-STCVRC-urltest-candidate-20260905',
            'policy': ('ui-update' if args.ui_update else 'core-update' if args.core_update else 'provider-repair' if args.provider_repair else
                       'four-choices' if args.four_choices else 'single-egress'),
            'repairedProviders': repaired_providers,
            'entries': [{'id': n, 'target': t, 'before': sha(b),
                         'after': sha(staged[n]) if n in staged else sha(b),
                         'replace': n in staged and staged[n] != b} for n, t, b in entries],
            'scriptSha256': sha((output / 'transaction.ps1').read_bytes()),
            'evidenceScriptSha256': sha((output / 'preserve-evidence.ps1').read_bytes()),
            'serviceOwnerDirectory': args.service_owner_directory,
            'yamlValidatorSha256': sha(validator)}
    if args.core_update:
        (output / 'owner-runtime.before.yaml').write_bytes(raw['clash-verge.yaml'])
        plan.update(runtimeLayout='approved', uiVersion='2.5.5', serviceOwnerSid=args.service_owner_sid,
                    serviceOwnerDirectory=owner, ownerRuntimeSha256=sha(raw['clash-verge.yaml']))
        if args.observer_config:
            expected_runtime = stmc_yaml.dump(observer_profile(runtime))
            (output / 'owner-runtime.expected.yaml').write_bytes(expected_runtime)
            plan.update(observerConfig=True, uiTask=args.ui_task,
                        observerRuntimeSha256=sha(expected_runtime))
    if args.ui_update:
        for label, data in installers.items():
            (output / ('ui-' + label + '.exe')).write_bytes(data)
        (output / 'settings.expected.yaml').write_bytes(expected_settings)
        (output / 'owner-runtime.expected.yaml').write_bytes(expected_runtime)
        plan.update(runtimeLayout='ui-migration', oldUiVersion=source_stack['uiVersion'], uiVersion=target_stack['uiVersion'],
                    sourceStack=source_name, targetStack=target_name,
                    oldRuntimeLayout='approved' if source_approved else 'legacy',
                    serviceOwnerSid=args.service_owner_sid, serviceOwnerDirectory=owner,
                    uiTask=args.ui_task, uiInstallers={k: sha(v) for k, v in installers.items()},
                    settingsExpectedSha256=sha(expected_settings), ownerRuntimeSha256=sha(expected_runtime))
        if source_approved:
            (output / 'owner-runtime.before.yaml').write_bytes(raw['clash-verge.yaml'])
            plan['oldOwnerRuntimeSha256'] = sha(raw['clash-verge.yaml'])
    (output / 'plan.json').write_text(json.dumps(plan, indent=2), encoding='utf-8')
    print(json.dumps({'staged': str(output), 'host': args.host, 'files': len(entries),
                      'planSha256': sha((output / 'plan.json').read_bytes()), 'runtimeChanged': False}))


if __name__ == '__main__':
    main()
