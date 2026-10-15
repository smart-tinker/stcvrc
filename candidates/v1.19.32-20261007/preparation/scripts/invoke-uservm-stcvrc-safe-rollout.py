"""Disposable stock-CVR/service validation of the guarded transaction."""
import base64
import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import time
import shutil

import stmc_yaml
from stcvrc_single_egress import build_profile, build_four_choices, build_provider_repair

PROJECT = Path(__file__).resolve().parents[1]
ACCESS = runpy.run_path(str(PROJECT / 'scripts/invoke-uservm-stcvrc-autoselect.py'))
ps, command = ACCESS['ps'], ACCESS['command']
RUNTIME = ACCESS['RUNTIME']
BUNDLE = PROJECT / 'local/artifacts/stcvrc-single-egress-20260906'
RELEASE = PROJECT / 'local/artifacts/stcvrc-v1.19.29'


def hash_file(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def upload(source, destination):
    command([ACCESS['SCP'], *ACCESS['OPTIONS'], str(source), ACCESS['TARGET'] + ':' + destination.replace('\\', '/')], 120)


def download(source, destination):
    command([ACCESS['SCP'], *ACCESS['OPTIONS'], ACCESS['TARGET'] + ':' + source.replace('\\', '/'), str(destination)], 60)


def provider_lab_profile(runtime):
    result = ACCESS['provider_config'](runtime)
    for name, provider in result['rule-providers'].items():
        provider['proxy'] = runtime['rule-providers'][name]['proxy']
    result.update({'mixed-port': 7897, 'external-controller': '127.0.0.1:9097',
                   'rules': ['MATCH,FOREIGN-EGRESS']})
    result['profile']['store-selected'] = True
    result['proxy-groups'].append({'name': 'LAB-UNCHANGED', 'type': 'select',
                                   'proxies': ['DIRECT', 'REJECT']})
    return result


def remote_json(path):
    raw = ps("$p='" + path + "';if((Get-Item -LiteralPath $p).Length -gt 1048576){throw 'Oversized'};[Convert]::ToBase64String([IO.File]::ReadAllBytes($p))")
    return json.loads(base64.b64decode(raw).decode('utf-8-sig'))


def wait_phase(root, phases, seconds=140):
    allowed = ','.join("'" + p + "'" for p in phases)
    code = f"""
$until=(Get-Date).AddSeconds({seconds});$file='{root}\\state.json';$phase='missing'
do {{
 if(Test-Path -LiteralPath $file){{$phase=([IO.File]::ReadAllText($file)|ConvertFrom-Json).phase}}
 if($phase -in @({allowed}) -or $phase -eq 'rollback-failed'){{break}}
 Start-Sleep -Seconds 1
}} while((Get-Date) -lt $until)
@{{phase=$phase}}|ConvertTo-Json -Compress
"""
    return json.loads(ps(code, seconds + 20))['phase']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--four-choices', action='store_true')
    mode.add_argument('--provider-repair', action='store_true')
    parser.add_argument('--bundle', type=Path, default=BUNDLE)
    args = parser.parse_args()
    profile_only = args.four_choices or args.provider_repair
    baseline_core = args.bundle / 'verge-mihomo.exe' if profile_only else RELEASE / 'verge-mihomo.exe'
    stamp = time.strftime('%Y%m%d-%H%M%S')
    local = PROJECT / 'local/labs' / ('stcvrc-safe-' + stamp)
    local.mkdir(parents=True, exist_ok=False)
    report = {'startedAt': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'cases': {}, 'error': None,
              'cleanupError': None, 'runtimeBefore': hash_file(RUNTIME),
              'policy': 'provider-repair' if args.provider_repair else 'four-choices' if args.four_choices else 'single-egress'}
    lab = None
    lab_created = False
    driver_ready = False
    baseline_accepted = False
    try:
        discovery = json.loads(ps("""
if($env:COMPUTERNAME -cne 'LABHOST'){throw 'Wrong host'}
$p=Join-Path $env:USERPROFILE 'stcvrc-fullstack-lab'
if(Test-Path -LiteralPath $p){throw 'Lab exists'}
if(Get-ScheduledTask -TaskName 'STCVRC-Safe-Rollout' -ErrorAction SilentlyContinue){throw 'Guard exists'}
if(Get-CimInstance Win32_Process | Where-Object {$_.Name -match 'clash|mihomo'}){throw 'Existing runtime'}
@{profile=$env:USERPROFILE;app=(Join-Path $env:APPDATA 'io.github.clash-verge-rev.clash-verge-rev');lab=$p}|ConvertTo-Json -Compress
"""))
        lab, remote_app = discovery['lab'], discovery['app']
        if discovery['profile'] != r'C:\Users\FixtureService':
            raise RuntimeError('Unexpected VM profile root')
        ps(f"$p='{lab}';if(Test-Path -LiteralPath $p){{throw 'Exists'}};$null=New-Item -ItemType Directory -Path $p;foreach($n in @('input','input\\rules','logs','transactions')){{$null=New-Item -ItemType Directory -Path (Join-Path $p $n)}};[IO.File]::WriteAllText((Join-Path $p '.codex-stcvrc-fullstack-lab'),'STCVRC_FULLSTACK_LAB_V1')")
        lab_created = True
        upload(PROJECT / 'scripts/uservm-stcvrc-fullstack.remote.ps1', lab + '\\fullstack.ps1')
        upload(PROJECT / 'scripts/uservm-stcvrc-safe-rollout.remote.ps1', lab + '\\driver.ps1')
        driver_ready = True
        invoke = f"& '{lab}\\driver.ps1'" + (' -ProviderRepair' if args.provider_repair else '')
        before = json.loads(ps(invoke + ' -Action Snapshot', 90))
        report['before'] = {**before['inventory'], 'footprintAbsent': before['baseline']['footprintAbsent'],
                            'elevated': before['baseline']['elevatedAdministrator']}
        if not report['before']['footprintAbsent'] or not report['before']['elevated']:
            raise RuntimeError('VM full-stack preflight rejected')
        baseline_accepted = True
        print(json.dumps({'stage': 'VM baseline', **report['before']}), flush=True)
        profile = RUNTIME.parent / 'profiles/Kmc2Vps0716A.yaml'
        uid = 'LSTCVRCGate'
        registry = {'current': uid, 'items': [
            {'uid': 'Merge', 'type': 'merge', 'file': 'Merge.yaml'},
            {'uid': 'Script', 'type': 'script', 'file': 'Script.js'},
            {'uid': uid, 'type': 'local', 'name': 'STCVRC disposable gate', 'file': uid + '.yaml',
             'selected': [{'name': 'VPS-DEFAULT', 'now': 'VPS-GREEN'}], 'updated': int(time.time())}]}
        if args.provider_repair:
            profile = local / 'lab-profile.yaml'
            profile.write_bytes(stmc_yaml.dump(provider_lab_profile(stmc_yaml.load(RUNTIME.read_bytes()))))
            registry['items'][-1]['selected'] = [
                {'name': 'FOREIGN-EGRESS', 'now': 'GC'},
                {'name': 'LAB-UNCHANGED', 'now': 'REJECT'}]
        settings = {'app_log_level': 'info', 'language': 'en', 'clash_core': 'verge-mihomo',
                    'enable_tun_mode': False, 'enable_system_proxy': False, 'enable_auto_launch': False,
                    'enable_silent_start': True, 'enable_proxy_guard': False, 'enable_dns_settings': False,
                    'enable_global_hotkey': False, 'auto_check_update': False,
                    'enable_external_controller': True, 'verge_mixed_port': 7897}
        for n, obj in [('profiles.yaml', registry), ('verge.yaml', settings)]:
            (local / n).write_bytes(stmc_yaml.dump(obj))
        inputs = {'profile.yaml': profile, 'old-core.exe': baseline_core,
                  'Clash.Verge_2.5.2_x64-setup.exe': RELEASE / 'Clash.Verge_2.5.2_x64-setup.exe',
                  'profiles.yaml': local / 'profiles.yaml', 'verge.yaml': local / 'verge.yaml'}
        if not args.provider_repair:
            for n in ['Country.mmdb', 'geoip.dat', 'geosite.dat']:
                inputs[n] = RUNTIME.parent / n
        expected = {'old-core.exe': ('40828a0f84c2c18fa917fa23246c7b87fc2c7d798c6a7c13a3db1dc997d94540' if profile_only else '71195c943be67017c5646ea2021734bc122fa83c58a408ab6713a2b25cb6b62b'),
                    'Clash.Verge_2.5.2_x64-setup.exe': 'ba42f00b1082e352352080170fe86ae411bcc854cb13f1b8bebc9025e8a7cbf4'}
        for n, value in expected.items():
            if hash_file(inputs[n]) != value:
                raise RuntimeError('Pinned lab binary hash mismatch')
        hashes = {n: hash_file(p) for n, p in inputs.items()}
        (local / 'hashes.json').write_text(json.dumps(hashes), encoding='utf-8')
        inputs['hashes.json'] = local / 'hashes.json'
        for n, source in inputs.items():
            upload(source, lab + '\\input\\' + n)
        if not args.provider_repair:
            for source in (RUNTIME.parent / 'rules').iterdir():
                if source.is_file():
                    upload(source, lab + '\\input\\rules\\' + source.name)
        report['setup'] = json.loads(ps(invoke + ' -Action Setup', 220))
        print(json.dumps({'stage': 'stock UI/service ready', 'version': report['setup']['version'],
                          'tunDisabled': report['setup']['tunDisabled']}), flush=True)
        if not report['setup']['tunDisabled'] or report['setup']['proxyEnabled']:
            raise RuntimeError('Lab isolation failed')
        if args.provider_repair:
            report['baselineCanaries'] = json.loads(ps(invoke + ' -Action Canary', 40))
            if not report['baselineCanaries']['pass']:
                raise RuntimeError('Existing VPS application path failed before transaction')
        source_app = local / 'baseline-app'
        (source_app / 'profiles').mkdir(parents=True)
        for name in ['profiles.yaml', 'verge.yaml', 'clash-verge.yaml', 'profiles/' + uid + '.yaml']:
            download(remote_app + '\\' + name.replace('/', '\\'), source_app / name)
        download(lab + '\\selectors.json', local / 'selectors.json')
        bundle = args.bundle
        if args.provider_repair:
            bundle = local / 'provider-lab-bundle'
            bundle.mkdir()
            baseline = stmc_yaml.load((source_app / 'profiles' / (uid + '.yaml')).read_bytes())
            (bundle / 'STCVRC-provider-repair.yaml').write_bytes(stmc_yaml.dump(build_provider_repair(baseline)))
            shutil.copyfile(baseline_core, bundle / 'verge-mihomo.exe')
            report['isolatedVpsProjection'] = True
            report['capturedSelectors'] = json.loads((local / 'selectors.json').read_text())
            if report['capturedSelectors'] != {'FOREIGN-EGRESS': 'GC', 'LAB-UNCHANGED': 'REJECT'}:
                raise RuntimeError('Lab selectors were not seeded as expected')
        for index, case in enumerate(['confirmed', 'killed-after-copy', 'no-confirmation'], 1):
            target = lab + '\\transactions\\stcvrc-safe-' + stamp + '-' + str(index)
            stage = local / ('stcvrc-safe-' + stamp + '-' + str(index))
            command([sys.executable, '-B', str(PROJECT / 'scripts/prepare-stcvrc-safe-rollout.py'),
                     '--app-root', str(source_app), '--old-core', str(baseline_core),
                     '--bundle', str(bundle), '--output', str(stage), '--host', 'LABHOST', '--lab',
                     '--target-app-root', remote_app, '--target-transaction-root', target,
                     '--selectors-json', str(local / 'selectors.json')] +
                    (['--provider-repair'] if args.provider_repair else ['--four-choices'] if args.four_choices else []))
            plan = json.loads((stage / 'plan.json').read_text(encoding='utf-8'))
            if profile_only and any(e['replace'] for e in plan['entries'] if e['id'] == 'core'):
                raise RuntimeError('Profile-only transaction must not replace core')
            if args.provider_repair and sorted(e['id'] for e in plan['entries'] if e['replace']) != ['profile', 'runtime']:
                raise RuntimeError('Provider-only transaction exceeds its scope')
            ps(f"$null=New-Item -ItemType Directory -Path '{target}'")
            for source in stage.iterdir():
                upload(source, target + '\\' + source.name)
            deadline = 300 if case == 'confirmed' else 75
            pause = 'AfterCopy' if case == 'killed-after-copy' else 'None'
            launch = json.loads(ps(f"& '{target}\\transaction.ps1' -Mode Launch -Transaction '{target}' -DeadlineSeconds {deadline} -LabPause {pause}"))
            wanted = 'lab-paused-after-copy' if case == 'killed-after-copy' else 'awaiting-confirmation'
            phase = wait_phase(target, [wanted, 'rolled-back'], 110)
            entry = {'phase': phase, 'launch': launch, 'planHash': hash_file(stage / 'plan.json'),
                     'scriptHash': hash_file(stage / 'transaction.ps1')}
            report['cases'][case] = entry
            if phase != wanted:
                for name in ['apply-error.json', 'rollback-error.json', 'watch-error.json', 'http-error.json', 'rollback-result.json']:
                    try:
                        entry[name] = remote_json(target + '\\' + name)
                    except Exception:
                        pass
                raise RuntimeError('Transaction did not reach expected phase')
            print(json.dumps({'stage': case, 'phase': phase}), flush=True)
            worker = remote_json(target + '\\armed.json')
            entry['workerPid'] = worker['pid']
            if case == 'confirmed':
                entry['withoutConsumerRejected'] = json.loads(ps(f"$rejected=$false;try{{& '{target}\\transaction.ps1' -Mode Confirm -Transaction '{target}'|Out-Null}}catch{{$rejected=$true}};@{{rejected=$rejected;phase=([IO.File]::ReadAllText('{target}\\state.json')|ConvertFrom-Json).phase}}|ConvertTo-Json -Compress"))
                entry['candidate'] = remote_json(target + '\\candidate-result.json')
                if args.four_choices:
                    entry['manualChoices'] = [json.loads(ps(invoke + ' -Action SelectForeign -Choice ' + choice))
                                              for choice in ['VPS-POOL', '4VPS', 'DIRECT', 'GC']]
                entry['uiRestart'] = json.loads(ps(invoke + ' -Action Inspect', 150))
                download(remote_app + '\\clash-verge.yaml', local / 'after-ui-runtime.yaml')
                for name in ['profiles.yaml', 'verge.yaml']:
                    download(remote_app + '\\' + name, local / ('after-ui-' + name))
                old = stmc_yaml.load((source_app / 'clash-verge.yaml').read_bytes())
                new = stmc_yaml.load((local / 'after-ui-runtime.yaml').read_bytes())
                candidate = (build_provider_repair if args.provider_repair else build_four_choices if args.four_choices else build_profile)(old)
                entry['uiPolicyPersisted'] = all(candidate[k] == new[k] for k in ['proxies', 'proxy-groups', 'rules', 'rule-providers', 'dns'])
                entry['uiBinaryUnchanged'] = entry['uiRestart']['uiHash'] == report['setup']['uiHash']
                entry['uiBeforeConfirmation'] = True
                if args.four_choices:
                    foreign = next(g for g in entry['uiRestart']['groups'] if g['name'] == 'FOREIGN-EGRESS')
                    entry['manualChoicePersisted'] = foreign['now'] == 'GC'
                    entry['coreUnchanged'] = entry['uiRestart']['coreHash'].lower() == expected['old-core.exe']
                    entry['returnToAuto'] = json.loads(ps(invoke + ' -Action SelectForeign -Choice VPS-POOL'))
                if args.provider_repair:
                    actual = {g['name']: g['now'] for g in entry['uiRestart']['groups'] if g['type'] == 'Selector'}
                    entry['allSelectorsPreserved'] = actual == report['capturedSelectors']
                    entry['coreUnchanged'] = entry['uiRestart']['coreHash'].lower() == expected['old-core.exe']
                    entry['registryPreserved'] = stmc_yaml.load((source_app / 'profiles.yaml').read_bytes()) == stmc_yaml.load((local / 'after-ui-profiles.yaml').read_bytes())
                entry['afterUiConfirm'] = json.loads(ps(f"& '{target}\\transaction.ps1' -Mode Confirm -Transaction '{target}' -ConsumerConfirmed", 80))
                ps(f"& '{target}\\transaction.ps1' -Mode Rollback -Transaction '{target}'", 100)
            elif case == 'killed-after-copy':
                ps(f"$p=Get-CimInstance Win32_Process -Filter 'ProcessId={worker['pid']}';if(-not $p -or -not $p.CommandLine.Contains('{target}')){{throw 'Wrong worker'}};Stop-Process -Id $p.ProcessId -Force")
                entry['workerKilled'] = True
                phase = wait_phase(target, ['rolled-back'], 140)
                if phase != 'rolled-back':
                    raise RuntimeError('Independent rollback failed after worker termination')
            else:
                phase = wait_phase(target, ['rolled-back'], 140)
                if phase != 'rolled-back':
                    raise RuntimeError('Independent rollback failed without confirmation')
            entry['rollback'] = remote_json(target + '\\rollback-result.json')
            entry['watchdog'] = remote_json(target + '\\watch-ready.json')
            entry['pass'] = entry['rollback']['pass'] and entry['watchdog']['session'] == 0
            if case == 'confirmed':
                entry['pass'] &= entry['withoutConsumerRejected']['rejected'] and entry['uiPolicyPersisted'] and entry['uiBinaryUnchanged'] and entry['afterUiConfirm']['phase'] == 'committed'
                if args.four_choices:
                    entry['pass'] &= entry['coreUnchanged'] and entry['manualChoicePersisted'] and entry['returnToAuto']['pass'] and all(c['pass'] for c in entry['manualChoices'])
                if args.provider_repair:
                    entry['pass'] &= entry['coreUnchanged'] and entry['allSelectorsPreserved'] and entry['registryPreserved']
            print(json.dumps({'stage': case, 'pass': entry['pass'], 'restored': True}), flush=True)
        report['allCasesPass'] = all(v['pass'] for v in report['cases'].values())
    except Exception as exc:
        report['error'] = type(exc).__name__ + ': ' + str(exc)
    finally:
        if driver_ready and baseline_accepted:
            try:
                clean = json.loads(ps(f"& '{lab}\\driver.ps1' -Action Cleanup", 180))
                report['after'] = {**clean['inventory'], 'cleanupPass': clean['cleanup']['pass'],
                                   'guardTaskAbsent': clean['guardTaskAbsent'],
                                   'footprintAbsent': clean['cleanup']['post']['footprintAbsent']}
                report['baselineMatch'] = report['after']['fingerprint'] == report['before']['fingerprint']
            except Exception as exc:
                report['cleanupError'] = type(exc).__name__ + ': ' + str(exc)
        elif lab_created:
            # A rejected baseline never authorizes cleanup of an existing CVR installation.
            try:
                ps(f"""
$p=[IO.Path]::GetFullPath('{lab}').TrimEnd('\\')
if($env:COMPUTERNAME -cne 'LABHOST' -or $p -ine 'C:\\Users\\FixtureService\\stcvrc-fullstack-lab'){{throw 'Unsafe staging root'}}
if([IO.File]::ReadAllText((Join-Path $p '.codex-stcvrc-fullstack-lab')) -cne 'STCVRC_FULLSTACK_LAB_V1'){{throw 'Missing staging guard'}}
$parent=$p
while($parent){{if((Get-Item -LiteralPath $parent -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){{throw 'Reparse path'}};$parent=Split-Path -Parent $parent}}
if(@(Get-ChildItem -LiteralPath $p -Recurse -Force | Where-Object {{$_.Attributes -band [IO.FileAttributes]::ReparsePoint}}).Count){{throw 'Reparse tree'}}
Remove-Item -LiteralPath $p -Recurse -Force
if(Test-Path -LiteralPath $p){{throw 'Staging cleanup failed'}}
""")
                report['stagingCleanupPass'] = True
            except Exception as exc:
                report['cleanupError'] = type(exc).__name__ + ': ' + str(exc)
        report['runtimeUnchanged'] = hash_file(RUNTIME) == report['runtimeBefore']
        report['finishedAt'] = time.strftime('%Y-%m-%dT%H:%M:%S%z')
        path = PROJECT / 'reports' / ('uservm-stcvrc-safe-rollout-' + stamp + '.json')
        path.write_text(json.dumps(report, indent=2), encoding='utf-8')
        print(json.dumps({'report': str(path), 'error': report['error'], 'cleanupError': report['cleanupError'],
                          'baselineMatch': report.get('baselineMatch'), 'runtimeUnchanged': report['runtimeUnchanged'],
                          'allCasesPass': report.get('allCasesPass')}), flush=True)
    return 0 if not report['error'] and not report['cleanupError'] and report.get('baselineMatch') and report.get('allCasesPass') and report['runtimeUnchanged'] else 1


if __name__ == '__main__':
    sys.exit(main())
