"""Bounded loopback-only userVM acceptance; never edits production runtime."""

import base64
import argparse
import copy
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import time

import stmc_yaml
from stcvrc_single_egress import (egress_groups, build_profile, four_choice_groups,
                                build_provider_repair)


PROJECT = Path(__file__).resolve().parents[1]
HOME = PROJECT.parents[1]
KEY = Path(r"C:\review-fixture\unavailable-key")
KNOWN = HOME / "vm_known_hosts"
TARGET = "fixture@192.0.2.137"
CORE = PROJECT / "local/artifacts/stcvrc-v1.19.29/verge-mihomo.exe"
EXPECTED = "71195C943BE67017C5646EA2021734BC122FA83C58A408AB6713A2B25CB6B62B"
RUNTIME = Path(os.environ["APPDATA"]) / "io.github.clash-verge-rev.clash-verge-rev/clash-verge.yaml"
OPTIONS = ["-F", "NUL", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3", "-o", f"UserKnownHostsFile={KNOWN}", "-i", str(KEY)]
SSH = str(Path(os.environ['WINDIR']) / 'System32/OpenSSH/ssh.exe')
SCP = str(Path(os.environ['WINDIR']) / 'System32/OpenSSH/scp.exe')


def ssh_options(via_fixture_relay=False):
    options = list(OPTIONS)
    if via_fixture_relay:
        options[1] = (Path.home() / '.ssh/config').as_posix()
        options += ['-J', 'fixture-relay']
    return options


def command(args, timeout=60):
    result = subprocess.run(args, capture_output=True, timeout=timeout)
    if result.returncode:
        # Never echo SSH/core/config output that could contain private data.
        raise RuntimeError(f"{Path(args[0]).name} exit {result.returncode}")
    return result.stdout.decode("utf-8-sig", errors="replace").strip()


def ps(code, timeout=60):
    code = "$ProgressPreference='SilentlyContinue';$ErrorActionPreference='Stop';" + code
    encoded = base64.b64encode(code.encode("utf-16le")).decode("ascii")
    return command([SSH, *OPTIONS, TARGET, "powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded], timeout)


def provider_config(runtime):
    """Project just the repaired providers and VPS paths into the bounded lab."""
    candidate = build_provider_repair(runtime)
    leaves = [p for p in candidate['proxies'] if p['name'] in ('4VPS', 'GC')]
    groups = [g for g in candidate['proxy-groups']
              if g['name'] in ('FOREIGN-EGRESS', 'VPS-POOL', 'VPS-LATENCY')]
    if (len(leaves) != 2 or any(p['type'] != 'vless' or p.get('dialer-proxy') for p in leaves)
            or groups != four_choice_groups()):
        raise ValueError('Provider gate requires the accepted four-choice policy')
    providers = copy.deepcopy(candidate.get('rule-providers', {}))
    if not providers:
        raise ValueError('No rule providers to test')
    for name, provider in providers.items():
        if (not re.fullmatch(r'[a-z0-9-]+', name) or provider.get('type') != 'http'
                or provider.get('proxy') != 'FOREIGN-EGRESS'):
            raise ValueError('Unexpected provider; explicit lab mapping required')
        provider['path'] = 'rules/' + name + '.cache'
    result = group_config(copy.deepcopy(leaves), False, four_choices=True)
    result['log-level'] = 'info'
    result['proxy-groups'] = copy.deepcopy(groups)
    result['rule-providers'] = providers
    result['rules'] = ['RULE-SET,' + name + ',DIRECT' for name in providers] + ['MATCH,DIRECT']
    return result


def group_config(proxies, synthetic, four_choices=False):
    url = "http://127.0.0.1:18080/health" if synthetic else "https://www.gstatic.com/generate_204"
    names = [p["name"] for p in proxies]
    return {
        "mixed-port": 17890, "allow-lan": False, "bind-address": "127.0.0.1",
        "external-controller": "127.0.0.1:19097", "secret": "stcvrc-autoselect-disposable",
        "mode": "rule", "log-level": "error", "ipv6": False, "unified-delay": False,
        "tun": {"enable": False}, "dns": {"enable": False},
        "profile": {"store-selected": False, "store-fake-ip": False},
        "proxies": proxies,
        "proxy-groups": [
            {"name": "_LAB-CONTROL", "type": "select", "hidden": True,
             "proxies": ["FOREIGN-EGRESS", "VPS-POOL", *names]},
            *(four_choice_groups(interval=2, timeout=1200, url=url) if four_choices else
              egress_groups(names, interval=2 if synthetic else 10,
                            timeout=1200 if synthetic else 5000, url=url)),
        ],
        "rules": ["MATCH,_LAB-CONTROL"],
    }


def main():
    global OPTIONS
    parser=argparse.ArgumentParser(description=__doc__)
    mode=parser.add_mutually_exclusive_group()
    mode.add_argument('--synthetic-only',action='store_true')
    mode.add_argument('--real-only',action='store_true')
    mode.add_argument('--closed-only',action='store_true')
    mode.add_argument('--full-only',action='store_true')
    mode.add_argument('--providers-only', action='store_true')
    parser.add_argument('--core-path', type=Path)
    parser.add_argument('--expected-core-sha256')
    parser.add_argument('--udp-probe', type=Path)
    parser.add_argument('--expected-probe-sha256')
    parser.add_argument('--full-profile', action='store_true')
    parser.add_argument('--profile-input', type=Path)
    parser.add_argument('--skip-body-download', action='store_true')
    parser.add_argument('--four-choices', action='store_true')
    parser.add_argument('--via-fixture_relay', action='store_true')
    args=parser.parse_args()
    OPTIONS = ssh_options(args.via_fixture_relay)
    if args.four_choices and not args.synthetic_only:
        parser.error('--four-choices currently requires --synthetic-only')
    if args.providers_only and (args.full_profile or args.profile_input or args.udp_probe):
        parser.error('--providers-only cannot enable full-profile or UDP tests')
    if args.full_only:
        args.full_profile = True
    if args.profile_input and not args.full_profile:
        parser.error('--profile-input requires --full-profile or --full-only')
    if bool(args.core_path) != bool(args.expected_core_sha256) or bool(args.udp_probe) != bool(args.expected_probe_sha256):
        parser.error('Explicit executable path and SHA256 must be supplied together')
    core = args.core_path or CORE
    expected = args.expected_core_sha256 or EXPECTED
    for path in (KEY, KNOWN, core, RUNTIME):
        if not path.is_file():
            raise RuntimeError("Required existing local input is missing")
    core_hash = hashlib.sha256(core.read_bytes()).hexdigest().upper()
    if core_hash != expected.upper():
        raise RuntimeError("Core hash mismatch")
    if args.udp_probe and hashlib.sha256(args.udp_probe.read_bytes()).hexdigest().upper() != args.expected_probe_sha256.upper():
        raise RuntimeError('UDP probe hash mismatch')
    runtime_bytes = RUNTIME.read_bytes()
    runtime = stmc_yaml.load(runtime_bytes)
    leaves = {p["name"]: copy.deepcopy(p) for p in runtime["proxies"] if p["name"] in ("4VPS", "VPS-GREEN", "GC")}
    if len(leaves) != 2 or '4VPS' not in leaves or any(p["type"] != "vless" or p.get("dialer-proxy") for p in leaves.values()):
        raise RuntimeError("Unexpected production leaf dependency")
    if 'GC' in leaves:
        leaves['VPS-GREEN'] = leaves.pop('GC')
        leaves['VPS-GREEN']['name'] = 'VPS-GREEN'
    stamp = time.strftime("%Y%m%d-%H%M%S")
    local = PROJECT / "local/labs" / ("stcvrc-autoselect-" + stamp)
    local.mkdir(parents=True, exist_ok=False)
    synthetic = group_config([
        {"name": "4VPS" if args.four_choices else "A", "type": "http", "server": "127.0.0.1", "port": 18081},
        {"name": "GC" if args.four_choices else "B", "type": "http", "server": "127.0.0.1", "port": 18082},
    ], True, args.four_choices)
    real = group_config([leaves["VPS-GREEN"], leaves["4VPS"]], False)
    for name, data in (("synthetic.json", synthetic), ("real.json", real)):
        (local / name).write_text(json.dumps(data, ensure_ascii=True), encoding="ascii")
    extra_inputs = []
    if args.providers_only:
        (local / 'providers.json').write_text(json.dumps(provider_config(runtime)), encoding='ascii')
        extra_inputs.append((local / 'providers.json', 'providers.json'))
    if args.udp_probe:
        extra_inputs.append((args.udp_probe, 'udp-probe.exe'))
    if args.full_profile:
        candidate = stmc_yaml.load(args.profile_input.read_bytes()) if args.profile_input else build_profile(runtime)
        if candidate != build_profile(runtime):
            raise RuntimeError('Candidate runtime does not match current single-policy transformation')
        full = copy.deepcopy(candidate)
        for key in ('port', 'socks-port', 'redir-port', 'tproxy-port', 'listeners', 'external-controller-pipe', 'external-controller-unix', 'external-controller-tls'):
            full.pop(key, None)
        for key in ('mixed-port', 'allow-lan', 'bind-address', 'external-controller', 'secret', 'profile'):
            full[key] = real[key]
        full['log-level'] = 'info'
        full['tun']['enable'] = False
        full['dns']['listen'] = '127.0.0.1:17853'
        for n, provider in full.get('rule-providers', {}).items():
            if provider.get('type') != 'http' or provider.get('path'):
                raise RuntimeError('Unexpected provider source; requires explicit resource mapping')
        (local / 'full.json').write_text(json.dumps(full, ensure_ascii=True), encoding='ascii')
        extra_inputs.append((local / 'full.json', 'full.json'))
        extra_inputs.append((PROJECT / 'scripts/uservm-stmc-two-vps-lab.remote.ps1', 'protocol-source.ps1'))
        for name in ('geoip.dat', 'geosite.dat', 'Country.mmdb'):
            extra_inputs.append((RUNTIME.parent / name, name))
        for resource in (RUNTIME.parent / 'rules').iterdir():
            if resource.is_file():
                extra_inputs.append((resource, 'rules/' + resource.name))
        if full['rules'] != candidate['rules'] or full['proxies'] != runtime['proxies']:
            raise RuntimeError('Full profile route/proxy drift')
    report = {"startedAt": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "syntheticOnly":args.synthetic_only, "realOnly":args.real_only, "closedOnly":args.closed_only, "fullOnly":args.full_only, "providersOnly":args.providers_only, "fullProfile":args.full_profile, "runtimeBeforeSha256": hashlib.sha256(runtime_bytes).hexdigest(), "coreSha256": core_hash, "run": None, "error": None, "cleanupError": None}
    remote = None
    if args.profile_input:
        report['candidateRuntimeSha256'] = hashlib.sha256(args.profile_input.read_bytes()).hexdigest()
    owned = False
    driver_ready = False
    try:
        discovery = json.loads(ps("""
if($env:COMPUTERNAME -ine 'LABHOST'){throw 'Wrong host'}
$lab=[IO.Path]::GetFullPath((Join-Path $env:USERPROFILE 'stcvrc-autoselect-lab')).TrimEnd('\\')
if(Test-Path -LiteralPath $lab){throw 'Lab already exists'}
if(@(Get-CimInstance Win32_Process | Where-Object {$_.Name -match 'mihomo|clash'}).Count){throw 'Existing core'}
if(@(Get-NetTCPConnection -State Listen | Where-Object {$_.LocalPort -in @(17890,19097,18080,18081,18082,17853)}).Count){throw 'Port occupied'}
if(@(Get-NetUDPEndpoint | Where-Object {$_.LocalPort -in @(17890,17853)}).Count){throw 'UDP port occupied'}
[ordered]@{host=$env:COMPUTERNAME;lab=$lab;labAbsent=$true}|ConvertTo-Json -Compress
"""))
        remote = discovery["lab"]
        if not remote.lower().startswith("c:\\users\\fixtureservice") or not remote.endswith("\\stcvrc-autoselect-lab"):
            raise RuntimeError("Unexpected remote owner path")
        report["discovery"] = discovery
        print(json.dumps({"stage": "preflight", "host": discovery["host"], "labAbsent": True}), flush=True)
        ps(f"$p='{remote}';if(Test-Path -LiteralPath $p){{throw 'Exists'}};New-Item -ItemType Directory -Path $p|Out-Null;New-Item -ItemType Directory -Path (Join-Path $p 'rules')|Out-Null;[IO.File]::WriteAllText((Join-Path $p '.guard'),'STCVRC_AUTOSELECT_V1')")
        owned = True
        inputs = [
            (PROJECT / "scripts/uservm-stcvrc-autoselect.remote.ps1", "driver.ps1"),
            (PROJECT / "scripts/stcvrc-autoselect-fixture.cs", "fixture.cs"),
            (core, "verge-mihomo.exe"),
            (local / "synthetic.json", "synthetic.json"),
            (local / "real.json", "real.json"),
        ] + extra_inputs
        invoke = f"& '{remote}\\driver.ps1'"
        for source, name in inputs:
            destination = remote.replace("\\", "/") + "/" + name
            command([SCP, *OPTIONS, str(source), f"{TARGET}:{destination}"], 120)
            if name == "driver.ps1":
                driver_ready = True
                report["before"] = json.loads(ps(invoke + " -Mode Snapshot", 90))
                if report["before"]["coreProcesses"] or report["before"]["listeners"] or report["before"].get('udpListeners'):
                    raise RuntimeError("Pre-run baseline not empty")
                print(json.dumps({"stage": "baseline", "fingerprint": report["before"]["fingerprint"]}), flush=True)
        report['inputHashes']={name:hashlib.sha256(source.read_bytes()).hexdigest() for source,name in inputs}
        print(json.dumps({"stage": "running", "baseline": report["before"]["fingerprint"]}), flush=True)
        flags = (' -SyntheticOnly' if args.synthetic_only else ' -RealOnly' if args.real_only else ' -ClosedOnly' if args.closed_only else ' -FullOnly' if args.full_only else '')
        if args.udp_probe:
            flags += ' -ExpectedProbeHash ' + args.expected_probe_sha256
        if args.full_profile:
            flags += ' -FullProfile'
        if args.skip_body_download:
            flags += ' -SkipBodyDownload'
        if args.four_choices:
            flags += ' -FourChoices'
        if args.providers_only:
            flags += ' -ProvidersOnly -ExpectedConfigHash ' + report['inputHashes']['providers.json']
        report["completion"] = json.loads(ps(invoke + f" -Mode Run -ExpectedCoreHash {core_hash}" + flags, 650))
        raw = ps(f"$p='{remote}\\result.json';if((Get-Item -LiteralPath $p).Length -gt 1048576){{throw 'Oversized report'}};[Convert]::ToBase64String([IO.File]::ReadAllBytes($p))", 30)
        report["run"] = json.loads(base64.b64decode(raw).decode('utf-8-sig'))
        if report['run'].get('error'):
            for name in ('core.out.log','core.err.log'):
                # Diagnostic files stay beside the private lab inputs, never in public reports.
                command([SCP, *OPTIONS, f'{TARGET}:{remote.replace(chr(92), "/")}/{name}', str(local / name)], 30)
    except Exception as exc:
        report["error"] = type(exc).__name__ + ": " + str(exc)
    finally:
        if owned and driver_ready:
            try:
                report["after"] = json.loads(ps(f"& '{remote}\\driver.ps1' -Mode Cleanup", 90))
            except Exception as exc:
                report["cleanupError"] = type(exc).__name__ + ": " + str(exc)
        elif owned:
            # Setup failures before the driver exists may only remove the exact guarded tree.
            try:
                ps(f"$p='{remote}';if(Test-Path -LiteralPath $p){{$i=Get-Item -LiteralPath $p -Force;if($i.FullName -ine $p -or ($i.Attributes -band [IO.FileAttributes]::ReparsePoint)){{throw 'Unsafe'}};if((Get-Content -LiteralPath (Join-Path $p '.guard') -Raw) -cne 'STCVRC_AUTOSELECT_V1'){{throw 'Wrong guard'}};Remove-Item -LiteralPath $p -Recurse -Force}}")
            except Exception as exc:
                report["cleanupError"] = type(exc).__name__ + ": " + str(exc)
        report["runtimeUnchanged"] = hashlib.sha256(RUNTIME.read_bytes()).hexdigest() == report["runtimeBeforeSha256"]
        before, after = report.get("before", {}), report.get("after", {})
        report["baselineMatch"] = bool(before and after and before["fingerprint"] == after["fingerprint"])
        report["cleanupPass"] = bool(after.get("labAbsent") and not after.get("coreProcesses") and not after.get("listeners") and not after.get('udpListeners') and not report["cleanupError"])
        required=('initial','toleranceFromFirst','toleranceFromSecond','degradation','continuity','oneDown','bothDown','recovery')
        if args.closed_only:
            required=('bothDown','recovery')
        if args.four_choices:
            required=('initial','manual4VPS','manualGC','manualDIRECT','manualFailure','oneDown','bothDown','recovery','continuity')
        synthetic=(report.get('run') or {}).get('synthetic',{})
        report['syntheticGatePass']=all(synthetic.get(name,{}).get('pass') is True for name in required)
        providers = (report.get('run') or {}).get('providers', {})
        report['providersGatePass'] = bool(providers.get('coldPass') and providers.get('refreshPass'))
        report["finishedAt"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        output = PROJECT / "reports" / ("uservm-stcvrc-autoselect-" + stamp + ".json")
        output.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(json.dumps({"report": str(output), "baselineMatch": report["baselineMatch"], "cleanupPass": report["cleanupPass"], "runtimeUnchanged": report["runtimeUnchanged"], "error": report["error"], "cleanupError": report["cleanupError"], "runError": (report.get("run") or {}).get("error")}), flush=True)
    gate_pass = report['providersGatePass'] if args.providers_only else (args.real_only or args.full_only or report['syntheticGatePass'])
    return 0 if gate_pass and report["runtimeUnchanged"] and report["cleanupPass"] and report["baselineMatch"] and not report["error"] and not (report.get("run") or {}).get("error") else 1


if __name__ == "__main__":
    sys.exit(main())
