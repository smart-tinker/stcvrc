"""Approved FixtureUser-session gate with exact restoration of pre-existing CVR data."""
import base64
import argparse
import hashlib
import gzip
from datetime import datetime
import json
from pathlib import Path
import runpy
import sys
import time
import zipfile

import stmc_yaml
from stcvrc_observer import observer_profile, LISTENERS, TARGETS
from stcvrc_lab_transport import run as transport_run, TransportFailure, lab_options, command_budget
from stcvrc_lab_stack import STACKS, stack_inputs, native_identity_check, prelogin_observer_check, desktop_acceptance, inventory_comparison
from stcvrc_corporate_gate import add_corporate_canaries
from stcvrc_rotation_gate import LISTENER as ROTATION_LISTENER

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--observer-bundle',type=Path,help='Unpacked payload directory with manifest.json and adjacent .zip')
parser.add_argument('--atomic-observer-bundle',type=Path,help='Pinned observer payload staged inside the candidate SYSTEM transaction; fresh absent userVM baseline only')
parser.add_argument('--atomic-observer-label',choices=('home','work'),default='home')
parser.add_argument('--observer-production',action='store_true',help='Accept the production installer on disposable userVM, then remove its exact footprint')
parser.add_argument('--via-fixture_relay',action='store_true')
parser.add_argument('--reboot',action='store_true')
parser.add_argument('--await-logon',action='store_true',help='Require real FixtureUser logon after reboot; no manual UI launch')
parser.add_argument('--stack',choices=STACKS,default='accepted')
parser.add_argument('--preserve-service-state',action='store_true')
parser.add_argument('--corporate-canaries',action='store_true',help='Separately approved parallel LT/Elitech sessions; loopback-only')
parser.add_argument('--corporate-idle-seconds',type=int,default=75,help='Bounded idle before the corporate check (75..600 seconds)')
parser.add_argument('--require-baseline-report',type=Path,help='Require same-context exact preflight against an earlier desktop report')
parser.add_argument('--rotation-gate',action='store_true',help='Bounded loopback REJECT load for native service log rotation')
parser.add_argument('--lt-packet-counters',action='store_true',help='Temporary NIC counters only during the approved corporate idle gate')
parser.add_argument('--core-rollout-gate',action='store_true',help='Core24g apply and automatic rollback inside stock CVR2.5.5, no TUN')
parser.add_argument('--observer-config-gate',action='store_true',help='Only observer profile/log settings under the existing core transaction on next stack')
parser.add_argument('--ui-migration-gate',action='store_true',help='Bounded stock UI2.5.2 -> 2.5.5 -> 2.5.2 transition, no TUN')
parser.add_argument('--ui-rollout-gate',action='store_true',help='Existing SYSTEM transaction: full UI/core upgrade and automatic rollback')
parser.add_argument('--ui-rollout-target-stack',choices=('next','candidate'),default='next',help='Pinned full UI/core target; source is --stack')
parser.add_argument('--tun-gate',action='store_true',help='Transient userVM TUN under unconfirmed core rollback or exact candidate UI/core rollback')
args=parser.parse_args()
if args.atomic_observer_bundle and (not args.ui_rollout_gate or args.ui_rollout_target_stack!='candidate' or args.observer_bundle or args.observer_production or args.reboot):
    parser.error('Atomic observer requires only the candidate UI/core transaction, without a separate installer or reboot')
if args.atomic_observer_bundle and (not args.atomic_observer_bundle.is_dir() or not (args.atomic_observer_bundle/'manifest.json').is_file() or not args.atomic_observer_bundle.with_suffix('.zip').is_file()):
    parser.error('Atomic observer bundle must be an unpacked directory with manifest.json and adjacent .zip')
if not args.atomic_observer_bundle and args.atomic_observer_label!='home':
    parser.error('Atomic observer label requires its bundle')
if args.observer_config_gate and (not args.core_rollout_gate or args.observer_bundle or args.tun_gate):
    parser.error('Observer config gate requires core-rollout-gate without observer bundle/TUN')
if args.tun_gate and (not (args.core_rollout_gate or (args.ui_rollout_gate and args.ui_rollout_target_stack=='candidate')) or args.observer_bundle):
    parser.error('TUN gate requires core-rollout-gate or exact candidate UI transaction, without a separate observer installer')
if args.observer_production and (not args.observer_bundle or args.stack not in ('next','candidate')):
    parser.error('Production observer acceptance requires next stack and the pinned bundle')
if args.observer_bundle and (not args.observer_bundle.is_dir()
        or not (args.observer_bundle/'manifest.json').is_file()
        or not args.observer_bundle.with_suffix('.zip').is_file()):
    parser.error('Observer bundle must be an unpacked directory with manifest.json and adjacent .zip')
if args.await_logon and not (args.reboot and args.observer_bundle):
    parser.error('--await-logon requires --reboot and --observer-bundle')
if not args.preserve_service_state:
    parser.error('Desktop gate requires explicitly approved --preserve-service-state')
if args.corporate_canaries and (args.stack not in ('next','next-baseline','candidate') or not args.observer_bundle):
    parser.error('Corporate canaries require the pinned next stack and packaged Python')
if not 75 <= args.corporate_idle_seconds <= 600 or (args.corporate_idle_seconds != 75 and not args.corporate_canaries):
    parser.error('Corporate idle must be 75..600 seconds with corporate canaries enabled')
if args.rotation_gate and (args.stack != 'next' or not args.observer_bundle or args.reboot):
    parser.error('Rotation gate requires next stack/packaged Python, without a reboot window')
if args.lt_packet_counters and (not args.corporate_canaries or args.reboot or args.rotation_gate):
    parser.error('LT counters require corporate canaries without reboot/rotation')
if args.core_rollout_gate and (args.stack != ('next' if args.observer_config_gate else 'next-baseline') or args.reboot or args.rotation_gate or args.corporate_canaries):
    parser.error('Core rollout gate requires next-baseline, without reboot/rotation/corporate sessions')
if args.ui_migration_gate and (args.stack != 'accepted' or args.reboot or args.rotation_gate or args.corporate_canaries or args.core_rollout_gate or args.observer_bundle):
    parser.error('UI migration gate requires accepted stack without other optional gates')
if args.ui_rollout_gate and ((args.stack,args.ui_rollout_target_stack) not in (('accepted','next'),('accepted','candidate'),('next','candidate')) or args.reboot or args.rotation_gate or args.corporate_canaries or args.core_rollout_gate or args.ui_migration_gate or args.observer_bundle):
    parser.error('UI rollback gate requires a reviewed source/target pair without other optional gates')
if not args.ui_rollout_gate and args.ui_rollout_target_stack != 'next':
    parser.error('UI target stack requires --ui-rollout-gate')

H = runpy.run_path(str(Path(__file__).with_name('invoke-uservm-stcvrc-safe-rollout.py')))
PROJECT, RUNTIME, RELEASE = H['PROJECT'], H['RUNTIME'], H['RELEASE']
if args.via_fixture_relay:
    H['ACCESS']['OPTIONS'][:]=H['ACCESS']['ssh_options'](True)
H['ACCESS']['OPTIONS'][:]=lab_options(H['ACCESS']['OPTIONS'])
stamp = time.strftime('%Y%m%d-%H%M%S')
local = PROJECT / 'local/labs' / ('stcvrc-desktop-autostart-' + stamp)
local.mkdir(parents=True, exist_ok=False)
lab = r'C:\Users\FixtureUser\stcvrc-fullstack-lab'
control = r'C:\Users\FixtureUser\stcvrc-autostart-control'
report = {'startedAt': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'error': None, 'pass':False,
          'cleanupError': None, 'homeBefore': H['hash_file'](RUNTIME)}
created = prepared = False
observer_installed=False
protected=r'C:\ProgramData\STCVRC-observer' if args.observer_production else r'C:\ProgramData\STCVRC-observer-lab'
observer_task='STCVRC-Observer' if args.observer_production else 'STCVRC-Observer-Lab'
observer_marker='.stcvrc-observer' if args.observer_production else '.stcvrc-observer-lab'
observer_marker_value='STCVRC_OBSERVER_V1' if args.observer_production else 'STCVRC_OBSERVER_LAB_V1'
production_arg=" -Production -ExpectedComputerName LABHOST -Label home" if args.observer_production else ''
observer_owner_arg=" -ServiceOwnerSid 'S-1-5-21-1-2-3-1001'" if args.stack in ('next','next-baseline','candidate') else ''
app=r'C:\Users\FixtureUser\AppData\Roaming\io.github.clash-verge-rev.clash-verge-rev'


def ps(code, timeout=60, *, read_only=False):
    access=H['ACCESS']
    code="$ProgressPreference='SilentlyContinue';$ErrorActionPreference='Stop';"+code
    encoded=base64.b64encode(code.encode('utf-16le')).decode('ascii')
    if len(encoded)>7500:
        packed=base64.b64encode(gzip.compress(code.encode('utf-8'),mtime=0)).decode('ascii')
        bootstrap=("$ErrorActionPreference='Stop';"
                   "$m=[IO.MemoryStream]::new([Convert]::FromBase64String('"+packed+"'));"
                   "$z=[IO.Compression.GZipStream]::new($m,[IO.Compression.CompressionMode]::Decompress);"
                   "$r=[IO.StreamReader]::new($z,[Text.Encoding]::UTF8);"
                   "try{$c=$r.ReadToEnd()}finally{$r.Dispose();$z.Dispose();$m.Dispose()};"
                   "& ([ScriptBlock]::Create($c))")
        encoded=base64.b64encode(bootstrap.encode('utf-16le')).decode('ascii')
    if len(encoded)>7500:
        raise ValueError('Use a staged script for an oversized encoded command')
    command=[access['SSH'],*access['OPTIONS'],
             access['TARGET'],'powershell','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-EncodedCommand',encoded]
    return transport_run(command,command_budget(timeout),local/'transport-errors',read_only=read_only)


def download(source, destination):
    access=H['ACCESS']
    command=[access['SCP'],*access['OPTIONS'],access['TARGET']+':'+source.replace('\\','/'),str(destination)]
    transport_run(command,120,local/'transport-errors',read_only=True)


def upload(source,destination):
    access=H['ACCESS']
    command=[access['SCP'],*access['OPTIONS'],str(source),access['TARGET']+':'+destination.replace('\\','/')]
    report['stage']='upload:'+Path(source).name
    print(json.dumps({'stage':report['stage']}),flush=True)
    limit=600 if Path(source).stat().st_size>32*1024*1024 else 180
    started=time.monotonic()
    try:
        transport_run(command,limit,local/'transport-errors')
    except TransportFailure as exc:
        report['uploadFailure']={'file':Path(source).name,'errorClass':exc.kind,'limitSeconds':limit}
        raise
    transfer={'file':Path(source).name,'bytes':Path(source).stat().st_size,
              'seconds':round(time.monotonic()-started,3)}
    report.setdefault('transfers',[]).append(transfer)
    print(json.dumps({'uploaded':transfer}),flush=True)


def observer_sample():
    if args.observer_production:
        # Observe the worker while it exists; do not infer zero overhead from a late empty sample.
        resource=json.loads(ps(r"""
$task='STCVRC-Observer';$deadline=(Get-Date).AddSeconds(55)
while((Get-ScheduledTask -TaskName $task).State -eq 'Running'){if((Get-Date) -gt $deadline){throw 'Observer timeout'};Start-Sleep -Seconds 1}
$started=[DateTime]::UtcNow
Start-ScheduledTask -TaskName $task
$deadline=(Get-Date).AddSeconds(55);$seen=@{};$samples=0;$peak=0;$observedRunning=$false
do {
 $processes=@(Get-CimInstance Win32_Process)
 $workers=@($processes|Where-Object {$_.ExecutablePath -ceq 'C:\ProgramData\STCVRC-observer\bin\python.exe'})
 $ids=@($workers.ProcessId)
 $children=@($processes|Where-Object {$_.ParentProcessId -in $ids})
 $rss=0
 foreach($item in @($workers)+@($children)){
  try {
   $p=Get-Process -Id $item.ProcessId -ErrorAction Stop
   $key=([string]$item.ProcessId+':'+$item.CreationDate.ToUniversalTime().ToString('o'))
   $seen[$key]=$p.TotalProcessorTime.TotalSeconds
   $rss+=$p.WorkingSet64
  }catch [Microsoft.PowerShell.Commands.ProcessCommandException]{}
 }
 if($workers.Count){$samples++;$observedRunning=$true}
 if($rss -gt $peak){$peak=$rss}
 $running=(Get-ScheduledTask -TaskName $task).State -eq 'Running'
 if(-not $running -and $observedRunning){break}
 if((Get-Date) -gt $deadline){throw 'Observer resource sample timed out'}
 Start-Sleep -Milliseconds 500
}while($true)
$info=Get-ScheduledTaskInfo -TaskName $task
@{sampleCount=$samples;observedProcesses=$seen.Count;peakObservedWorkingSetBytes=$peak;observedCpuSeconds=($seen.Values|Measure-Object -Sum).Sum;wallSeconds=([DateTime]::UtcNow-$started).TotalSeconds;lastTaskResult=$info.LastTaskResult;completeCpuAccounting=$false;at=$started.ToString('o')}|ConvertTo-Json -Compress
""",125))
        report.setdefault('observerResources',[]).append(resource)
        if resource['sampleCount']<1 or resource['lastTaskResult']!=0:
            raise RuntimeError('Observer resource sample missing or task failed')
    else:
        ps("$task='"+observer_task+"';$deadline=(Get-Date).AddSeconds(55);while((Get-ScheduledTask -TaskName $task).State -eq 'Running'){if((Get-Date) -gt $deadline){throw 'Observer timeout'};Start-Sleep -Seconds 1};Start-ScheduledTask -TaskName $task;Start-Sleep -Seconds 2;$deadline=(Get-Date).AddSeconds(55);while((Get-ScheduledTask -TaskName $task).State -eq 'Running'){if((Get-Date) -gt $deadline){throw 'Observer timeout'};Start-Sleep -Seconds 1}",125)
    return observer_rows()


def observer_rows():
    raw=ps("$file=Get-ChildItem -LiteralPath '"+protected+"\\data\\timeline' -Filter '*.jsonl'|Sort-Object Name|Select-Object -Last 1;[Convert]::ToBase64String([IO.File]::ReadAllBytes($file.FullName))",read_only=True)
    return [json.loads(x) for x in base64.b64decode(raw).decode('ascii').splitlines()]


def production_observer_readback():
    result=json.loads(ps(r"""
$root='C:\ProgramData\STCVRC-observer'
$task=Get-ScheduledTask -TaskName 'STCVRC-Observer'
$sid=if($task.Principal.UserId -like 'S-1-*'){$task.Principal.UserId}else{([Security.Principal.NTAccount]::new($task.Principal.UserId)).Translate([Security.Principal.SecurityIdentifier]).Value}
$acl=Get-Acl -LiteralPath $root
$rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
$allowed=@('S-1-5-18','S-1-5-32-544')
$aclPass=$acl.AreAccessRulesProtected -and $rules.Count -eq 2 -and @($rules|Where-Object {$_.IdentityReference.Value -cnotin $allowed -or $_.AccessControlType -ne 'Allow' -or $_.FileSystemRights -ne 'FullControl'}).Count -eq 0
$taskPass=$sid -ceq 'S-1-5-18' -and $task.Principal.LogonType -eq 'ServiceAccount' -and $task.Principal.RunLevel -eq 'Highest' -and $task.Actions.Count -eq 1 -and $task.Actions[0].Execute -ceq ($root+'\bin\python.exe') -and $task.Settings.MultipleInstances -eq 'IgnoreNew' -and $task.Settings.ExecutionTimeLimit -eq 'PT50S' -and -not $task.Settings.WakeToRun -and -not $task.Settings.DisallowStartIfOnBatteries -and -not $task.Settings.StopIfGoingOnBatteries
$boot=@($task.Triggers|Where-Object {$_.CimClass.CimClassName -eq 'MSFT_TaskBootTrigger'}).Count -eq 1
$minute=@($task.Triggers|Where-Object {$_.Repetition.Interval -eq 'PT1M'}).Count -eq 1
$manifest=[IO.File]::ReadAllText(($root+'\manifest.json'))|ConvertFrom-Json
$hashPass=$true
foreach($e in $manifest.files.PSObject.Properties){if((Get-FileHash -LiteralPath (Join-Path $root $e.Name)).Hash -ine $e.Value){$hashPass=$false}}
@{pass=($aclPass -and $taskPass -and $boot -and $minute -and $hashPass);protectedAcl=$aclPass;systemTask=$taskPass;bootTrigger=$boot;minuteTrigger=$minute;payloadHashes=$hashPass;host=$env:COMPUTERNAME;productionHost=$false;principalSid=$sid;taskSettings=@{logon=[string]$task.Principal.LogonType;runLevel=[string]$task.Principal.RunLevel;multiple=[string]$task.Settings.MultipleInstances;limit=$task.Settings.ExecutionTimeLimit;wake=$task.Settings.WakeToRun}}|ConvertTo-Json -Depth 4 -Compress
""",90,read_only=True))
    return result


def desired_state_summary():
    return json.loads(ps(r"""
$root='C:\ProgramData\clash-verge-service'
$states=@(Get-ChildItem -LiteralPath $root -Recurse -Filter 'desired-state.json' -File | ForEach-Object {
 $state=[IO.File]::ReadAllText($_.FullName)|ConvertFrom-Json
 @{shouldRun=$state.core_should_be_running;generation=$state.generation;modifiedUtc=$_.LastWriteTimeUtc.ToString('o')}
})
@{at=(Get-Date).ToString('o');states=$states}|ConvertTo-Json -Depth 4 -Compress
""",read_only=True))


def corporate_canaries():
    return json.loads(ps("& '"+control+"\\observer-payload\\bin\\python.exe' -I -B '"+control+
        "\\corporate.py' --probe '"+lab+"\\input\\corporate-canaries.json'",65,read_only=True))


def packet_counters(action, timeout=60):
    return json.loads(ps("& '"+control+"\\observer-payload\\bin\\python.exe' -I -B '"+
        control+"\\pktmon.py' --action "+action+" --run-id "+stamp+
        " --seconds "+str(args.corporate_idle_seconds),timeout))


def stage_transaction_files(stage,target):
    # The observer package has nested payload paths. One pinned archive avoids
    # per-file transports and still verifies every extracted byte before Launch.
    files=sorted(path for path in stage.rglob('*') if path.is_file())
    if not files or any(path.is_symlink() or (getattr(path.lstat(),'st_file_attributes',0)&1024) for path in stage.rglob('*')):
        raise RuntimeError('Unsafe or empty transaction staging')
    hashes={path.relative_to(stage).as_posix():H['hash_file'](path) for path in files}
    payload=local/'transaction-input.zip'
    with zipfile.ZipFile(payload,'w',compression=zipfile.ZIP_DEFLATED) as archive:
        for path in files:archive.write(path,path.relative_to(stage).as_posix())
        archive.writestr('_staged-hashes.json',json.dumps(hashes))
    remote=target+'\\transaction-input.zip'
    upload(payload,remote)
    ps("$p='"+remote+"';if((Get-FileHash -LiteralPath $p).Hash -ine '"+H['hash_file'](payload)+"'){throw 'Transaction archive hash mismatch'};Expand-Archive -LiteralPath $p -DestinationPath '"+target+"';Remove-Item -LiteralPath $p",timeout=180)
    ps("$root='"+target+"';$h=[IO.File]::ReadAllText((Join-Path $root '_staged-hashes.json'))|ConvertFrom-Json;foreach($e in $h.PSObject.Properties){if((Get-FileHash -LiteralPath (Join-Path $root $e.Name)).Hash -ine $e.Value){throw 'Transaction input hash mismatch'}}",read_only=True)


def atomic_observer_baseline():
    # This lab path does not acquire ownership of an existing observer.
    observed=json.loads(ps(r"""
if($env:COMPUTERNAME -cne 'LABHOST'){throw 'Wrong VM'}
$root='C:\ProgramData\STCVRC-observer'
@{rootAbsent=(-not (Test-Path -LiteralPath $root));taskAbsent=(-not (Get-ScheduledTask -TaskName 'STCVRC-Observer' -ErrorAction SilentlyContinue));workersAbsent=(@(Get-CimInstance Win32_Process|Where-Object {$_.ExecutablePath -like ($root+'\*')}).Count -eq 0)}|ConvertTo-Json -Compress
""",read_only=True))
    if not all(observed.get(key) is True for key in ('rootAbsent','taskAbsent','workersAbsent')):
        raise RuntimeError('Atomic observer lab requires a fresh absent baseline; existing deployment is not owned by this harness')
    return observed


def atomic_observer_health(target,observer_sha):
    until=time.monotonic()+65
    while time.monotonic()<until:
        observed=json.loads(ps(r"""
$tx='__TRANSACTION__';$root='C:\ProgramData\STCVRC-observer'
$plan=[IO.File]::ReadAllText(($tx+'\plan.json'))|ConvertFrom-Json
$armed=[IO.File]::ReadAllText(($tx+'\armed.json'))|ConvertFrom-Json
$phase=([IO.File]::ReadAllText(($tx+'\state.json'))|ConvertFrom-Json).phase
$task=Get-ScheduledTask -TaskName 'STCVRC-Observer'
$info=Get-ScheduledTaskInfo -TaskName 'STCVRC-Observer'
$sid=if($task.Principal.UserId -like 'S-1-*'){$task.Principal.UserId}else{([Security.Principal.NTAccount]::new($task.Principal.UserId)).Translate([Security.Principal.SecurityIdentifier]).Value}
$owned=($sid -ceq 'S-1-5-18' -and $task.Actions.Count -eq 1 -and $task.Actions[0].Execute -ceq ($root+'\bin\python.exe') -and $task.Actions[0].Arguments -ceq $plan.observer.newArguments -and $task.Actions[0].WorkingDirectory -ceq ($root+'\bin'))
$file=Get-ChildItem -LiteralPath ($root+'\data\timeline') -Filter '*.jsonl' -ErrorAction SilentlyContinue|Sort-Object Name|Select-Object -Last 1
$row=$null
if($file){$last=Get-Content -LiteralPath $file.FullName -Tail 1|ConvertFrom-Json;$row=@{observedUtc=$last.observedUtc;label=$last.label;checkpoint=$last.checkpoint;observerSha256=$last.observerSha256;coreSha256=$last.binaries.core.sha256;components=$last.components}}
@{phase=$phase;manifestMatch=((Get-FileHash -LiteralPath ($root+'\manifest.json')).Hash -ieq $plan.observer.newManifestHash);taskOwned=$owned;taskState=[string]$task.State;taskResult=$info.LastTaskResult;armedAt=$armed.processCreated;row=$row}|ConvertTo-Json -Depth 6 -Compress
""".replace('__TRANSACTION__',target),timeout=20,read_only=True))
        row=observed.get('row') or {}
        fresh=False
        try:fresh=datetime.fromisoformat(row['observedUtc'].replace('Z','+00:00'))>=datetime.fromisoformat(observed['armedAt'].replace('Z','+00:00'))
        except (KeyError,TypeError,ValueError):pass
        if (observed.get('phase')=='awaiting-confirmation' and observed.get('manifestMatch') is True
                and observed.get('taskOwned') is True and observed.get('taskState')=='Ready'
                and observed.get('taskResult')==0 and fresh and row.get('label')==args.atomic_observer_label
                and row.get('checkpoint') in ('new','ok') and row.get('observerSha256')==observer_sha
                and row.get('coreSha256')==STACKS['candidate']['coreSha256']
                and all(row.get('components',{}).get(key)=='ok' for key in ('host','controller','binaries'))):
            return observed
        if observed.get('phase')!='awaiting-confirmation':break
        time.sleep(2)
    raise RuntimeError('Candidate observer has no fresh completed pinned row/task result before the bounded timeout')


def atomic_observer_cleanup(target):
    # An absent-baseline transaction preserves its newly collected history.
    # Archive that history before removing only this run's inactive lab remainder.
    guard=r"""
if($env:COMPUTERNAME -cne 'LABHOST'){throw 'Wrong VM'}
$tx='__TRANSACTION__';$root=[IO.Path]::GetFullPath('C:\ProgramData\STCVRC-observer')
$plan=[IO.File]::ReadAllText(($tx+'\plan.json'))|ConvertFrom-Json
$state=[IO.File]::ReadAllText(($tx+'\state.json'))|ConvertFrom-Json
$armed=[IO.File]::ReadAllText(($tx+'\armed.json'))|ConvertFrom-Json
$rollback=[IO.File]::ReadAllText(($tx+'\rollback-result.json'))|ConvertFrom-Json
if(-not $plan.lab -or $plan.host -cne 'LABHOST' -or $plan.root -cne $tx -or $root -cne 'C:\ProgramData\STCVRC-observer' -or $plan.observer.root -cne $root -or $plan.observer.task -cne 'STCVRC-Observer' -or $plan.observer.oldPresent -isnot [bool] -or $plan.observer.oldPresent -or $state.phase -cne 'rolled-back'){throw 'Observer lab cleanup scope mismatch'}
if($armed.planHash -ine (Get-FileHash -LiteralPath ($tx+'\plan.json')).Hash -or $rollback.pass -ne $true -or $rollback.observerRestored -ne $true){throw 'Observer rollback identity/result unconfirmed'}
if(Get-ScheduledTask -TaskName 'STCVRC-Observer' -ErrorAction SilentlyContinue){throw 'Observer task still present'}
if(Get-CimInstance Win32_Process|Where-Object {$_.ExecutablePath -like ($root+'\*')}){throw 'Observer worker still present'}
if(Test-Path -LiteralPath $root){
 $ancestor=$root;while($ancestor){if((Get-Item -LiteralPath $ancestor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Observer reparse ancestor'};$ancestor=Split-Path -Parent $ancestor}
 $items=@(Get-ChildItem -LiteralPath $root -Recurse -Force)
 if($items|Where-Object {$_.Attributes -band [IO.FileAttributes]::ReparsePoint}){throw 'Observer cleanup reparse'}
 foreach($name in @('.stcvrc-observer','.stcvrc-transaction','.stcvrc-claim.json')){if(-not (Test-Path -LiteralPath (Join-Path $root $name) -PathType Leaf)){throw 'Observer cleanup claim missing'}}
 if([IO.File]::ReadAllText(($root+'\.stcvrc-observer')) -cne 'STCVRC_OBSERVER_V1'){throw 'Observer cleanup marker mismatch'}
 if([IO.File]::ReadAllText(($root+'\.stcvrc-transaction')) -cne $tx){throw 'Observer cleanup transaction marker mismatch'}
 $claim=[IO.File]::ReadAllText(($root+'\.stcvrc-claim.json'))|ConvertFrom-Json
 if($claim.root -cne $root -or $claim.transaction -cne $tx -or $claim.planHash -ine $armed.planHash){throw 'Observer cleanup claim mismatch'}
 if(Get-ChildItem -LiteralPath $root -Directory|Where-Object Name -notin @('data','bin')){throw 'Unexpected observer directory'}
 if($items|Where-Object {-not $_.PSIsContainer -and $_.FullName -cnotin @(($root+'\.stcvrc-observer'),($root+'\.stcvrc-transaction'),($root+'\.stcvrc-claim.json')) -and -not $_.FullName.StartsWith(($root+'\data\'),[StringComparison]::OrdinalIgnoreCase)}){throw 'Observer payload or unexpected file remains'}
 if(($items|Where-Object {-not $_.PSIsContainer}|Measure-Object Length -Sum).Sum -gt 67108864){throw 'Observer evidence size limit'}
}
""".replace('__TRANSACTION__',target)
    observed=json.loads(ps(guard+"\n@{rootPresent=[bool](Test-Path -LiteralPath $root)}|ConvertTo-Json -Compress",read_only=True))
    if observed['rootPresent']:
        archive=control+'\\atomic-observer-evidence.zip'
        ps(guard+"\nCompress-Archive -LiteralPath $root -DestinationPath '"+archive+"'",timeout=120)
        download(archive,local/'atomic-observer-evidence.zip')
        # Re-evaluate the same ownership/inactive guards after archival too.
        ps(guard+"\nRemove-Item -LiteralPath $root -Recurse -Force")
    return atomic_observer_baseline()


def lab_cleanup_allowed():
    if report.get('pendingSystemTransaction'):
        report['cleanupError']='SYSTEM transaction recovery unconfirmed; lab retained for its independent guard'
        report['pass']=False
        return False
    return True


def core_rollout_gate(ui_update=False):
    print(json.dumps({'stage':'ui-system-transaction' if ui_update else 'approved-core-transaction'}),flush=True)
    snapshot=local/'core-input';(snapshot/'profiles').mkdir(parents=True)
    sid='S-1-5-21-1-2-3-1001'
    owner=r'C:\ProgramData\clash-verge-service\users'+'\\'+hashlib.sha256(sid.encode('ascii')).hexdigest()
    for name in ('profiles.yaml','verge.yaml'):
        download(app+'\\'+name,snapshot/name)
    registry=stmc_yaml.load((snapshot/'profiles.yaml').read_bytes())
    active=[entry for entry in registry['items'] if entry.get('uid')==registry['current']]
    if len(active)!=1 or active[0].get('file')!='LSTCVRCGate.yaml':
        raise RuntimeError('Unexpected disposable profile identity')
    download(app+'\\profiles\\LSTCVRCGate.yaml',snapshot/'profiles/LSTCVRCGate.yaml')
    original_name=args.stack if ui_update else ('next' if args.observer_config_gate else 'accepted')
    target_name=args.ui_rollout_target_stack if ui_update else 'next'
    original_stack=STACKS[original_name]
    target_stack=STACKS[target_name]
    approved_source=original_stack['uiVersion'] != '2.5.2'
    if ui_update:
        download(app+r'\clash-verge.yaml',snapshot/'clash-verge.yaml')
    if not ui_update or approved_source:
        download(owner+r'\runtime\config.yaml',snapshot/'owner-runtime.yaml')
    selected={group['name']:group['now'] for group in report['setup']['groups'] if group['type']=='Selector'}
    (snapshot/'selectors.json').write_text(json.dumps(selected),encoding='ascii')
    stage=local/'core-transaction'
    target=lab+'\\transactions\\stcvrc-safe-'+stamp
    command=[sys.executable,'-B',str(PROJECT/'scripts/prepare-stcvrc-safe-rollout.py'),
        '--ui-update' if ui_update else '--core-update','--lab','--host','LABHOST','--app-root',str(snapshot),
        '--old-core',str(PROJECT/original_stack['core']),
        '--candidate-core',str(PROJECT/target_stack['core']),
        '--service-owner-sid',sid,
        '--output',str(stage),'--target-app-root',app,'--target-transaction-root',target,
        '--selectors-json',str(snapshot/'selectors.json')]
    if ui_update:command += ['--source-stack',original_name,'--target-stack',target_name]
    if not ui_update or approved_source:command += ['--runtime-config',str(snapshot/'owner-runtime.yaml')]
    if args.observer_config_gate:command += ['--observer-config']
    if args.atomic_observer_bundle:
        entry_baseline=atomic_observer_baseline()
        report['atomicObserverBeforeTransaction']=entry_baseline
        command += ['--observer-bundle',str(args.atomic_observer_bundle),'--observer-baseline-absent',
                    '--observer-label',args.atomic_observer_label]
    H['command'](command,60)
    ps("if(Test-Path -LiteralPath '"+target+"'){throw 'Transaction exists'};$null=New-Item -ItemType Directory -Path '"+target+"'")
    stage_transaction_files(stage,target)
    entry={'preflight':json.loads(ps("& '"+target+"\\transaction.ps1' -Mode Preflight -Transaction '"+target+"'",50,read_only=True))}
    if args.tun_gate:
        source=PROJECT/'scripts/uservm-stcvrc-tun-gate.ps1'
        upload(source,target+'\\tun-gate.ps1')
        ps("if((Get-FileHash -LiteralPath '"+target+"\\tun-gate.ps1').Hash -ine '"+H['hash_file'](source)+"'){throw 'TUN gate hash mismatch'}",read_only=True)
    try:
        deadline=300 if ui_update or args.tun_gate else 180
        # Submission may succeed remotely even when the management reply is lost.
        report['pendingSystemTransaction']=target
        entry['launch']=json.loads(ps("& '"+target+"\\transaction.ps1' -Mode Launch -Transaction '"+target+"' -DeadlineSeconds "+str(deadline),40))
        until=time.monotonic()+deadline+200
        phases=[]
        tun_submitted=False
        atomic_checked=False
        observer_checked=False
        while time.monotonic()<until:
            try:
                phase=ps("$p='"+target+"\\state.json';if(Test-Path -LiteralPath $p){([IO.File]::ReadAllText($p)|ConvertFrom-Json).phase}else{'pending'}",read_only=True)
            except TransportFailure:
                if not tun_submitted:raise
                time.sleep(5)
                continue
            if not phases or phases[-1]!=phase:
                phases.append(phase);print(json.dumps({'coreTransactionPhase':phase}),flush=True)
            if phase in ('rolled-back','rollback-failed'):
                break
            if args.observer_config_gate and phase=='awaiting-confirmation' and not observer_checked:
                observer_checked=True
                entry['observerConfig']=json.loads(ps(r"""
$ports=@(Get-NetTCPConnection -State Listen|Where-Object LocalPort -in 18981,18982)
$core=@(Get-CimInstance Win32_Process -Filter "Name='verge-mihomo.exe'")
$env:NO_PROXY=''
$rows=@()
foreach($pair in @(@('4VPS',18981),@('GC',18982))){
 foreach($target in @(@('google204','https://www.gstatic.com/generate_204',204),@('control','https://www.cloudflare.com/cdn-cgi/trace',200))){
  $code=& curl.exe --disable --silent --show-error --proxy ('http://127.0.0.1:'+$pair[1]) --connect-timeout 5 --max-time 8 --max-filesize 8192 --output NUL --write-out '%{http_code}' $target[1] 2>$null
  $rows+=@{leaf=$pair[0];target=$target[0];success=($LASTEXITCODE -eq 0 -and [string]$code -ceq [string]$target[2])}
 }
}
$listeners=($core.Count -eq 1 -and $ports.Count -eq 2 -and @($ports|Where-Object {$_.LocalAddress -cne '127.0.0.1' -or $_.OwningProcess -ne $core[0].ProcessId}).Count -eq 0)
@{pass=($listeners -and @($rows|Where-Object {-not $_.success}).Count -eq 0);listenersOwnedLoopback=$listeners;applications=$rows}|ConvertTo-Json -Depth 5 -Compress
""",55,read_only=True))
            if args.atomic_observer_bundle and phase=='awaiting-confirmation' and not atomic_checked:
                atomic_checked=True
                observer_manifest=json.loads((args.atomic_observer_bundle/'manifest.json').read_text())
                try:
                    entry['atomicObserverCandidate']=atomic_observer_health(target,observer_manifest['files']['bin/stcvrc_observer.py'])
                except (RuntimeError,TransportFailure) as exc:
                    # Do not start outer restoration while the independent guard
                    # still owns a pending transaction. Wait for rollback below.
                    entry['atomicObserverCandidateError']=type(exc).__name__
            if args.tun_gate and phase=='awaiting-confirmation' and not tun_submitted and (not args.atomic_observer_bundle or 'atomicObserverCandidate' in entry):
                tun_submitted=True
                print(json.dumps({'stage':'TUN-under-SYSTEM-deadline'}),flush=True)
                try:
                    entry['tun']=json.loads(ps("& '"+target+"\\tun-gate.ps1' -Action Probe -Transaction '"+target+"'",105))
                except TransportFailure as exc:
                    entry['tunSubmissionUncertain']=exc.kind
                # Never Confirm: automatic rollback must remove the still-enabled TUN.
            error='False' if tun_submitted else ps("[bool](Test-Path -LiteralPath '"+target+"\\apply-error.json')",read_only=True)
            if error=='True' and phase=='pending':
                raise RuntimeError('Apply failed before mutation; see private transaction evidence')
            time.sleep(3)
        entry['phases']=phases
        if phase!='rolled-back':
            raise RuntimeError('Automatic core rollback did not complete in the bounded window')
        report['pendingSystemTransaction']=None
        for name in ('candidate-result.json','rollback-result.json','history-before-result.json'):
            download(target+'\\'+name,local/('core-'+name))
        candidate=json.loads((local/'core-candidate-result.json').read_text(encoding='utf-8-sig'))
        rollback=json.loads((local/'core-rollback-result.json').read_text(encoding='utf-8-sig'))
        entry.update(candidate=candidate,rollback=rollback)
        entry['pass']=(candidate['pass'] is True and rollback['pass'] is True
                       and rollback['executingCoreHash']==original_stack['coreSha256'])
        if args.observer_config_gate:
            entry['pass'] &= entry.get('observerConfig',{}).get('pass') is True and rollback.get('uiStopped') is False
        if args.atomic_observer_bundle:
            entry['pass'] &= 'atomicObserverCandidate' in entry and rollback.get('observerRestored') is True
        if args.tun_gate:
            download(target+'\\tun-result.json',local/'tun-result.json')
            entry['tun']=json.loads((local/'tun-result.json').read_text(encoding='utf-8-sig'))
            entry['tunRecovery']=json.loads(ps("& '"+target+"\\tun-gate.ps1' -Action Recovery -Transaction '"+target+"'",40))
            entry['pass'] &= entry['tun']['pass'] is True and entry['tunRecovery']['pass'] is True
        if ui_update:
            entry['pass'] &= rollback.get('uiVersion')==original_stack['uiVersion'] and rollback.get('uiStopped') is False
            for label in ('new','old'):
                download(target+'\\ui-'+label+'-result.json',local/('ui-'+label+'-result.json'))
                entry['ui'+label.title()]=json.loads((local/('ui-'+label+'-result.json')).read_text(encoding='utf-8-sig'))
            entry['pass'] &= entry['uiNew']['version']==target_stack['uiVersion'] and entry['uiOld']['version']==original_stack['uiVersion']
        return entry
    finally:
        # Keep logs/events and state, not another copy of profiles or binaries.
        zip_path=control+'\\core-transaction-evidence.zip'
        ps("$root='"+target+"';$files=@(Get-ChildItem -LiteralPath $root -File|Where-Object {$_.Name -match '(result|error|worker|ready)\\.json$' -or $_.Name -in @('state.json','armed.json')});$dirs=@(Get-ChildItem -LiteralPath $root -Directory -Filter 'history-*');$paths=@($files.FullName)+@($dirs.FullName);if($paths.Count){Compress-Archive -LiteralPath $paths -DestinationPath '"+zip_path+"'}",120)
        if ps("[bool](Test-Path -LiteralPath '"+zip_path+"')",read_only=True)=='True':
            download(zip_path,local/'core-transaction-evidence.zip')
        if args.atomic_observer_bundle:
            entry['atomicObserverRestored']=atomic_observer_cleanup(target)


def ui_migration_gate():
    def snapshot(label, runtime_path):
        directory=local/label;directory.mkdir()
        for name,source in (('profile.yaml',app+r'\profiles\LSTCVRCGate.yaml'),
                            ('profiles.yaml',app+r'\profiles.yaml'),
                            ('verge.yaml',app+r'\verge.yaml'),('runtime.yaml',runtime_path)):
            download(source,directory/name)
        return {p.name:stmc_yaml.load(p.read_bytes()) for p in directory.iterdir()}

    before=snapshot('ui-before',report['setup']['runtimeConfigPath'])
    selected={g['name']:g['now'] for g in report['setup']['groups'] if g['type']=='Selector'}
    results={}
    report['uiMigration']=results
    try:
        results['upgrade']=step('UpgradeUi',240)['value']
        after=snapshot('ui-upgraded',results['upgrade']['runtimeConfigPath'])
        results['profileUnchanged']=before['profile.yaml']==after['profile.yaml']
        results['registryUnchanged']=before['profiles.yaml']==after['profiles.yaml']
        results['settingsChangedKeys']=sorted(k for k,v in before['verge.yaml'].items() if after['verge.yaml'].get(k)!=v)
        keys=('proxies','proxy-groups','rules','rule-providers','dns','tun','listeners')
        results['runtimePolicyUnchanged']=all(before['runtime.yaml'].get(k)==after['runtime.yaml'].get(k) for k in keys)
        results['upgradeSelectorsPreserved']=results['upgrade']['selectors']==selected
    finally:
        # The outer S4U guard still restores the VM if this controlled downgrade fails.
        if 'upgrade' in results:
            results['rollback']=step('RollbackUi',240)['value']
            restored=snapshot('ui-restored',results['rollback']['runtimeConfigPath'])
            results['restoredConfigEquivalent']=all(before[name]==restored[name] for name in before)
            results['rollbackSelectorsPreserved']=results['rollback']['selectors']==selected
    results['pass']=(results['upgrade']['pass'] and results['rollback']['pass']
        and results['upgrade']['uiVersion']=='2.5.5' and results['rollback']['uiVersion']=='2.5.2'
        and results['upgrade']['coreHash'].lower()==STACKS['next']['coreSha256']
        and results['rollback']['coreHash'].lower()==STACKS['accepted']['coreSha256']
        and not results['settingsChangedKeys']
        and all(results[k] for k in ('profileUnchanged','registryUnchanged','runtimePolicyUnchanged',
            'upgradeSelectorsPreserved','restoredConfigEquivalent','rollbackSelectorsPreserved')))
    return results['pass']


def step(action, timeout=90):
    report['stage'] = action
    print(json.dumps({'stage': action}), flush=True)
    try:
        if action == 'Restore':
            ps(f"""
$result='{control}\\Restore.result.json'
if(-not(Test-Path -LiteralPath $result)){{
 $task=Get-ScheduledTask -TaskName 'STCVRC-userVM-Autostart-Cleanup'
 if($task.Principal.LogonType -ne 'S4U' -or -not $task.Actions[0].Arguments.Contains('{control}\\desktop.ps1')){{throw 'Unexpected recovery task'}}
 Start-ScheduledTask -TaskName $task.TaskName
}}
""")
        else:
            ps(r"""
$task='STCVRC-userVM-Desktop-Gate'
if(Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue){throw 'Invocation already running'}
""" + f"""
$a=New-ScheduledTaskAction -Execute 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe' -Argument '-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "{control}\\desktop.ps1" -Action {action}'
$p=New-ScheduledTaskPrincipal -UserId 'S-1-5-21-1-2-3-1001' -LogonType Interactive -RunLevel Highest
$s=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
$null=Register-ScheduledTask -TaskName $task -Action $a -Principal $p -Settings $s
Start-ScheduledTask -TaskName $task
$result='{control}\\{action}.result.json'
$until=(Get-Date).AddSeconds({timeout})
while(-not(Test-Path -LiteralPath $result)){{if((Get-Date) -gt $until){{throw 'Desktop step timed out'}};Start-Sleep -Seconds 1}}
""", timeout + 20)
    except TransportFailure as exc:
        report.setdefault('submissionUncertain',{})[action]=exc.kind
    deadline=time.monotonic()+timeout
    while True:
        raw=ps(f"$p='{control}\\{action}.result.json';if(Test-Path -LiteralPath $p){{[Convert]::ToBase64String([IO.File]::ReadAllBytes($p))}}else{{'PENDING'}}",read_only=True)
        if raw != 'PENDING':
            break
        if time.monotonic()>=deadline:
            raise RuntimeError('No durable action result; submission was not repeated')
        time.sleep(2)
    result = json.loads(base64.b64decode(raw))
    if result.get('action')!=action or result.get('runId')!=stamp:
        raise RuntimeError('Unexpected durable action result')
    if not result['ok']:
        report['remoteError'] = result.get('error')
        raise RuntimeError('Desktop step failed; see sanitized remoteError')
    return result


try:
    if args.atomic_observer_bundle:
        report['atomicObserverBaseline']=atomic_observer_baseline()
    if args.observer_bundle:
        ps("if(Test-Path -LiteralPath '"+protected+"'){throw 'Observer footprint'};if(Get-ScheduledTask -TaskName 'STCVRC-Observer*' -ErrorAction SilentlyContinue){throw 'Observer tasks'}")
    ps(r"""
if($env:COMPUTERNAME -cne 'LABHOST'){throw 'Wrong VM'}
$sid='S-1-5-21-1-2-3-1001'
$desktop=@(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" | Where-Object {$_.SessionId -gt 0 -and (Invoke-CimMethod -InputObject $_ -MethodName GetOwnerSid).Sid -eq $sid})
$desktopSessions=@($desktop|Select-Object -ExpandProperty SessionId -Unique)
if($desktopSessions.Count -ne 1){throw 'Approved FixtureUser desktop missing'}
if(Get-CimInstance Win32_Process | Where-Object Name -match 'clash|mihomo'){throw 'Existing runtime'}
foreach($n in @('Clash Verge','Clash Verge (Admin)','STCVRC-userVM-Desktop-Gate','STCVRC-userVM-Autostart-Cleanup')){if(Get-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue){throw 'Existing task'}}
foreach($p in @('C:\Users\FixtureUser\stcvrc-fullstack-lab','C:\Users\FixtureUser\stcvrc-autostart-control','C:\Program Files\Clash Verge')){if(Test-Path -LiteralPath $p){throw 'Existing footprint'}}
$p='C:\Users\FixtureUser';while($p){if((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse ancestor'};$p=Split-Path -Parent $p}
""")
    ps(f"$null=New-Item -ItemType Directory -Path '{lab}','{control}';foreach($n in @('input','input\\rules','logs','transactions')){{$null=New-Item -ItemType Directory -Path (Join-Path '{lab}' $n)}};[IO.File]::WriteAllText('{lab}\\.codex-stcvrc-fullstack-lab','STCVRC_FULLSTACK_LAB_V1');[IO.File]::WriteAllText('{control}\\.stcvrc-desktop-gate','STCVRC_DESKTOP_GATE_V1');[IO.File]::WriteAllText('{control}\\run-id.txt','{stamp}')")
    created = True
    probe=local/'transfer-probe.bin'
    probe.write_bytes(b'STCVRC_TRANSFER_V1\n'*64)
    upload(probe,lab+'\\input\\transfer-probe.bin')
    actual=ps("if($env:COMPUTERNAME -cne 'LABHOST'){throw 'Wrong VM'};(Get-FileHash -LiteralPath '"+lab+"\\input\\transfer-probe.bin').Hash",read_only=True)
    download(lab+'\\input\\transfer-probe.bin',local/'transfer-return.bin')
    report['transferPass']=(actual.lower()==H['hash_file'](probe)==H['hash_file'](local/'transfer-return.bin'))
    if not report['transferPass']:
        raise RuntimeError('Management transfer hash mismatch')
    ps("$p='"+lab+"\\input\\transfer-probe.bin';if((Resolve-Path -LiteralPath $p).Path -cne $p){throw 'Transfer path mismatch'};if((Get-FileHash -LiteralPath $p).Hash -ine '"+H['hash_file'](probe)+"'){throw 'Transfer content changed'};Remove-Item -LiteralPath $p")
    for src, dest in [('uservm-stcvrc-fullstack.remote.ps1', lab + '\\fullstack.ps1'),
                      ('uservm-stcvrc-fullstack.remote.ps1', control + '\\fullstack.ps1'),
                      ('uservm-stcvrc-safe-rollout.remote.ps1', lab + '\\driver.ps1'),
                      ('uservm-stcvrc-ui-autostart.remote.ps1', lab + '\\autostart.ps1'),
                      ('preserve-stcvrc-evidence.ps1', control + '\\preserve.ps1'),
                      ('uservm-stcvrc-desktop-autostart.remote.ps1', control + '\\desktop.ps1')]:
        upload(PROJECT / 'scripts' / src, dest)
    report['before'] = step('Snapshot')['value']['inventory']
    download(lab+'\\inventory-before.json',local/'inventory-before.json')
    if args.require_baseline_report:
        expected=json.loads(args.require_baseline_report.read_text(encoding='utf-8'))['before']
        report['requiredBaselineComparison']=inventory_comparison(expected,report['before'])
        if report['requiredBaselineComparison']['baselineMatch'] is not True:
            raise RuntimeError('Required original baseline not restored; no runtime installation attempted')
    report['guardProbe'] = step('GuardProbe')['value']
    if not report['guardProbe']['pass']:
        raise RuntimeError('Noninteractive recovery identity failed')
    uid = 'LSTCVRCGate'
    registry = {'current': uid, 'items': [
        {'uid': 'Merge', 'type': 'merge', 'file': 'Merge.yaml'},
        {'uid': 'Script', 'type': 'script', 'file': 'Script.js'},
        {'uid': uid, 'type': 'local', 'name': 'STCVRC disposable autostart gate',
         'file': uid + '.yaml', 'updated': int(time.time())}]}
    settings = {'app_log_level': 'info', 'language': 'en', 'clash_core': 'verge-mihomo',
                'enable_tun_mode': False, 'enable_system_proxy': False, 'enable_auto_launch': True,
                'enable_silent_start': False, 'enable_proxy_guard': False, 'enable_dns_settings': False,
                'enable_global_hotkey': False, 'auto_check_update': False,
                'enable_external_controller': True, 'verge_mixed_port': 7897}
    profile = H['provider_lab_profile'](stmc_yaml.load(RUNTIME.read_bytes()))
    if args.observer_bundle:
        profile=observer_profile(profile)
        settings.update(app_log_max_size=4096,app_log_max_count=32,auto_log_clean=3)
    if args.rotation_gate:
        ps("if(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue|Where-Object LocalPort -eq 18985){throw 'Rotation listener collision'}",read_only=True)
        profile.setdefault('listeners',[]).append(ROTATION_LISTENER.copy())
        upload(PROJECT/'scripts/stcvrc_rotation_gate.py',control+'\\rotation.py')
        script_hash=H['hash_file'](PROJECT/'scripts/stcvrc_rotation_gate.py')
        ps("if((Get-FileHash -LiteralPath '"+control+"\\rotation.py').Hash -ine '"+script_hash+"'){throw 'Rotation script hash mismatch'}",read_only=True)
    if args.corporate_canaries:
        ps("if(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue|Where-Object LocalPort -in 18983,18984){throw 'Corporate lab listener collision'}",read_only=True)
        home_settings=stmc_yaml.load((RUNTIME.parent/'verge.yaml').read_bytes())
        profile,corporate=add_corporate_canaries(profile,stmc_yaml.load(RUNTIME.read_bytes()),home_settings)
        profile['log-level']='debug'
        (local/'corporate-canaries.json').write_text(json.dumps(corporate),encoding='utf-8')
        upload(PROJECT/'scripts/stcvrc_corporate_gate.py',control+'\\corporate.py')
        script_hash=H['hash_file'](PROJECT/'scripts/stcvrc_corporate_gate.py')
        ps("if((Get-FileHash -LiteralPath '"+control+"\\corporate.py').Hash -ine '"+script_hash+"'){throw 'Corporate probe script hash mismatch'}",read_only=True)
        if args.lt_packet_counters:
            leaf=next(p for p in profile['proxies'] if p['name']=='LT-OPENVPN')
            endpoint={'server':leaf['server'],'port':leaf['port'],'transport':leaf['proto']}
            (local/'pktmon-endpoint.json').write_text(json.dumps(endpoint),encoding='ascii')
            for source,name in ((PROJECT/'scripts/stcvrc_pktmon_gate.py','pktmon.py'),
                                (local/'pktmon-endpoint.json','pktmon-endpoint.json')):
                upload(source,control+'\\'+name)
                expected_hash=H['hash_file'](source)
                ps("if((Get-FileHash -LiteralPath '"+control+'\\'+name+"').Hash -ine '"+expected_hash+"'){throw 'Pktmon input hash mismatch'}",read_only=True)
    for name, obj in [('profiles.yaml', registry), ('verge.yaml', settings), ('profile.yaml', profile)]:
        (local / name).write_bytes(stmc_yaml.dump(obj))
    inputs = {name: local / name for name in ['profiles.yaml', 'verge.yaml', 'profile.yaml']}
    if args.corporate_canaries:
        inputs['corporate-canaries.json']=local/'corporate-canaries.json'
    stack, binaries = stack_inputs(PROJECT,args.stack)
    report['stack']=stack
    inputs.update(binaries)
    if args.ui_migration_gate:
        next_stack,next_binaries=stack_inputs(PROJECT,'next')
        next_stack['coreName']='migration-core.exe'
        inputs[next_stack['coreName']]=PROJECT/STACKS['next']['core']
        inputs[next_stack['installerName']]=next_binaries[next_stack['installerName']]
        migration_files={s[field]:s[hash_field] for s in (stack,next_stack)
                         for field,hash_field in (('coreName','coreSha256'),('installerName','installerSha256'))}
        for name,digest in migration_files.items():
            if H['hash_file'](inputs[name])!=digest:raise RuntimeError('UI migration pinned input mismatch')
        (local/'ui-migration.json').write_text(json.dumps({'schema':1,'old':stack,'new':next_stack,'files':migration_files}),encoding='ascii')
        inputs['ui-migration.json']=local/'ui-migration.json'
    expected = {stack['coreName']:stack['coreSha256'],
                stack['installerName']:stack['installerSha256']}
    for name, digest in expected.items():
        if H['hash_file'](inputs[name]) != digest:
            raise RuntimeError('Pinned binary mismatch')
    (local/'stack-manifest.json').write_text(json.dumps(stack),encoding='utf-8')
    inputs['stack-manifest.json']=local/'stack-manifest.json'
    (local / 'hashes.json').write_text(json.dumps({n: H['hash_file'](p) for n, p in inputs.items()}), encoding='utf-8')
    inputs['hashes.json'] = local / 'hashes.json'
    for name, path in inputs.items():
        upload(path, lab + '\\input\\' + name)
    manifest_hash=H['hash_file'](local/'hashes.json')
    report['inputHashes']=json.loads(ps(f"""
$root='{lab}\\input'
$manifest=Join-Path $root 'hashes.json'
if((Get-FileHash -LiteralPath $manifest).Hash -ine '{manifest_hash}'){{throw 'Input manifest mismatch'}}
$hashes=[IO.File]::ReadAllText($manifest)|ConvertFrom-Json
foreach($entry in $hashes.PSObject.Properties){{
 if($entry.Name -notmatch '^[A-Za-z0-9._-]+$' -or $entry.Value -notmatch '^[0-9a-f]{{64}}$'){{throw 'Invalid input manifest'}}
 $file=Join-Path $root $entry.Name
 if((Get-Item -LiteralPath $file).Attributes -band [IO.FileAttributes]::ReparsePoint){{throw 'Input reparse'}}
 if((Get-FileHash -LiteralPath $file).Hash -ine $entry.Value){{throw 'Input content mismatch'}}
}}
@{{pass=$true;files=@($hashes.PSObject.Properties).Count}}|ConvertTo-Json -Compress
""",120,read_only=True))
    if not report['inputHashes']['pass']:
        raise RuntimeError('Bulk input verification failed before Arm')
    if args.observer_bundle:
        upload(args.observer_bundle.with_suffix('.zip'),control+'\\observer-payload.zip')
        upload(PROJECT/'scripts/install-stcvrc-observer-lab.ps1',control+'\\observer-install.ps1')
        if args.observer_production:
            # Original root/task absence was proved above; the existing outer restore guard owns removal.
            ps("[IO.File]::WriteAllText('"+control+"\\observer-production.run','"+stamp+"')")
        expected_zip=H['hash_file'](args.observer_bundle.with_suffix('.zip'))
        ps("if((Get-FileHash -LiteralPath '"+control+"\\observer-payload.zip').Hash -ine '"+expected_zip+"'){throw 'Payload mismatch'};Expand-Archive -LiteralPath '"+control+"\\observer-payload.zip' -DestinationPath '"+control+"\\observer-payload'",120)
        report['observerProcessTests']=json.loads(ps(f"""
$bin='{control}\\observer-payload\\bin'
$stdout='{control}\\observer-tests.stdout.txt';$stderr='{control}\\observer-tests.stderr.txt'
$p=Start-Process -FilePath ($bin+'\\python.exe') -ArgumentList @('-I','-B','-m','unittest','test_stcvrc_observer','test_stcvrc_observer_process','-v') -WorkingDirectory $bin -WindowStyle Hidden -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
$handle=$p.Handle
if(-not $p.WaitForExit(90000)){{$p.Kill();$p.WaitForExit();throw 'Packaged observer tests timed out'}}
$result=@{{exitCode=$p.ExitCode;pass=($p.ExitCode -eq 0);completedAt=(Get-Date).ToString('o')}}
[IO.File]::WriteAllText('{control}\\observer-tests.result.json',($result|ConvertTo-Json -Compress))
$result|ConvertTo-Json -Compress
""",110))
        for name in ('observer-tests.stdout.txt','observer-tests.stderr.txt','observer-tests.result.json'):
            download(control+'\\'+name,local/name)
        if not report['observerProcessTests']['pass']:
            raise RuntimeError('Packaged observer process tests failed before runtime mutation')
    # Uploads are not part of the guarded runtime window.
    if args.lt_packet_counters:
        report['packetCounterPreflight']=packet_counters('preflight')
    report['guard'] = step('Arm')['value']
    prepared = True
    report['isolation'] = step('Isolate', 120)['value']
    report['setup'] = step('Setup', 220)['value']
    report['stackReadbackPass']=(report['setup']['coreHash'].lower()==stack['coreSha256']
                               and stack['coreVersionToken'] in report['setup']['version']
                               and report['setup']['uiVersion'].split('.')[:3]==stack['uiVersion'].split('.'))
    if not report['stackReadbackPass']:
        raise RuntimeError('Installed stack does not match the pinned pair')
    if not report['setup']['tunDisabled'] or report['setup']['proxyEnabled']:
        raise RuntimeError('Lab isolation failed')
    report['baselineCanaries'] = step('Canary', 40)['value']
    if args.corporate_canaries:
        report['corporateBefore']=corporate_canaries()
    if args.observer_bundle:
        manifest_hash=H['hash_file'](args.observer_bundle/'manifest.json')
        ps("& '"+control+"\\observer-install.ps1' -Action Install -Bundle '"+control+"\\observer-payload' -AppDirectory '"+app+"' -ManifestSha256 '"+manifest_hash+"'"+observer_owner_arg+production_arg,180)
        observer_installed=True
        if args.observer_production:
            report['observerProduction']=production_observer_readback()
            if not report['observerProduction']['pass']:
                raise RuntimeError('Production observer task or protection contract failed')
        if not args.observer_production:
            ps("$a=New-ScheduledTaskAction -Execute ($env:SystemRoot+'\\System32\\WindowsPowerShell\\v1.0\\powershell.exe') -Argument '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"C:\\ProgramData\\STCVRC-observer-lab\\bin\\stcvrc-observer-lab-guard.ps1\"';$t=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(20);$s=New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries;$null=Register-ScheduledTask -TaskName 'STCVRC-Observer-Lab-Guard' -Action $a -Trigger $t -Settings $s -User SYSTEM -RunLevel Highest")
        report['observerBefore']=observer_sample()
        report['nativeIdentity']=native_identity_check(report['observerBefore'])
        if not report['nativeIdentity']['pass']:
            # A health refresh between samples may leave no repeated timestamp yet.
            report['observerBefore']=observer_sample()
            report['nativeIdentity']=native_identity_check(report['observerBefore'])
    # Distinct evidence avoids a cross-account delete and reuse of an earlier sample.
    report['taskLaunch'] = step('Test', 120)['value']
    report['afterCanaries'] = step('CanaryAfter', 40)['value']
    download(r'C:\Users\FixtureUser\AppData\Roaming\io.github.clash-verge-rev.clash-verge-rev\verge.yaml', local / 'after-settings.yaml')
    report['flagPersisted'] = stmc_yaml.load((local / 'after-settings.yaml').read_bytes()).get('enable_auto_launch') is True
    report['selectorsPreserved'] = report['taskLaunch']['selectors'] == {'FOREIGN-EGRESS': 'GC', 'LAB-UNCHANGED': 'REJECT'}
    report['pass'] = all([report['taskLaunch']['pass'], report['baselineCanaries']['pass'], report['afterCanaries']['pass'], report['flagPersisted'], report['selectorsPreserved']])
    if args.core_rollout_gate:
        report['coreRollout']=core_rollout_gate()
        report['coreRollbackUi']=step('Inspect',60)['value']
        report['pass'] &= report['coreRollout']['pass'] and report['coreRollbackUi']['coreHash'].lower()==stack['coreSha256']
    if args.ui_rollout_gate:
        if not report['pass']:raise RuntimeError('Baseline UI/canary failed before SYSTEM migration')
        report['uiRollout']=core_rollout_gate(ui_update=True)
        report['uiRollbackReadback']=step('Inspect',60)['value']
        report['pass'] &= report['uiRollout']['pass'] and report['uiRollbackReadback']['coreHash'].lower()==stack['coreSha256']
    if args.ui_migration_gate:
        if not report['pass']:raise RuntimeError('Baseline UI/canary failed before migration')
        report['pass'] &= ui_migration_gate()
    if args.corporate_canaries:
        if args.lt_packet_counters:
            report['packetCounterStart']=packet_counters('start')
        report['corporateAfterRestart']=corporate_canaries()
        report['corporateIdleSeconds']=args.corporate_idle_seconds
        if args.lt_packet_counters:
            report['packetCounterObservation']=packet_counters('observe',args.corporate_idle_seconds+45)
            download(control+'\\pktmon-counters.jsonl',local/'pktmon-counters.jsonl')
        else:
            time.sleep(args.corporate_idle_seconds)
        report['corporateAfterIdle']=corporate_canaries()
        if args.lt_packet_counters:
            report['packetCounterStop']=packet_counters('stop')
        if not report['corporateAfterIdle']['pass']:
            report['corporateRecovery']=[]
            for _ in range(2):
                time.sleep(15)
                report['corporateRecovery'].append(corporate_canaries())
        report['pass'] &= all(report[key]['pass'] for key in ('corporateBefore','corporateAfterRestart','corporateAfterIdle'))
    if args.observer_bundle:
        if args.rotation_gate:
            print(json.dumps({'stage':'NativeRotation'}),flush=True)
            report['nativeRotation']=json.loads(ps(f"""
$python='{control}\\observer-payload\\bin\\python.exe'
$stdout='{control}\\rotation.stdout.json';$stderr='{control}\\rotation.stderr.txt'
$p=Start-Process -FilePath $python -ArgumentList @('-I','-B','\"{control}\\rotation.py\"','--run-id','{stamp}','--core-sha256','{stack['coreSha256']}') -WorkingDirectory '{control}\\observer-payload\\bin' -WindowStyle Hidden -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
$handle=$p.Handle
if(-not $p.WaitForExit(510000)){{$p.Kill();$p.WaitForExit();throw 'Rotation worker exceeded bound'}}
if(-not(Test-Path -LiteralPath $stdout) -or (Get-Item -LiteralPath $stdout).Length -eq 0){{throw 'Rotation worker did not produce evidence'}}
Get-Content -LiteralPath $stdout -Raw
""",540))
            report['pass'] &= report['nativeRotation']['pass']
            if args.corporate_canaries:
                report['corporateAfterRotation']=corporate_canaries()
                report['pass'] &= report['corporateAfterRotation']['pass']
        report['observerAfter']=observer_sample()
        if args.observer_production:
            report['productionMinuteTriggerObserved']=any(event.get('id')==107
                for row in report['observerAfter'] for event in row.get('scheduler',{}).get('events',[]))
        report['nativeIdentity']=native_identity_check(report['observerAfter'])
        report['pass'] &= report['nativeIdentity']['pass']
        download(report['setup']['runtimeConfigPath'],local/'observer-runtime.yaml')
        runtime=stmc_yaml.load((local/'observer-runtime.yaml').read_bytes())
        read_settings=stmc_yaml.load((local/'after-settings.yaml').read_bytes())
        report['listenersPreserved']=all(x in runtime.get('listeners',[]) for x in LISTENERS)
        report['rotationSettingsPreserved']=all(read_settings.get(k)==settings[k] for k in ('app_log_max_size','app_log_max_count','auto_log_clean'))
        old_ids={x['sampleId'] for x in report['observerBefore']}
        new_ids={x['sampleId'] for x in report['observerAfter']}
        report['historyPreserved']=old_ids<new_ids
        probes=[p for row in report['observerAfter'] for p in row['application']]
        expected_pairs={(listener['proxy'],target[0]) for listener in LISTENERS for target in TARGETS}
        observed_pairs={(p.get('leaf'),p.get('target')) for p in probes}
        report['observerApplicationsPass']=expected_pairs<=observed_pairs and all(p.get('success') is True for p in probes)
        if args.stack in ('next','next-baseline','candidate') or args.ui_migration_gate:
            report['observerLayoutPass']=all(
                row.get('runtimeLayout')=='service-owner'
                and row.get('binaries',{}).get('core',{}).get('sha256')==stack['coreSha256']
                and row.get('components',{}).get('controller')=='ok'
                for row in report['observerAfter'])
            report['pass'] &= report['observerLayoutPass']
        report['pass'] &= all(report.get(k) is True for k in ('listenersPreserved','rotationSettingsPreserved','historyPreserved','observerApplicationsPass'))
    if args.reboot:
        if not args.observer_bundle or not report['pass']:
            raise RuntimeError('Reboot requires passing observer full-stack baseline')
        before_boot=ps("(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')",read_only=True)
        report['desiredBeforeBoot']=desired_state_summary()
        report['routingStartupContract']='after-logon' if args.await_logon else 'before-logon'
        print(json.dumps({'stage':'Reboot','awaitLogon':args.await_logon}),flush=True)
        try:
            ps("if($env:COMPUTERNAME -cne 'LABHOST'){throw 'Wrong host'};shutdown.exe /r /t 5 /d p:4:1;if($LASTEXITCODE -ne 0){throw 'Reboot request failed'}")
        except TransportFailure as exc:
            report['rebootSubmissionUncertain']=exc.kind
        deadline=time.monotonic()+360
        after_boot=before_boot
        while time.monotonic()<deadline:
            time.sleep(10)
            try:
                after_boot=ps("(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')",read_only=True)
                if after_boot!=before_boot:
                    break
            except TransportFailure:
                continue
        if after_boot==before_boot:
            raise RuntimeError('Reboot not proven; request was not resubmitted')
        report['bootChanged']=True
        if args.await_logon:
            # Wait for the boot-triggered worker, without starting a sample ourselves.
            ps("$until=(Get-Date).AddSeconds(60);while((Get-ScheduledTask -TaskName '"+observer_task+"').State -eq 'Running'){if((Get-Date) -gt $until){throw 'Boot observer timeout'};Start-Sleep -Seconds 1}",75,read_only=True)
            report['observerAfterBoot']=observer_rows()
        else:
            report['observerAfterBoot']=observer_sample()
        prior_ids={x['sampleId'] for x in report['observerAfter']}
        boot_ids={x['sampleId'] for x in report['observerAfterBoot']}
        report['historySurvivedBoot']=prior_ids<boot_ids
        state=json.loads(ps("$s=Get-CimInstance Win32_Service -Filter \"Name='clash_verge_service'\";$c=@(Get-CimInstance Win32_Process -Filter \"Name='verge-mihomo.exe'\");@{serviceRunning=($s.State -eq 'Running');coreOwned=($c.Count -eq 1 -and $c[0].SessionId -eq 0 -and $c[0].ParentProcessId -eq $s.ProcessId);interactiveCount=@(Get-CimInstance Win32_Process -Filter \"Name='explorer.exe'\").Count}|ConvertTo-Json -Compress",read_only=True))
        report['postBootOwnership']=state
        report['desiredAfterBoot']=desired_state_summary()
        if not args.await_logon:
            report['pass'] &= report['historySurvivedBoot'] and state['coreOwned'] and state['serviceRunning']
        else:
            report['preloginObserver']=prelogin_observer_check(report['observerAfterBoot'],after_boot,state['interactiveCount'])
            if not report['preloginObserver']['pass'] or not report['historySurvivedBoot']:
                raise RuntimeError('Pre-login observer proof failed')
            report['stage']='AwaitFixtureUserLogon'
            print(json.dumps({'stage':report['stage'],'seconds':360,'launchUiManually':False}),flush=True)
            deadline=time.monotonic()+360
            while True:
                count=int(ps("$sid='S-1-5-21-1-2-3-1001';@(Get-CimInstance Win32_Process -Filter \"Name='explorer.exe'\"|Where-Object {$_.SessionId -gt 0 -and (Invoke-CimMethod -InputObject $_ -MethodName GetOwnerSid).Sid -eq $sid}).Count",read_only=True))
                report['logonDesktopCount']=count
                if count==1:
                    report['logonWaitOutcome']='observed'
                    break
                if count>1 or time.monotonic()>=deadline:
                    report['logonWaitOutcome']='multiple-desktops' if count>1 else 'timeout'
                    raise RuntimeError('Expected single FixtureUser logon not observed within guard window')
                time.sleep(10)
            report['logonLaunch']=step('VerifyLogon',120)['value']
            report['logonCanaries']=step('CanaryLogon',40)['value']
            report['pass'] &= (report['logonLaunch']['pass'] and report['logonCanaries']['pass']
                               and report['logonLaunch']['coreHash'].lower()==stack['coreSha256']
                               and report['logonLaunch']['selectors']==report['taskLaunch']['selectors'])
            report['observerAfterLogon']=observer_sample()
            deadline=time.monotonic()+330
            while True:
                new_rows=[row for row in report['observerAfterLogon'] if row['sampleId'] not in boot_ids]
                probes=[probe for row in new_rows for probe in row['application']]
                pairs={(p.get('leaf'),p.get('target')) for p in probes}
                if expected_pairs<=pairs or time.monotonic()>=deadline:
                    break
                time.sleep(15)
                report['observerAfterLogon']=observer_rows()
            report['postLogonApplicationsPass']=expected_pairs<=pairs and all(p.get('success') is True for p in probes)
            report['pass'] &= report['postLogonApplicationsPass']
except Exception as exc:
    report['error'] = type(exc).__name__
    report['failedStage'] = report.get('stage')
    if isinstance(exc,TransportFailure):
        report['transportFailureClass']=exc.kind
    if isinstance(exc, RuntimeError) and str(exc).startswith('ssh.exe exit '):
        report['transportFailure'] = str(exc)
finally:
    if not lab_cleanup_allowed():
        # Do not race the independent Watch with a second restoration path.
        prepared=created=False
    if prepared:
        try:
            ps("$logs='"+app+"\\logs';if(Test-Path -LiteralPath $logs){if(Get-ChildItem -LiteralPath $logs -Recurse -Force|Where-Object {$_.Attributes -band [IO.FileAttributes]::ReparsePoint}){throw 'Log reparse'};if((Get-ChildItem -LiteralPath $logs -Recurse -File|Measure-Object Length -Sum).Sum -gt 33554432){throw 'Lab evidence size limit'};& '"+control+"\\preserve.ps1' -AppDirectory '"+app+"' -Destination '"+control+"\\cvr-evidence' -MaxLogBytes 33554432 -RequireComplete -SkipEvents;Compress-Archive -LiteralPath '"+control+"\\cvr-evidence' -DestinationPath '"+control+"\\cvr-evidence.zip'}",120)
            download(control+'\\cvr-evidence.zip',local/'cvr-evidence.zip')
            report['cvrEvidenceSaved']=True
        except Exception as exc:
            report['cvrEvidenceError']=type(exc).__name__
            report['pass']=False
        if args.stack in ('next','next-baseline','candidate') or args.ui_rollout_gate or args.ui_migration_gate:
            try:
                owner_key=hashlib.sha256(b'S-1-5-21-1-2-3-1001').hexdigest()
                owner_root='C:\\ProgramData\\clash-verge-service\\users\\'+owner_key
                saved=ps("$r='C:\\ProgramData\\clash-verge-service';if(Test-Path -LiteralPath '"+owner_root+"\\logs'){if([IO.File]::ReadAllText(($r+'\\.stcvrc-desktop-state')) -cne '"+stamp+"'){throw 'Not lab service state'};$logs='"+owner_root+"\\logs';if(Get-ChildItem -LiteralPath $logs -Recurse -Force|Where-Object {$_.Attributes -band [IO.FileAttributes]::ReparsePoint}){throw 'Log reparse'};if((Get-ChildItem -LiteralPath $logs -Recurse -File|Measure-Object Length -Sum).Sum -gt 134217728){throw 'Lab evidence size limit'};$null=& '"+control+"\\preserve.ps1' -AppDirectory '"+owner_root+"' -Destination '"+control+"\\service-evidence' -MaxLogBytes 134217728 -RequireComplete -SkipEvents;Compress-Archive -LiteralPath '"+control+"\\service-evidence' -DestinationPath '"+control+"\\service-evidence.zip';'SAVED'}else{'NO_LOGS'}",180)
                if saved == 'SAVED':
                    download(control+'\\service-evidence.zip',local/'service-evidence.zip')
                report['nativeServiceEvidence']=saved
                diagnostic=ps("$p='"+lab+"\\runtime-not-ready.json';if(Test-Path -LiteralPath $p){Get-Content -LiteralPath $p -Raw}else{'null'}",read_only=True)
                report['runtimeNotReady']=json.loads(diagnostic)
            except Exception as exc:
                report['nativeServiceEvidenceError']=type(exc).__name__
                report['pass']=False
        if args.ui_migration_gate:
            try:
                ps("$root='"+control+"';$paths=@(Get-ChildItem -LiteralPath $root|Where-Object {$_.Name -match '^(UpgradeUi|RollbackUi)(-history|-(service|installer)\\.json|\\.result\\.json)$'}|Select-Object -ExpandProperty FullName);if($paths.Count){Compress-Archive -LiteralPath $paths -DestinationPath '"+control+"\\ui-migration-evidence.zip'}",120)
                download(control+'\\ui-migration-evidence.zip',local/'ui-migration-evidence.zip')
                report['uiMigrationEvidenceSaved']=True
            except Exception as exc:
                report['uiMigrationEvidenceError']=type(exc).__name__
                report['pass']=False
    try:
        if args.observer_bundle and prepared:
            # The stock-CVR restoration must not race the observer's reader.
            if args.observer_production:
                ps("& '"+control+"\\observer-install.ps1' -Action RemoveTask"+production_arg+observer_owner_arg)
                ps("$until=(Get-Date).AddSeconds(15);while(Get-CimInstance Win32_Process|Where-Object {$_.ExecutablePath -ceq '"+protected+"\\bin\\python.exe'}){if((Get-Date) -gt $until){throw 'Observer still running'};Start-Sleep -Seconds 1}",20,read_only=True)
                if observer_installed:
                    kept=observer_rows()
                    previous={r['sampleId'] for r in report.get('observerAfter',report.get('observerBefore',[]))}
                    report['productionRemoveTaskPreservesHistory']=bool(previous) and previous<={r['sampleId'] for r in kept}
                    report['pass'] &= report['productionRemoveTaskPreservesHistory']
            else:
                ps("if(Test-Path -LiteralPath '"+protected+"\\bin\\stcvrc-observer-lab-guard.ps1'){& '"+protected+"\\bin\\stcvrc-observer-lab-guard.ps1';Start-Sleep -Seconds 2}")
                ps("$t=Get-ScheduledTask -TaskName 'STCVRC-Observer-Lab-Guard' -ErrorAction SilentlyContinue;if($t){if($t.Actions.Arguments -notlike '*C:\\ProgramData\\STCVRC-observer-lab\\bin\\stcvrc-observer-lab-guard.ps1*'){throw 'Unexpected observer guard'};Unregister-ScheduledTask -TaskName 'STCVRC-Observer-Lab-Guard' -Confirm:$false}")
            if observer_installed:
                try:
                    ps("Compress-Archive -LiteralPath '"+protected+"\\data' -DestinationPath '"+control+"\\observer-evidence.zip'")
                    download(control+'\\observer-evidence.zip',local/'observer-evidence.zip')
                except Exception as exc:
                    report['observerEvidenceError']=type(exc).__name__
                    report['pass']=False
            ps("$p='"+protected+"';if(Test-Path -LiteralPath $p){if((Resolve-Path -LiteralPath $p).Path -cne $p -or [IO.File]::ReadAllText((Join-Path $p '"+observer_marker+"')) -cne '"+observer_marker_value+"'){throw 'Observer cleanup guard'};if(Get-ChildItem -LiteralPath $p -Recurse -Force|Where-Object {$_.Attributes -band [IO.FileAttributes]::ReparsePoint}){throw 'Observer reparse'};Remove-Item -LiteralPath $p -Recurse -Force}")
            report['observerRootAbsent']=ps("-not (Test-Path -LiteralPath '"+protected+"')",read_only=True)=='True'
    except Exception as exc:
        report['observerCleanupError'] = type(exc).__name__
        report['pass'] = False
    try:
        if prepared:
            restored = step('Restore', 210)
            report['preserved'] = restored.get('preserved')
            report['channelRestored'] = restored.get('channelRestored')
            report['after'] = restored.get('inventory')
            download(control+'\\inventory-after.json',local/'inventory-after.json')
            download(control+'\\Restore.result.json',local/'restore-result.json')
            report['cleanupPass'] = restored.get('cleanup', {}).get('cleanup', {}).get('pass', False)
            report['baselineComparison'] = inventory_comparison(report['before'], report.get('after') or {})
            report['baselineMatch'] = report['baselineComparison']['baselineMatch']
            if not report['preserved']['pass'] or not report['baselineMatch'] or not report['channelRestored']:
                raise RuntimeError('Restoration verification failed; control directory retained')
        if created:
            ps(r"""
if($env:COMPUTERNAME -cne 'LABHOST'){throw 'Wrong VM'}
if(Get-CimInstance Win32_Process | Where-Object Name -match 'clash|mihomo'){throw 'Runtime still present'}
if(Get-ScheduledTask | Where-Object TaskName -match 'STCVRC|Clash Verge'){throw 'Tasks still present'}
foreach($entry in @(@('C:\Users\FixtureUser\stcvrc-fullstack-lab','.codex-stcvrc-fullstack-lab','STCVRC_FULLSTACK_LAB_V1'),@('C:\Users\FixtureUser\stcvrc-autostart-control','.stcvrc-desktop-gate','STCVRC_DESKTOP_GATE_V1'))){
 $p=[IO.Path]::GetFullPath($entry[0]);if(-not(Test-Path -LiteralPath $p)){continue}
 if($p -notin @('C:\Users\FixtureUser\stcvrc-fullstack-lab','C:\Users\FixtureUser\stcvrc-autostart-control')){throw 'Unsafe exact path'}
 if([IO.File]::ReadAllText((Join-Path $p $entry[1])) -cne $entry[2]){throw 'Missing guard'}
 if(Get-ChildItem -LiteralPath $p -Filter 'saved-*'){throw 'Backups remain'}
 $parent=$p;while($parent){if((Get-Item -LiteralPath $parent -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse parent'};$parent=Split-Path -Parent $parent}
 if(@(Get-ChildItem -LiteralPath $p -Recurse -Force | Where-Object {$_.Attributes -band [IO.FileAttributes]::ReparsePoint}).Count){throw 'Reparse tree'}
 Remove-Item -LiteralPath $p -Recurse -Force
}
""")
            report['stagingRemoved'] = True
    except Exception as exc:
        report['cleanupError'] = type(exc).__name__ + ': ' + str(exc)
    report['homeUnchanged'] = H['hash_file'](RUNTIME) == report['homeBefore']
    report['acceptancePass'] = desktop_acceptance(report)
    report['finishedAt'] = time.strftime('%Y-%m-%dT%H:%M:%S%z')
    report['functionalPass'] = report.get('pass') is True and not report.get('error')
    path = PROJECT / 'reports' / ('uservm-stcvrc-desktop-autostart-' + stamp + '.json')
    path.write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps({'report': str(path), 'functionalPass':report['functionalPass'], **{k: report.get(k) for k in ['acceptancePass','error','cleanupError','baselineMatch','cleanupPass','stagingRemoved','homeUnchanged','remoteError']}}), flush=True)
sys.exit(0 if report['acceptancePass'] else 1)
