import base64
import ast
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
from datetime import datetime
import subprocess
import sys
import tempfile
import unittest
import zipfile
from types import SimpleNamespace
from unittest.mock import patch

SCRIPT = Path(__file__).with_name('uservm-stcvrc-tun-gate.ps1')


def harness_arguments(arguments):
    source=SCRIPT.with_name('invoke-uservm-stcvrc-desktop-autostart.py')
    tree=ast.parse(source.read_text())
    nodes=[]
    for node in tree.body:
        if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='H' for t in node.targets):
            break
        if not isinstance(node,(ast.Import,ast.ImportFrom)):
            nodes.append(node)
    namespace={'__doc__':'isolated argument validation','argparse':__import__('argparse'),
               'Path':Path,'STACKS':dict.fromkeys(('accepted','next','next-baseline','candidate'))}
    with patch.object(sys,'argv',['desktop',*arguments]),contextlib.redirect_stderr(io.StringIO()):
        exec(compile(ast.Module(body=nodes,type_ignores=[]),str(source),'exec'),namespace)
    return namespace['args']


def harness_function(name, namespace):
    source=SCRIPT.with_name('invoke-uservm-stcvrc-desktop-autostart.py')
    nodes=[node for node in ast.parse(source.read_text()).body if isinstance(node,ast.FunctionDef) and node.name==name]
    if not nodes:
        raise AssertionError('Missing harness behavior: '+name)
    exec(compile(ast.Module(body=nodes,type_ignores=[]),str(source),'exec'),namespace)
    return namespace[name]


def powershell(code, timeout=25):
    code="$ProgressPreference='SilentlyContinue';Import-Module Microsoft.PowerShell.Utility\n"+code
    shell = Path(os.environ['WINDIR'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
    result = subprocess.run([str(shell), '-NoProfile', '-NonInteractive', '-EncodedCommand',
        base64.b64encode(code.encode('utf-16le')).decode()], capture_output=True, timeout=timeout)
    if result.returncode:
        raise AssertionError(result.stderr.decode(errors='replace'))
    return result.stdout.decode('utf-8-sig').strip()


@unittest.skipUnless(os.name == 'nt', 'PowerShell isolated TUN control flow')
class CandidateTunTests(unittest.TestCase):
    def test_watch_completed_between_leaves_blocks_later_selector_write(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            root=Path(directory)
            (root/'plan.json').write_bytes(b'fixture-plan')
            (root/'armed.json').write_text(json.dumps({
                'deadline':'2040-01-01T00:00:00Z',
                'planHash':hashlib.sha256(b'fixture-plan').hexdigest(),
                'boot':'2026-10-15T00:00:00.0000000Z'}))
            (root/'watch-ready.json').write_text(json.dumps({'pid':123,'session':0}))
            (root/'state.json').write_text(json.dumps({'phase':'awaiting-confirmation'}))
            code=r'''
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('__SCRIPT__',[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Production source parse failure'}
foreach($name in @('Assert-Watch','Probe-Leaf')){
 $fn=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true)
 if(-not $fn){throw ('Missing production function: '+$name)}
 . ([ScriptBlock]::Create($fn.Extent.Text))
}
$root='__ROOT__';$script:puts=0;$script:selector='VPS-POOL';$script:serialized=$false;$script:taskState='Running'
$shell=$env:SystemRoot+'\System32\WindowsPowerShell\v1.0\powershell.exe'
$expected='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$root+'\transaction.ps1" -Mode Watch -Transaction "'+$root+'"'
function Get-ScheduledTask {param($TaskName) [pscustomobject]@{Principal=@{UserId='S-1-5-18'};State=$script:taskState;Actions=@(@{Execute=$shell;Arguments=$expected})}}
function Get-CimInstance {param($ClassName,$Filter)
 if($ClassName -ceq 'Win32_OperatingSystem'){return @{LastBootUpTime=[DateTime]::Parse('2026-10-15T00:00:00Z').ToUniversalTime()}}
 [pscustomobject]@{SessionId=0;ExecutablePath=$shell;CommandLine=($shell+' '+$expected)}
}
function Invoke-CimMethod {param($InputObject,$MethodName) @{Sid='S-1-5-18'}}
function Api {param($Path,$Method='Get',$Body=$null)
 if($Path -cne '/proxies/FOREIGN-EGRESS'){throw 'Unexpected fixture API path'}
 if($Method -ceq 'Put'){
  $probe=$null
  try{$probe=[IO.File]::Open(($root+'\transaction.lock'),'OpenOrCreate','ReadWrite','None')}
  catch [IO.IOException]{$script:serialized=$true}
  finally{if($probe){$probe.Dispose()}}
  $script:puts++;$script:selector=$Body.name;return
 }
 # Stop at the read-only I/O boundary: no DNS, sockets or curl run in this test.
 throw 'Fixture leaf I/O boundary'
}
$firstReachedIo=$false
try{$null=Probe-Leaf 'GC'}catch{if($_.Exception.Message -cne 'Fixture leaf I/O boundary'){throw};$firstReachedIo=$true}
# Model completed Watch recovery between leaves using its real transaction lock.
# The selector decision path and fresh guard check above remain production AST.
$watchLock=[IO.File]::Open(($root+'\transaction.lock'),'OpenOrCreate','ReadWrite','None')
try{
 $script:selector='VPS-POOL'
 [IO.File]::WriteAllText(($root+'\state.json'),'{"phase":"rolled-back"}')
 $script:taskState='Ready'
}finally{$watchLock.Dispose()}
$laterRejected=$false
try{$null=Probe-Leaf '4VPS'}catch{$laterRejected=($_.Exception.Message -cne 'Fixture leaf I/O boundary')}
$lock=$null;$lockAvailable=$false
try{$lock=[IO.File]::Open(($root+'\transaction.lock'),'OpenOrCreate','ReadWrite','None');$lockAvailable=$true}finally{if($lock){$lock.Dispose()}}
@{puts=$script:puts;selector=$script:selector;firstReachedIo=$firstReachedIo;firstWriteSerialized=$script:serialized;laterRejected=$laterRejected;recoveryLockAvailable=$lockAvailable}|ConvertTo-Json -Compress
'''.replace('__SCRIPT__',str(SCRIPT)).replace('__ROOT__',str(root))
            observed=json.loads(powershell(code))
            print('TUN_SELECTOR_WATCH_OBSERVATION '+json.dumps(observed),flush=True)
            self.assertEqual(observed['puts'],1,observed)
            self.assertEqual(observed['selector'],'VPS-POOL',observed)
            self.assertTrue(all(observed[key] for key in (
                'firstReachedIo','firstWriteSerialized','laterRejected','recoveryLockAvailable')),observed)

    def test_live_runtime_must_match_pinned_candidate_or_original_generation(self):
        code=r'''
$ErrorActionPreference='Stop';$null='{}'|ConvertFrom-Json
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('__SCRIPT__',[ref]$tokens,[ref]$errors)
$fn=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Assert-Runtime'},$true)
if(-not $fn){throw 'Missing live runtime identity gate'}
. ([ScriptBlock]::Create($fn.Extent.Text))
$plan=@{policy='ui-update';uiVersion='2.5.8';oldUiVersion='2.5.5';newVersion='candidate-version';oldVersion='baseline-version';entries=@(@{id='core';before='old-hash';after='new-hash'})}
$approved='C:\ProgramData\clash-verge-service\cores\verge-mihomo.exe'
function Get-CimInstance {param($ClassName,$Filter)
 if($ClassName -ceq 'Win32_Service'){return @{State='Running';StartMode='Auto';StartName='LocalSystem';PathName='C:\ProgramData\clash-verge-service\bin\clash-verge-service.exe';ProcessId=12}}
 @([pscustomobject]@{ExecutablePath=$approved;ProcessId=13;ParentProcessId=$script:parent;SessionId=0})
}
function Api {param($Path) @{version=$script:version}}
function Get-FileHash {param($LiteralPath) @{Hash=$script:hash}}
function Get-Item {param($LiteralPath) @{VersionInfo=@{ProductVersion=($script:ui+'.0')}}}
foreach($case in @('candidate','baseline','core-only-baseline','wrong-hash','wrong-version','wrong-ui','wrong-parent')){
 $script:hash='new-hash';$script:version='candidate-version';$script:ui='2.5.8';$script:parent=12
 $plan.policy='ui-update';$plan.uiVersion='2.5.8';$plan.oldUiVersion='2.5.5'
 switch($case){
  'baseline' {$script:hash='old-hash';$script:version='baseline-version';$script:ui='2.5.5'}
  'core-only-baseline' {$plan.policy='core-update';$plan.uiVersion='2.5.5';$plan.oldUiVersion=$null;$script:hash='old-hash';$script:version='baseline-version';$script:ui='2.5.5'}
  'wrong-hash' {$script:hash='unrelated'}
  'wrong-version' {$script:version='unrelated'}
  'wrong-ui' {$script:ui='2.5.7'}
  'wrong-parent' {$script:parent=99}
 }
 $rejected=$false;try{$null=Assert-Runtime -Candidate:($case -cnotin @('baseline','core-only-baseline'))}catch{$rejected=$true}
 if($rejected -ne ($case -like 'wrong-*')){throw ('Unexpected runtime verdict: '+$case)}
}
'''.replace('__SCRIPT__',str(SCRIPT))
        powershell(code)

    def test_recovery_is_bound_to_successful_fresh_probe_plan_dns_and_rollback(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            root=Path(directory)
            (root/'plan.json').write_bytes(b'fixture-plan')
            (root/'armed.json').write_text(json.dumps({'deadline':'2040-01-01T00:00:00Z'}))
            (root/'state.json').write_text(json.dumps({'phase':'rolled-back'}))
            (root/'rollback-result.json').write_text(json.dumps({'pass':True,'filesRestored':True}))
            code=r'''
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('__SCRIPT__',[ref]$tokens,[ref]$errors)
$branch=$null
foreach($s in $ast.FindAll({param($n) $n -is [Management.Automation.Language.IfStatementAst]},$true)){
 foreach($clause in $s.Clauses){if(-not $branch -and $clause.Item1.Extent.Text -ceq "`$Action -eq 'Probe'"){$branch=$s.ElseClause}}
}
$body=$branch.Extent.Text;$body=$body.Substring(1,$body.Length-2)
$root='__ROOT__';$plan=@{selectors=[pscustomobject]@{}}
function Network-State {@{routeHash='fresh-route';dnsHash=$script:dns;tunUp=0}}
function Api {param($Path,$Method,$Body) @{tun=@{enable=$false}}}
function Assert-Runtime {param([switch]$Candidate) @{pass=$true}}
foreach($case in @('valid','dns','plan','probe','rollback','deadline')){
 $script:dns='fresh-dns'
 $probe=@{pass=$true;before=@{routeHash='fresh-route';dnsHash='fresh-dns';tunUp=0};planHash=(Get-FileHash -LiteralPath ($root+'\plan.json')).Hash;watch=@{deadline='2040-01-01T00:00:00Z'}}
 $rollback=@{pass=$true;filesRestored=$true}
 switch($case){
  'dns' {$script:dns='changed-dns'}
  'plan' {$probe.planHash='other-plan'}
  'probe' {$probe.pass=$false}
  'rollback' {$rollback.pass=$false}
  'deadline' {$probe.watch.deadline='other-deadline'}
 }
 [IO.File]::WriteAllText(($root+'\tun-result.json'),($probe|ConvertTo-Json -Depth 6))
 [IO.File]::WriteAllText(($root+'\rollback-result.json'),($rollback|ConvertTo-Json))
 $result=@{pass=$false}
 try{. ([ScriptBlock]::Create($body))}catch{$result.pass=$false}
 if($result.pass -ne ($case -ceq 'valid')){throw ('Unexpected recovery verdict: '+$case)}
}
'''.replace('__SCRIPT__',str(SCRIPT)).replace('__ROOT__',str(root))
            powershell(code)

    def test_probe_rechecks_guard_after_baseline_before_tun_patch(self):
        temp=self.enterContext(tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')))
        code=r'''
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('__SCRIPT__',[ref]$tokens,[ref]$errors)
$branch=$null
foreach($s in $ast.FindAll({param($n) $n -is [Management.Automation.Language.IfStatementAst]},$true)){
 foreach($clause in $s.Clauses){if(-not $branch -and $clause.Item1.Extent.Text -ceq "`$Action -eq 'Probe'"){$branch=$clause.Item2}}
}
$body=$branch.Extent.Text;$body=$body.Substring(1,$body.Length-2)
$root='__ROOT__';$result=@{};$script:checks=0;$script:patched=$false;$script:serialized=$false
function Test-Path {param($LiteralPath) $false}
function Assert-Watch {
 $script:checks++
 if($script:checks -gt 1){
  $probe=$null;try{$probe=[IO.File]::Open(($root+'\transaction.lock'),'OpenOrCreate','ReadWrite','None')}catch [IO.IOException]{$script:serialized=$true}finally{if($probe){$probe.Dispose()}}
  throw 'Fixture deadline elapsed after baseline'
 }
 @{deadline='fixture'}
}
function Assert-Runtime {param([switch]$Candidate) @{}}
function Network-State {@{routeHash='fresh';dnsHash='fresh';tunUp=0}}
function Api {param($Path,$Method,$Body)
 if($Method -ceq 'Patch'){$script:patched=$true}
 @{tun=@{enable=$script:patched}}
}
function Start-Sleep {param($Seconds)}
function Probe-Leaf {param($Leaf) @{pass=$true}}
function Get-FileHash {param($LiteralPath) @{Hash='fixture'}}
$rejected=$false;try{. ([ScriptBlock]::Create($body))}catch{$rejected=$true}
if(-not $rejected -or $script:patched -or $script:checks -ne 2 -or -not $script:serialized){throw 'TUN patch lacks a serialized fresh guard recheck'}
'''.replace('__SCRIPT__',str(SCRIPT)).replace('__ROOT__',temp)
        powershell(code)

    def test_guard_rechecks_live_system_identity_boot_and_exact_watch_action(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as temp:
            root=Path(temp)
            (root/'plan.json').write_bytes(b'fixture-plan')
            (root/'armed.json').write_text(json.dumps({'deadline':'2040-01-01T00:00:00Z','planHash':hashlib.sha256(b'fixture-plan').hexdigest(),'boot':'2026-10-15T00:00:00.0000000Z'}))
            (root/'watch-ready.json').write_text(json.dumps({'pid':123,'session':0}))
            (root/'state.json').write_text(json.dumps({'phase':'awaiting-confirmation'}))
            code=r'''
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('__SCRIPT__',[ref]$tokens,[ref]$errors)
$fn=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Assert-Watch'},$true)
. ([ScriptBlock]::Create($fn.Extent.Text))
$root='__ROOT__'
$shell=$env:SystemRoot+'\System32\WindowsPowerShell\v1.0\powershell.exe'
$expected='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$root+'\transaction.ps1" -Mode Watch -Transaction "'+$root+'"'
function Get-ScheduledTask {param($TaskName) [pscustomobject]@{Principal=@{UserId=$script:sid};State=$script:state;Actions=@(@{Execute=$shell;Arguments=$script:action})}}
function Get-CimInstance {param($ClassName,$Filter)
 if($ClassName -ceq 'Win32_OperatingSystem'){return @{LastBootUpTime=$script:boot}}
 if(-not $script:worker){return}
 [pscustomobject]@{SessionId=0;ExecutablePath=$shell;CommandLine=($shell+' '+$script:command)}
}
function Invoke-CimMethod {param($InputObject,$MethodName) @{Sid=$script:owner}}
$armedOriginal=[IO.File]::ReadAllText(($root+'\armed.json'))
foreach($case in @('valid','owner','task-owner','action','root-suffix','boot','stopped','worker','hash','phase','deadline')){
 $script:owner='S-1-5-18';$script:sid='S-1-5-18';$script:action=$expected;$script:command=$expected;$script:state='Running';$script:worker=$true
 $script:boot=[DateTime]::Parse('2026-10-15T00:00:00Z').ToUniversalTime()
 [IO.File]::WriteAllText(($root+'\state.json'),'{"phase":"awaiting-confirmation"}')
 [IO.File]::WriteAllText(($root+'\armed.json'),$armedOriginal)
 switch($case){
  'owner' {$script:owner='S-1-5-19'}
  'task-owner' {$script:sid='S-1-5-19'}
  'action' {$script:action=$expected.Replace('-Mode Watch','-Mode Apply')}
  'root-suffix' {$script:command=$expected.Replace(('"'+$root+'"'),('"'+$root+'-other"'))}
  'boot' {$script:boot=$script:boot.AddDays(1)}
  'stopped' {$script:state='Ready'}
  'worker' {$script:worker=$false}
  'hash' {[IO.File]::WriteAllText(($root+'\armed.json'),$armedOriginal.Replace('planHash','differentHash'))}
  'phase' {[IO.File]::WriteAllText(($root+'\state.json'),'{"phase":"rolling-back"}')}
  'deadline' {[IO.File]::WriteAllText(($root+'\armed.json'),$armedOriginal.Replace('2040-01-01','2000-01-01'))}
 }
 $rejected=$false;$failure='';try{$null=Assert-Watch}catch{$rejected=$true;$failure=$_.Exception.Message}
 if($rejected -eq ($case -ceq 'valid')){throw ('Unexpected guard result: '+$case+' '+$failure)}
}
'''.replace('__SCRIPT__',str(SCRIPT)).replace('__ROOT__',str(root))
            powershell(code)

    def test_exact_candidate_pair_is_admitted_without_opening_other_ui_versions(self):
        # Execute the production assertion, with only the immutable plan supplied
        # as fixture. The fallback exercises the old inline assertion for RED.
        code = r'''
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('__SCRIPT__',[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Syntax'}
$fn=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Assert-Transaction'},$true)
if($fn){. ([ScriptBlock]::Create($fn.Extent.Text));$check={Assert-Transaction}}
else{
 $old=$ast.Find({param($n) $n -is [Management.Automation.Language.IfStatementAst] -and $n.Extent.Text.Contains("throw 'Unexpected transaction'")},$true)
 $check=[ScriptBlock]::Create($old.Extent.Text)
}
$root='C:\Users\FixtureUser\stcvrc-fullstack-lab\transactions\stcvrc-safe-20261015-120000'
$plan=@{schema=1;lab=$true;host='LABHOST';root=$root;policy='ui-update';tunEnabled=$false;runtimeLayout='ui-migration';sourceStack='next';targetStack='candidate';oldUiVersion='2.5.5';uiVersion='2.5.8';oldVersion='1.19.31-STCVRC-lab-20260924g';newVersion='1.19.32-STCVRC-candidate-20261007';uiInstallers=@{new='821c0f5957f84c8f7d14532044840e8280d708af24a6a143db360b49bd1e7302'};entries=@(@{id='core';before='5eef492d112a6ee9e81bce2298369f9feb5b63fbae9efc7e5a5dd9fc7441b439';after='b072d09f0754b92cbe737757d2c63111d20ecf00e5d90b534ce2f9492feb9986'})}
. $check
foreach($field in @('uiVersion','newVersion','targetStack','runtimeLayout','tunEnabled','sourceStack')){
 $saved=$plan[$field];$plan[$field]=if($field -ceq 'tunEnabled'){$true}else{'unreviewed'}
 $rejected=$false;try{. $check}catch{$rejected=$true};$plan[$field]=$saved
 if(-not $rejected){throw ('Candidate drift admitted: '+$field)}
}
$plan.sourceStack='accepted';$plan.oldUiVersion='2.5.2';$plan.oldVersion='1.19.29-STCVRC-urltest-candidate-20260905';$plan.entries[0].before='40828a0f84c2c18fa917fa23246c7b87fc2c7d798c6a7c13a3db1dc997d94540'
. $check
$plan.entries[0].after='wrong-core'
$rejected=$false;try{. $check}catch{$rejected=$true};if(-not $rejected){throw 'Wrong candidate binary admitted'}
'''.replace('__SCRIPT__', str(SCRIPT).replace("'", "''"))
        powershell(code)


class TunGateTests(unittest.TestCase):
    def test_outer_cleanup_does_not_race_unconfirmed_system_recovery(self):
        for pending in (None,r'C:\pending'):
            report={'pass':True,'pendingSystemTransaction':pending}
            operation=harness_function('lab_cleanup_allowed',{'report':report})
            self.assertEqual(operation(),not bool(pending))
            if pending:self.assertFalse(report['pass'])

    def test_atomic_cleanup_archives_before_remove_and_reads_back_exact_absence(self):
        calls=[]
        def ps(code,**kw):
            calls.append(('ps',code,kw))
            return json.dumps({'rootPresent':True})
        namespace={'json':json,'ps':ps,'control':r'C:\control','local':Path('local-fixture'),
                   'download':lambda a,b:calls.append(('download',a,b)),
                   'atomic_observer_baseline':lambda:calls.append(('readback',)) or {'rootAbsent':True,'taskAbsent':True,'workersAbsent':True}}
        operation=harness_function('atomic_observer_cleanup',namespace)
        self.assertTrue(operation(r'C:\transaction')['rootAbsent'])
        download_index=next(i for i,c in enumerate(calls) if c[0]=='download')
        removal_index=next(i for i,c in enumerate(calls) if c[0]=='ps' and 'Remove-Item -LiteralPath $root -Recurse' in c[1])
        self.assertLess(download_index,removal_index)
        self.assertEqual(calls[-1][0],'readback')

    def test_atomic_health_requires_completed_fresh_candidate_observer_row(self):
        observed={'phase':'awaiting-confirmation','manifestMatch':True,'taskOwned':True,
                  'taskState':'Ready','taskResult':0,'armedAt':'2026-10-15T00:00:00Z',
                  'row':{'observedUtc':'2026-10-15T00:00:01Z','label':'home','checkpoint':'new',
                         'observerSha256':'observer-pin','coreSha256':'core-pin',
                         'components':{'host':'ok','controller':'ok','binaries':'ok'}}}
        for field in (None,'manifestMatch','taskOwned','taskResult','coreSha256','observerSha256','observedUtc'):
            fixture=json.loads(json.dumps(observed))
            if field in ('manifestMatch','taskOwned'):fixture[field]=False
            elif field=='taskResult':fixture[field]=1
            elif field in ('coreSha256','observerSha256'):fixture['row'][field]='wrong-pin'
            elif field=='observedUtc':fixture['row'][field]='2026-10-14T00:00:00Z'
            ticks=iter((0,0,1000))
            namespace={'json':json,'datetime':datetime,'Path':Path,
                'args':SimpleNamespace(atomic_observer_label='home'),
                'STACKS':{'candidate':{'coreSha256':'core-pin'}},
                'time':SimpleNamespace(monotonic=lambda:next(ticks),sleep=lambda n:None),
                'ps':lambda *a,**kw:json.dumps(fixture)}
            operation=harness_function('atomic_observer_health',namespace)
            if field:
                with self.subTest(field=field),self.assertRaises(RuntimeError):operation(r'C:\fixture','observer-pin')
            else:self.assertEqual(operation(r'C:\fixture','observer-pin'),fixture)

    def test_transaction_staging_includes_nested_observer_payload(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            root=Path(directory);stage=root/'stage';(stage/'observer.new/bin').mkdir(parents=True)
            (stage/'transaction.ps1').write_bytes(b'fixture')
            (stage/'observer.new/bin/python.exe').write_bytes(b'fixture-only')
            uploaded=[];calls=[]
            namespace={'Path':Path,'json':json,'zipfile':zipfile,'local':root,
                       'H':{'hash_file':lambda p:hashlib.sha256(p.read_bytes()).hexdigest()},
                       'upload':lambda p,t:uploaded.append((p,t)),
                       'ps':lambda code,**kw:calls.append((code,kw))}
            operation=harness_function('stage_transaction_files',namespace)
            operation(stage,r'C:\fixture\transaction')
            self.assertEqual(len(uploaded),1)
            with zipfile.ZipFile(uploaded[0][0]) as archive:
                hashes=json.loads(archive.read('_staged-hashes.json'))
                self.assertEqual(set(hashes),{'transaction.ps1','observer.new/bin/python.exe'})
                for name,digest in hashes.items():
                    self.assertEqual(hashlib.sha256(archive.read(name)).hexdigest(),digest)
            self.assertTrue(any(call[1].get('read_only') is True for call in calls))

    def test_atomic_observer_baseline_rejects_existing_root_task_or_worker(self):
        for field in (None,'rootAbsent','taskAbsent','workersAbsent'):
            observed=dict.fromkeys(('rootAbsent','taskAbsent','workersAbsent'),True)
            if field:observed[field]=False
            namespace={'json':json,'ps':lambda *a,**kw:json.dumps(observed)}
            operation=harness_function('atomic_observer_baseline',namespace)
            if field:
                with self.subTest(field=field),self.assertRaises(RuntimeError):operation()
            else:self.assertEqual(operation(),observed)

    def test_atomic_observer_can_only_join_exact_candidate_transaction(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            bundle=Path(directory)/'observer';bundle.mkdir()
            (bundle/'manifest.json').write_text('{}')
            bundle.with_suffix('.zip').write_bytes(b'fixture; staging validates exact payload')
            common=['--preserve-service-state','--atomic-observer-bundle',str(bundle)]
            candidate=common+['--stack','next','--ui-rollout-gate','--ui-rollout-target-stack','candidate','--tun-gate']
            self.assertEqual(harness_arguments(candidate).atomic_observer_bundle,bundle)
            for argv in (common,candidate+['--observer-bundle',str(bundle)],candidate+['--reboot']):
                with self.subTest(argv=argv),self.assertRaises(SystemExit):
                    harness_arguments(argv)

    def test_harness_allows_candidate_tun_but_not_unreviewed_combinations(self):
        common=['--preserve-service-state']
        candidate=common+['--stack','next','--ui-rollout-gate','--ui-rollout-target-stack','candidate','--tun-gate']
        self.assertTrue(harness_arguments(candidate).tun_gate)
        self.assertTrue(harness_arguments(common+['--stack','next-baseline','--core-rollout-gate','--tun-gate']).tun_gate)
        for argv in (common+['--tun-gate'], candidate+['--reboot'],
                     common+['--stack','accepted','--ui-rollout-gate','--tun-gate']):
            with self.subTest(argv=argv),self.assertRaises(SystemExit):
                harness_arguments(argv)

    def test_transient_guarded_lab_scope(self):
        source = SCRIPT.read_text()
        self.assertIn("$env:COMPUTERNAME -cne 'LABHOST'", source)
        self.assertIn("$plan.policy -cne 'core-update'", source)
        self.assertLess(source.index('$result.watch=Assert-Watch'), source.index("Api '/configs' Patch"))
        self.assertIn('--noproxy', source)
        self.assertIn("$observed.type -ceq 'Tun'", source)
        self.assertIn('$observed.chains -contains $Leaf', source)
        self.assertIn('$result.leftEnabledForRollback', source)
        self.assertNotIn('Register-ScheduledTask', source)
        self.assertNotIn('Remove-NetRoute', source)
        self.assertNotIn('Set-DnsClient', source)

    def test_harness_uses_existing_timer_without_confirm_or_repeat(self):
        source = SCRIPT.with_name('invoke-uservm-stcvrc-desktop-autostart.py').read_text()
        body = source[source.index('def core_rollout_gate'):source.index('def ui_migration_gate')]
        self.assertIn('deadline=300 if ui_update or args.tun_gate else 180', body)
        self.assertLess(body.index('tun_submitted=True'), body.index("-Action Probe -Transaction"))
        self.assertNotIn('-Mode Confirm', body)
        self.assertIn("entry['tunRecovery']['pass'] is True", body)


if __name__ == '__main__':
    unittest.main()
