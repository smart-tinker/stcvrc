"""Execute full production rollback paths against isolated offline fixtures.

Only AST-selected PowerShell functions and the selected transaction try block
run: no full script startup/Guard, real task or service mutations, process
launches, network requests, ACL changes or VM access. Payload and transaction
state are real temporary files; task primitives are in-memory.
"""
import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SOURCE = Path(__file__).with_name("stcvrc-safe-rollout.ps1")


@unittest.skipUnless(os.name == "nt", "Windows PowerShell offline rollback fixture")
class ObserverRecoveryFailureTest(unittest.TestCase):
    def run_scenario(self, failure="none", foreign=False, mode="baseline", full_apply=False):
        scratch = os.environ.get("TMPDIR") or str(Path(os.environ["LOCALAPPDATA"]) / "hermes/cache/scratch")
        with tempfile.TemporaryDirectory(prefix="stcvrc-recovery-", dir=scratch) as tmp:
            code = r"""
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$env:PSModulePath=(Join-Path $PSHOME 'Modules')+';'+(Join-Path $env:ProgramFiles 'WindowsPowerShell/Modules')
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('__SOURCE__',[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Production source parse failure'}
# Define production functions without executing full script startup/Guard.
foreach($f in $ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)){
 . ([ScriptBlock]::Create($f.Extent.Text))
}
$Root='__ROOT__';$StatePath=Join-Path $Root 'state.json'
$observer=Join-Path $Root 'observer';$Core=Join-Path $Root 'core.exe';$ExecutingCore=$Core
$Ui=Join-Path $env:WINDIR 'System32\cmd.exe';$ServiceName='fixture-service'
$CachePath=Join-Path $Root 'cache-absent';$TaskName='fixture-guard';$ApplyTaskName='fixture-apply'
$failure='__FAILURE__';$foreign=__FOREIGN__;$fixtureMode='__FIXTURE_MODE__';$fullApply=__FULL_APPLY__
$absent=$foreign -or $fixtureMode -cne 'baseline'
$script:events=@();$script:disableCount=0;$script:stopCount=0;$script:unregisterCount=0
$script:startCount=0;$script:guardActive=$true;$script:taskPresent=$true;$script:taskEnabled=$true
$script:taskXml='candidate-task-xml';$script:taskArguments='candidate-args'
$script:taskDescription='foreign transaction';$script:forcedOverwriteCount=0
$script:copyObserverCalls=0;$script:rootRaceInjected=$false;$script:baselineCalls=0
$script:foreignStopObserverCalls=0;$script:guardTaskPresent=$false
[IO.File]::WriteAllText($Core,'candidate-core')
[IO.File]::WriteAllText((Join-Path $Root 'core.old'),'baseline-core')
[IO.File]::WriteAllText((Join-Path $Root 'mutation.started'),'fixture')
Write-Json (Join-Path $Root 'backup.json') @{cachePresent=$false}
foreach($folder in @('observer.old','observer.new','observer')){
 [IO.Directory]::CreateDirectory((Join-Path $Root ($folder+'\bin')))|Out-Null
}
[IO.Directory]::CreateDirectory((Join-Path $observer 'data'))|Out-Null
[IO.File]::WriteAllText((Join-Path $observer '.stcvrc-observer'),'STCVRC_OBSERVER_V1')
[IO.File]::WriteAllText((Join-Path $observer 'data\history.jsonl'),'history survives rollback')
foreach($generation in @('old','new')){
 $bundle=Join-Path $Root ('observer.'+$generation)
 [IO.File]::WriteAllText((Join-Path $bundle 'bin\python.exe'),($generation+'-python'))
 [IO.File]::WriteAllText((Join-Path $bundle 'bin\stcvrc_observer.py'),($generation+'-observer'))
 $files=@{'bin/python.exe'=(Hash (Join-Path $bundle 'bin\python.exe'));'bin/stcvrc_observer.py'=(Hash (Join-Path $bundle 'bin\stcvrc_observer.py'))}
 Write-Json (Join-Path $bundle 'manifest.json') @{schemaVersion=1;files=$files}
 if($generation -ceq 'old'){$oldFiles=$files}else{$newFiles=$files}
}
[IO.File]::WriteAllText((Join-Path $Root 'observer-task.old.xml'),'baseline-task-xml')
foreach($name in @('bin\python.exe','bin\stcvrc_observer.py','manifest.json')){
 [IO.File]::Copy((Join-Path $Root ('observer.new\'+$name)),(Join-Path $observer $name),$true)
}
$o=@{root=$observer;task='fixture-observer';oldPresent=(-not $absent);
 oldFiles=($oldFiles|ConvertTo-Json|ConvertFrom-Json);newFiles=($newFiles|ConvertTo-Json|ConvertFrom-Json);
 oldManifestHash=(Hash (Join-Path $Root 'observer.old\manifest.json'));
 newManifestHash=(Hash (Join-Path $Root 'observer.new\manifest.json'));
 oldTaskHash=(Hash (Join-Path $Root 'observer-task.old.xml'));oldArguments='baseline-args';newArguments='candidate-args'}
if($absent){$o.oldFiles=[pscustomobject]@{};$o.oldTaskHash=$null;$o.oldArguments=$null;$o.oldManifestHash=$null}
$Plan=@{policy='ui-update';oldVersion='baseline-version';newVersion='candidate-version';uiTask='fixture-ui';entries=@(@{id='core';target=$Core;before=(Hash (Join-Path $Root 'core.old'))});observer=$o}
$PlanPath=Join-Path $Root 'plan.json';Write-Json $PlanPath $Plan
# Instrument the real Stop-Observer without replacing its ownership decisions.
$stopObserverActual=${function:Stop-Observer}
$script:stopObserverCalls=0
function Stop-Observer {
 $script:stopObserverCalls++
 if($script:rootRaceInjected){$script:foreignStopObserverCalls++}
 . $stopObserverActual
}
function Get-ScheduledTask($TaskName,$ErrorAction){
 if($fullApply -and $TaskName -ceq 'fixture-guard'){
  if($script:guardTaskPresent){@{fixture='guard'}}
  return
 }
 if($TaskName -cne $o.task){throw 'Unexpected task lookup'}
 if($script:taskPresent){@{TaskPath='\';Description=$script:taskDescription;Settings=@{Enabled=$script:taskEnabled};
  Actions=@(@{Execute=(Join-Path $observer 'bin\python.exe');Arguments=$script:taskArguments;WorkingDirectory=(Join-Path $observer 'bin')});
  Principal=@{UserId='S-1-5-18';LogonType='ServiceAccount';RunLevel='Highest'}}}
}
function Disable-ScheduledTask($TaskName){
 $script:disableCount++;$script:taskEnabled=$false
 if($fixtureMode -ceq 'interrupted-disable' -and $script:disableCount -eq 1){throw 'fixture-interrupted-after-disable-before-receipt'}
}
function Stop-ScheduledTask($TaskName){$script:stopCount++}
function Start-ScheduledTask($TaskName){
 if($fullApply -and $TaskName -ceq 'fixture-guard'){
  Write-Json (Join-Path $Root 'watch-ready.json') @{pid=$PID;session=0}
  $script:events+='guard-started'
  return
 }
 $script:startCount++;$script:taskEnabled=$true;$script:events+='observer-started'
}
function Register-ScheduledTask($TaskName,$Xml,$Action,$Trigger,$Settings,$Principal,$Description,[switch]$Force){
 if($fullApply -and $TaskName -ceq 'fixture-guard'){$script:guardTaskPresent=$true;return}
 if($Xml){
  if($Xml -cne 'baseline-task-xml'){throw 'Unexpected fixture task registration'}
  $script:taskPresent=$true;$script:taskArguments='baseline-args';$script:taskXml=$Xml;$script:taskEnabled=$true
 }else{
  if($script:taskPresent){
   if(-not $Force){throw 'fixture-task-already-exists'}
   $script:forcedOverwriteCount++
  }
  $script:taskPresent=$true;$script:taskArguments='candidate-args';$script:taskXml='created-candidate-task-xml'
  $script:taskDescription=$Description;$script:taskEnabled=$true
  if($fixtureMode -ceq 'interrupted-register'){throw 'fixture-interrupted-after-registration-before-receipt'}
 }
}
function Unregister-ScheduledTask($TaskName,[switch]$Confirm){$script:unregisterCount++;$script:taskPresent=$false}
function Export-ScheduledTask($TaskName){
 if($fullApply -and $TaskName -ceq 'fixture-ui'){return 'fixture-ui-task-xml'}
 # Real scheduler XML changes when Disable-ScheduledTask flips Enabled. Keep
 # an actual namespaced XML document so production normalization runs here.
 if($script:taskXml -ceq 'baseline-task-xml'){$script:taskXml}
 else{'<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><RegistrationInfo><Description>'+[Security.SecurityElement]::Escape($script:taskDescription)+'</Description></RegistrationInfo><Settings><Enabled>'+([string]$script:taskEnabled).ToLowerInvariant()+'</Enabled><FixtureGeneration>'+[Security.SecurityElement]::Escape($script:taskXml)+'</FixtureGeneration></Settings></Task>'}
}
function Get-CimInstance($ClassName,$Filter){
 if($fullApply){
  if($ClassName -ceq 'Win32_Service'){return @{PathName=$ServiceExe}}
  if($ClassName -ceq 'Win32_OperatingSystem'){return @{LastBootUpTime=[DateTime]::Parse('2000-01-01T00:00:00Z')}}
  if($ClassName -ceq 'Win32_Process' -and $Filter){return @{CreationDate=[DateTime]::Parse('2000-01-01T00:00:00Z')}}
 }
 if($ClassName -cne 'Win32_Process'){throw 'Unexpected fixture CIM call'}
 @()
}
function Assert-ObserverAcl {}
function Assert-ObserverSchedule($Xml){}
function Set-Acl($LiteralPath,$AclObject){}
function New-ScheduledTaskAction($Execute,$Argument,$WorkingDirectory){
 if($fixtureMode -ceq 'register-race'){
  $script:taskPresent=$true;$script:taskXml='foreign-race-task-xml';$script:taskArguments='candidate-args'
  $script:taskDescription='foreign racing transaction';$script:taskEnabled=$true
  $script:foreignTaskBefore=@{xml=$script:taskXml;arguments=$script:taskArguments;description=$script:taskDescription;enabled=$script:taskEnabled}|ConvertTo-Json -Compress
 }
 @{Execute=$Execute;Arguments=$Argument;WorkingDirectory=$WorkingDirectory}
}
function New-ScheduledTaskTrigger([switch]$AtStartup,[switch]$Once,$At,$RepetitionInterval){@{fixture=$true}}
function New-ScheduledTaskSettingsSet($MultipleInstances,$ExecutionTimeLimit,$RestartCount,$RestartInterval,[switch]$StartWhenAvailable,[switch]$AllowStartIfOnBatteries,[switch]$DontStopIfGoingOnBatteries){@{Enabled=$true}}
function New-ScheduledTaskPrincipal($UserId,$LogonType,$RunLevel){@{UserId=$UserId;LogonType=$LogonType;RunLevel=$RunLevel}}
function Preserve-History($Label){}
function Stop-Runtime {$script:events+='core-stopped'}
function Install-UiGeneration($New){
 if($New){if(-not $fullApply){throw 'Unexpected candidate install'};$script:events+='candidate-ui-installed'}
 else{$script:events+='baseline-ui-installed'}
}
function Register-ApprovedCore($Hash){
 if($fullApply -and $Hash -ceq $Plan.entries[0].after){$script:events+='candidate-core-registered'}
 else{$script:events+='baseline-core-registered'}
}
function Register-UiService($Hash){}
function Get-OwnerUiTask {@{fixture='owner-ui'}}
function Remove-ApplyTask {$script:events+='apply-task-removed'}
function Candidate-Check {throw 'Fixture candidate health reached after failed root acquisition'}
function Start-Service($Name){$script:events+='service-started'}
function Start-OwnerUi {$script:events+='owner-ui-started'}
function Wait-Core($Version){
 $script:events+='core-wait'
 if($failure -ceq 'core-wait'){throw 'fixture-core-wait-failure'}
 $script:events+='core-ready'
}
function Check-OwnerRuntime {$script:events+='owner-runtime-checked'}
function Restore-Selectors {$script:events+='selectors-restored'}
function Check-Selectors {$script:events+='selectors-checked'}
function Check-Http {
 $script:events+='http-checked'
 if($failure -ceq 'http'){throw 'fixture-http-failure'}
 @(@{pass=$true;fixture=$true})
}
function Remove-GuardTask {$script:guardActive=$false;$script:events+='guard-removed'}
function Snapshot-Observer {
 $map=[ordered]@{}
 if(Test-Path -LiteralPath $observer){
  foreach($file in @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $observer -Recurse -File|Sort-Object FullName)){
   $map[$file.FullName.Substring($observer.Length+1)]=Hash $file.FullName
  }
 }
 @{rootPresent=(Test-Path -LiteralPath $observer);files=$map;taskPresent=$script:taskPresent;taskEnabled=$script:taskEnabled;taskXml=$script:taskXml;taskArguments=$script:taskArguments;taskDescription=$script:taskDescription}|ConvertTo-Json -Depth 5 -Compress
}
if($absent -and -not $foreign){[IO.Directory]::Delete($observer,$true);$script:taskPresent=$false}
# Run the actual last absence check, then inject the competing installation
# before Apply-Observer reaches its following Test-Path/mutation boundary.
$assertObserverBaselineActual=${function:Assert-ObserverBaseline}
function Assert-ObserverBaseline {
 & $assertObserverBaselineActual
 $script:baselineCalls++
 if($fixtureMode -cin @('root-race','root-race-empty') -and -not $script:rootRaceInjected -and (-not $fullApply -or $script:baselineCalls -eq 2)){
  [IO.Directory]::CreateDirectory($observer)|Out-Null
  if($fixtureMode -ceq 'root-race'){
  [IO.Directory]::CreateDirectory((Join-Path $observer 'bin'))|Out-Null
  [IO.Directory]::CreateDirectory((Join-Path $observer 'data'))|Out-Null
  [IO.File]::WriteAllText((Join-Path $observer '.stcvrc-observer'),'STCVRC_OBSERVER_V1')
  [IO.File]::WriteAllText((Join-Path $observer 'bin\\python.exe'),'foreign-directory-race-python')
  [IO.File]::WriteAllText((Join-Path $observer 'bin\\stcvrc_observer.py'),'foreign-directory-race-observer')
  [IO.File]::WriteAllText((Join-Path $observer 'data\\history.jsonl'),'history survives rollback')
  [IO.File]::WriteAllBytes((Join-Path $observer 'data\\foreign-owned.bin'),[byte[]]@(0,17,128,255))
  $foreignFiles=@{'bin/python.exe'=(Hash (Join-Path $observer 'bin\\python.exe'));'bin/stcvrc_observer.py'=(Hash (Join-Path $observer 'bin\\stcvrc_observer.py'))}
  Write-Json (Join-Path $observer 'manifest.json') @{schemaVersion=77;owner='foreign-directory-race';files=$foreignFiles}
  $script:taskPresent=$true;$script:taskEnabled=$false;$script:taskXml='foreign-directory-race-task-xml'
  $script:taskArguments='foreign-directory-race-args';$script:taskDescription='foreign directory owner'
  }
  $script:rootRaceInjected=$true;$script:events+='foreign-root-created-after-baseline'
  $script:foreignObserverBefore=Snapshot-Observer
 }
}
$copyObserverActual=${function:Copy-ObserverPayload}
function Copy-ObserverPayload([bool]$Candidate){
 $script:copyObserverCalls++
 & $copyObserverActual $Candidate
 if($Candidate -and $absent -and -not $foreign -and $fixtureMode -cnotin @('root-race','root-race-empty')){
  [IO.Directory]::CreateDirectory((Join-Path $observer 'data'))|Out-Null
  [IO.File]::WriteAllText((Join-Path $observer 'data\history.jsonl'),'history survives rollback')
  if($fixtureMode -ceq 'partial-apply'){throw 'fixture-partial-apply-failure'}
 }
}
$writeJsonActual=${function:Write-Json}
$script:rootReceiptInterrupted=$false;$script:claimedRootEmptyAtInterruption=$false
$unrelated=Join-Path $Root 'unrelated-owned.bin'
[IO.File]::WriteAllBytes($unrelated,[byte[]]@(0,17,128,255))
$unrelatedHash=Hash $unrelated
function Write-Json([string]$Path,$Value){
 if($fixtureMode -clike 'interrupted-root-receipt*' -and $Path -ceq (Join-Path $Root 'observer-created.json')){
  # Intercept only after the real atomic Move and before its durable receipt.
  # Assert the injection boundary rather than simulating directory acquisition.
  if($script:rootReceiptInterrupted){throw 'Unexpected repeated root receipt write'}
  if(-not (Test-Path -LiteralPath $observer) -or (Test-Path -LiteralPath (Join-Path $Root 'observer.create'))){throw 'Fixture did not reach post-Move boundary'}
  if(Test-Path -LiteralPath $Path){throw 'Fixture root receipt already exists'}
  if([IO.File]::ReadAllText((Join-Path $observer '.stcvrc-transaction')) -cne $Root){throw 'Fixture root transaction mismatch'}
  $allowedProof=@('.stcvrc-observer','.stcvrc-transaction')
  $embedded=Join-Path $observer '.stcvrc-claim.json'
  if(Test-Path -LiteralPath $embedded){
   $proof=Read-Json $embedded
   if($proof.root -cne $observer -or $proof.transaction -cne $Root -or $proof.planHash -cne (Hash $PlanPath)){throw 'Fixture embedded acquisition proof mismatch'}
   $allowedProof+='.stcvrc-claim.json'
  }
  $unexpected=@(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $observer -Force|Where-Object {$_.PSIsContainer -or $_.Name -cnotin $allowedProof})
  $script:claimedRootEmptyAtInterruption=($unexpected.Count -eq 0) -and -not $script:taskPresent -and $script:copyObserverCalls -eq 0
  if(-not $script:claimedRootEmptyAtInterruption){throw 'Fixture root contains unexpected pre-payload state'}
  $script:rootReceiptInterrupted=$true;$script:events+='interrupted-after-root-move-before-receipt'
  # Recovery must preserve independently appended evidence, even in this early
  # owned-root state. This is fixture data, not execution of the observer.
  [IO.Directory]::CreateDirectory((Join-Path $observer 'data'))|Out-Null
  [IO.File]::WriteAllText((Join-Path $observer 'data\history.jsonl'),'history survives rollback')
  if($fixtureMode -ceq 'interrupted-root-receipt-missing-proof'){
   if(-not (Test-Path -LiteralPath $embedded)){throw 'Fixture embedded proof unavailable for missing-proof control'}
   [IO.File]::Delete($embedded)
  }elseif($fixtureMode -ceq 'interrupted-root-receipt-corrupt-proof'){
   if(-not (Test-Path -LiteralPath $embedded)){throw 'Fixture embedded proof unavailable for corrupt-proof control'}
   $proof=Read-Json $embedded;$proof.planHash=('0'*64)
   & $writeJsonActual $embedded $proof
  }
  $script:interruptedObserverBefore=Snapshot-Observer
  throw 'fixture-interrupted-after-root-move-before-receipt'
 }
 & $writeJsonActual $Path $Value
}
$before=Snapshot-Observer
$applyRejected=$false;$applyReason=$null
$rollbackRejected=$false;$rollbackReason=$null
if($fullApply){
 # Invoke the real outer Apply try/catch/finally, including its actual recovery
 # call and file lock. Only host effect boundaries above are fixture adapters.
 $transactionTry=@($ast.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.TryStatementAst]})
 if($transactionTry.Count -ne 1){throw 'Expected unique production transaction try/catch/finally'}
 $Mode='Apply';$LabPause='None';$DeadlineSeconds=300;$Lock=$null
 $ServiceExe=Join-Path $Root 'fixture-service.exe';$PowerShell='fixture-not-executed'
 [IO.File]::WriteAllText($Core,'baseline-core')
 [IO.File]::WriteAllText((Join-Path $Root 'core.new'),'candidate-core')
 $Plan.entries[0].replace=$true;$Plan.entries[0].after=Hash (Join-Path $Root 'core.new')
 Write-Json $PlanPath $Plan
 [IO.File]::Delete((Join-Path $Root 'core.old'))
 [IO.File]::Delete((Join-Path $Root 'mutation.started'))
 try{. ([ScriptBlock]::Create($transactionTry[0].Extent.Text))}catch{$applyRejected=$true;$applyReason=$_.Exception.Message}
 $rollbackRejected=(Test-Path -LiteralPath (Join-Path $Root 'rollback-result.json')) -and -not (Read-Json (Join-Path $Root 'rollback-result.json')).pass
 if($rollbackRejected){$rollbackReason=$applyReason}
 if($script:rootRaceInjected){$before=$script:foreignObserverBefore}
 if($script:rootReceiptInterrupted){$before=$script:interruptedObserverBefore}
}elseif($absent){
 # The empty baseline was captured before this separately-owned installation.
 # It deliberately has exact candidate bytes and normal task identity: hashes
 # or a generic observer marker do not prove ownership by this transaction.
 try{Apply-Observer}catch{$applyRejected=$true;$applyReason=$_.Exception.Message}
 if($fixtureMode -cin @('root-race','root-race-empty') -and $script:rootRaceInjected){$before=$script:foreignObserverBefore}
 if($fixtureMode -cin @('task-replaced','task-hash-drift')){
  $script:taskXml='foreign-replacement-task-xml'
  if($fixtureMode -ceq 'task-replaced'){$script:taskDescription='replacement foreign transaction'}
  $before=Snapshot-Observer
 }
}
if(-not $fullApply){try{Restore-Old}catch{$rollbackRejected=$true;$rollbackReason=$_.Exception.Message}}
$repeatRejected=$false;$repeatReason=$null
if($fixtureMode -ceq 'complete-apply-repeat' -and -not $rollbackRejected){
 try{Restore-Old}catch{$repeatRejected=$true;$repeatReason=$_.Exception.Message}
}
$phase=(Read-Json $StatePath).phase
$resultPath=Join-Path $Root 'rollback-result.json';$result=$null
if(Test-Path -LiteralPath $resultPath){$result=Read-Json $resultPath}
$observerRestored=$false
if(-not $absent){
 try{
  Assert-ObserverFiles $observer $o.oldFiles $o.oldManifestHash
  $observerRestored=$script:taskPresent -and $script:taskEnabled -and $script:taskArguments -ceq 'baseline-args' -and $script:taskXml -ceq 'baseline-task-xml' -and $script:startCount -gt 0
 }catch{}
}
$history=Join-Path $observer 'data\history.jsonl'
$historyPreserved=(Test-Path -LiteralPath $history) -and [IO.File]::ReadAllText($history) -ceq 'history survives rollback'
$foreignTaskAfter=@{xml=$script:taskXml;arguments=$script:taskArguments;description=$script:taskDescription;enabled=$script:taskEnabled}|ConvertTo-Json -Compress
$payloadRemoved=(-not (Test-Path -LiteralPath (Join-Path $observer 'bin\python.exe'))) -and (-not (Test-Path -LiteralPath (Join-Path $observer 'bin\stcvrc_observer.py'))) -and (-not (Test-Path -LiteralPath (Join-Path $observer 'manifest.json')))
$lockReleased=$false
try {
 $probe=[IO.File]::Open((Join-Path $Root 'transaction.lock'),'OpenOrCreate','ReadWrite','None')
 $probe.Dispose();$lockReleased=$true
}catch{}
@{scope='offline AST fixtures; no live tasks/services/network/VM';failure=$failure;foreign=$foreign;
 applyRejected=$applyRejected;applyReason=$applyReason;rollbackRejected=$rollbackRejected;rollbackReason=$rollbackReason;
  repeatRejected=$repeatRejected;repeatReason=$repeatReason;
 coreRestored=([IO.File]::ReadAllText($Core) -ceq 'baseline-core');observerRestored=$observerRestored;
 historyPreserved=$historyPreserved;payloadRemoved=$payloadRemoved;mode=$fixtureMode;
 forcedOverwriteCount=$script:forcedOverwriteCount;foreignRaceTaskUnchanged=($script:taskPresent -and $script:foreignTaskBefore -ceq $foreignTaskAfter);
 observerUnchanged=((Snapshot-Observer) -ceq $before);phase=$phase;guardActive=$script:guardActive;
 successRecorded=($null -ne $result -and $result.pass -eq $true);events=$script:events;
  taskPresent=$script:taskPresent;taskEnabled=$script:taskEnabled;
  rootRaceInjected=$script:rootRaceInjected;copyObserverCalls=$script:copyObserverCalls;startCount=$script:startCount;
  baselineCalls=$script:baselineCalls;fullApply=$fullApply;lockReleased=$lockReleased;foreignStopObserverCalls=$script:foreignStopObserverCalls;
  rootRaceBefore=$(if($script:rootRaceInjected){$before|ConvertFrom-Json}else{$null});
  rootRaceAfter=$(if($script:rootRaceInjected){Snapshot-Observer|ConvertFrom-Json}else{$null});
  rootClaimPresent=(Test-Path -LiteralPath (Join-Path $Root 'observer-created.json'));
  embeddedClaimPresent=(Test-Path -LiteralPath (Join-Path $observer '.stcvrc-claim.json'));
  rootReceiptInterrupted=$script:rootReceiptInterrupted;claimedRootEmptyAtInterruption=$script:claimedRootEmptyAtInterruption;
  observerMarkerPreserved=((Test-Path -LiteralPath (Join-Path $observer '.stcvrc-observer')) -and [IO.File]::ReadAllText((Join-Path $observer '.stcvrc-observer')) -ceq 'STCVRC_OBSERVER_V1');
  transactionMarkerMatches=((Test-Path -LiteralPath (Join-Path $observer '.stcvrc-transaction')) -and [IO.File]::ReadAllText((Join-Path $observer '.stcvrc-transaction')) -ceq $Root);
  unrelatedFileUnchanged=((Test-Path -LiteralPath $unrelated) -and (Hash $unrelated) -ceq $unrelatedHash);
  taskIntentPresent=(Test-Path -LiteralPath (Join-Path $Root 'observer-task.intent.json'));
  taskClaimPresent=(Test-Path -LiteralPath (Join-Path $Root 'observer-task.created.json'));
  transactionMarkerPresent=(Test-Path -LiteralPath (Join-Path $observer '.stcvrc-transaction'));
  stopObserverCalls=$script:stopObserverCalls;disableCount=$script:disableCount;stopCount=$script:stopCount;unregisterCount=$script:unregisterCount}|ConvertTo-Json -Depth 6 -Compress
"""
            replacements = {
                "__SOURCE__": str(SOURCE).replace("'", "''"),
                "__ROOT__": str(Path(tmp)).replace("'", "''"),
                "__FAILURE__": failure,
                "__FOREIGN__": "$true" if foreign else "$false",
                "__FIXTURE_MODE__": mode,
                "__FULL_APPLY__": "$true" if full_apply else "$false",
            }
            for token, value in replacements.items():
                code = code.replace(token, value)
            shell = Path(os.environ["WINDIR"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
            fixture_script = Path(tmp) / "rollback-fixture.ps1"
            fixture_script.write_text(code, encoding="utf-8-sig")
            result = subprocess.run(
                [str(shell), "-NoProfile", "-NonInteractive", "-File", str(fixture_script)],
                capture_output=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
            report = json.loads(result.stdout.decode("utf-8-sig"))
            print("OBSERVER_RECOVERY_OBSERVATION " + json.dumps(report, sort_keys=True), flush=True)
            return report

    def assert_failed_rollback_retains_guard(self, report):
        self.assertTrue(report["rollbackRejected"], report)
        self.assertTrue(report["coreRestored"], report)
        self.assertTrue(report["historyPreserved"], report)
        self.assertTrue(report["guardActive"], report)
        self.assertEqual(report["phase"], "rollback-incomplete", report)
        self.assertFalse(report["successRecorded"], report)

    def test_external_http_failure_does_not_skip_observer_recovery(self):
        report = self.run_scenario(failure="http")
        self.assert_failed_rollback_retains_guard(report)
        self.assertIn("core-ready", report["events"], report)
        self.assertIn("http-checked", report["events"], report)
        self.assertTrue(report["observerRestored"], report)

    def test_core_wait_failure_still_attempts_observer_recovery(self):
        report = self.run_scenario(failure="core-wait")
        self.assert_failed_rollback_retains_guard(report)
        self.assertIn("core-wait", report["events"], report)
        self.assertNotIn("http-checked", report["events"], report)
        self.assertTrue(report["observerRestored"], report)

    def test_rejected_foreign_observer_survives_full_ui_core_rollback(self):
        report = self.run_scenario(foreign=True)
        self.assertTrue(report["applyRejected"], report)
        self.assertEqual(report["applyReason"], "Observer baseline absence changed", report)
        self.assertTrue(report["coreRestored"], report)
        self.assertIn("baseline-ui-installed", report["events"], report)
        self.assertTrue(report["historyPreserved"], report)
        self.assertTrue(report["observerUnchanged"], report)
        self.assertEqual(report["stopObserverCalls"], 0, report)
        self.assertEqual(report["disableCount"], 0, report)
        self.assertEqual(report["stopCount"], 0, report)
        self.assertEqual(report["unregisterCount"], 0, report)

    def test_fixture_healthy_baseline_restores_observer_and_disarms_guard(self):
        report = self.run_scenario()
        self.assertFalse(report["rollbackRejected"], report)
        self.assertTrue(report["coreRestored"], report)
        self.assertTrue(report["observerRestored"], report)
        self.assertTrue(report["historyPreserved"], report)
        self.assertEqual(report["phase"], "rolled-back", report)
        self.assertTrue(report["successRecorded"], report)
        self.assertFalse(report["guardActive"], report)

    def test_own_partial_apply_removes_only_owned_payload_and_preserves_history(self):
        report = self.run_scenario(mode="partial-apply")
        self.assertTrue(report["applyRejected"], report)
        self.assertEqual(report["applyReason"], "fixture-partial-apply-failure", report)
        self.assertFalse(report["rollbackRejected"], report)
        self.assertTrue(report["coreRestored"], report)
        self.assertTrue(report["payloadRemoved"], report)
        self.assertTrue(report["historyPreserved"], report)
        self.assertTrue(report["successRecorded"], report)
        self.assertFalse(report["guardActive"], report)

    def test_full_apply_recovers_owned_root_after_move_before_created_receipt(self):
        report = self.run_scenario(mode="interrupted-root-receipt", full_apply=True)
        self.assertTrue(report["fullApply"], report)
        self.assertTrue(report["rootReceiptInterrupted"], report)
        self.assertTrue(report["claimedRootEmptyAtInterruption"], report)
        self.assertTrue(report["applyRejected"], report)
        self.assertIn("interrupted-after-root-move-before-receipt", report["events"], report)
        self.assertFalse(report["rootClaimPresent"], report)
        self.assertEqual(report["copyObserverCalls"], 0, report)
        self.assertTrue(report["payloadRemoved"], report)
        self.assertFalse(report["taskPresent"], report)
        self.assertFalse(report["taskIntentPresent"], report)
        self.assertFalse(report["taskClaimPresent"], report)
        self.assertTrue(report["observerMarkerPreserved"], report)
        self.assertTrue(report["transactionMarkerMatches"], report)
        self.assertTrue(report["historyPreserved"], report)
        self.assertTrue(report["unrelatedFileUnchanged"], report)
        for counter in ("disableCount", "stopCount", "unregisterCount", "startCount", "forcedOverwriteCount"):
            self.assertEqual(report[counter], 0, report)
        self.assertTrue(report["coreRestored"], report)
        self.assertTrue(report["lockReleased"], report)
        self.assertIn("baseline-ui-installed", report["events"], report)
        self.assertIn("baseline-core-registered", report["events"], report)
        self.assertIn("apply-task-removed", report["events"], report)
        self.assertFalse(report["rollbackRejected"], report)
        self.assertTrue(report["successRecorded"], report)
        self.assertEqual(report["phase"], "rolled-back", report)
        self.assertFalse(report["guardActive"], report)

    def assert_interrupted_unproved_root_preserved(self, report):
        self.assertTrue(report["fullApply"], report)
        self.assertTrue(report["rootReceiptInterrupted"], report)
        self.assertTrue(report["claimedRootEmptyAtInterruption"], report)
        self.assertTrue(report["applyRejected"], report)
        self.assertIn("interrupted-after-root-move-before-receipt", report["events"], report)
        self.assertFalse(report["rootClaimPresent"], report)
        self.assertTrue(report["rollbackRejected"], report)
        self.assertEqual(report["phase"], "rollback-failed", report)
        self.assertTrue(report["guardActive"], report)
        self.assertFalse(report["successRecorded"], report)
        self.assertTrue(report["observerUnchanged"], report)
        self.assertTrue(report["observerMarkerPreserved"], report)
        self.assertTrue(report["transactionMarkerMatches"], report)
        self.assertTrue(report["historyPreserved"], report)
        self.assertTrue(report["unrelatedFileUnchanged"], report)
        self.assertFalse(report["taskPresent"], report)
        self.assertFalse(report["taskIntentPresent"], report)
        self.assertFalse(report["taskClaimPresent"], report)
        for counter in ("copyObserverCalls", "disableCount", "stopCount", "unregisterCount", "startCount", "forcedOverwriteCount"):
            self.assertEqual(report[counter], 0, report)
        self.assertTrue(report["coreRestored"], report)
        self.assertTrue(report["lockReleased"], report)

    def test_full_apply_preserves_root_when_both_acquisition_receipts_are_missing(self):
        report = self.run_scenario(mode="interrupted-root-receipt-missing-proof", full_apply=True)
        self.assert_interrupted_unproved_root_preserved(report)
        self.assertFalse(report["embeddedClaimPresent"], report)

    def test_full_apply_preserves_root_when_only_embedded_receipt_is_corrupt(self):
        report = self.run_scenario(mode="interrupted-root-receipt-corrupt-proof", full_apply=True)
        self.assert_interrupted_unproved_root_preserved(report)
        self.assertTrue(report["embeddedClaimPresent"], report)

    def test_foreign_task_registration_race_never_uses_force_or_removes_task(self):
        report = self.run_scenario(mode="register-race")
        self.assertTrue(report["applyRejected"], report)
        self.assertEqual(report["applyReason"], "fixture-task-already-exists", report)
        self.assertTrue(report["coreRestored"], report)
        self.assertEqual(report["forcedOverwriteCount"], 0, report)
        self.assertTrue(report["foreignRaceTaskUnchanged"], report)
        self.assertEqual(report["disableCount"], 0, report)
        self.assertEqual(report["stopCount"], 0, report)
        self.assertEqual(report["unregisterCount"], 0, report)

    def test_foreign_directory_after_last_absence_check_is_preserved_by_apply_and_rollback(self):
        report = self.run_scenario(mode="root-race")
        self.assertTrue(report["rootRaceInjected"], report)
        self.assertTrue(report["applyRejected"], report)
        self.assert_failed_rollback_retains_guard(report)
        self.assertIn("baseline-ui-installed", report["events"], report)
        self.assertEqual(report["copyObserverCalls"], 0, report)
        self.assertTrue(report["observerUnchanged"], report)
        self.assertFalse(report["rootClaimPresent"], report)
        self.assertFalse(report["taskIntentPresent"], report)
        self.assertFalse(report["taskClaimPresent"], report)
        self.assertFalse(report["transactionMarkerPresent"], report)
        for counter in ("stopObserverCalls", "disableCount", "stopCount", "unregisterCount", "startCount", "forcedOverwriteCount"):
            self.assertEqual(report[counter], 0, report)

    def assert_full_apply_collision_is_preserved(self, report):
        self.assertTrue(report["fullApply"], report)
        self.assertTrue(report["rootRaceInjected"], report)
        self.assertEqual(report["baselineCalls"], 2, report)
        self.assertTrue(report["applyRejected"], report)
        self.assertTrue(report["rollbackRejected"], report)
        self.assertTrue(report["coreRestored"], report)
        self.assertIn("candidate-ui-installed", report["events"], report)
        self.assertIn("candidate-core-registered", report["events"], report)
        self.assertIn("baseline-ui-installed", report["events"], report)
        self.assertIn("baseline-core-registered", report["events"], report)
        self.assertEqual(report["copyObserverCalls"], 0, report)
        self.assertTrue(report["observerUnchanged"], report)
        self.assertEqual(report["rootRaceBefore"], report["rootRaceAfter"], report)
        self.assertFalse(report["rootClaimPresent"], report)
        self.assertFalse(report["taskIntentPresent"], report)
        self.assertFalse(report["taskClaimPresent"], report)
        self.assertFalse(report["transactionMarkerPresent"], report)
        for counter in ("foreignStopObserverCalls", "disableCount", "stopCount", "unregisterCount", "startCount", "forcedOverwriteCount"):
            self.assertEqual(report[counter], 0, report)
        self.assertFalse(report["successRecorded"], report)
        self.assertTrue(report["guardActive"], report)
        # The real outer Apply catch preserves FAIL but names its terminal
        # phase rollback-failed after Restore-Old records rollback-incomplete.
        self.assertEqual(report["phase"], "rollback-failed", report)
        self.assertIn("apply-task-removed", report["events"], report)
        self.assertTrue(report["lockReleased"], report)

    def test_full_apply_preserves_foreign_directory_created_after_last_absence_check(self):
        report = self.run_scenario(mode="root-race", full_apply=True)
        self.assert_full_apply_collision_is_preserved(report)
        self.assertTrue(report["historyPreserved"], report)
        self.assertTrue(report["taskPresent"], report)
        self.assertFalse(report["taskEnabled"], report)

    def test_full_apply_preserves_empty_foreign_directory_after_last_absence_check(self):
        report = self.run_scenario(mode="root-race-empty", full_apply=True)
        self.assert_full_apply_collision_is_preserved(report)
        self.assertEqual(report["rootRaceAfter"]["files"], {}, report)
        self.assertTrue(report["rootRaceAfter"]["rootPresent"], report)
        self.assertFalse(report["taskPresent"], report)

    def test_foreign_task_replacement_after_own_install_is_not_stopped_or_removed(self):
        report = self.run_scenario(mode="task-replaced")
        self.assertFalse(report["applyRejected"], report)
        self.assertTrue(report["coreRestored"], report)
        self.assertTrue(report["observerUnchanged"], report)
        self.assertEqual(report["disableCount"], 0, report)
        self.assertEqual(report["stopCount"], 0, report)
        self.assertEqual(report["unregisterCount"], 0, report)
        self.assertTrue(report["guardActive"], report)
        self.assertFalse(report["successRecorded"], report)

    def test_same_identity_task_with_unclaimed_xml_hash_is_preserved(self):
        report = self.run_scenario(mode="task-hash-drift")
        self.assertFalse(report["applyRejected"], report)
        self.assertTrue(report["coreRestored"], report)
        self.assertTrue(report["observerUnchanged"], report)
        self.assertEqual(report["stopObserverCalls"], 0, report)
        self.assertEqual(report["disableCount"], 0, report)
        self.assertEqual(report["stopCount"], 0, report)
        self.assertEqual(report["unregisterCount"], 0, report)
        self.assertTrue(report["guardActive"], report)
        self.assertFalse(report["successRecorded"], report)

    def test_own_complete_install_accepts_quiesced_xml_and_cleans_payload(self):
        report = self.run_scenario(mode="complete-apply")
        self.assertFalse(report["applyRejected"], report)
        self.assertFalse(report["rollbackRejected"], report)
        self.assertTrue(report["coreRestored"], report)
        self.assertTrue(report["payloadRemoved"], report)
        self.assertTrue(report["historyPreserved"], report)
        self.assertEqual(report["unregisterCount"], 1, report)
        self.assertTrue(report["successRecorded"], report)
        self.assertFalse(report["guardActive"], report)

    def assert_owned_interrupted_task_recovered(self, report):
        self.assertTrue(report["coreRestored"], report)
        self.assertTrue(report["historyPreserved"], report)
        self.assertTrue(report["payloadRemoved"], report)
        self.assertFalse(report["taskPresent"], report)
        self.assertEqual(report["unregisterCount"], 1, report)
        self.assertFalse(report["rollbackRejected"], report)
        self.assertTrue(report["successRecorded"], report)
        self.assertFalse(report["guardActive"], report)

    def test_registered_owned_task_is_recovered_when_created_receipt_is_missing(self):
        report = self.run_scenario(mode="interrupted-register")
        self.assertTrue(report["applyRejected"], report)
        self.assert_owned_interrupted_task_recovered(report)

    def test_disabled_owned_task_is_recovered_before_quiesced_receipt_is_written(self):
        report = self.run_scenario(mode="interrupted-disable")
        self.assertFalse(report["applyRejected"], report)
        self.assert_owned_interrupted_task_recovered(report)

    def test_repeated_rollback_keeps_owned_absent_baseline_cleanup_idempotent(self):
        report = self.run_scenario(mode="complete-apply-repeat")
        self.assertFalse(report["applyRejected"], report)
        self.assert_owned_interrupted_task_recovered(report)
        self.assertFalse(report["repeatRejected"], report)
        self.assertEqual(report["phase"], "rolled-back", report)

    def test_recovery_xml_hash_normalizes_only_task_enabled(self):
        code = r'''
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('__SOURCE__',[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Production source parse failure'}
foreach($name in @('Hash-ObserverTask','Get-ObserverRecoveryXml')){
 $f=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true)
 if(-not $f){throw ('Missing production function: '+$name)}
 . ([ScriptBlock]::Create($f.Extent.Text))
}
$xml='<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers><Settings><Enabled>true</Enabled><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy></Settings></Task>'
$disabled=$xml.Replace('<Settings><Enabled>true</Enabled>','<Settings><Enabled>false</Enabled>')
$changedSetting=$xml.Replace('IgnoreNew','Parallel')
$changedTrigger=$xml.Replace('<BootTrigger><Enabled>true</Enabled>','<BootTrigger><Enabled>false</Enabled>')
$expected=Hash-ObserverTask (Get-ObserverRecoveryXml $xml)
@{enabledSame=($expected -ceq (Hash-ObserverTask (Get-ObserverRecoveryXml $disabled)));
 settingDifferent=($expected -cne (Hash-ObserverTask (Get-ObserverRecoveryXml $changedSetting)));
 triggerDifferent=($expected -cne (Hash-ObserverTask (Get-ObserverRecoveryXml $changedTrigger)))}|ConvertTo-Json -Compress
'''.replace("__SOURCE__", str(SOURCE).replace("'", "''"))
        shell = Path(os.environ["WINDIR"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
        result = subprocess.run(
            [str(shell), "-NoProfile", "-NonInteractive", "-EncodedCommand",
             base64.b64encode(code.encode("utf-16le")).decode()],
            capture_output=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        report = json.loads(result.stdout.decode("utf-8-sig"))
        self.assertEqual(report, {"enabledSame": True, "settingDifferent": True, "triggerDifferent": True})


if __name__ == "__main__":
    unittest.main()
