"""Real staging and AST transaction adapters; no live tasks/services/network."""
import base64
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest

HERE = Path(__file__).parent
PREPARE = runpy.run_path(str(HERE / 'prepare-stcvrc-safe-rollout.py'))
APP = r'C:\Users\Fixture\AppData\Roaming\io.github.clash-verge-rev.clash-verge-rev'
SID = 'S-1-5-21-1-2-3-1001'
ROOT = r'C:\ProgramData\STCVRC-observer'


def package(root, version):
    (root / 'bin').mkdir(parents=True)
    files = {'bin/python.exe': b'fixture-python', 'bin/stcvrc_observer.py': version}
    for name, data in files.items():
        (root / name).write_bytes(data)
    manifest = {'schemaVersion': 1, 'files': {k: hashlib.sha256(v).hexdigest() for k, v in files.items()}}
    (root / 'manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
    return files


def task_xml(arguments):
    return ('<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
            '<Principals><Principal><UserId>S-1-5-18</UserId><LogonType>ServiceAccount</LogonType>'
            '<RunLevel>HighestAvailable</RunLevel></Principal></Principals>'
            '<Triggers><BootTrigger/><TimeTrigger><Repetition><Interval>PT1M</Interval></Repetition>'
            '<StartBoundary>2026-10-15T00:00:00</StartBoundary></TimeTrigger></Triggers>'
            '<Settings><Enabled>true</Enabled><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>'
            '<ExecutionTimeLimit>PT50S</ExecutionTimeLimit><StartWhenAvailable>true</StartWhenAvailable>'
            '<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>'
            '<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><WakeToRun>false</WakeToRun></Settings>'
            '<Actions><Exec><Command>' + ROOT + r'\bin\python.exe</Command><Arguments>' +
            arguments + '</Arguments><WorkingDirectory>' + ROOT + r'\bin</WorkingDirectory></Exec></Actions></Task>')


class ObserverTransactionTest(unittest.TestCase):
    def run_ps(self, code):
        code = ("$env:PSModulePath=(Join-Path $PSHOME 'Modules')+';'+(Join-Path $env:ProgramFiles 'WindowsPowerShell/Modules');$ProgressPreference='SilentlyContinue';\n" + code)
        with tempfile.TemporaryDirectory() as folder:
            code = code.replace('__SOURCE__', str(HERE / 'stcvrc-safe-rollout.ps1')).replace('__TEMP__', folder)
            shell = Path(os.environ['WINDIR']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
            return subprocess.run([str(shell), '-NoProfile', '-NonInteractive', '-EncodedCommand',
                                   base64.b64encode(code.encode('utf-16le')).decode()], capture_output=True, timeout=30)

    def stage(self, bundle, before=None, xml=None, absent=False):
        function = PREPARE.get('observer_transaction_inputs')
        self.assertIsNotNone(function, 'Missing integrated observer staging')
        return function(bundle, before, xml, absent, 'home', APP, SID)

    def test_existing_observer_payload_and_task_are_both_pinned(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            old, new = root / 'old', root / 'new'
            before = package(old, b'old-observer')
            after = package(new, b'new-observer')
            (old / '.stcvrc-observer').write_text('STCVRC_OBSERVER_V1')
            arguments = '-I -B "' + ROOT + r'\bin\stcvrc_observer.py" --app-dir "' + APP + '" --data-dir "' + ROOT + r'\data" --label home --active'
            xml = root / 'task.xml'
            xml.write_text(task_xml(arguments), encoding='utf-8')
            plan, staged = self.stage(new, old, xml)
            self.assertTrue(plan['oldPresent'])
            self.assertEqual(plan['oldArguments'], arguments)
            self.assertEqual(plan['oldFiles'], {k: hashlib.sha256(v).hexdigest() for k, v in before.items()})
            self.assertEqual(plan['newFiles'], {k: hashlib.sha256(v).hexdigest() for k, v in after.items()})
            self.assertEqual(staged['observer.old/bin/stcvrc_observer.py'], b'old-observer')
            self.assertEqual(staged['observer.new/bin/stcvrc_observer.py'], b'new-observer')
            self.assertIn('--service-owner-sid ' + SID, plan['newArguments'])
            self.assertIn('observer-task.old.xml', staged)

    def test_disabled_or_unbounded_observer_task_baseline_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            old, new = root / 'old', root / 'new'
            package(old, b'old'); package(new, b'new')
            (old / '.stcvrc-observer').write_text('STCVRC_OBSERVER_V1')
            arguments = '-I -B "' + ROOT + r'\bin\stcvrc_observer.py" --app-dir "' + APP + '" --data-dir "' + ROOT + r'\data" --label home --active'
            xml = root / 'task.xml'
            for old_text, new_text in (('<Enabled>true</Enabled>', '<Enabled>false</Enabled>'),
                                       ('PT50S', 'PT0S'), ('PT1M', 'PT1S'),
                                       ('<WakeToRun>false</WakeToRun>', '<WakeToRun>true</WakeToRun>')):
                with self.subTest(new_text=new_text):
                    xml.write_text(task_xml(arguments).replace(old_text, new_text), encoding='utf-8')
                    with self.assertRaises(ValueError):
                        self.stage(new, old, xml)

    def test_absence_is_explicit_and_payload_drift_never_stages(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            bundle = root / 'bundle'; package(bundle, b'new')
            with self.assertRaises(ValueError):
                self.stage(bundle)
            plan, staged = self.stage(bundle, absent=True)
            self.assertFalse(plan['oldPresent'])
            self.assertEqual(plan['oldFiles'], {})
            self.assertNotIn('observer-task.old.xml', staged)
            (bundle / 'bin/python.exe').write_bytes(b'corrupt')
            with self.assertRaises(ValueError):
                self.stage(bundle, absent=True)

    def test_foreign_payload_or_task_configuration_never_stages(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            old, new = root / 'old', root / 'new'
            package(old, b'old'); package(new, b'new')
            (old / '.stcvrc-observer').write_text('STCVRC_OBSERVER_V1')
            arguments = '-I -B "' + ROOT + r'\bin\stcvrc_observer.py" --app-dir "' + APP + '" --data-dir "' + ROOT + r'\data" --label home --active'
            xml = root / 'task.xml'
            xml.write_text(task_xml(arguments).replace('S-1-5-18', 'S-1-1-0'), encoding='utf-8')
            with self.assertRaises(ValueError): self.stage(new, old, xml)
            xml.write_text(task_xml(arguments), encoding='utf-8')
            (old / 'bin/foreign.dll').write_bytes(b'foreign')
            with self.assertRaises(ValueError): self.stage(new, old, xml)

    @unittest.skipUnless(os.name == 'nt', 'PowerShell absent baseline adapter')
    def test_absent_baseline_removes_candidate_task_and_payload_not_new_history(self):
        code = r'''
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('__SOURCE__',[ref]$tokens,[ref]$errors)
foreach($name in @('No-Reparse','Restore-Observer')){
 $f=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
 . ([ScriptBlock]::Create($f.Extent.Text))
}
$Root='__TEMP__';$observer=Join-Path $Root 'target';New-Item -ItemType Directory -Path (Join-Path $observer 'bin'),(Join-Path $observer 'data') -Force|Out-Null
[IO.File]::WriteAllText((Join-Path $observer '.stcvrc-observer'),'STCVRC_OBSERVER_V1')
[IO.File]::WriteAllText((Join-Path $observer 'data\history.jsonl'),'retained evidence')
[IO.File]::WriteAllText((Join-Path $observer 'manifest.json'),'candidate')
[IO.File]::WriteAllText((Join-Path $observer 'bin\python.exe'),'candidate')
$Plan=@{observer=@{root=$observer;task='STCVRC-Observer';oldPresent=$false;newFiles=([pscustomobject]@{'bin/python.exe'='fixture'})}}
$script:task=$true
function Assert-ObserverBackup {}
function Stop-Observer {}
function Get-ScheduledTask($TaskName,$ErrorAction){if($script:task){@{Name='STCVRC-Observer'}}}
function Unregister-ScheduledTask($TaskName,[switch]$Confirm){$script:task=$false}
Restore-Observer
if($script:task -or (Test-Path -LiteralPath (Join-Path $observer 'bin\python.exe')) -or (Test-Path -LiteralPath (Join-Path $observer 'manifest.json'))){throw 'Candidate operational footprint remains'}
if([IO.File]::ReadAllText((Join-Path $observer 'data\history.jsonl')) -cne 'retained evidence'){throw 'History lost'}
'''
        result = self.run_ps(code)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))

    @unittest.skipUnless(os.name == 'nt', 'PowerShell schedule/ACL validation adapter')
    def test_live_schedule_and_protected_root_acl_are_read_back(self):
        code = r'''
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('__SOURCE__',[ref]$tokens,[ref]$errors)
foreach($name in @('Assert-ObserverSchedule','Assert-ObserverAcl')){
 $f=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
 if(-not $f){throw ('Missing validation function: '+$name)}
 . ([ScriptBlock]::Create($f.Extent.Text))
}
$xml=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__XML__'))
Assert-ObserverSchedule $xml
foreach($bad in @($xml.Replace('PT50S','PT0S'),$xml.Replace('PT1M','PT1S'),$xml.Replace('<Enabled>true</Enabled>','<Enabled>false</Enabled>'),$xml.Replace('<WakeToRun>false</WakeToRun>','<WakeToRun>true</WakeToRun>'))){
 $rejected=$false;try{Assert-ObserverSchedule $bad}catch{$rejected=$true};if(-not $rejected){throw 'Unbounded live schedule accepted'}
}
function Get-Acl($LiteralPath){
 $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false)
 $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-18'))
 foreach($sid in @('S-1-5-18','S-1-5-32-544')){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
 if($script:foreign -or ($script:childUnsafe -and $LiteralPath -like '*python.exe')){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-1-0'),'Modify','ContainerInherit,ObjectInherit','None','Allow'))}
 return $acl
}
function No-Reparse($Path){}
function Get-ChildItem($LiteralPath,[switch]$Recurse,[switch]$Force){[pscustomobject]@{FullName='fixture\bin\python.exe'}}
$Plan=@{observer=@{root='fixture'}}
$script:foreign=$false;Assert-ObserverAcl
$script:foreign=$true;$rejected=$false;try{Assert-ObserverAcl}catch{$rejected=$true};if(-not $rejected){throw 'World-writable SYSTEM payload accepted'}
$script:foreign=$false;$script:childUnsafe=$true;$rejected=$false;try{Assert-ObserverAcl}catch{$rejected=$true};if(-not $rejected){throw 'Safe root hid world-writable child payload'}
'''.replace('__XML__', base64.b64encode(task_xml('fixture').encode()).decode())
        result = self.run_ps(code)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))

    @unittest.skipUnless(os.name == 'nt', 'PowerShell AST transaction adapter')
    def test_partial_observer_update_restores_payload_task_but_not_history(self):
        code = r'''
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('__SOURCE__',[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Transaction parse failure'}
foreach($name in @('Hash','Hash-ObserverTask','Read-Json','Write-Json','No-Reparse','Assert-ObserverFiles','Get-ObserverTask','Assert-ObserverBackup','Restore-Observer','Stop-Observer','Copy-ObserverPayload')){
 $f=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
 if(-not $f){throw ('Missing observer transaction function: '+$name)}
 . ([ScriptBlock]::Create($f.Extent.Text))
}
$Root='__TEMP__';$observer=Join-Path $Root 'target'
New-Item -ItemType Directory -Path (Join-Path $observer 'bin') -Force|Out-Null
New-Item -ItemType Directory -Path (Join-Path $observer 'data') -Force|Out-Null
[IO.File]::WriteAllText((Join-Path $observer '.stcvrc-observer'),'STCVRC_OBSERVER_V1')
[IO.File]::WriteAllText((Join-Path $observer 'data\history.jsonl'),'history must remain')
$old=Join-Path $Root 'observer.old';$new=Join-Path $Root 'observer.new'
foreach($folder in @($old,$new)){New-Item -ItemType Directory -Path (Join-Path $folder 'bin') -Force|Out-Null}
[IO.File]::WriteAllText((Join-Path $old 'bin\python.exe'),'old-python')
[IO.File]::WriteAllText((Join-Path $old 'bin\stcvrc_observer.py'),'old-observer')
[IO.File]::WriteAllText((Join-Path $new 'bin\python.exe'),'new-python')
[IO.File]::WriteAllText((Join-Path $new 'bin\stcvrc_observer.py'),'new-observer')
[IO.File]::WriteAllText((Join-Path $new 'bin\new-only.dll'),'new-extra')
$oldFiles=@{'bin/python.exe'=(Hash (Join-Path $old 'bin\python.exe'));'bin/stcvrc_observer.py'=(Hash (Join-Path $old 'bin\stcvrc_observer.py'))}
$newFiles=@{'bin/python.exe'=(Hash (Join-Path $new 'bin\python.exe'));'bin/stcvrc_observer.py'=(Hash (Join-Path $new 'bin\stcvrc_observer.py'));'bin/new-only.dll'=(Hash (Join-Path $new 'bin\new-only.dll'))}
foreach($pair in @(@($old,$oldFiles),@($new,$newFiles))){Write-Json (Join-Path $pair[0] 'manifest.json') @{schemaVersion=1;files=$pair[1]}}
$xml=Join-Path $Root 'observer-task.old.xml';[IO.File]::WriteAllText($xml,'old-xml')
$o=@{root=$observer;task='STCVRC-Observer';oldPresent=$true;oldFiles=($oldFiles|ConvertTo-Json|ConvertFrom-Json);newFiles=($newFiles|ConvertTo-Json|ConvertFrom-Json);oldManifestHash=(Hash (Join-Path $old 'manifest.json'));newManifestHash=(Hash (Join-Path $new 'manifest.json'));oldTaskHash=(Hash $xml);oldArguments='old-args';newArguments='new-args'}
$Plan=@{observer=$o};$script:taskArguments='new-args';$script:started=$false;$script:disabled=$false
function Get-ScheduledTask($TaskName,$ErrorAction){@{TaskPath='\';Actions=@(@{Execute=(Join-Path $observer 'bin\python.exe');Arguments=$script:taskArguments;WorkingDirectory=(Join-Path $observer 'bin')});Principal=@{UserId='S-1-5-18';LogonType='ServiceAccount';RunLevel='Highest'}}}
function Disable-ScheduledTask($TaskName){$script:disabled=$true}
function Stop-ScheduledTask($TaskName){}
function Get-CimInstance($Class){@()}
function Register-ScheduledTask($TaskName,$Xml,[switch]$Force){if($Xml -cne 'old-xml'){throw 'Wrong XML restored'};$script:taskArguments='old-args'}
function Export-ScheduledTask($TaskName){'old-xml'}
function Assert-ObserverAcl {$script:aclChecked=$true}
function Start-ScheduledTask($TaskName){if(-not $script:aclChecked){throw 'Old SYSTEM payload started before ACL readback'};$script:started=$true}
# A partial replacement may contain old, new, or missing tracked files.
[IO.File]::Copy((Join-Path $new 'bin\python.exe'),(Join-Path $observer 'bin\python.exe'))
[IO.File]::Copy((Join-Path $new 'bin\new-only.dll'),(Join-Path $observer 'bin\new-only.dll'))
[IO.File]::Copy((Join-Path $new 'manifest.json'),(Join-Path $observer 'manifest.json'))
Restore-Observer
if(-not $script:started -or -not $script:disabled -or $script:taskArguments -cne 'old-args'){throw 'Observer task not restored'}
Assert-ObserverFiles $observer $o.oldFiles $o.oldManifestHash
if([IO.File]::ReadAllText((Join-Path $observer 'data\history.jsonl')) -cne 'history must remain'){throw 'History was rolled back'}
if(Test-Path -LiteralPath (Join-Path $observer 'bin\new-only.dll')){throw 'Candidate-only file survives'}
@{pass=$true;historyPreserved=$true;oldTaskRestored=$true}|ConvertTo-Json -Compress
'''
        result = self.run_ps(code)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))

    def common_rollback_script(self):
        return r'''
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('__SOURCE__',[ref]$tokens,[ref]$errors)
foreach($name in @('Hash','Restore-Old')){
 $f=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
 . ([ScriptBlock]::Create($f.Extent.Text))
}
$Root='__TEMP__';$Core=Join-Path $Root 'core.exe';$ExecutingCore=$Core;$ServiceName='fixture'
[IO.File]::WriteAllText($Core,'candidate-core');[IO.File]::WriteAllText((Join-Path $Root 'core.old'),'old-core')
[IO.File]::WriteAllText((Join-Path $Root 'mutation.started'),'fixture')
$Plan=@{policy='ui-update';entries=@(@{id='core';target=$Core;before=(Hash (Join-Path $Root 'core.old'))});observer=@{root='fixture'}}
$Ui='C:\Windows\System32\cmd.exe';$CachePath=Join-Path $Root 'absent-cache'
$script:events=@()
function State($Phase){$script:events+=$Phase}
function Read-Json($Path){@{cachePresent=$false}}
function Assert-ObserverBackup {$script:events+='backup-verified'}
function Stop-Observer {$script:events+='observer-stopped'}
function Preserve-History($Label){}
function Stop-Runtime {$script:events+='core-stopped'}
function Install-UiGeneration($New){$script:events+='old-ui-installed'}
function Register-ApprovedCore($Hash){}
function Register-UiService($Hash){}
function Start-Service($Name){}
function Start-OwnerUi {}
function Wait-Core($Version){}
function Check-OwnerRuntime {}
function Restore-Selectors {}
function Check-Selectors {}
function Check-Http {@()}
function Restore-Observer {$script:events+='observer-restored'}
function Write-Json($Path,$Value){}
function Remove-GuardTask {$script:events+='guard-removed'}
Restore-Old
$joinedEvents=$script:events -join ','
foreach($event in @('backup-verified','observer-stopped','old-ui-installed','observer-restored','rolled-back','guard-removed')){if($script:events -cnotcontains $event){throw ('Missing: '+$event+' in '+$joinedEvents)}}
if([Array]::IndexOf($script:events,'backup-verified') -gt [Array]::IndexOf($script:events,'core-stopped') -or [Array]::IndexOf($script:events,'observer-restored') -gt [Array]::IndexOf($script:events,'rolled-back')){throw ('Unsafe rollback order: '+$joinedEvents)}
if([IO.File]::ReadAllText($Core) -cne 'old-core'){throw 'Core not restored'}
'''

    @unittest.skipUnless(os.name == 'nt', 'PowerShell common rollback adapter')
    def test_common_ui_core_rollback_cannot_finish_before_observer_restore(self):
        result = self.run_ps(self.common_rollback_script())
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))

    @unittest.skipUnless(os.name == 'nt', 'PowerShell independent recovery adapter')
    def test_observer_backup_or_task_failure_cannot_block_core_recovery(self):
        for failure in ('Assert-ObserverBackup', 'Stop-Observer', 'Restore-Observer'):
            with self.subTest(failure=failure):
                code = self.common_rollback_script().split('Restore-Old\n$joinedEvents=')[0]
                code += '\nfunction ' + failure + " {throw 'fixture observer failure'}\n"
                if failure != 'Restore-Observer':
                    code += "function Restore-Observer {throw 'fixture observer failure'}\n"
                code += r'''
$rejected=$false;try{Restore-Old}catch{$rejected=$true}
if(-not $rejected){throw 'Incomplete observer recovery reported success'}
if([IO.File]::ReadAllText($Core) -cne 'old-core' -or $script:events -cnotcontains 'old-ui-installed'){throw 'Observer failure blocked core/UI network recovery'}
if($script:events -ccontains 'rolled-back' -or $script:events -ccontains 'guard-removed'){throw 'Incomplete observer recovery removed guard'}
'''
                result = self.run_ps(code)
                self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))

    @unittest.skipUnless(os.name == 'nt', 'PowerShell actual collector health adapter')
    def test_observer_health_needs_completed_task_and_fresh_matching_row(self):
        code = r'''
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('__SOURCE__',[ref]$tokens,[ref]$errors)
foreach($name in @('Hash','No-Reparse','Wait-ObserverHealth')){
 $f=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
 if(-not $f){throw ('Missing health function: '+$name)}
 . ([ScriptBlock]::Create($f.Extent.Text))
}
$Root='__TEMP__';$owner=Join-Path $Root 'owner';$observer=Join-Path $Root 'observer'
New-Item -ItemType Directory -Path (Join-Path $observer 'data\timeline'),(Join-Path $owner 'runtime') -Force|Out-Null
[IO.File]::WriteAllText((Join-Path $Root 'mutation.started'),'fixture')
[IO.File]::WriteAllText((Join-Path $owner 'runtime\config.yaml'),'actual runtime')
$Plan=@{newVersion='new-version';serviceOwnerDirectory=$owner;entries=@(@{id='core';after='pinned-core'});observer=@{root=$observer;task='STCVRC-Observer';label='home';newFiles=([pscustomobject]@{'bin/stcvrc_observer.py'='pinned-observer'})}}
$row=@{schemaVersion=1;checkpoint='new';observedUtc=[DateTime]::UtcNow.ToString('o');label='home';sampleId=('a'*64);observerSha256='pinned-observer';runtimeLayout='service-owner';runtimeHash=(Hash (Join-Path $owner 'runtime\config.yaml'));coreVersion='new-version';components=@{host='ok';controller='ok';version='ok';binaries='ok'};binaries=@{core=@{sha256='pinned-core'}};host=@{service=@{status='running';pid=11};processes=@(@{role='verge-mihomo.exe';parent=11;session=0})}}
$timeline=Join-Path $observer 'data\timeline\2026-10-15.jsonl'
function Save-Row {[IO.File]::WriteAllText($timeline,($row|ConvertTo-Json -Depth 10 -Compress)+"`n")}
$script:result=0;$script:state='Ready'
function Get-ScheduledTask($TaskName){@{State=$script:state}}
function Get-ScheduledTaskInfo($TaskName){@{LastTaskResult=$script:result;LastRunTime=[DateTime]::UtcNow}}
Save-Row
$healthy=Wait-ObserverHealth 0
if(-not $healthy.pass -or $healthy.sampleId -cne ('a'*64)){throw 'Fresh completed collector not accepted'}
foreach($case in @('exit1','stale','wrong-core','wrong-runtime','running','bad-checkpoint')){
 $script:result=0;$script:state='Ready';$row.checkpoint='ok';$row.observedUtc=[DateTime]::UtcNow.ToString('o');$row.binaries.core.sha256='pinned-core';$row.runtimeHash=Hash (Join-Path $owner 'runtime\config.yaml')
 switch($case){'exit1'{$script:result=1};'stale'{$row.observedUtc=[DateTime]::UtcNow.AddMinutes(-5).ToString('o')};'wrong-core'{$row.binaries.core.sha256='wrong'};'wrong-runtime'{$row.runtimeHash='wrong'};'running'{$script:state='Running'};'bad-checkpoint'{$row.checkpoint='invalid'}}
 Save-Row
 $rejected=$false;try{$null=Wait-ObserverHealth 0}catch{$rejected=$true};if(-not $rejected){throw ('Unhealthy collector accepted: '+$case)}
}
'''
        result = self.run_ps(code)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))

    @unittest.skipUnless(os.name == 'nt', 'PowerShell fresh observer ownership adapter')
    def test_observer_appearance_during_ui_upgrade_is_rejected_before_writes(self):
        code = r'''
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('__SOURCE__',[ref]$tokens,[ref]$errors)
foreach($name in @('No-Reparse','Assert-ObserverBaseline','Apply-Observer')){
 $f=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
 . ([ScriptBlock]::Create($f.Extent.Text))
}
$Root='__TEMP__';$observer=Join-Path $Root 'observer'
$Plan=@{observer=@{root=$observer;task='STCVRC-Observer';oldPresent=$false}}
function Assert-ObserverBackup {}
function Get-ScheduledTask($TaskName,$ErrorAction){if($script:taskPresent){@{State='Ready'}}}
function Copy-ObserverPayload($Candidate){$script:writes=$true;throw 'Payload write attempted'}
function New-Item($ItemType,$Path){$script:writes=$true;throw 'Root mutation attempted'}
foreach($case in @('root-appeared','task-appeared')){
 if($case -ceq 'root-appeared'){[IO.Directory]::CreateDirectory($observer)|Out-Null;$script:taskPresent=$false}else{[IO.Directory]::Delete($observer);$script:taskPresent=$true}
 $script:writes=$false;$rejected=$false;try{Apply-Observer}catch{$rejected=$true}
 if(-not $rejected -or $script:writes){throw ('Fresh observer appearance overwrote ownership: '+$case)}
}
'''
        result = self.run_ps(code)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))


if __name__ == '__main__':
    unittest.main()
