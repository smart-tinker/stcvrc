[CmdletBinding()]
param([ValidateSet('Snapshot','GuardProbe','GuardRun','Isolate','Arm','Setup','Inspect','UpgradeUi','RollbackUi','Canary','CanaryAfter','CanaryLogon','Test','VerifyLogon','Restore')][string]$Action)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$env:PSModulePath=(Join-Path $PSHOME 'Modules')+';'+(Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules')
$root='C:\Users\FixtureUser\stcvrc-autostart-control'
$lab='C:\Users\FixtureUser\stcvrc-fullstack-lab'
$sid='S-1-5-21-1-2-3-1001'
if($env:COMPUTERNAME -cne 'LABHOST' -or $env:USERPROFILE -ine 'C:\Users\FixtureUser' -or [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne $sid){throw 'Wrong desktop identity'}
if([IO.File]::ReadAllText((Join-Path $root '.stcvrc-desktop-gate')) -cne 'STCVRC_DESKTOP_GATE_V1'){throw 'Control guard missing'}

function Assert-Tree([string]$Path){
    $p=[IO.Path]::GetFullPath($Path).TrimEnd('\')
    $parent=$p
    while($parent){
        if(Test-Path -LiteralPath $parent){if((Get-Item -LiteralPath $parent -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse ancestor'}}
        $parent=Split-Path -Parent $parent
    }
    if(Test-Path -LiteralPath $p -PathType Container){
        if(@(Get-ChildItem -LiteralPath $p -Recurse -Force | Where-Object {$_.Attributes -band [IO.FileAttributes]::ReparsePoint}).Count){throw 'Reparse tree'}
    }
}
function Fingerprint([string]$Path){
    if(-not(Test-Path -LiteralPath $Path)){return 'ABSENT'}
    Assert-Tree $Path
    $item=Get-Item -LiteralPath $Path -Force
    $items=if($item.PSIsContainer){@(Get-ChildItem -LiteralPath $Path -Recurse -Force | Sort-Object FullName)}else{@($item)}
    $rows=@($items | ForEach-Object {[ordered]@{name=$_.FullName.Substring($Path.Length);directory=[bool]$_.PSIsContainer;length=if($_.PSIsContainer){0}else{$_.Length};sha=if($_.PSIsContainer){''}else{(Get-FileHash -LiteralPath $_.FullName).Hash};modified=$_.LastWriteTimeUtc.ToString('o')}})
    $bytes=[Text.Encoding]::UTF8.GetBytes(($rows|ConvertTo-Json -Depth 4 -Compress))
    $hasher=[Security.Cryptography.SHA256]::Create()
    try{([BitConverter]::ToString($hasher.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$hasher.Dispose()}
}
function Read-Driver([string]$Step){
    $raw=& (Join-Path $lab 'driver.ps1') -ProviderRepair -Action $Step
    ($raw -join "`n")|ConvertFrom-Json
}
function Restore-Preserved {
    $planPath=Join-Path $root 'preserve-plan.json'
    if(-not(Test-Path -LiteralPath $planPath)){return @{pass=$true;paths=0}}
    $plan=[IO.File]::ReadAllText($planPath)|ConvertFrom-Json
    foreach($entry in $plan){
        if($entry.path -notin $script:allowedPaths -or $entry.backup -notmatch '^saved-[0-9]+$'){throw 'Unexpected preservation entry'}
        $saved=Join-Path $root $entry.backup
        Assert-Tree $entry.path
        Assert-Tree $saved
        if(Test-Path -LiteralPath $saved){
            if((Fingerprint $saved) -cne $entry.fingerprint){throw 'Backup content changed'}
            if(Test-Path -LiteralPath $entry.path){throw 'Restore destination not empty'}
            Move-Item -LiteralPath $saved -Destination $entry.path
        }
        if((Fingerprint $entry.path) -cne $entry.fingerprint){throw 'Preserved content mismatch'}
        if($entry.acl -and (Get-Acl -LiteralPath $entry.path).Sddl -cne $entry.acl){throw 'Preserved root ACL mismatch'}
    }
    @{pass=$true;paths=@($plan).Count}
}
$allowedPaths=@(
    'C:\Users\FixtureUser\AppData\Roaming\io.github.clash-verge-rev.clash-verge-rev',
    'C:\Users\FixtureUser\AppData\Local\io.github.clash-verge-rev.clash-verge-rev',
    (Join-Path ([Environment]::GetFolderPath('Desktop')) 'Clash Verge.lnk'),
    (Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'Clash Verge.lnk'),
    (Join-Path ([Environment]::GetFolderPath('StartMenu')) 'Programs\Clash Verge.lnk'),
    (Join-Path ([Environment]::GetFolderPath('CommonStartMenu')) 'Programs\Clash Verge.lnk'),
    'C:\ProgramData\clash-verge-service'
)
$runId=[IO.File]::ReadAllText((Join-Path $root 'run-id.txt'))
if($runId -notmatch '^[0-9]{8}-[0-9]{6}$'){throw 'Invalid run identity'}
$result=@{at=(Get-Date).ToString('o');runId=$runId;action=$Action;ok=$false}
try {
    Assert-Tree $root
    # Delete only the invocation definition, not its running worker.
    $bridge=Get-ScheduledTask -TaskName 'STCVRC-userVM-Desktop-Gate' -ErrorAction SilentlyContinue
    if($bridge){
        if(-not $bridge.Actions[0].Arguments.Contains((Join-Path $root 'desktop.ps1'))){throw 'Unknown invocation task'}
        Unregister-ScheduledTask -TaskName $bridge.TaskName -Confirm:$false
    }
    if($Action -eq 'Snapshot'){
        $value=Read-Driver Snapshot
        $cvr=$value.baseline.state.cvr
        if($cvr.installPresent -or $cvr.service -or $cvr.processes.Count -or $cvr.uninstallEntries.Count -or $cvr.runEntries.Count -or $cvr.tunAdapters.Count){throw 'Existing integration blocks lab'}
        $result.value=$value
    } elseif($Action -eq 'GuardProbe'){
        $name='STCVRC-userVM-Recovery-Probe'
        if(Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue){throw 'Existing recovery probe'}
        $a=New-ScheduledTaskAction -Execute (Join-Path $PSHOME 'powershell.exe') -Argument ('-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "'+(Join-Path $root 'desktop.ps1')+'" -Action GuardRun')
        $p=New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType S4U -RunLevel Highest
        $s=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 1)
        $null=Register-ScheduledTask -TaskName $name -Action $a -Principal $p -Settings $s
        try {
            Start-ScheduledTask -TaskName $name
            $path=Join-Path $root 'GuardRun.result.json'
            $until=(Get-Date).AddSeconds(40)
            while(-not(Test-Path -LiteralPath $path)){if((Get-Date) -gt $until){throw 'Batch recovery probe timed out'};Start-Sleep -Seconds 1}
            $child=[IO.File]::ReadAllText($path)|ConvertFrom-Json
            if(-not $child.ok -or $child.runId -cne $runId -or $child.action -cne 'GuardRun'){throw 'Invalid batch recovery result'}
            $result.value=$child.value
        } finally {
            Stop-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $name -Confirm:$false
        }
    } elseif($Action -eq 'GuardRun'){
        $session=[Diagnostics.Process]::GetCurrentProcess().SessionId
        $principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        $admin=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        $result.value=@{pass=($session -eq 0 -and $admin);session=$session;admin=$admin;identityMatched=$true}
    } elseif($Action -eq 'Isolate'){
        $planPath=Join-Path $root 'preserve-plan.json'
        if(Test-Path -LiteralPath $planPath){throw 'Preservation plan exists'}
        $plan=@();$i=0
        foreach($path in $allowedPaths){
            $plan+=@{path=$path;backup=('saved-'+$i);fingerprint=(Fingerprint $path);acl=if(Test-Path -LiteralPath $path){(Get-Acl -LiteralPath $path).Sddl}else{$null}}
            $i++
        }
        [IO.File]::WriteAllText($planPath,($plan|ConvertTo-Json -Depth 5))
        foreach($entry in $plan){
            if($entry.fingerprint -ne 'ABSENT'){
                $destination=Join-Path $root $entry.backup
                Assert-Tree $destination
                if((Resolve-Path -LiteralPath $entry.path).Path -ine $entry.path -or [IO.Path]::GetFullPath($destination) -cne $destination){throw 'Preservation path mismatch'}
                Move-Item -LiteralPath $entry.path -Destination $destination
                if((Fingerprint $destination) -cne $entry.fingerprint){throw 'Moved backup mismatch'}
                if((Get-Acl -LiteralPath $destination).Sddl -cne $entry.acl){throw 'Moved backup ACL mismatch'}
            }
        }
        [IO.File]::WriteAllText((Join-Path $root 'isolated.ok'),'STCVRC_ISOLATED_V1')
        $stateRoot='C:\ProgramData\clash-verge-service'
        if(Test-Path -LiteralPath $stateRoot){throw 'Original service state was not isolated'}
        Assert-Tree $stateRoot
        $null=New-Item -ItemType Directory -Path $stateRoot
        [IO.File]::WriteAllText((Join-Path $stateRoot '.stcvrc-desktop-state'),$runId)
        $result.value=@{pass=$true;paths=$plan.Count}
    } elseif($Action -eq 'Arm'){
        $raw=& (Join-Path $lab 'autostart.ps1') -Action Arm -GuardMinutes 30
        $result.value=($raw -join "`n")|ConvertFrom-Json
        $channel='Microsoft-Windows-TaskScheduler/Operational'
        $configuration=New-Object Diagnostics.Eventing.Reader.EventLogConfiguration($channel)
        try {
            $saved=@{enabled=$configuration.IsEnabled;maxBytes=$configuration.MaximumSizeInBytes;mode=[string]$configuration.LogMode}
            [IO.File]::WriteAllText((Join-Path $root 'task-channel.json'),($saved|ConvertTo-Json -Compress))
            $configuration.IsEnabled=$true
            $configuration.SaveChanges()
        } finally {$configuration.Dispose()}
    } elseif($Action -in @('Setup','Inspect','UpgradeUi','RollbackUi','Canary','CanaryAfter','CanaryLogon')){
        if($Action -eq 'Setup' -and -not(Test-Path -LiteralPath (Join-Path $root 'isolated.ok'))){throw 'Isolation not complete'}
        $driverAction=if($Action -in @('CanaryAfter','CanaryLogon')){'Canary'}else{$Action}
        $result.value=Read-Driver $driverAction
    } elseif($Action -in @('Test','VerifyLogon')){
        $raw=& (Join-Path $lab 'autostart.ps1') -Action $Action
        $result.value=($raw -join "`n")|ConvertFrom-Json
    } elseif($Action -eq 'Restore'){
        $observerIntent=Join-Path $root 'observer-production.run'
        if(Test-Path -LiteralPath $observerIntent){
            if([IO.File]::ReadAllText($observerIntent) -cne $runId){throw 'Unexpected observer acceptance owner'}
            $null=& (Join-Path $root 'observer-install.ps1') -Action RemoveTask -Production -ExpectedComputerName LABHOST -Label home -ServiceOwnerSid 'S-1-5-21-1-2-3-1001'
        }
        $packetCleanupFailed=$false
        if(Test-Path -LiteralPath (Join-Path $root 'pktmon-state.json')){
            try {
                $raw=& (Join-Path $root 'observer-payload\bin\python.exe') -I -B (Join-Path $root 'pktmon.py') --action stop --run-id $runId
                if($LASTEXITCODE -ne 0){throw 'Pktmon cleanup failed'}
                $result.packetCounterCleanup=($raw -join "`n")|ConvertFrom-Json
            } catch {$packetCleanupFailed=$true}
        }
        if(Test-Path -LiteralPath (Join-Path $root 'isolated.ok')){
            # Keep inventory functions loaded after the lab directory is removed.
            $driverText=[IO.File]::ReadAllText((Join-Path $lab 'driver.ps1'))
            $tokens=$null;$errors=$null
            $ast=[Management.Automation.Language.Parser]::ParseInput($driverText,[ref]$tokens,[ref]$errors)
            $function=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Inventory'},$true)
            . (Join-Path $root 'fullstack.ps1') -Mode Library -LabRoot $lab
            . ([ScriptBlock]::Create($function.Extent.Text))
            if(Test-Path -LiteralPath (Join-Path $lab 'autostart-owned.json')){
                $raw=& (Join-Path $lab 'autostart.ps1') -Action Cleanup
                $result.cleanup=($raw -join "`n")|ConvertFrom-Json
            }else{$result.cleanup=Read-Driver Cleanup}
            # The original remains in saved-6; only the newly marked lab state is removed.
            $stateRoot='C:\ProgramData\clash-verge-service'
            $plan=[IO.File]::ReadAllText((Join-Path $root 'preserve-plan.json'))|ConvertFrom-Json
            $stateEntry=@($plan|Where-Object path -eq $stateRoot)
            if($stateEntry.Count -ne 1 -or $stateEntry[0].backup -cne 'saved-6'){throw 'Service state was not preserved'}
            $savedState=Join-Path $root $stateEntry[0].backup
            if((Fingerprint $savedState) -cne $stateEntry[0].fingerprint){throw 'Original service state backup differs'}
            if($stateEntry[0].acl -and (Get-Acl -LiteralPath $savedState).Sddl -cne $stateEntry[0].acl){throw 'Original service state ACL differs'}
            if(Get-Service -Name 'clash_verge_service' -ErrorAction SilentlyContinue){throw 'Service still installed'}
            Assert-Tree $stateRoot
            if(Test-Path -LiteralPath $stateRoot){
                if((Resolve-Path -LiteralPath $stateRoot).Path -cne 'C:\ProgramData\clash-verge-service'){throw 'State root mismatch'}
                if([IO.File]::ReadAllText((Join-Path $stateRoot '.stcvrc-desktop-state')) -cne $runId){throw 'Lab state marker mismatch'}
                Remove-Item -LiteralPath $stateRoot -Recurse -Force
            }
            $result.preserved=Restore-Preserved
            $result.inventory=Inventory -EvidencePath (Join-Path $root 'inventory-after.json')
        } else {
            $result.preserved=Restore-Preserved
            $guard=Get-ScheduledTask -TaskName 'STCVRC-userVM-Autostart-Cleanup' -ErrorAction SilentlyContinue
            if($guard){
                if(-not $guard.Actions[0].Arguments.Contains((Join-Path $root 'desktop.ps1'))){throw 'Unknown restore guard'}
                Unregister-ScheduledTask -TaskName $guard.TaskName -Confirm:$false
            }
        }
        $channelState=Join-Path $root 'task-channel.json'
        if(Test-Path -LiteralPath $channelState){
            $saved=[IO.File]::ReadAllText($channelState)|ConvertFrom-Json
            $configuration=New-Object Diagnostics.Eventing.Reader.EventLogConfiguration('Microsoft-Windows-TaskScheduler/Operational')
            try {
                if($configuration.MaximumSizeInBytes -ne $saved.maxBytes -or [string]$configuration.LogMode -cne $saved.mode){throw 'Unexpected channel configuration drift'}
                $configuration.IsEnabled=[bool]$saved.enabled
                $configuration.SaveChanges()
                $result.channelRestored=($configuration.IsEnabled -eq $saved.enabled)
            } finally {$configuration.Dispose()}
        }
        if($packetCleanupFailed){throw 'Pktmon cleanup requires inspection; core/original restoration already attempted'}
        $result.value=@{pass=$true}
    }
    $result.ok=$true
} catch {
    $result.error=@{type=$_.Exception.GetType().FullName;script=[IO.Path]::GetFileName($_.InvocationInfo.ScriptName);line=$_.InvocationInfo.ScriptLineNumber;errorId=$_.FullyQualifiedErrorId}
}
$output=Join-Path $root ($Action+'.result.json')
[IO.File]::WriteAllText(($output+'.tmp'),($result|ConvertTo-Json -Depth 18 -Compress))
Move-Item -LiteralPath ($output+'.tmp') -Destination $output -Force
