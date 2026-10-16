[CmdletBinding()]
param([ValidateSet('Arm','Test','VerifyLogon','Cleanup')][string]$Action,[ValidateRange(10,30)][int]$GuardMinutes=10)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$env:PSModulePath=(Join-Path $PSHOME 'Modules')+';'+(Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules')
$lab=Join-Path $env:USERPROFILE 'stcvrc-fullstack-lab'
if($env:COMPUTERNAME -cne 'LABHOST' -or $env:USERPROFILE -notin @('C:\Users\FixtureService','C:\Users\FixtureUser')){throw 'Wrong lab identity'}
. (Join-Path $lab 'fullstack.ps1') -Mode Library -LabRoot $lab
Assert-GuardedLab
$cleanupTask='STCVRC-userVM-Autostart-Cleanup'
$marker=Join-Path $lab 'autostart-owned.json'
$script=Join-Path $lab 'autostart.ps1'
$user=[Security.Principal.WindowsIdentity]::GetCurrent().Name
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$desktopGuard=Join-Path $env:USERPROFILE 'stcvrc-autostart-control\desktop.ps1'

if($Action -eq 'Arm'){
    foreach($name in @('Clash Verge','Clash Verge (Admin)',$cleanupTask)){
        if(Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue){throw 'Existing task blocks disposable gate'}
    }
    [IO.File]::WriteAllText($marker,(@{sid=$sid;ui=$UiPath}|ConvertTo-Json -Compress))
    $arguments='-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "'+$script+'" -Action Cleanup'
    if($env:USERPROFILE -ieq 'C:\Users\FixtureUser'){
        if(-not(Test-Path -LiteralPath $desktopGuard)){throw 'Desktop restore guard missing'}
        $arguments='-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "'+$desktopGuard+'" -Action Restore'
    }
    $taskAction=New-ScheduledTaskAction -Execute (Join-Path $PSHOME 'powershell.exe') -Argument $arguments
    $trigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes($GuardMinutes)
    $principal=New-ScheduledTaskPrincipal -UserId $user -LogonType S4U -RunLevel Highest
    $settings=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 4)
    Register-ScheduledTask -TaskName $cleanupTask -Action $taskAction -Trigger $trigger -Principal $principal -Settings $settings | Out-Null
    @{armed=$true;deadline=$trigger.StartBoundary}|ConvertTo-Json -Compress
    exit 0
}

$owned=[IO.File]::ReadAllText($marker)|ConvertFrom-Json
if($owned.sid -cne $sid -or $owned.ui -ine $UiPath){throw 'Wrong task ownership marker'}
if($Action -in @('Test','VerifyLogon')){
  if($Action -eq 'Test'){
    if(Get-ScheduledTask -TaskName 'Clash Verge' -ErrorAction SilentlyContinue){throw 'Task already exists'}
    # Same user/logon/action/settings contract as stock v2.5.2 schtasks.rs.
    $taskAction=New-ScheduledTaskAction -Execute $UiPath
    $trigger=New-ScheduledTaskTrigger -AtLogOn -User $user
    $principal=New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
    $settings=New-ScheduledTaskSettingsSet -MultipleInstances Parallel -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -DisallowHardTerminate -ExecutionTimeLimit ([TimeSpan]::Zero) -Priority 3
    Register-ScheduledTask -TaskName 'Clash Verge' -Action $taskAction -Trigger $trigger -Principal $principal -Settings $settings | Out-Null
    $null=Stop-ExactProcesses -Names @('clash-verge.exe') -AllowedPaths @($UiPath)
    Start-Sleep -Seconds 2
    Start-ScheduledTask -TaskName 'Clash Verge'
  }
    # VerifyLogon only reads the runtime; it must not repair or launch it.
    $runtime=Wait-CvrRuntime -TimeoutSeconds 70
    $ControllerHeaders=@{Authorization=('Bearer '+(Get-ControllerSecret))}
    $config=Invoke-Controller -Path '/configs'
    $service=Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
    $core=Get-CimInstance Win32_Process -Filter "Name='verge-mihomo.exe'"
    $task=Get-ScheduledTask -TaskName 'Clash Verge'
    $taskInfo=Get-ScheduledTaskInfo -TaskName 'Clash Verge'
    $selectors=[ordered]@{}
    foreach($p in (Invoke-Controller -Path '/proxies').proxies.PSObject.Properties){
        if($p.Value.type -eq 'Selector' -and $p.Name -ne 'GLOBAL'){$selectors[$p.Name]=$p.Value.now}
    }
    $coreOwned=($service.State -eq 'Running' -and $service.StartName -eq 'LocalSystem' -and $core.SessionId -eq 0 -and $core.ParentProcessId -eq $service.ProcessId)
    $uiOwned=($runtime.ui.sessionId -gt 0 -and $runtime.ui.ownerSid -eq $sid)
    $pass=($coreOwned -and $uiOwned -and -not $config.tun.enable -and $task.Principal.RunLevel -eq 'Limited' -and $task.Principal.LogonType -eq 'Interactive')
    $logonProof=$null
    if($Action -eq 'VerifyLogon'){
        $boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime
        $events=@(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TaskScheduler/Operational';StartTime=$boot;Id=110,119} -ErrorAction SilentlyContinue | Where-Object {
            $xml=[xml]$_.ToXml()
            @($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TaskName' -and $_.'#text' -ceq '\Clash Verge' }).Count -eq 1
        } | ForEach-Object {@{id=$_.Id;record=$_.RecordId;utc=$_.TimeCreated.ToUniversalTime().ToString('o')}})
        $logonProof=@{events=$events;logonTriggered=(@($events | Where-Object id -eq 119).Count -gt 0);manualTriggered=(@($events | Where-Object id -eq 110).Count -gt 0);ranAfterBoot=($taskInfo.LastRunTime -gt $boot)}
        $pass=$pass -and $logonProof.logonTriggered -and -not $logonProof.manualTriggered -and $logonProof.ranAfterBoot -and $task.Triggers[0].CimClass.CimClassName -eq 'MSFT_TaskLogonTrigger'
    }
    @{at=(Get-Date).ToString('o');pass=$pass;ui=$runtime.ui;coreHash=$runtime.executingCoreHash;coreOwned=$coreOwned;uiOwned=$uiOwned;tunDisabled=(-not $config.tun.enable);selectors=$selectors;task=@{name=$task.TaskName;principal=$task.Principal.UserId;runLevel=[string]$task.Principal.RunLevel;logonType=[string]$task.Principal.LogonType;trigger=$task.Triggers[0].CimClass.CimClassName;action=$task.Actions[0].Execute;lastRun=$taskInfo.LastRunTime.ToString('o');lastResult=$taskInfo.LastTaskResult};logonProof=$logonProof;rebootTested=($Action -eq 'VerifyLogon')}|ConvertTo-Json -Depth 6 -Compress
    exit 0
}

if($Action -eq 'Cleanup'){
    $task=Get-ScheduledTask -TaskName 'Clash Verge' -ErrorAction SilentlyContinue
    if($task){
        if($task.Actions.Count -ne 1 -or $task.Actions[0].Execute -ine $UiPath){throw 'Unknown stock autostart action'}
        $taskSid=if($task.Principal.UserId -match '^S-1-'){[string]$task.Principal.UserId}else{([Security.Principal.NTAccount]::new($task.Principal.UserId)).Translate([Security.Principal.SecurityIdentifier]).Value}
        if($taskSid -cne $sid){throw 'Unknown stock autostart user'}
        Unregister-ScheduledTask -TaskName 'Clash Verge' -Confirm:$false
    }
    $guard=Get-ScheduledTask -TaskName $cleanupTask -ErrorAction SilentlyContinue
    if($guard){
        if(-not $guard.Actions[0].Arguments.Contains($script) -and -not ($env:USERPROFILE -ieq 'C:\Users\FixtureUser' -and $guard.Actions[0].Arguments.Contains($desktopGuard))){throw 'Unknown cleanup task'}
        Unregister-ScheduledTask -TaskName $cleanupTask -Confirm:$false
    }
    & (Join-Path $lab 'driver.ps1') -Action Cleanup
}
