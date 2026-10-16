param(
    [ValidateSet('Install','Status','RemoveTask')][string]$Action,
    [string]$Bundle,
    [string]$AppDirectory,
    [string]$ManifestSha256,
    [string]$ServiceOwnerSid,
    [switch]$Production,
    [string]$ExpectedComputerName,
    [ValidateSet('home','work','lab')][string]$Label='lab'
)
$ErrorActionPreference='Stop'
$env:PSModulePath=(Join-Path $PSHOME 'Modules')+';'+(Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules')
function Resolve-ObserverScope([bool]$Production,[string]$ExpectedComputerName,[string]$Label,[string]$ServiceOwnerSid,[string]$HostName){
    if($Production){
        if(-not $ExpectedComputerName -or $ExpectedComputerName -cne $HostName -or $Label -cnotin @('home','work') -or $ServiceOwnerSid -cnotmatch '^S-1-5-21-\d+-\d+-\d+-\d+$'){throw 'Production requires explicit host, label and service owner'}
        return @{root='C:\ProgramData\STCVRC-observer';task='STCVRC-Observer';marker='.stcvrc-observer';value='STCVRC_OBSERVER_V1'}
    }
    if($HostName -cne 'LABHOST' -or $Label -cne 'lab'){throw 'Lab installer only accepts LABHOST/lab'}
    @{root='C:\ProgramData\STCVRC-observer-lab';task='STCVRC-Observer-Lab';marker='.stcvrc-observer-lab';value='STCVRC_OBSERVER_LAB_V1'}
}
$scope=Resolve-ObserverScope ([bool]$Production) $ExpectedComputerName $Label $ServiceOwnerSid $env:COMPUTERNAME
$principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Administrator required'}
$root=$scope.root
$taskName=$scope.task
$marker=$scope.marker
$markerValue=$scope.value
function Assert-NoReparse([string]$Path){
    $current=[IO.Path]::GetFullPath($Path)
    while($current){
        if((Test-Path -LiteralPath $current) -and ((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Reparse path rejected'}
        $current=Split-Path -Parent $current
    }
}
Assert-NoReparse $root
if($Action -eq 'Install') {
    if((Test-Path -LiteralPath $root) -or (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)){throw 'Existing lab footprint'}
    if($ServiceOwnerSid){
        if(-not $Production -and ($ServiceOwnerSid -cne 'S-1-5-21-1-2-3-1001' -or $AppDirectory -cne 'C:\Users\FixtureUser\AppData\Roaming\io.github.clash-verge-rev.clash-verge-rev')){throw 'Unapproved lab service owner'}
        $profile=Get-CimInstance Win32_UserProfile -Filter "SID='$ServiceOwnerSid'"
        if(-not $profile -or $profile.LocalPath -notmatch '^C:\\Users\\[^\\]+$' -or $AppDirectory -ine (Join-Path $profile.LocalPath 'AppData\Roaming\io.github.clash-verge-rev.clash-verge-rev')){throw 'Owner profile differs'}
        $version=(Get-Item -LiteralPath 'C:\Program Files\Clash Verge\clash-verge.exe').VersionInfo.ProductVersion
        if(($version.Split('.')[0..2] -join '.') -cnotin @('2.5.5','2.5.7','2.5.8')){throw 'Unreviewed owner-scoped UI version'}
        if(-not $Production -and [IO.File]::ReadAllText('C:\ProgramData\clash-verge-service\.stcvrc-desktop-state') -cne [IO.File]::ReadAllText('C:\Users\FixtureUser\stcvrc-autostart-control\run-id.txt')){throw 'Not current lab service state'}
    }
    Assert-NoReparse $Bundle
    Assert-NoReparse $AppDirectory
    $source=(Resolve-Path -LiteralPath $Bundle).Path
    $app=(Resolve-Path -LiteralPath $AppDirectory).Path
    if(-not $Production){
        if($app -cnotin @('C:\Users\FixtureService\stcvrc-observer-lab\app','C:\Users\FixtureUser\AppData\Roaming\io.github.clash-verge-rev.clash-verge-rev')){throw 'Unexpected lab app root'}
        if($app -clike 'C:\Users\FixtureUser\*' -and [IO.File]::ReadAllText('C:\Users\FixtureUser\stcvrc-autostart-control\isolated.ok') -cne 'STCVRC_ISOLATED_V1'){throw 'Desktop isolation gate missing'}
    }
    Assert-NoReparse (Join-Path $source 'manifest.json')
    if((Get-FileHash -LiteralPath (Join-Path $source 'manifest.json') -Algorithm SHA256).Hash -ine $ManifestSha256){throw 'Manifest hash mismatch'}
    $manifest=[IO.File]::ReadAllText((Join-Path $source 'manifest.json'))|ConvertFrom-Json
    if($manifest.schemaVersion -ne 1 -or -not $manifest.files.'bin/python.exe' -or -not $manifest.files.'bin/stcvrc_observer.py'){throw 'Incomplete package manifest'}
    foreach($entry in $manifest.files.PSObject.Properties){
        if($entry.Name -notmatch '^bin/[a-zA-Z0-9_./+-]+$' -or $entry.Name.Contains('..')){throw 'Invalid package path'}
        $path=Join-Path $source $entry.Name
        Assert-NoReparse $path
        if((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ine $entry.Value){throw 'Package hash mismatch'}
    }
    $null=New-Item -ItemType Directory -Path $root
    $acl=New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    foreach($sid in @('S-1-5-18','S-1-5-32-544')){
        $rule=New-Object Security.AccessControl.FileSystemAccessRule(([Security.Principal.SecurityIdentifier]$sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $root -AclObject $acl
    [IO.File]::WriteAllText((Join-Path $root $marker),$markerValue)
    foreach($entry in $manifest.files.PSObject.Properties){
        $target=Join-Path $root $entry.Name
        $null=New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force
        Copy-Item -LiteralPath (Join-Path $source $entry.Name) -Destination $target
        if((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ine $entry.Value){throw 'Protected copy hash mismatch'}
    }
    Copy-Item -LiteralPath (Join-Path $source 'manifest.json') -Destination (Join-Path $root 'manifest.json')
    if((Get-FileHash -LiteralPath (Join-Path $root 'manifest.json')).Hash -ine $ManifestSha256){throw 'Protected manifest hash mismatch'}
    $exe=Join-Path $root 'bin\python.exe'
    $arguments='-I -B "'+(Join-Path $root 'bin\stcvrc_observer.py')+'" --app-dir "'+$app+'" --data-dir "'+(Join-Path $root 'data')+'" --label '+$Label+' --active'
    if($ServiceOwnerSid){$arguments+=' --service-owner-sid '+$ServiceOwnerSid}
    $actionObject=New-ScheduledTaskAction -Execute $exe -Argument $arguments -WorkingDirectory (Join-Path $root 'bin')
    $triggers=@((New-ScheduledTaskTrigger -AtStartup),(New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)))
    $settings=New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Seconds 50) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    $identity=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $null=Register-ScheduledTask -TaskName $taskName -Action $actionObject -Trigger $triggers -Settings $settings -Principal $identity
    Start-ScheduledTask -TaskName $taskName
}
if($Action -eq 'RemoveTask') {
    $task=Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if($task){
        if([IO.File]::ReadAllText((Join-Path $root $marker)) -cne $markerValue -or @($task.Actions).Count -ne 1 -or $task.Actions.Execute -cne (Join-Path $root 'bin\python.exe') -or -not $task.Actions.Arguments.Contains((Join-Path $root 'bin\stcvrc_observer.py'))){throw 'Unexpected task action'}
        Stop-ScheduledTask -TaskName $taskName
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    }
}
$task=Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
@{taskPresent=($null -ne $task);taskState=$(if($task){[string]$task.State}else{'absent'});rootPresent=(Test-Path -LiteralPath $root)}|ConvertTo-Json -Compress
