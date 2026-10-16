[CmdletBinding()]
param([ValidateSet('Snapshot','Setup','Inspect','UpgradeUi','RollbackUi','Cleanup','SelectForeign','Canary')][string]$Action, [ValidateSet('VPS-POOL','4VPS','GC','DIRECT')][string]$Choice, [switch]$ProviderRepair)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$lab=Join-Path $env:USERPROFILE 'stcvrc-fullstack-lab'
if($env:COMPUTERNAME -cne 'LABHOST'){throw 'Wrong host'}
. (Join-Path $lab 'fullstack.ps1') -Mode Library -LabRoot $lab
Assert-GuardedLab
function Read-InputHashes { [IO.File]::ReadAllText((Join-Path $lab 'input\hashes.json')) | ConvertFrom-Json }

if($Action -in @('UpgradeUi','RollbackUi')){
    $inputRoot=Join-Path $lab 'input'
    $migrationRoot=Join-Path $lab 'ui-migration'
    $manifestPath=Join-Path $inputRoot 'ui-migration.json'
    Assert-NoReparseAncestors $manifestPath
    $migration=[IO.File]::ReadAllText($manifestPath)|ConvertFrom-Json
    if($migration.schema -ne 1 -or $migration.old.uiVersion -cne '2.5.2' -or $migration.new.uiVersion -cne '2.5.5'){throw 'Unreviewed UI transition'}
    foreach($entry in $migration.files.PSObject.Properties){
        if([IO.Path]::GetFileName($entry.Name) -cne $entry.Name){throw 'Migration input path'}
        $file=Join-Path $inputRoot $entry.Name
        Assert-NoReparseAncestors $file
        if((Get-FileHash -LiteralPath $file).Hash -ine $entry.Value){throw 'Migration input hash'}
    }
    function Run-Installer([string]$Path,[string[]]$Arguments=@('/S')){
        $parameters=@{FilePath=$Path;WindowStyle='Hidden';PassThru=$true}
        if($Arguments.Count){$parameters.ArgumentList=$Arguments}
        $p=Start-Process @parameters
        try {
            $handle=$p.Handle
            if(-not $p.WaitForExit(120000)){$p.Kill();$p.WaitForExit();throw 'UI migration installer timeout'}
            if($p.ExitCode -ne 0){throw 'UI migration installer failed'}
        }finally{$p.Dispose()}
    }
    function Stop-MigrationRuntime {
        $null=Stop-ExactProcesses -Names @('clash-verge.exe') -AllowedPaths @($UiPath)
        $service=Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if($service -and $service.Status -ne 'Stopped'){
            Stop-Service -Name $ServiceName -Force
            $service.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(20))
        }
        $null=Stop-ExactProcesses -Names @('verge-mihomo.exe') -AllowedPaths @($InstalledCorePath,'C:\ProgramData\clash-verge-service\cores\verge-mihomo.exe')
    }
    $currentVersion=(Get-Item -LiteralPath $UiPath).VersionInfo.ProductVersion
    $expected=if($Action -eq 'UpgradeUi'){$migration.old}else{$migration.new}
    if($currentVersion -cne $expected.uiVersion -or (Get-FileHash -LiteralPath $RuntimeCorePath).Hash -ine $expected.coreSha256){throw 'UI migration baseline mismatch'}
    $control=Join-Path $env:USERPROFILE 'stcvrc-autostart-control'
    $preserve=@{AppDirectory=$AppRoot;Destination=(Join-Path $control ($Action+'-history'));RequireComplete=$true}
    if($RuntimeLayout.approved){$preserve.ServiceOwnerDirectory=Split-Path -Parent $RuntimeLayout.logs}
    $null=& (Join-Path $control 'preserve.ps1') @preserve
    Stop-MigrationRuntime
    if($Action -eq 'UpgradeUi'){
        if(Test-Path -LiteralPath $migrationRoot){throw 'Migration backup already exists'}
        $null=New-Item -ItemType Directory -Path $migrationRoot
        $backup=@()
        foreach($relative in @('profiles.yaml','verge.yaml','clash-verge.yaml','cache.db','profiles\LSTCVRCGate.yaml')){
            $source=Join-Path $AppRoot $relative
            Assert-NoReparseAncestors $source
            $present=Test-Path -LiteralPath $source
            $name='file-'+$backup.Count
            if($present){[IO.File]::Copy($source,(Join-Path $migrationRoot $name),$false)}
            $backup+=@{relative=$relative;backup=$name;present=$present;sha256=if($present){(Get-FileHash -LiteralPath $source).Hash}else{$null}}
        }
        [IO.File]::WriteAllText((Join-Path $migrationRoot 'backup.json'),($backup|ConvertTo-Json -Depth 4))
        $target=$migration.new
    }else{
        $backup=[IO.File]::ReadAllText((Join-Path $migrationRoot 'backup.json'))|ConvertFrom-Json
        foreach($entry in $backup){
            if($entry.relative -notin @('profiles.yaml','verge.yaml','clash-verge.yaml','cache.db','profiles\LSTCVRCGate.yaml') -or $entry.backup -notmatch '^file-[0-4]$'){throw 'Unexpected migration backup target'}
            if($entry.present -and (Get-FileHash -LiteralPath (Join-Path $migrationRoot $entry.backup)).Hash -ine $entry.sha256){throw 'Migration backup drift'}
        }
        $uninstaller=Join-Path $InstallRoot 'uninstall.exe'
        Assert-NoReparseAncestors $uninstaller
        Run-Installer $ServiceUninstallPath @()
        if(Get-Service -Name $ServiceName -ErrorAction SilentlyContinue){throw 'New service remains before UI downgrade'}
        # NSIS must not fork into Temp; wait for the actual uninstall and its exit code.
        Run-Installer $uninstaller @('/S',('_?='+$InstallRoot))
        $target=$migration.old
    }
    Run-Installer (Join-Path $inputRoot $target.installerName)
    $versionDeadline=(Get-Date).AddSeconds(30)
    do {
        $actualVersion=if(Test-Path -LiteralPath $UiPath){[Diagnostics.FileVersionInfo]::GetVersionInfo($UiPath).ProductVersion}else{$null}
        if($actualVersion -ceq $target.uiVersion){break}
        Start-Sleep -Seconds 1
    }while((Get-Date) -lt $versionDeadline)
    [IO.File]::WriteAllText((Join-Path $control ($Action+'-installer.json')),(@{expected=$target.uiVersion;actual=$actualVersion;sha256=if(Test-Path -LiteralPath $UiPath){(Get-FileHash -LiteralPath $UiPath).Hash}else{$null}}|ConvertTo-Json))
    if($actualVersion -cne $target.uiVersion){throw 'Installed UI version mismatch'}
    Stop-MigrationRuntime
    Copy-Item -LiteralPath (Join-Path $inputRoot $target.coreName) -Destination $InstalledCorePath -Force
    if($Action -eq 'RollbackUi'){
        foreach($entry in $backup){
            $destination=Join-Path $AppRoot $entry.relative
            Assert-NoReparseAncestors $destination
            if($entry.present){[IO.File]::Copy((Join-Path $migrationRoot $entry.backup),$destination,$true)}
            elseif(Test-Path -LiteralPath $destination){Remove-Item -LiteralPath $destination -Force}
            if($entry.present -and (Get-FileHash -LiteralPath $destination).Hash -ine $entry.sha256){throw 'Migration restore hash mismatch'}
        }
    }
    if($Action -eq 'UpgradeUi'){
        Run-Installer $ServiceInstallPath @('--install-service','--install-core',('"'+$InstalledCorePath+'"'),'--sha256',$target.coreSha256)
        if((Get-FileHash -LiteralPath 'C:\ProgramData\clash-verge-service\cores\verge-mihomo.exe').Hash -ine $target.coreSha256){throw 'Migration approved core mismatch'}
    }else{
        $service=Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if(-not $service){Run-Installer $ServiceInstallPath @()}
    }
    [IO.File]::WriteAllText((Join-Path $inputRoot 'stack-manifest.json'),($target|ConvertTo-Json -Depth 4))
    $serviceState=Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
    $expectedService=if($Action -eq 'UpgradeUi'){'C:\ProgramData\clash-verge-service\bin\clash-verge-service.exe'}else{Join-Path $InstallRoot 'resources\clash-verge-service.exe'}
    [IO.File]::WriteAllText((Join-Path $control ($Action+'-service.json')),(@{state=$serviceState.State;pathMatched=($serviceState.PathName.Trim('"') -ieq $expectedService);startMode=$serviceState.StartMode}|ConvertTo-Json))
    if($serviceState.PathName.Trim('"') -ine $expectedService){throw 'UI migration service path mismatch'}
    Start-Service -Name $ServiceName
    # Reload the stock layout after the installer changes the service generation.
    . (Join-Path $lab 'fullstack.ps1') -Mode Library -LabRoot $lab
    $null=Start-Ui
    $runtime=Wait-CvrRuntime -TimeoutSeconds 30
    $ControllerHeaders=@{Authorization=('Bearer '+(Get-ControllerSecret))}
    $cfg=Invoke-Controller -Path '/configs'
    $groups=(Invoke-Controller -Path '/proxies').proxies
    $selectorsBeforeRestore=@{}
    if($Action -eq 'UpgradeUi'){
        $expectedSelectors=[IO.File]::ReadAllText((Join-Path $lab 'selectors.json'))|ConvertFrom-Json
        foreach($entry in $expectedSelectors.PSObject.Properties){
            $group=$groups.($entry.Name)
            if($entry.Name -ceq 'GLOBAL' -or $group.type -cne 'Selector' -or $group.all -cnotcontains $entry.Value){throw 'Captured migration selector mismatch'}
            $selectorsBeforeRestore[$entry.Name]=$group.now
            $null=Invoke-Controller -Path ('/proxies/'+[uri]::EscapeDataString($entry.Name)) -Method Put -Body @{name=$entry.Value}
        }
        $groups=(Invoke-Controller -Path '/proxies').proxies
    }
    $selected=@{}
    foreach($entry in $groups.PSObject.Properties){if($entry.Name -ne 'GLOBAL' -and $entry.Value.type -ceq 'Selector'){$selected[$entry.Name]=$entry.Value.now}}
    $canary=(& (Join-Path $lab 'driver.ps1') -Action Canary -ProviderRepair)-join "`n"|ConvertFrom-Json
    @{pass=($runtime.coreOwned -and -not $cfg.tun.enable -and $canary.pass);uiVersion=(Get-Item -LiteralPath $UiPath).VersionInfo.ProductVersion;coreHash=$runtime.executingCoreHash;runtimeConfigPath=$RuntimePath;selectors=$selected;selectorsBeforeRestore=$selectorsBeforeRestore;canary=$canary;historyPreserved=$true;configRestored=($Action -eq 'RollbackUi')}|ConvertTo-Json -Depth 5 -Compress
    exit 0
}

if($Action -eq 'Canary'){
    $checks=@()
    foreach($x in @(@('gstatic','https://www.gstatic.com/generate_204',204),@('control','https://www.cloudflare.com/cdn-cgi/trace',200))){
        $timer=[Diagnostics.Stopwatch]::StartNew()
        $status=0;$webStatus=$null
        try {$status=[int](Invoke-WebRequest -Uri $x[1] -Proxy 'http://127.0.0.1:7897' -UseBasicParsing -TimeoutSec 10).StatusCode}
        catch {if($_.Exception.Response){$status=[int]$_.Exception.Response.StatusCode};$webStatus=[string]$_.Exception.Status}
        $checks+=,@{name=$x[0];status=$status;webStatus=$webStatus;elapsedMs=$timer.ElapsedMilliseconds;pass=($status -eq $x[2] -and -not $webStatus)}
    }
    @{checks=$checks;pass=(-not @($checks | Where-Object {-not $_.pass}).Count)}|ConvertTo-Json -Depth 4 -Compress
    exit 0
}

if($Action -eq 'SelectForeign'){
    if(-not $Choice){throw 'Choice required'}
    $ControllerHeaders=@{Authorization=('Bearer '+(Get-ControllerSecret))}
    $group=Invoke-Controller -Path '/proxies/FOREIGN-EGRESS'
    if($group.type -ne 'Selector' -or ($group.all -join ',') -cne 'VPS-POOL,4VPS,GC,DIRECT'){throw 'Unexpected policy'}
    $null=Invoke-Controller -Path '/proxies/FOREIGN-EGRESS' -Method Put -Body @{name=$Choice}
    $current=(Invoke-Controller -Path '/proxies/FOREIGN-EGRESS').now
    @{choice=$Choice;now=$current;pass=($current -ceq $Choice)}|ConvertTo-Json -Compress
    exit 0
}

function Inventory([string]$EvidencePath) {
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    $principal=New-Object Security.Principal.WindowsPrincipal($identity)
    $context=@{schema=1;principalHash=(Get-StringSha256 $identity.User.Value);
        elevated=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);
        processBits=([IntPtr]::Size*8);appDataHash=(Get-StringSha256 $env:APPDATA);
        hkcuRootHash=(Get-StringSha256 (Get-PSDrive HKCU).Root)}
    $allServices=@(Get-CimInstance Win32_Service | Sort-Object Name | ForEach-Object {
        $type=Get-ItemPropertyValue -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\'+$_.Name) -Name Type
        [pscustomobject]@{Name=$_.Name;StartMode=$_.StartMode;PathName=$_.PathName;PerUserInstance=[bool]($type -band 128)}
    })
    $values=[ordered]@{
        routes=@(Get-NetRoute | Sort-Object InterfaceIndex,DestinationPrefix,NextHop | Select-Object InterfaceIndex,DestinationPrefix,NextHop,RouteMetric,PolicyStore)
        dns=@(Get-DnsClientServerAddress | Sort-Object InterfaceIndex,AddressFamily | Select-Object InterfaceIndex,AddressFamily,ServerAddresses)
        services=@($allServices | Where-Object {-not $_.PerUserInstance} | Select-Object Name,StartMode,PathName)
        tasks=@(Get-ScheduledTask | Sort-Object TaskPath,TaskName | Select-Object TaskPath,TaskName)
        firewall=@(Get-NetFirewallRule | Sort-Object Name | Select-Object Name,Enabled,Direction,Action)
        hiddify=@(if(Test-Path -LiteralPath (Join-Path $env:APPDATA 'Hiddify')){Get-ChildItem -LiteralPath (Join-Path $env:APPDATA 'Hiddify') -Recurse -File | Sort-Object FullName | Select-Object FullName,Length,LastWriteTimeUtc})
        proxy=Get-ItemPropertyValue 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name ProxyEnable
        winhttp=(@(netsh winhttp show proxy) -join "`n")
    }
    $hashes=[ordered]@{}
    foreach($key in $values.Keys){$hashes[$key]=Get-StringSha256 (ConvertTo-Json -InputObject $values[$key] -Depth 8 -Compress)}
    if($EvidencePath){
        $taskDefinitions=@(Get-ScheduledTask | Sort-Object TaskPath,TaskName | ForEach-Object {
            @{path=$_.TaskPath;name=$_.TaskName;xml=(Export-ScheduledTask -TaskPath $_.TaskPath -TaskName $_.TaskName)}
        })
        [IO.File]::WriteAllText($EvidencePath,(@{at=(Get-Date).ToString('o');context=$context;values=$values;allServices=$allServices;taskDefinitions=$taskDefinitions}|ConvertTo-Json -Depth 10 -Compress))
    }
    @{schema=3;context=$context;fingerprint=(Get-StringSha256 ($values|ConvertTo-Json -Depth 8 -Compress));componentHashes=$hashes;routes=$values.routes.Count;services=$values.services.Count;perUserInstances=@($allServices|Where-Object PerUserInstance).Count;tasks=$values.tasks.Count;firewall=$values.firewall.Count;hiddify=$values.hiddify.Count}
}

if($Action -eq 'Snapshot'){
    if(Get-ScheduledTask -TaskName 'STCVRC-Safe-*' -ErrorAction SilentlyContinue){throw 'Existing transaction task'}
    @{baseline=Get-HostBaseline;inventory=(Inventory -EvidencePath (Join-Path $lab 'inventory-before.json'))}|ConvertTo-Json -Depth 12 -Compress
    exit 0
}
if($Action -eq 'Setup'){
    $baseline=Get-HostBaseline
    if(-not $baseline.footprintAbsent -or -not $baseline.elevatedAdministrator){throw 'Full-stack preflight failed'}
    $inputs=Read-InputHashes
    foreach($name in $inputs.PSObject.Properties.Name){
        if((Get-FileHash -LiteralPath (Join-Path $lab ('input\'+$name))).Hash -ine $inputs.$name){throw 'Lab input hash mismatch'}
    }
    $installerName='Clash.Verge_2.5.2_x64-setup.exe';$coreName='old-core.exe'
    $stackPath=Join-Path $lab 'input\stack-manifest.json'
    if(Test-Path -LiteralPath $stackPath){
        $stack=[IO.File]::ReadAllText($stackPath)|ConvertFrom-Json
        if($stack.schema -ne 1 -or $stack.installerName -notmatch '^Clash\.Verge_2\.5\.(2|5|7)_x64-setup\.exe$' -or $stack.coreName -cne 'gate-core.exe'){throw 'Invalid stack manifest'}
        $installerName=$stack.installerName;$coreName=$stack.coreName
        if($inputs.$installerName -cne $stack.installerSha256 -or $inputs.$coreName -cne $stack.coreSha256){throw 'Stack digest mismatch'}
    }
    $install=Invoke-HiddenProcess -Path (Join-Path $lab ('input\'+$installerName)) -Arguments @('/S') -Wait
    if($install.ExitCode -ne 0){throw 'Stock UI setup failed'}
    foreach($p in @(Get-CvrProcesses)){if($p.executablePath -ieq $UiPath){Stop-Process -Id $p.pid -Force}}
    $null=New-Item -ItemType Directory -Path (Join-Path $AppRoot 'profiles'),(Join-Path $AppRoot 'rules') -Force
    $dataFiles=@('profiles.yaml','verge.yaml')
    if(-not $ProviderRepair){$dataFiles+=@('Country.mmdb','geoip.dat','geosite.dat')}
    foreach($name in $dataFiles){
        Copy-Item -LiteralPath (Join-Path $lab ('input\'+$name)) -Destination (Join-Path $AppRoot $name) -Force
    }
    Copy-Item -LiteralPath (Join-Path $lab 'input\profile.yaml') -Destination $ProfilePath -Force
    [IO.File]::WriteAllText((Join-Path $AppRoot 'profiles\Merge.yaml'),"# disposable gate`n")
    [IO.File]::WriteAllText((Join-Path $AppRoot 'profiles\Script.js'),'function main(config) { return config; }')
    foreach($p in Get-ChildItem -LiteralPath (Join-Path $lab 'input\rules') -File){Copy-Item -LiteralPath $p.FullName -Destination (Join-Path $AppRoot ('rules\'+$p.Name))}
    Copy-Item -LiteralPath (Join-Path $lab ('input\'+$coreName)) -Destination $InstalledCorePath -Force
    $service=Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if(-not $service){$si=Invoke-HiddenProcess -Path $ServiceInstallPath -Wait;if($si.ExitCode -ne 0){throw 'Stock service install failed'}}
    if($RuntimeLayout.approved){
        # CVR 2.5.5 executes an installer-approved copy, not the UI resource file.
        $approved=Invoke-HiddenProcess -Path $ServiceInstallPath -Arguments @('--install-core',('"'+$InstalledCorePath+'"'),'--sha256',$stack.coreSha256) -Wait
        if($approved.ExitCode -ne 0){throw 'Official core approval failed'}
        Assert-NoReparseAncestors $RuntimeCorePath
        if((Get-FileHash -LiteralPath $RuntimeCorePath).Hash -ine $stack.coreSha256){throw 'Approved core copy hash mismatch'}
    }
    $null=Start-Ui
    if($ProviderRepair){
        $ControllerHeaders=@{Authorization=('Bearer '+(Get-ControllerSecret))}
        foreach($pair in @(@('FOREIGN-EGRESS','GC'),@('LAB-UNCHANGED','REJECT'))){
            $null=Invoke-Controller -Path ('/proxies/'+$pair[0]) -Method Put -Body @{name=$pair[1]}
            if((Invoke-Controller -Path ('/proxies/'+$pair[0])).now -cne $pair[1]){throw 'Lab selector seed failed'}
        }
    }
}
if($Action -in @('Setup','Inspect')){
    if($Action -eq 'Inspect'){$null=Start-Ui}
    $secret=Get-ControllerSecret
    $runtime=Wait-CvrRuntime -TimeoutSeconds 10
    $ControllerHeaders=@{Authorization=('Bearer '+$secret)}
    $cfg=Invoke-Controller -Path '/configs'
    if($cfg.tun.enable){throw 'Lab unexpectedly enabled TUN'}
    $groups=(Invoke-Controller -Path '/proxies').proxies
    $selectors=[ordered]@{}
    $excluded=if($ProviderRepair){@('GLOBAL')}else{@('VPS-DEFAULT','VPS-AUTO','VPS-ONLY','FOREIGN-EGRESS','VPS-POOL','GLOBAL')}
    foreach($p in $groups.PSObject.Properties){if($p.Value.type -eq 'Selector' -and $p.Name -notin $excluded){$selectors[$p.Name]=$p.Value.now}}
    [IO.File]::WriteAllText((Join-Path $lab 'selectors.json'),($selectors|ConvertTo-Json -Compress))
    @{at=(Get-Date).ToString('o');version=(Invoke-Controller -Path '/version').version;uiVersion=(Get-Item -LiteralPath $UiPath).VersionInfo.ProductVersion;coreHash=$runtime.executingCoreHash;approvedCoreLayout=$RuntimeLayout.approved;runtimeCorePath=$RuntimeCorePath;runtimeConfigPath=$RuntimePath;runtimeLogPath=$RuntimeLayout.logs;coreOwned=$runtime.coreOwned;uiHash=(Get-FileHash $UiPath).Hash;processes=@(Get-CvrProcesses);tunDisabled=(-not $cfg.tun.enable);proxyEnabled=[bool](Get-ItemPropertyValue 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name ProxyEnable);groups=@($groups.PSObject.Properties | Where-Object {$_.Value.type -in @('Selector','URLTest','Fallback') -and $_.Name -ne 'GLOBAL'} | ForEach-Object {@{name=$_.Name;type=$_.Value.type;now=$_.Value.now;hidden=$_.Value.hidden;fixed=$_.Value.fixed}})}|ConvertTo-Json -Depth 7 -Compress
    exit 0
}
if($Action -eq 'Cleanup'){
    $applyTask=Get-ScheduledTask -TaskName 'STCVRC-Safe-Apply' -ErrorAction SilentlyContinue
    if($applyTask){
        if(-not $applyTask.Actions[0].Arguments.Contains((Join-Path $lab 'transactions'))){throw 'Unknown apply task'}
        Stop-ScheduledTask -TaskName 'STCVRC-Safe-Apply'
        Unregister-ScheduledTask -TaskName 'STCVRC-Safe-Apply' -Confirm:$false
    }
    $task=Get-ScheduledTask -TaskName 'STCVRC-Safe-Rollout' -ErrorAction SilentlyContinue
    if($task){
        if(-not $task.Actions[0].Arguments.Contains((Join-Path $lab 'transactions'))){throw 'Unknown guard task'}
        Stop-ScheduledTask -TaskName 'STCVRC-Safe-Rollout'
        Unregister-ScheduledTask -TaskName 'STCVRC-Safe-Rollout' -Confirm:$false
    }
    foreach($p in Get-CimInstance Win32_Process -Filter "Name='powershell.exe'"){
        if($p.ProcessId -ne $PID -and $p.CommandLine -and $p.CommandLine.Contains((Join-Path $lab 'transactions')) -and $p.CommandLine.Contains('transaction.ps1')){Stop-Process -Id $p.ProcessId -Force}
    }
    if(@(Get-ChildItem -LiteralPath $lab -Recurse -Force | Where-Object {$_.Attributes -band [IO.FileAttributes]::ReparsePoint}).Count){throw 'Unsafe lab tree'}
    $raw=& powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $lab 'fullstack.ps1') -Mode Cleanup -LabRoot $lab
    $clean=($raw -join "`n") | ConvertFrom-Json
    @{cleanup=$clean;inventory=Inventory;guardTaskAbsent=(-not [bool](Get-ScheduledTask -TaskName 'STCVRC-Safe-*' -ErrorAction SilentlyContinue))}|ConvertTo-Json -Depth 14 -Compress
    exit 0
}
