[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Preflight','Launch','Apply','Watch','Confirm','Rollback')][string]$Mode,
    [Parameter(Mandatory)][string]$Transaction,
    [ValidateRange(30,600)][int]$DeadlineSeconds=300,
    [switch]$ConsumerConfirmed,
    [ValidateSet('None','AfterStop','AfterCopy')][string]$LabPause='None'
)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$Root=[IO.Path]::GetFullPath($Transaction).TrimEnd('\')
$PlanPath=Join-Path $Root 'plan.json'
$Plan=[IO.File]::ReadAllText($PlanPath) | ConvertFrom-Json
$TaskName='STCVRC-Safe-Rollout'
$ApplyTaskName='STCVRC-Safe-Apply'
$ServiceName='clash_verge_service'
$Core='C:\Program Files\Clash Verge\verge-mihomo.exe'
$Ui='C:\Program Files\Clash Verge\clash-verge.exe'
$ServiceExe='C:\Program Files\Clash Verge\resources\clash-verge-service.exe'
$ApprovalHelper='C:\Program Files\Clash Verge\resources\clash-verge-service-install.exe'
$ServiceUninstaller='C:\Program Files\Clash Verge\resources\clash-verge-service-uninstall.exe'
$InstallRoot=Split-Path -Parent $Core
$ApprovedCore='C:\ProgramData\clash-verge-service\cores\verge-mihomo.exe'
$approvedLayout=$Plan.runtimeLayout -ceq 'approved' -or ($Plan.policy -ceq 'ui-update' -and $Plan.oldRuntimeLayout -ceq 'approved')
$ExecutingCore=if($approvedLayout){$ApprovedCore}else{$Core}
if($approvedLayout){$ServiceExe='C:\ProgramData\clash-verge-service\bin\clash-verge-service.exe'}
$StatePath=Join-Path $Root 'state.json'
$CachePath=Join-Path $Plan.appRoot 'cache.db'
$PowerShell=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$Headers=@{Authorization=('Bearer '+$Plan.controllerSecret)}
$Lock=$null

function Hash([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Read-Json([string]$Path) { [IO.File]::ReadAllText($Path) | ConvertFrom-Json }
function Write-Json([string]$Path,$Value) {
    $tmp=$Path+'.tmp'
    [IO.File]::WriteAllText($tmp,($Value | ConvertTo-Json -Depth 10),[Text.UTF8Encoding]::new($false))
    for($attempt=0;$attempt -lt 20;$attempt++){
        try {
            if(Test-Path -LiteralPath $Path){[IO.File]::Replace($tmp,$Path,($Path+'.previous'))}else{[IO.File]::Move($tmp,$Path)}
            return
        } catch [IO.IOException] {
            if($attempt -eq 19){throw}
            Start-Sleep -Milliseconds 50
        }
    }
}
function State([string]$Phase) {
    Write-Json $StatePath @{phase=$Phase;at=[DateTime]::UtcNow.ToString('o')}
}
function No-Reparse([string]$Path) {
    $current=[IO.Path]::GetFullPath($Path)
    while($current){
        if(Test-Path -LiteralPath $current){
            if((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse path rejected'}
        }
        $current=Split-Path -Parent $current
    }
}
function Guard {
    if($Plan.schema -ne 1 -or $Plan.host -cne $env:COMPUTERNAME -or $Root -ine $Plan.root){throw 'Transaction host/root mismatch'}
    $profileRoot=Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $Plan.appRoot))
    $expectedApp=Join-Path $profileRoot 'AppData\Roaming\io.github.clash-verge-rev.clash-verge-rev'
    if($profileRoot -notmatch '^C:\\Users\\[^\\]+$' -or $Plan.appRoot -ine $expectedApp){throw 'AppData owner boundary mismatch'}
    $parent=if($Plan.lab){Join-Path $profileRoot 'stcvrc-fullstack-lab\transactions'}else{Join-Path $profileRoot 'Documents\HomeLab\projects\stcvrc\local\rollouts'}
    if((Split-Path -Parent $Root) -ine $parent -or (Split-Path -Leaf $Root) -notmatch '^stcvrc-safe-[0-9-]+$'){throw 'Unsafe transaction root'}
    if(($Plan.lab -and $env:COMPUTERNAME -cne 'LABHOST') -or (-not $Plan.lab -and $env:COMPUTERNAME -cne 'FIXTURE-HOME')){throw 'Wrong host scope'}
    if($LabPause -ne 'None' -and -not $Plan.lab){throw 'Fault injection is lab-only'}
    No-Reparse $Root; No-Reparse $Plan.appRoot; No-Reparse $Core
    if($Plan.runtimeLayout){
      if($Plan.policy -ceq 'ui-update'){
        $pair=$Plan.oldUiVersion+'->'+$Plan.uiVersion
        $oldLayout=if($Plan.oldUiVersion -ceq '2.5.2'){'legacy'}else{'approved'}
        if($Plan.runtimeLayout -cne 'ui-migration' -or $pair -cnotin @('2.5.2->2.5.5','2.5.2->2.5.8','2.5.5->2.5.8') -or $Plan.oldRuntimeLayout -cne $oldLayout -or $Plan.uiTask -cnotin @('Clash Verge','ClashVergeInteractiveLimited')){throw 'Unreviewed UI migration'}
        if($oldLayout -ceq 'approved' -and (Hash (Join-Path $Root 'owner-runtime.before.yaml')) -cne $Plan.oldOwnerRuntimeSha256){throw 'Old owner runtime backup drift'}
        if($Mode -in @('Preflight','Launch','Apply')){
            Assert-UiVersion $Plan.oldUiVersion
            $null=Get-OwnerUiTask
        }
        foreach($label in @('old','new')){
            $installer=Join-Path $Root ('ui-'+$label+'.exe')
            No-Reparse $installer
            if((Hash $installer) -cne $Plan.uiInstallers.$label){throw 'Pinned UI installer drift'}
        }
        if((Hash (Join-Path $Root 'settings.expected.yaml')) -cne $Plan.settingsExpectedSha256 -or (Hash (Join-Path $Root 'owner-runtime.expected.yaml')) -cne $Plan.ownerRuntimeSha256){throw 'Migration expectation drift'}
        if($Plan.serviceOwnerSid -cnotmatch '^S-1-5-21-\d+-\d+-\d+-\d+$'){throw 'Invalid service owner SID'}
      }else{
        if($Plan.runtimeLayout -cne 'approved' -or $Plan.policy -cne 'core-update' -or $Plan.uiVersion -cne '2.5.5' -or $Plan.serviceOwnerSid -cnotmatch '^S-1-5-21-\d+-\d+-\d+-\d+$'){throw 'Unreviewed runtime layout'}
        Assert-UiVersion $Plan.uiVersion
      }
        $sha=[Security.Cryptography.SHA256]::Create()
        try {$ownerHash=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::ASCII.GetBytes($Plan.serviceOwnerSid)))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
        $expectedOwner=Join-Path 'C:\ProgramData\clash-verge-service\users' $ownerHash
        if($Plan.serviceOwnerDirectory -cne $expectedOwner){throw 'Service owner boundary mismatch'}
        $owner=Get-CimInstance Win32_UserProfile -Filter "SID='$($Plan.serviceOwnerSid)'"
        if(-not $owner -or $owner.LocalPath -ine $profileRoot){throw 'Service owner profile mismatch'}
        foreach($path in @($ExecutingCore,$ServiceExe,$ApprovalHelper,$expectedOwner)){No-Reparse $path}
        $replaced=@($Plan.entries|Where-Object replace|Select-Object -ExpandProperty id)
        if($Plan.observerConfig){
            $coreEntry=$Plan.entries|Where-Object id -ceq 'core'
            if($Plan.policy -cne 'core-update' -or $replaced -cnotcontains 'profile' -or @($replaced|Where-Object {$_ -cnotin @('profile','settings')}).Count -or $coreEntry.before -cne $coreEntry.after -or $Plan.oldVersion -cne $Plan.newVersion -or $Plan.uiTask -cnotin @('Clash Verge','ClashVergeInteractiveLimited')){throw 'Observer configuration boundary mismatch'}
            if((Hash (Join-Path $Root 'owner-runtime.expected.yaml')) -cne $Plan.observerRuntimeSha256){throw 'Observer runtime expectation drift'}
            if($Mode -in @('Preflight','Launch','Apply')){$null=Get-OwnerUiTask}
        }elseif($replaced.Count -ne 1 -or $replaced[0] -cne 'core'){throw 'Core-only mutation boundary mismatch'}
    }elseif($Plan.policy -ceq 'core-update'){throw 'Core update requires approved runtime layout'}
    if((Hash $PSCommandPath) -cne $Plan.scriptSha256){throw 'Transaction script hash mismatch'}
    if($Mode -in @('Preflight','Launch','Apply')){
        $preserver=Join-Path $Root 'preserve-evidence.ps1'
        No-Reparse $preserver
        if(-not $Plan.evidenceScriptSha256 -or (Hash $preserver) -cne $Plan.evidenceScriptSha256){throw 'Evidence preserver hash mismatch'}
    }
    if($Mode -in @('Preflight','Launch','Apply','Confirm') -or $Plan.policy -ceq 'ui-update'){
        $validator=Join-Path $Root 'yaml-equivalence.exe'
        No-Reparse $validator
        if(-not $Plan.yamlValidatorSha256 -or (Hash $validator) -cne $Plan.yamlValidatorSha256){throw 'YAML validator hash mismatch'}
    }
    if([IO.Path]::GetFileName($Plan.profileFile) -cne $Plan.profileFile){throw 'Unsafe active profile filename'}
    $targets=@{core=$Core;profile=(Join-Path $Plan.appRoot ('profiles\'+$Plan.profileFile));runtime=(Join-Path $Plan.appRoot 'clash-verge.yaml');registry=(Join-Path $Plan.appRoot 'profiles.yaml');settings=(Join-Path $Plan.appRoot 'verge.yaml')}
    if($Plan.runtimeLayout -ceq 'approved'){$targets.Remove('runtime')}
    if(@($Plan.entries).Count -ne $targets.Count -or @($Plan.entries.id | Sort-Object -Unique).Count -ne $targets.Count){throw 'Entry set mismatch'}
    if($Plan.policy -ceq 'provider-repair'){
        if((@($Plan.entries | Where-Object {$_.replace} | Select-Object -ExpandProperty id | Sort-Object) -join ',') -cne 'profile,runtime'){throw 'Provider-only mutation boundary mismatch'}
        if(($Plan.repairedProviders -join ',') -cne 'ru-service-domains,tspu-foreign-domains'){throw 'Provider repair set mismatch'}
        if(-not $Plan.selectors.'FOREIGN-EGRESS'){throw 'Foreign selector was not captured'}
    }
    foreach($e in $Plan.entries){
        if(-not $targets.ContainsKey($e.id) -or $e.target -ine $targets[$e.id]){throw 'Unexpected transaction target'}
        No-Reparse $e.target
        if($Mode -in @('Preflight','Launch','Apply') -and $e.replace -and (Hash (Join-Path $Root ($e.id+'.new'))) -cne $e.after){throw 'Staged input hash mismatch'}
    }
}
function Acquire-Lock {
    $until=(Get-Date).AddSeconds(15)
    do {try {$script:Lock=[IO.File]::Open((Join-Path $Root 'transaction.lock'),'OpenOrCreate','ReadWrite','None');return}catch{Start-Sleep -Milliseconds 200}} while((Get-Date) -lt $until)
    throw 'Transaction lock timeout'
}
function Api([string]$Path,[string]$Method='Get',$Body=$null,[int]$Timeout=5) {
    $p=@{Uri=('http://127.0.0.1:9097'+$Path);Method=$Method;Headers=$Headers;TimeoutSec=$Timeout;UseBasicParsing=$true}
    if($null -ne $Body){$p.Body=$Body|ConvertTo-Json -Compress;$p.ContentType='application/json'}
    Invoke-RestMethod @p
}
function Exact-Processes([string]$Path) {
    @(Get-CimInstance Win32_Process | Where-Object {$_.ExecutablePath -and $_.ExecutablePath.Replace('\\?\','') -ieq $Path})
}
function Set-UiLayout([bool]$Approved) {
    $script:ExecutingCore=if($Approved){$ApprovedCore}else{$Core}
    $script:ServiceExe=if($Approved){'C:\ProgramData\clash-verge-service\bin\clash-verge-service.exe'}else{Join-Path $InstallRoot 'resources\clash-verge-service.exe'}
}
function Assert-UiVersion([string]$Expected) {
    if(-not (Test-Path -LiteralPath $Ui) -or [Diagnostics.FileVersionInfo]::GetVersionInfo($Ui).ProductVersion -cne $Expected){throw 'Installed UI layout mismatch'}
}
function Get-OwnerUiTask {
    $task=Get-ScheduledTask -TaskName $Plan.uiTask
    $sid=if($task.Principal.UserId -like 'S-1-*'){$task.Principal.UserId}else{([Security.Principal.NTAccount]::new($task.Principal.UserId)).Translate([Security.Principal.SecurityIdentifier]).Value}
    if($task.TaskPath -cne '\' -or @($task.Actions).Count -ne 1 -or $task.Actions[0].Execute.Trim('"') -ine $Ui -or $task.Actions[0].Arguments -or $sid -cne $Plan.serviceOwnerSid -or $task.Principal.LogonType -ne 'Interactive' -or $task.Principal.RunLevel -ne 'Limited'){throw 'Unreviewed UI launch task'}
    return $task
}
function Start-OwnerUi {
    $backup=Read-Json (Join-Path $Root 'backup.json')
    $xml=Join-Path $Root 'ui-task.old.xml'
    if((Hash $xml) -cne $backup.uiTaskHash){throw 'UI task backup drift'}
    $null=Register-ScheduledTask -TaskName $Plan.uiTask -Xml ([IO.File]::ReadAllText($xml)) -Force
    $null=Get-OwnerUiTask
    Start-ScheduledTask -TaskName $Plan.uiTask
    $deadline=(Get-Date).AddSeconds(45)
    do {
        $processes=@(Exact-Processes $Ui)
        if($processes.Count -eq 1 -and $processes[0].SessionId -gt 0 -and (Invoke-CimMethod -InputObject $processes[0] -MethodName GetOwnerSid).Sid -ceq $Plan.serviceOwnerSid){return}
        Start-Sleep -Seconds 1
    }while((Get-Date) -lt $deadline)
    throw 'Owner desktop UI did not start'
}
function Run-UiInstaller([string]$Path,[string[]]$Arguments=@('/S')) {
    No-Reparse $Path
    $parameters=@{FilePath=$Path;WindowStyle='Hidden';PassThru=$true}
    if($Arguments.Count){$parameters.ArgumentList=$Arguments}
    $p=Start-Process @parameters
    try {
        $handle=$p.Handle
        $child=Get-CimInstance Win32_Process -Filter "ProcessId=$($p.Id)"
        if($child){Write-Json (Join-Path $Root 'installer-worker.json') @{pid=$p.Id;createdUtc=$child.CreationDate.ToUniversalTime().ToString('o');path=$Path}}
        if(-not $p.WaitForExit(120000)){$p.Kill();$p.WaitForExit();throw 'UI installer timeout'}
        if($p.ExitCode -ne 0){throw 'UI installer failed'}
    }finally{$p.Dispose()}
}
function Install-UiGeneration([bool]$New) {
    $label=if($New){'new'}else{'old'}
    $version=if($New){$Plan.uiVersion}else{$Plan.oldUiVersion}
    if(-not $New){
        # A partial upgrade can leave either service generation or no service at all.
        if(Test-Path -LiteralPath $ServiceUninstaller){Run-UiInstaller $ServiceUninstaller @()}
        if(Get-Service -Name $ServiceName -ErrorAction SilentlyContinue){throw 'Service remains before downgrade'}
        $uninstaller=Join-Path $InstallRoot 'uninstall.exe'
        if(Test-Path -LiteralPath $uninstaller){Run-UiInstaller $uninstaller @('/S',('_?='+$InstallRoot))}
    }
    Run-UiInstaller (Join-Path $Root ('ui-'+$label+'.exe'))
    $deadline=(Get-Date).AddSeconds(30)
    do {
        try {Assert-UiVersion $version;break}catch{if((Get-Date) -ge $deadline){throw};Start-Sleep -Seconds 1}
    }while($true)
    Stop-Runtime
    Set-UiLayout ($version -cne '2.5.2')
    Write-Json (Join-Path $Root ('ui-'+$label+'-result.json')) @{version=$version;sha256=(Hash $Ui);at=[DateTime]::UtcNow.ToString('o')}
}
function Register-UiService([string]$ExpectedHash) {
    if((Hash $Core) -cne $ExpectedHash){throw 'UI service core input mismatch'}
    if($ExecutingCore -ceq $ApprovedCore){
        Run-UiInstaller $ApprovalHelper @('--install-service','--install-core',('"'+$Core+'"'),'--sha256',$ExpectedHash)
    }elseif(-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)){
        Run-UiInstaller $ApprovalHelper @()
    }
    $s=Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
    if(-not $s -or $s.PathName.Trim('"') -ine $ServiceExe -or (Hash $ExecutingCore) -cne $ExpectedHash){throw 'UI service registration mismatch'}
}
function Restore-Selectors {
    $groups=(Api '/proxies').proxies
    foreach($p in $Plan.selectors.PSObject.Properties){
        if($p.Name -ceq 'GLOBAL' -or $groups.($p.Name).type -cne 'Selector' -or $p.Value -cnotin $groups.($p.Name).all){throw 'Captured selector is not available'}
        $null=Api ('/proxies/'+[uri]::EscapeDataString($p.Name)) Put @{name=$p.Value}
    }
}
function Register-ApprovedCore([string]$ExpectedHash) {
    if($Plan.observerConfig){return}
    if($Plan.runtimeLayout -cne 'approved'){return}
    foreach($path in @($Core,$ApprovalHelper,$ExecutingCore)){No-Reparse $path}
    if((Hash $Core) -cne $ExpectedHash){throw 'Core approval input mismatch'}
    $p=Start-Process -FilePath $ApprovalHelper -ArgumentList @('--install-core',('"'+$Core+'"'),'--sha256',$ExpectedHash) -WindowStyle Hidden -PassThru
    try {
        $handle=$p.Handle
        $child=Get-CimInstance Win32_Process -Filter "ProcessId=$($p.Id)"
        if($child){
            if($child.ExecutablePath -ine $ApprovalHelper){throw 'Core approval child identity mismatch'}
            Write-Json (Join-Path $Root 'approval-worker.json') @{pid=$p.Id;createdUtc=$child.CreationDate.ToUniversalTime().ToString('o');path=$ApprovalHelper}
        }
        if(-not $p.WaitForExit(90000)){$p.Kill();$p.WaitForExit();throw 'Core approval timed out'}
        if($p.ExitCode -ne 0){throw 'Official core approval failed'}
    }finally{$p.Dispose()}
    if((Hash $ExecutingCore) -cne $ExpectedHash){throw 'Approved core copy mismatch'}
}
function Check-OwnerRuntime([switch]$Candidate) {
    if($Plan.policy -ceq 'ui-update'){
        if($ExecutingCore -ceq $ApprovedCore){
            $expected=if(-not $Candidate -and $Plan.oldRuntimeLayout -ceq 'approved'){'owner-runtime.before.yaml'}else{'owner-runtime.expected.yaml'}
            Assert-YamlEqual (Join-Path $Root $expected) (Join-Path $Plan.serviceOwnerDirectory 'runtime\config.yaml')
        }
        return
    }
    if($Plan.runtimeLayout -cne 'approved'){return}
    $before=Join-Path $Root 'owner-runtime.before.yaml'
    $expectedHash=$Plan.ownerRuntimeSha256
    if($Candidate -and $Plan.observerConfig){$before=Join-Path $Root 'owner-runtime.expected.yaml';$expectedHash=$Plan.observerRuntimeSha256}
    $actual=Join-Path $Plan.serviceOwnerDirectory 'runtime\config.yaml'
    $validator=Join-Path $Root 'yaml-equivalence.exe'
    foreach($path in @($before,$actual,$validator)){No-Reparse $path}
    if(-not $expectedHash -or (Hash $before) -cne $expectedHash){throw 'Owner runtime backup drift'}
    if((Hash $actual) -ceq $expectedHash){return}
    if((Hash $validator) -cne $Plan.yamlValidatorSha256){throw 'Owner runtime validator drift'}
    $equal=& $validator $before $actual
    if($LASTEXITCODE -ne 0 -or $equal -cne 'STCVRC_YAML_EQUAL'){throw 'Owner runtime policy drift'}
}
function Assert-YamlEqual([string]$Expected,[string]$Actual) {
    foreach($path in @($Expected,$Actual)){No-Reparse $path}
    $equal=& (Join-Path $Root 'yaml-equivalence.exe') $Expected $Actual
    if($LASTEXITCODE -ne 0 -or $equal -cne 'STCVRC_YAML_EQUAL'){throw 'Migration YAML data drift'}
}
function Preserve-History([ValidateSet('before','rollback')][string]$Phase) {
    $preserver=Join-Path $Root 'preserve-evidence.ps1'
    No-Reparse $preserver
    if(-not $Plan.evidenceScriptSha256 -or (Hash $preserver) -cne $Plan.evidenceScriptSha256){throw 'Evidence preserver hash mismatch'}
    $destination=Join-Path $Root ('history-'+$Phase+'-'+[DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss-fffffff'))
    $parameters=@{Destination=$destination;AppDirectory=$Plan.appRoot;Days=14;RequireComplete=$true}
    if($Plan.serviceOwnerDirectory -and ($Plan.policy -cne 'ui-update' -or (Test-Path -LiteralPath (Join-Path $Plan.serviceOwnerDirectory 'logs')))){$parameters.ServiceOwnerDirectory=$Plan.serviceOwnerDirectory}
    $null=& $preserver @parameters
    $manifestPath=Join-Path $destination 'manifest.json'
    $manifest=Read-Json $manifestPath
    if($manifest.status -cne 'preserved' -or $manifest.host -cne $env:COMPUTERNAME){throw 'History preservation not complete'}
    Write-Json (Join-Path $Root ('history-'+$Phase+'-result.json')) @{pass=$true;manifestSha256=(Hash $manifestPath);directory=[IO.Path]::GetFileName($destination);at=[DateTime]::UtcNow.ToString('o')}
}
function Stop-Runtime {
    foreach($p in (Exact-Processes $Ui)){Stop-Process -Id $p.ProcessId -Force}
    $s=Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if($s -and $s.Status -ne 'Stopped'){Stop-Service -Name $ServiceName -Force;$s.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(20))}
    foreach($path in (@($Core,$ExecutingCore,$ApprovedCore)|Select-Object -Unique)){
        foreach($p in (Exact-Processes $path)){Stop-Process -Id $p.ProcessId -Force}
        if(@(Exact-Processes $path).Count){throw 'Core remains after stop'}
    }
}
function Wait-Core([string]$Version,[int]$Seconds=45) {
    $until=(Get-Date).AddSeconds($Seconds)
    do {
        try {
            $s=Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
            $c=@(Exact-Processes $ExecutingCore)
            $v=Api '/version'
            $cfg=Api '/configs'
            $ports=@(Get-NetTCPConnection -State Listen | Where-Object {$_.OwningProcess -eq $c[0].ProcessId} | Select-Object -ExpandProperty LocalPort)
            if($s.State -eq 'Running' -and $s.StartMode -eq 'Auto' -and $s.StartName -ceq 'LocalSystem' -and $s.PathName.Trim('"') -ieq $ServiceExe -and $c.Count -eq 1 -and $c[0].ParentProcessId -eq $s.ProcessId -and $c[0].SessionId -eq 0 -and $v.version -ceq $Version -and $ports -contains 7897 -and $ports -contains 9097 -and [bool]$cfg.tun.enable -eq [bool]$Plan.tunEnabled){return}
        } catch {}
        Start-Sleep -Seconds 1
    } while((Get-Date) -lt $until)
    throw 'Expected service-owned core/controller did not become ready'
}
function Check-Http {
    $result=@()
    foreach($x in @(@('gstatic','https://www.gstatic.com/generate_204',204),@('control','https://www.cloudflare.com/cdn-cgi/trace',200))){
        $attempts=@()
        for($attempt=1;$attempt -le 2;$attempt++){
            $timer=[Diagnostics.Stopwatch]::StartNew()
            try {
                $r=Invoke-WebRequest -Uri $x[1] -Proxy 'http://127.0.0.1:7897' -UseBasicParsing -TimeoutSec 10
                if([int]$r.StatusCode -ne $x[2]){throw 'Application canary status mismatch'}
                $attempts+=,@{attempt=$attempt;status=[int]$r.StatusCode;elapsedMs=$timer.ElapsedMilliseconds}
                break
            } catch {
                $code=if($_.Exception.Response){[int]$_.Exception.Response.StatusCode}else{0}
                $attempts+=,@{attempt=$attempt;status=$code;type=$_.Exception.GetType().Name;webStatus=[string]$_.Exception.Status;baseType=$_.Exception.GetBaseException().GetType().Name;hresult=$_.Exception.GetBaseException().HResult;elapsedMs=$timer.ElapsedMilliseconds}
                Write-Json (Join-Path $Root 'http-error.json') @{name=$x[0];attempts=$attempts;at=[DateTime]::UtcNow.ToString('o')}
                if($attempt -eq 2){throw}
                Start-Sleep -Seconds 1
            }
        }
        $result+=,@{name=$x[0];status=[int]$r.StatusCode;attempts=$attempts}
    }
    return $result
}
function Check-Selectors {
    $groups=(Api '/proxies').proxies
    foreach($p in $Plan.selectors.PSObject.Properties){if($groups.($p.Name).now -cne $p.Value){throw 'Captured manual selector drift'}}
}
function Candidate-Check([switch]$RefreshProviders) {
    if($Plan.policy -ceq 'ui-update'){Set-UiLayout $true;Assert-UiVersion $Plan.uiVersion;$null=Get-OwnerUiTask}
    Wait-Core $Plan.newVersion
    Check-OwnerRuntime -Candidate
    if((Hash $ExecutingCore) -cne ($Plan.entries|Where-Object id -eq 'core').after){throw 'Executing candidate core mismatch'}
    $reserialized=@()
    foreach($e in $Plan.entries){
        if($Plan.policy -ceq 'ui-update' -and $e.id -in @('runtime','settings')){
            if($e.id -ceq 'settings'){Assert-YamlEqual (Join-Path $Root 'settings.expected.yaml') $e.target}
            $reserialized+=,$e.id
            continue
        }
        if((Hash $e.target) -ceq $e.after){continue}
        if($e.id -notin @('runtime','registry','settings')){throw 'Candidate file drift'}
        $expected=Join-Path $Root ($e.id+$(if($e.replace){'.new'}else{'.old'}))
        No-Reparse $expected
        if((Hash $expected) -cne $e.after){throw 'Expected YAML file drift'}
        $equal=& (Join-Path $Root 'yaml-equivalence.exe') $expected $e.target
        if($LASTEXITCODE -ne 0 -or $equal -cne 'STCVRC_YAML_EQUAL'){throw 'Candidate YAML data drift'}
        $reserialized+=,$e.id
    }
    $groups=(Api '/proxies').proxies
    if($groups.PSObject.Properties.Name -contains 'VPS-DEFAULT' -or $groups.PSObject.Properties.Name -contains 'VPS-AUTO'){throw 'Retired group remains'}
    if($Plan.policy -in @('four-choices','provider-repair','core-update','ui-update')){
        if($groups.'FOREIGN-EGRESS'.type -cne 'Selector' -or $groups.'FOREIGN-EGRESS'.hidden -or ($groups.'FOREIGN-EGRESS'.all -join ',') -cne 'VPS-POOL,4VPS,GC,DIRECT'){throw 'Foreign choices drift'}
        if($groups.'VPS-POOL'.type -cne 'Fallback' -or -not $groups.'VPS-POOL'.hidden -or $groups.'VPS-POOL'.fixed -or ($groups.'VPS-POOL'.all -join ',') -cne 'VPS-LATENCY,DIRECT'){throw 'Automatic fallback drift'}
        if($groups.'VPS-LATENCY'.type -cne 'URLTest' -or -not $groups.'VPS-LATENCY'.hidden -or $groups.'VPS-LATENCY'.fixed -or ($groups.'VPS-LATENCY'.all -join ',') -cne 'GC,4VPS'){throw 'Latency pool drift'}
    } else {
        if($groups.'FOREIGN-EGRESS'.fixed -or $groups.'VPS-POOL'.fixed -or -not $groups.'VPS-POOL'.hidden){throw 'Foreign policy is not automatic/hidden'}
        if(($groups.'FOREIGN-EGRESS'.all -join ',') -cne 'VPS-POOL,DIRECT' -or ($groups.'VPS-POOL'.all -join ',') -cne 'VPS-GREEN,4VPS'){throw 'Foreign policy topology drift'}
    }
    Check-Selectors
    $http=Check-Http
    $foreign=(Api '/proxies/FOREIGN-EGRESS').now
    if($Plan.policy -in @('provider-repair','core-update','ui-update') -and $foreign -in @('4VPS','GC')){$leaf=$foreign}
    else {
        if($foreign -cne 'VPS-POOL'){throw 'Management acceptance requires a working VPS, not DIRECT'}
        if($Plan.policy -in @('four-choices','provider-repair','core-update','ui-update') -and (Api '/proxies/VPS-POOL').now -cne 'VPS-LATENCY'){throw 'Management acceptance requires a working VPS leaf'}
        $leaf=if($Plan.policy -in @('four-choices','provider-repair','core-update','ui-update')){(Api '/proxies/VPS-LATENCY').now}else{(Api '/proxies/VPS-POOL').now}
    }
    $providers=@()
    if($Plan.policy -ceq 'provider-repair'){
        $since=(Get-Item -LiteralPath (Join-Path $Root 'mutation.started')).LastWriteTimeUtc
        foreach($name in $Plan.repairedProviders){
            if($RefreshProviders){$null=Api ('/providers/rules/'+$name) Put $null 35}
            $provider=(Api '/providers/rules').providers.$name
            if($provider.ruleCount -le 0 -or [DateTime]::Parse($provider.updatedAt).ToUniversalTime() -lt $since){throw 'Repaired provider did not fetch fresh rules'}
            $providers+=,@{name=$name;ruleCount=$provider.ruleCount;updatedAt=$provider.updatedAt}
        }
    }
    return @{pass=$true;http=$http;pool=$leaf;providers=$providers;consumerConfirmed=$false;yamlReserialized=$reserialized;coreVersion=(Api '/version').version;executingCoreHash=(Hash $ExecutingCore)}
}
function Remove-GuardTask {
    $task=Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if($task){
        if(@($task.Actions).Count -ne 1 -or -not $task.Actions[0].Arguments.Contains($Root)){throw 'Foreign task collision'}
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
    Remove-ApplyTask
}
function Remove-ApplyTask {
    $task=Get-ScheduledTask -TaskName $ApplyTaskName -ErrorAction SilentlyContinue
    if($task){
        if(@($task.Actions).Count -ne 1 -or -not $task.Actions[0].Arguments.Contains($Root)){throw 'Foreign apply task collision'}
        Unregister-ScheduledTask -TaskName $ApplyTaskName -Confirm:$false
    }
}
function Restore-Old {
    State 'rolling-back'
    $backup=Read-Json (Join-Path $Root 'backup.json')
    foreach($e in $Plan.entries){if((Hash (Join-Path $Root ($e.id+'.old'))) -cne $e.before){throw 'Rollback backup hash mismatch'}}
    if($Plan.policy -ceq 'ui-update'){
        try {Preserve-History 'rollback'}catch{Write-Json (Join-Path $Root 'history-rollback-error.json') @{type=$_.Exception.GetType().Name;at=[DateTime]::UtcNow.ToString('o')}}
    }
    Stop-Runtime
    if(Test-Path -LiteralPath (Join-Path $Root 'mutation.started')){
        if($Plan.policy -ceq 'ui-update'){Install-UiGeneration $false}
        foreach($e in $Plan.entries){[IO.File]::Copy((Join-Path $Root ($e.id+'.old')),$e.target,$true)}
        if($backup.cachePresent){
            if((Hash (Join-Path $Root 'cache.old')) -cne $backup.cacheHash){throw 'Cache backup hash mismatch'}
            [IO.File]::Copy((Join-Path $Root 'cache.old'),$CachePath,$true)
        } elseif(Test-Path -LiteralPath $CachePath){Remove-Item -LiteralPath $CachePath -Force}
    }
    foreach($e in $Plan.entries){if((Hash $e.target) -cne $e.before){throw 'Restored file hash mismatch'}}
    Register-ApprovedCore ($Plan.entries|Where-Object id -eq 'core').before
    if($Plan.policy -ceq 'ui-update'){Register-UiService ($Plan.entries|Where-Object id -eq 'core').before}
    Start-Service -Name $ServiceName
    if($Plan.policy -ceq 'ui-update' -or $Plan.observerConfig){Start-OwnerUi}
    Wait-Core $Plan.oldVersion
    Check-OwnerRuntime
    if($Plan.policy -in @('core-update','ui-update')){Restore-Selectors}
    if($Plan.policy -ceq 'ui-update'){
        foreach($e in $Plan.entries|Where-Object id -in @('runtime','registry','settings')){Assert-YamlEqual (Join-Path $Root ($e.id+'.old')) $e.target}
    }
    if($Plan.policy -in @('provider-repair','core-update','ui-update')){Check-Selectors}
    $http=Check-Http
    State 'rolled-back'
    Write-Json (Join-Path $Root 'rollback-result.json') @{pass=$true;at=[DateTime]::UtcNow.ToString('o');http=$http;coreHash=(Hash $Core);executingCoreHash=(Hash $ExecutingCore);filesRestored=$true;uiStopped=($Plan.policy -cne 'ui-update' -and -not $Plan.observerConfig);uiVersion=[Diagnostics.FileVersionInfo]::GetVersionInfo($Ui).ProductVersion}
    Remove-GuardTask
}
function Stop-ApplyWorker {
    $armed=Read-Json (Join-Path $Root 'armed.json')
    $p=Get-CimInstance Win32_Process -Filter "ProcessId=$($armed.pid)"
    if($p -and $p.CreationDate.ToUniversalTime().ToString('o') -ceq $armed.processCreated -and $p.CommandLine.Contains($Root) -and $p.CommandLine.Contains('Apply')){Stop-Process -Id $p.ProcessId -Force}
    $helperState=Join-Path $Root 'approval-worker.json'
    if(Test-Path -LiteralPath $helperState){
        $child=Read-Json $helperState
        $p=Get-CimInstance Win32_Process -Filter "ProcessId=$($child.pid)"
        if($child.path -ceq $ApprovalHelper -and $p -and $p.ExecutablePath -ieq $ApprovalHelper -and $p.CreationDate.ToUniversalTime().ToString('o') -ceq $child.createdUtc){Stop-Process -Id $p.ProcessId -Force}
    }
    $installerState=Join-Path $Root 'installer-worker.json'
    if($Plan.policy -ceq 'ui-update' -and (Test-Path -LiteralPath $installerState)){
        $child=Read-Json $installerState
        $allowed=@((Join-Path $Root 'ui-new.exe'),(Join-Path $Root 'ui-old.exe'),$ApprovalHelper,$ServiceUninstaller,(Join-Path $InstallRoot 'uninstall.exe'))
        $p=Get-CimInstance Win32_Process -Filter "ProcessId=$($child.pid)"
        if($child.path -cin $allowed -and $p -and $p.ExecutablePath.Replace('\\?\','') -ieq $child.path -and $p.CreationDate.ToUniversalTime().ToString('o') -ceq $child.createdUtc){Stop-Process -Id $p.ProcessId -Force}
    }
}

Guard
if($Mode -eq 'Preflight'){
    foreach($e in $Plan.entries){if((Hash $e.target) -cne $e.before){throw 'Baseline file drift'}}
    Wait-Core $Plan.oldVersion
    Check-OwnerRuntime
    if((Hash $ExecutingCore) -cne ($Plan.entries|Where-Object id -eq 'core').before){throw 'Executing core differs from baseline'}
    if($Plan.policy -in @('provider-repair','core-update','ui-update')){Check-Selectors}
    @{pass=$true;host=$env:COMPUTERNAME;runtimeChanged=$false}|ConvertTo-Json -Compress
    exit 0
}
$admin=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if(-not $admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Elevated token required'}
if($Mode -eq 'Launch'){
    if((Test-Path -LiteralPath $StatePath) -or (Get-ScheduledTask -TaskName $ApplyTaskName -ErrorAction SilentlyContinue) -or (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)){throw 'A transaction is already pending or this one was used'}
    $action=New-ScheduledTaskAction -Execute $PowerShell -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$PSCommandPath+'" -Mode Apply -Transaction "'+$Root+'" -DeadlineSeconds '+$DeadlineSeconds+' -LabPause '+$LabPause)
    $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 12)
    $null=Register-ScheduledTask -TaskName $ApplyTaskName -Action $action -Principal $principal -Settings $settings
    Start-ScheduledTask -TaskName $ApplyTaskName
    @{launched=$true;task=$ApplyTaskName}|ConvertTo-Json -Compress
    exit 0
}
try {
    if($Mode -eq 'Watch'){
        $armed=Read-Json (Join-Path $Root 'armed.json')
        if($armed.planHash -cne (Hash $PlanPath)){throw 'Armed plan drift'}
        Write-Json (Join-Path $Root 'watch-ready.json') @{pid=$PID;session=(Get-Process -Id $PID).SessionId;at=[DateTime]::UtcNow.ToString('o')}
        do {
            $phase=(Read-Json $StatePath).phase
            if($phase -in @('committed','rolled-back')){Acquire-Lock;Remove-GuardTask;exit 0}
            $boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
            if([DateTime]::UtcNow -ge [DateTime]::Parse($armed.deadline).ToUniversalTime() -or $boot -cne $armed.boot){break}
            Start-Sleep -Seconds 2
        } while($true)
        Stop-ApplyWorker
        Acquire-Lock
        if((Read-Json $StatePath).phase -notin @('committed','rolled-back')){Restore-Old}
    } elseif($Mode -eq 'Apply'){
        Acquire-Lock
        if(Test-Path -LiteralPath $StatePath){throw 'Transaction already used'}
        if(Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue){throw 'Another guarded rollout is pending'}
        $acl=Get-Acl -LiteralPath $Root
        $owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        $acl.SetAccessRuleProtection($true,$false)
        foreach($sid in @('S-1-5-18','S-1-5-32-544',$owner)){
            $rule=[Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow')
            $acl.AddAccessRule($rule)
        }
        Set-Acl -LiteralPath $Root -AclObject $acl
        $s=Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
        if($s.PathName.Trim('"') -ine $ServiceExe){throw 'Unexpected service binary'}
        Wait-Core $Plan.oldVersion
        Check-OwnerRuntime
        if((Hash $ExecutingCore) -cne ($Plan.entries|Where-Object id -eq 'core').before){throw 'Executing core differs from baseline'}
        if($Plan.policy -in @('provider-repair','core-update','ui-update')){Check-Selectors}
        Preserve-History 'before'
        foreach($e in $Plan.entries){
            if((Hash $e.target) -cne $e.before){throw 'Baseline file drift'}
            [IO.File]::Copy($e.target,(Join-Path $Root ($e.id+'.old')),$false)
            if((Hash (Join-Path $Root ($e.id+'.old'))) -cne $e.before){throw 'Backup mismatch'}
        }
        $backupInfo=@{cachePresent=$false;cacheHash=$null}
        if($Plan.policy -ceq 'ui-update' -or $Plan.observerConfig){
            $null=Get-OwnerUiTask
            $xml=Join-Path $Root 'ui-task.old.xml'
            [IO.File]::WriteAllText($xml,(Export-ScheduledTask -TaskName $Plan.uiTask))
            $backupInfo.uiTaskHash=Hash $xml
        }
        Write-Json (Join-Path $Root 'backup.json') $backupInfo
        $proc=Get-CimInstance Win32_Process -Filter "ProcessId=$PID"
        Write-Json (Join-Path $Root 'armed.json') @{pid=$PID;processCreated=$proc.CreationDate.ToUniversalTime().ToString('o');deadline=[DateTime]::UtcNow.AddSeconds($DeadlineSeconds).ToString('o');planHash=(Hash $PlanPath);boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')}
        State 'armed'
        $action=New-ScheduledTaskAction -Execute $PowerShell -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$PSCommandPath+'" -Mode Watch -Transaction "'+$Root+'"')
        $triggers=@((New-ScheduledTaskTrigger -AtStartup),(New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds($DeadlineSeconds)))
        $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $settings=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 15) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
        $null=Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $triggers -Principal $principal -Settings $settings
        Start-ScheduledTask -TaskName $TaskName
        $until=(Get-Date).AddSeconds(20)
        while(-not (Test-Path -LiteralPath (Join-Path $Root 'watch-ready.json')) -and (Get-Date) -lt $until){Start-Sleep -Milliseconds 200}
        $ready=Read-Json (Join-Path $Root 'watch-ready.json')
        if($ready.session -ne 0 -or -not (Get-Process -Id $ready.pid -ErrorAction SilentlyContinue)){throw 'Independent SYSTEM watchdog not ready'}
        Stop-Runtime
        if($LabPause -eq 'AfterStop'){State 'lab-paused-after-stop';Start-Sleep -Seconds 600}
        foreach($e in $Plan.entries){if((Hash $e.target) -cne $e.before){throw 'Baseline changed during quiesce'}}
        if(Test-Path -LiteralPath $CachePath){
            No-Reparse $CachePath
            [IO.File]::Copy($CachePath,(Join-Path $Root 'cache.old'),$false)
            $backupInfo.cachePresent=$true;$backupInfo.cacheHash=Hash (Join-Path $Root 'cache.old')
            Write-Json (Join-Path $Root 'backup.json') $backupInfo
        }
        [IO.File]::WriteAllText((Join-Path $Root 'mutation.started'),'STCVRC_SAFE_V1')
        State 'applying'
        if($Plan.policy -ceq 'ui-update'){Install-UiGeneration $true}
        foreach($e in $Plan.entries){if($e.replace){[IO.File]::Copy((Join-Path $Root ($e.id+'.new')),$e.target,$true)}}
        Register-ApprovedCore ($Plan.entries|Where-Object id -eq 'core').after
        if($Plan.policy -ceq 'ui-update'){Register-UiService ($Plan.entries|Where-Object id -eq 'core').after}
        if($LabPause -eq 'AfterCopy'){State 'lab-paused-after-copy';Start-Sleep -Seconds 600}
        Start-Service -Name $ServiceName
        if($Plan.policy -ceq 'ui-update' -or $Plan.observerConfig){Start-OwnerUi}
        Wait-Core $Plan.newVersion
        if($Plan.policy -ceq 'four-choices'){
            foreach($g in @('VPS-POOL','VPS-LATENCY')){$null=Api ('/proxies/'+$g) Delete}
            $null=Api '/proxies/FOREIGN-EGRESS' Put @{name='VPS-POOL'}
        } elseif($Plan.policy -notin @('provider-repair','core-update','ui-update')) {
            foreach($g in @('FOREIGN-EGRESS','VPS-POOL')){$null=Api ('/proxies/'+$g) Delete}
        }
        Restore-Selectors
        $check=Candidate-Check -RefreshProviders
        Write-Json (Join-Path $Root 'candidate-result.json') $check
        State 'awaiting-confirmation'
    } elseif($Mode -eq 'Confirm'){
        if(-not $ConsumerConfirmed){throw 'A fresh real consumer exchange must be confirmed explicitly'}
        Acquire-Lock
        if((Read-Json $StatePath).phase -cne 'awaiting-confirmation'){throw 'Candidate is not awaiting confirmation'}
        $armed=Read-Json (Join-Path $Root 'armed.json')
        if([DateTime]::UtcNow -ge [DateTime]::Parse($armed.deadline).ToUniversalTime().AddSeconds(-15)){throw 'Confirmation too close to rollback deadline'}
        $null=Candidate-Check
        State 'committed'
        Remove-GuardTask
    } else {
        Stop-ApplyWorker
        Acquire-Lock
        Restore-Old
    }
} catch {
    $errorType=$_.Exception.GetType().Name
    Write-Json (Join-Path $Root ($Mode.ToLowerInvariant()+'-error.json')) @{type=$errorType;line=$_.InvocationInfo.ScriptLineNumber;at=[DateTime]::UtcNow.ToString('o')}
    if($Mode -eq 'Apply' -and (Test-Path -LiteralPath (Join-Path $Root 'watch-ready.json'))){
        try {Restore-Old} catch {State 'rollback-failed'}
    }
    throw ('STCVRC transaction failed: '+$errorType)
} finally {
    try {if($Mode -eq 'Apply'){Remove-ApplyTask}}
    finally {if($Lock){$Lock.Dispose()}}
}
@{mode=$Mode;phase=(Read-Json $StatePath).phase;transaction=$Root}|ConvertTo-Json -Compress
