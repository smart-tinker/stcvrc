[CmdletBinding()]
param([Parameter(Mandatory)][ValidateSet('Probe','Recovery')][string]$Action,
      [Parameter(Mandatory)][string]$Transaction)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$root=[IO.Path]::GetFullPath($Transaction).TrimEnd('\')
if($env:COMPUTERNAME -cne 'LABHOST' -or $root -cnotmatch '^C:\\Users\\FixtureUser\\stcvrc-fullstack-lab\\transactions\\stcvrc-safe-[0-9]{8}-[0-9]{6}$'){throw 'Wrong lab scope'}
$plan=[IO.File]::ReadAllText((Join-Path $root 'plan.json'))|ConvertFrom-Json
function Assert-Transaction {
    if($plan.schema -ne 1 -or -not $plan.lab -or $plan.host -cne 'LABHOST' -or $plan.root -cne $root -or $plan.tunEnabled){throw 'Unexpected transaction'}
    if($plan.policy -cne 'core-update'){
        $core=@($plan.entries|Where-Object id -ceq 'core')
        $sources=@{
            accepted=@('2.5.2','1.19.29-STCVRC-urltest-candidate-20260905','40828a0f84c2c18fa917fa23246c7b87fc2c7d798c6a7c13a3db1dc997d94540')
            next=@('2.5.5','1.19.31-STCVRC-lab-20260924g','5eef492d112a6ee9e81bce2298369f9feb5b63fbae9efc7e5a5dd9fc7441b439')
        }
        $source=$sources[$plan.sourceStack]
        if($plan.policy -cne 'ui-update' -or $plan.runtimeLayout -cne 'ui-migration' -or $plan.targetStack -cne 'candidate' -or $plan.uiVersion -cne '2.5.8' -or $plan.newVersion -cne '1.19.32-STCVRC-candidate-20261007' -or $core.Count -ne 1 -or $core[0].after -cne 'b072d09f0754b92cbe737757d2c63111d20ecf00e5d90b534ce2f9492feb9986' -or $plan.uiInstallers.new -cne '821c0f5957f84c8f7d14532044840e8280d708af24a6a143db360b49bd1e7302' -or -not $source -or $plan.oldUiVersion -cne $source[0] -or $plan.oldVersion -cne $source[1] -or $core[0].before -cne $source[2]){throw 'Unreviewed candidate TUN pair'}
    }
}
Assert-Transaction
$headers=@{Authorization=('Bearer '+$plan.controllerSecret)}
function Api([string]$Path,[string]$Method='Get',$Body=$null){
    $args=@{Uri=('http://127.0.0.1:9097'+$Path);Headers=$headers;Method=$Method;TimeoutSec=5;UseBasicParsing=$true}
    if($null -ne $Body){$args.Body=$Body|ConvertTo-Json -Depth 8 -Compress;$args.ContentType='application/json'}
    Invoke-RestMethod @args
}
function Network-State {
    $routes=@(Get-NetRoute|Sort-Object InterfaceIndex,DestinationPrefix,NextHop|Select-Object InterfaceIndex,DestinationPrefix,NextHop,RouteMetric,PolicyStore)
    $dns=@(Get-DnsClientServerAddress|Sort-Object InterfaceIndex,AddressFamily|Select-Object InterfaceIndex,AddressFamily,ServerAddresses)
    $hash=[Security.Cryptography.SHA256]::Create()
    try {
        $fingerprint=([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes(($routes|ConvertTo-Json -Compress))))).Replace('-','').ToLowerInvariant()
        $dnsHash=([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes(($dns|ConvertTo-Json -Depth 4 -Compress))))).Replace('-','').ToLowerInvariant()
    }finally{$hash.Dispose()}
    @{routeHash=$fingerprint;dnsHash=$dnsHash;routeCount=$routes.Count;tunUp=@(Get-NetAdapter -IncludeHidden|Where-Object {$_.Name -ceq 'STCVRC-Lab-TUN' -and $_.Status -eq 'Up'}).Count}
}
function Assert-Watch {
    $armed=[IO.File]::ReadAllText((Join-Path $root 'armed.json'))|ConvertFrom-Json
    $ready=[IO.File]::ReadAllText((Join-Path $root 'watch-ready.json'))|ConvertFrom-Json
    $phase=([IO.File]::ReadAllText((Join-Path $root 'state.json'))|ConvertFrom-Json).phase
    $task=Get-ScheduledTask -TaskName 'STCVRC-Safe-Rollout'
    $sid=if($task.Principal.UserId -like 'S-1-*'){$task.Principal.UserId}else{([Security.Principal.NTAccount]::new($task.Principal.UserId)).Translate([Security.Principal.SecurityIdentifier]).Value}
    $worker=Get-CimInstance Win32_Process -Filter "ProcessId=$($ready.pid)"
    $remaining=([DateTime]::Parse($armed.deadline).ToUniversalTime()-[DateTime]::UtcNow).TotalSeconds
    $shell=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $expected='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+(Join-Path $root 'transaction.ps1')+'" -Mode Watch -Transaction "'+$root+'"'
    if($phase -cne 'awaiting-confirmation' -or $sid -cne 'S-1-5-18' -or $task.State -ne 'Running' -or $ready.session -ne 0 -or -not $worker -or $worker.SessionId -ne 0 -or $worker.ExecutablePath -ine $shell -or -not $worker.CommandLine.EndsWith((' '+$expected),[StringComparison]::Ordinal) -or @($task.Actions).Count -ne 1 -or $task.Actions[0].Execute -ine $shell -or $task.Actions[0].Arguments -cne $expected -or $remaining -lt 120){throw 'Independent rollback not ready'}
    if((Invoke-CimMethod -InputObject $worker -MethodName GetOwnerSid).Sid -cne 'S-1-5-18'){throw 'Rollback worker is not SYSTEM'}
    if((Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o') -cne $armed.boot){throw 'Rollback boot changed'}
    if($armed.planHash -ine (Get-FileHash -LiteralPath (Join-Path $root 'plan.json')).Hash){throw 'Armed plan changed'}
    @{system=$true;running=$true;deadline=$armed.deadline;secondsRemaining=[int]$remaining}
}
function Assert-Runtime([switch]$Candidate) {
    $entry=@($plan.entries|Where-Object id -ceq 'core')
    if($entry.Count -ne 1){throw 'Missing unique core identity'}
    $version=if($Candidate){$plan.newVersion}else{$plan.oldVersion}
    $expectedHash=if($Candidate){$entry[0].after}else{$entry[0].before}
    $ui=if(-not $Candidate -and $plan.policy -ceq 'ui-update'){$plan.oldUiVersion}else{$plan.uiVersion}
    $legacy=$ui -ceq '2.5.2'
    $corePath=if($legacy){'C:\Program Files\Clash Verge\verge-mihomo.exe'}else{'C:\ProgramData\clash-verge-service\cores\verge-mihomo.exe'}
    $servicePath=if($legacy){'C:\Program Files\Clash Verge\resources\clash-verge-service.exe'}else{'C:\ProgramData\clash-verge-service\bin\clash-verge-service.exe'}
    $workers=@(Get-CimInstance Win32_Process -Filter "Name='verge-mihomo.exe'")
    $service=Get-CimInstance Win32_Service -Filter "Name='clash_verge_service'"
    if($workers.Count -ne 1 -or $workers[0].SessionId -ne 0 -or $workers[0].ExecutablePath -ine $corePath -or $workers[0].ParentProcessId -ne $service.ProcessId -or $service.State -cne 'Running' -or $service.StartMode -cne 'Auto' -or $service.StartName -cne 'LocalSystem' -or $service.PathName.Trim('"') -ine $servicePath){throw 'Unexpected service-owned runtime'}
    $actualHash=(Get-FileHash -LiteralPath $corePath).Hash
    $actualVersion=(Api '/version').version
    $actualUi=((Get-Item -LiteralPath 'C:\Program Files\Clash Verge\clash-verge.exe').VersionInfo.ProductVersion.Split('.')[0..2] -join '.')
    if($actualHash -ine $expectedHash -or $actualVersion -cne $version -or $actualUi -cne $ui){throw 'Runtime differs from exact transaction generation'}
    @{pass=$true;coreHash=$actualHash;version=$actualVersion;uiVersion=$actualUi}
}
function Probe-Leaf([string]$Leaf){
    $selectorLock=[IO.File]::Open((Join-Path $root 'transaction.lock'),'OpenOrCreate','ReadWrite','None')
    try {
        $null=Assert-Watch
        $null=Api '/proxies/FOREIGN-EGRESS' Put @{name=$Leaf}
    }finally{$selectorLock.Dispose()}
    $selected=(Api '/proxies/FOREIGN-EGRESS').now
    $address=@([Net.Dns]::GetHostAddresses('www.cloudflare.com')|Where-Object AddressFamily -eq 'InterNetwork')[0]
    $socket=[Net.Sockets.TcpClient]::new()
    $observed=$null
    try {
        $pending=$socket.BeginConnect($address,443,$null,$null)
        if(-not $pending.AsyncWaitHandle.WaitOne(8000)){throw 'TUN TCP timeout'}
        $socket.EndConnect($pending)
        $port=$socket.Client.LocalEndPoint.Port
        for($i=0;$i -lt 10;$i++){
            $connection=@((Api '/connections').connections|Where-Object {$_.metadata.sourcePort -eq $port -and $_.metadata.destinationPort -eq '443'})
            if($connection.Count -eq 1){$observed=@{type=$connection[0].metadata.type;chains=@($connection[0].chains);rule=$connection[0].rule};break}
            Start-Sleep -Milliseconds 200
        }
    } finally {$socket.Close()}
    $checks=@(foreach($target in @(@('google-204','https://www.gstatic.com/generate_204',204),@('control-body','https://www.cloudflare.com/cdn-cgi/trace',200))){
        $raw=& "$env:SystemRoot\System32\curl.exe" --silent --noproxy '*' --connect-timeout 5 --max-time 12 --max-filesize 16384 --output NUL --write-out '%{http_code} %{time_total} %{size_download}' $target[1]
        $code=$LASTEXITCODE
        $parts=($raw -join '').Trim().Split(' ')
        @{target=$target[0];exitCode=$code;status=$parts[0];seconds=$parts[1];bytes=$parts[2];pass=($code -eq 0 -and $parts[0] -eq [string]$target[2])}
    })
    @{leaf=$Leaf;selected=$selected;connection=$observed;application=$checks;pass=($selected -ceq $Leaf -and $observed -and $observed.type -ceq 'Tun' -and $observed.chains -contains $Leaf -and @($checks|Where-Object {-not $_.pass}).Count -eq 0)}
}
$result=@{action=$Action;at=[DateTime]::UtcNow.ToString('o');pass=$false}
try {
    if($Action -eq 'Probe'){
        if(Test-Path -LiteralPath (Join-Path $root 'tun-result.json')){throw 'TUN probe cannot be repeated'}
        $result.watch=Assert-Watch
        $result.planHash=(Get-FileHash -LiteralPath (Join-Path $root 'plan.json')).Hash
        $result.runtime=Assert-Runtime -Candidate
        if((Api '/configs').tun.enable){throw 'TUN baseline enabled'}
        $result.before=Network-State
        if($result.before.tunUp){throw 'Existing lab TUN'}
        # Baseline capture is read-only but may take time; do not enable TUN
        # using a guard observation made before that capture.
        $tunLock=[IO.File]::Open((Join-Path $root 'transaction.lock'),'OpenOrCreate','ReadWrite','None')
        try {
            $result.watch=Assert-Watch
            # Serialize only the bounded enable call against Confirm/Watch/rollback.
            # No persisted settings/DNS change; restore restarts disabled baseline.
            $null=Api '/configs' Patch @{tun=@{enable=$true;device='STCVRC-Lab-TUN';stack='gvisor';mtu=1400;'auto-route'=$true;'auto-detect-interface'=$true;'strict-route'=$false;'dns-hijack'=@();'route-exclude-address'=@('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')}}
        }finally{$tunLock.Dispose()}
        Start-Sleep -Seconds 2
        $result.enabled=[bool](Api '/configs').tun.enable
        $result.during=Network-State
        $result.leaves=@(Probe-Leaf 'GC';Probe-Leaf '4VPS')
        $result.leftEnabledForRollback=[bool](Api '/configs').tun.enable
        $result.pass=($result.enabled -and $result.during.tunUp -eq 1 -and $result.during.routeHash -cne $result.before.routeHash -and $result.leftEnabledForRollback -and @($result.leaves|Where-Object {-not $_.pass}).Count -eq 0)
    } else {
        $probe=[IO.File]::ReadAllText((Join-Path $root 'tun-result.json'))|ConvertFrom-Json
        $phase=([IO.File]::ReadAllText((Join-Path $root 'state.json'))|ConvertFrom-Json).phase
        $armed=[IO.File]::ReadAllText((Join-Path $root 'armed.json'))|ConvertFrom-Json
        $rollback=[IO.File]::ReadAllText((Join-Path $root 'rollback-result.json'))|ConvertFrom-Json
        $result.network=Network-State
        $result.disabled=-not (Api '/configs').tun.enable
        $result.routeRestored=$result.network.routeHash -ceq $probe.before.routeHash
        $result.dnsRestored=$result.network.dnsHash -ceq $probe.before.dnsHash
        $result.baselineBound=($probe.planHash -ceq (Get-FileHash -LiteralPath (Join-Path $root 'plan.json')).Hash -and $probe.watch.deadline -ceq $armed.deadline)
        $result.selectorsRestored=$true
        foreach($entry in $plan.selectors.PSObject.Properties){if((Api ('/proxies/'+[Uri]::EscapeDataString($entry.Name))).now -cne $entry.Value){$result.selectorsRestored=$false}}
        $result.runtime=Assert-Runtime
        $result.pass=($phase -ceq 'rolled-back' -and $probe.pass -eq $true -and $rollback.pass -eq $true -and $rollback.filesRestored -eq $true -and $result.baselineBound -and $result.disabled -and $result.routeRestored -and $result.dnsRestored -and $result.selectorsRestored -and $result.network.tunUp -eq 0)
    }
} catch {$result.error=@{type=$_.Exception.GetType().Name;line=$_.InvocationInfo.ScriptLineNumber}}
$file=if($Action -eq 'Probe'){'tun-result.json'}else{'tun-recovery-result.json'}
[IO.File]::WriteAllText((Join-Path $root $file),($result|ConvertTo-Json -Depth 9 -Compress))
$result|ConvertTo-Json -Depth 9 -Compress
