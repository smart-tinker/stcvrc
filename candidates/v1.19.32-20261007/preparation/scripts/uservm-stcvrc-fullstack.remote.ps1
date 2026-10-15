[CmdletBinding()]
param(
    [ValidateSet('Library', 'Snapshot', 'Run', 'Cleanup')]
    [string]$Mode,
    [string]$LabRoot = (Join-Path $env:USERPROFILE 'stcvrc-fullstack-lab'),
    [string]$ExpectedInstallerSha256,
    [string]$ExpectedCoreSha256,
    [string]$ExpectedGeoIpSha256,
    [string]$ExpectedProfileSha256,
    [string]$ExpectedUiVersion = '2.5.2',
    [string]$ExpectedStockCoreVersion = '1.19.29',
    [string]$ExpectedCustomCoreToken = '1.19.29-STCVRC-openvpn-rekey-9e235082',
    [string]$ExpectedPrimaryEgress,
    [string]$ExpectedGreenEgress = '198.51.100.32',
    [int]$MixedPort = 7897,
    [int]$ControllerPort = 9097
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$ServiceName = 'clash_verge_service'
$TaskName = 'STCVRC-userVM-FullStack-Gate'
$ExpectedLabRoot = Join-Path $env:USERPROFILE 'stcvrc-fullstack-lab'
$GuardPath = Join-Path $LabRoot '.codex-stcvrc-fullstack-lab'
$InstallerPath = Join-Path $LabRoot 'input\Clash.Verge_2.5.2_x64-setup.exe'
$CandidateCorePath = Join-Path $LabRoot 'input\verge-mihomo.exe'
$CandidateProfilePath = Join-Path $LabRoot 'input\profile.yaml'
$CandidateGeoIpPath = Join-Path $LabRoot 'input\Country.mmdb'
$StockCoreBackupPath = Join-Path $LabRoot 'stock-verge-mihomo.exe'
$LogRoot = Join-Path $LabRoot 'logs'
$InstallRoot = 'C:\Program Files\Clash Verge'
$UiPath = Join-Path $InstallRoot 'clash-verge.exe'
$InstalledCorePath = Join-Path $InstallRoot 'verge-mihomo.exe'
$ServiceInstallPath = Join-Path $InstallRoot 'resources\clash-verge-service-install.exe'
$ServiceUninstallPath = Join-Path $InstallRoot 'resources\clash-verge-service-uninstall.exe'
$AppRoot = Join-Path $env:APPDATA 'io.github.clash-verge-rev.clash-verge-rev'
$LocalAppRoot = Join-Path $env:LOCALAPPDATA 'io.github.clash-verge-rev.clash-verge-rev'
$ProfileUid = 'LSTCVRCGate'
$ProfilePath = Join-Path $AppRoot "profiles\$ProfileUid.yaml"
$RuntimePath = Join-Path $AppRoot 'clash-verge.yaml'
$ControllerBase = "http://127.0.0.1:$ControllerPort"
$ControllerHeaders = @{}

function Resolve-NormalizedPath {
    param([Parameter(Mandatory)][string]$Path)
    $value=$Path.Trim().Trim('"')
    if($value -match '^\\\\\?\\[A-Za-z]:\\'){$value=$value.Substring(4)}
    if($value.StartsWith('\\?\') -or $value.StartsWith('\\.\')){throw 'Unsupported device path'}
    [IO.Path]::GetFullPath($value).TrimEnd('\')
}

function Test-SamePath {
    param([string]$Left, [string]$Right)
    if ([string]::IsNullOrWhiteSpace($Left) -or [string]::IsNullOrWhiteSpace($Right)) { return $false }
    [string]::Equals((Resolve-NormalizedPath $Left), (Resolve-NormalizedPath $Right), [StringComparison]::OrdinalIgnoreCase)
}

function Get-StringSha256 {
    param([string]$Value)
    $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { -join ($algorithm.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) } finally { $algorithm.Dispose() }
}

function Get-LabRuntimeLayout {
    param($Stack,[string]$Sid)
    if(-not $Stack -or $Stack.uiVersion -ceq '2.5.2'){
        return @{core=$InstalledCorePath;config=(Join-Path $AppRoot 'clash-verge.yaml');logs=(Join-Path $AppRoot 'logs\service');approved=$false}
    }
    if($Stack.schema -ne 1 -or $Stack.uiVersion -cnotin @('2.5.5','2.5.7','2.5.8') -or $Sid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$'){throw 'Unreviewed service runtime layout'}
    $owner=Join-Path 'C:\ProgramData\clash-verge-service\users' (Get-StringSha256 $Sid)
    @{core='C:\ProgramData\clash-verge-service\cores\verge-mihomo.exe';config=(Join-Path $owner 'runtime\config.yaml');logs=(Join-Path $owner 'logs');approved=$true}
}

function Assert-NoReparseAncestors {
    param([string]$Path)
    $p=Resolve-NormalizedPath $Path
    while($p){
        if((Test-Path -LiteralPath $p) -and ((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Runtime reparse path'}
        $p=Split-Path -Parent $p
    }
}

function Get-ProcessOwner {
    param([Parameter(Mandatory)]$Process)
    try {
        $owner = Invoke-CimMethod -InputObject $Process -MethodName GetOwner -ErrorAction Stop
        if ($owner.ReturnValue -eq 0) {
            if ($owner.Domain) { return "$($owner.Domain)\$($owner.User)" }
            return [string]$owner.User
        }
    } catch { }
    $null
}

function Get-ProcessOwnerSid {
    param([Parameter(Mandatory)]$Process)
    try {
        $owner = Invoke-CimMethod -InputObject $Process -MethodName GetOwnerSid -ErrorAction Stop
        if ($owner.ReturnValue -eq 0) { return [string]$owner.Sid }
    } catch { }
    $null
}

function Get-CvrProcesses {
    @(
        Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -in @('clash-verge.exe', 'verge-mihomo.exe', 'clash-verge-service.exe') } |
            Sort-Object Name, ProcessId |
            ForEach-Object {
                [ordered]@{
                    name = [string]$_.Name
                    pid = [int]$_.ProcessId
                    parentPid = [int]$_.ParentProcessId
                    sessionId = [int]$_.SessionId
                    owner = Get-ProcessOwner $_
                    ownerSid = Get-ProcessOwnerSid $_
                    executablePath = [string]$_.ExecutablePath
                }
            }
    )
}

function Get-UninstallEntries {
    $roots = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    @(
        foreach ($root in $roots) {
            Get-ItemProperty -Path $root -ErrorAction SilentlyContinue |
                Where-Object { [string]$_.DisplayName -match '(?i)Clash Verge' } |
                ForEach-Object {
                    [ordered]@{
                        key = [string]$_.PSPath
                        displayName = [string]$_.DisplayName
                        displayVersion = [string]$_.DisplayVersion
                        installLocation = [string]$_.InstallLocation
                        uninstallString = [string]$_.UninstallString
                    }
                }
        }
    )
}

function Get-RunEntries {
    $key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    $item = Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue
    if (-not $item) { return @() }
    @(
        $item.PSObject.Properties |
            Where-Object { $_.Name -notmatch '^PS' -and ([string]$_.Name -match '(?i)clash|verge' -or [string]$_.Value -match '(?i)clash-verge') } |
            Sort-Object Name |
            ForEach-Object { [ordered]@{ name = [string]$_.Name; value = [string]$_.Value } }
    )
}

function Get-HostBaseline {
    $defaultRoute = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1
    $internetSettings = Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
    $winHttpText = ([string](netsh.exe winhttp show proxy | Out-String)).Trim() -replace '\r\n', "`n"
    $hiddifyRoot = Join-Path $env:APPDATA 'Hiddify'
    $hiddifyItem = if (Test-Path -LiteralPath $hiddifyRoot) { Get-Item -LiteralPath $hiddifyRoot -Force } else { $null }
    $hiddifyFiles = if ($hiddifyItem) { @(Get-ChildItem -LiteralPath $hiddifyRoot -File -Recurse -Force -ErrorAction SilentlyContinue) } else { @() }
    $service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    $dns = @(
        Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.ServerAddresses.Count -gt 0 } |
            Sort-Object InterfaceIndex |
            ForEach-Object { [ordered]@{ interfaceIndex = $_.InterfaceIndex; serverAddresses = @($_.ServerAddresses) } }
    )
    $tunAdapters = @(
        Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '(?i)clash|mihomo|meta' -or $_.InterfaceDescription -match '(?i)clash|mihomo|meta' } |
            Sort-Object InterfaceIndex |
            ForEach-Object { [ordered]@{ interfaceIndex = $_.InterfaceIndex; name = $_.Name; status = [string]$_.Status } }
    )
    $state = [ordered]@{
        defaultRoute = if ($defaultRoute) {
            [ordered]@{
                interfaceIndex = $defaultRoute.InterfaceIndex
                nextHop = $defaultRoute.NextHop
                routeMetric = $defaultRoute.RouteMetric
                interfaceMetric = $defaultRoute.InterfaceMetric
            }
        } else { $null }
        winInet = [ordered]@{
            proxyEnable = if ($internetSettings) { [int]$internetSettings.ProxyEnable } else { 0 }
            proxyServer = if ($internetSettings) { [string]$internetSettings.ProxyServer } else { '' }
            autoConfigUrl = if ($internetSettings) { [string]$internetSettings.AutoConfigURL } else { '' }
        }
        winHttpSha256 = Get-StringSha256 $winHttpText
        dns = $dns
        hiddify = [ordered]@{
            present = [bool]$hiddifyItem
            fileCount = $hiddifyFiles.Count
            rootLastWriteUtc = if ($hiddifyItem) { $hiddifyItem.LastWriteTimeUtc.ToString('o') } else { $null }
        }
        cvr = [ordered]@{
            installPresent = Test-Path -LiteralPath $InstallRoot
            appRootPresent = Test-Path -LiteralPath $AppRoot
            localAppRootPresent = Test-Path -LiteralPath $LocalAppRoot
            service = if ($service) { [ordered]@{ name = $service.Name; state = $service.State; startMode = $service.StartMode; pathName = $service.PathName } } else { $null }
            processes = @(Get-CvrProcesses)
            taskPresent = [bool]$task
            uninstallEntries = @(Get-UninstallEntries)
            runEntries = @(Get-RunEntries)
            tunAdapters = $tunAdapters
        }
    }
    $canonical = $state | ConvertTo-Json -Depth 10 -Compress
    $footprintAbsent = (
        -not $state.cvr.installPresent -and -not $state.cvr.appRootPresent -and -not $state.cvr.localAppRootPresent -and
        -not $state.cvr.service -and @($state.cvr.processes).Count -eq 0 -and -not $state.cvr.taskPresent -and
        @($state.cvr.uninstallEntries).Count -eq 0 -and @($state.cvr.runEntries).Count -eq 0 -and @($state.cvr.tunAdapters).Count -eq 0
    )
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    [ordered]@{
        capturedAt = (Get-Date).ToString('o')
        host = $env:COMPUTERNAME
        user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        elevatedAdministrator = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        labAbsent = -not (Test-Path -LiteralPath $LabRoot)
        mixedPortFree = -not [bool](Get-NetTCPConnection -LocalPort $MixedPort -State Listen -ErrorAction SilentlyContinue)
        controllerPortFree = -not [bool](Get-NetTCPConnection -LocalPort $ControllerPort -State Listen -ErrorAction SilentlyContinue)
        footprintAbsent = $footprintAbsent
        stateFingerprint = Get-StringSha256 $canonical
        state = $state
    }
}

function Assert-GuardedLab {
    if (-not (Test-SamePath $LabRoot $ExpectedLabRoot)) { throw 'Refusing unexpected LabRoot.' }
    if (-not (Test-Path -LiteralPath $LabRoot -PathType Container)) { throw 'LabRoot is missing.' }
    $item = Get-Item -LiteralPath $LabRoot -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Refusing a reparse-point LabRoot.' }
    if (-not (Test-Path -LiteralPath $GuardPath -PathType Leaf)) { throw 'Guard file is missing.' }
    if ((Get-Content -LiteralPath $GuardPath -Raw).Trim() -cne 'STCVRC_FULLSTACK_LAB_V1') { throw 'Guard file content is invalid.' }
}

function Assert-Hash {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Expected, [Parameter(Mandatory)][string]$Label)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "$Label is missing." }
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    if ($actual -cne $Expected) { throw "$Label SHA-256 mismatch." }
    $actual
}

function Invoke-Version {
    param([Parameter(Mandatory)][string]$Path)
    ((& $Path -v 2>&1 | Out-String).Trim())
}

function Invoke-HiddenProcess {
    param([Parameter(Mandatory)][string]$Path, [string[]]$Arguments = @(), [switch]$Wait)
    $parameters = @{ FilePath = $Path; PassThru = $true; WindowStyle = 'Hidden' }
    if ($Arguments.Count -gt 0) { $parameters.ArgumentList = $Arguments }
    if ($Wait) { $parameters.Wait = $true }
    Start-Process @parameters
}

function Stop-ExactProcesses {
    param([string[]]$Names, [string[]]$AllowedPaths)
    $normalizedAllowed = @($AllowedPaths | ForEach-Object { Resolve-NormalizedPath $_ })
    $stopped = @()
    foreach ($process in Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -in $Names -and $_.ExecutablePath }) {
        $candidate = Resolve-NormalizedPath $process.ExecutablePath
        if ($candidate -in $normalizedAllowed) {
            Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
            $stopped += [int]$process.ProcessId
        }
    }
    $stopped
}

function Get-ControllerSecret {
    if (-not (Test-Path -LiteralPath $RuntimePath -PathType Leaf)) { return '' }
    Assert-NoReparseAncestors $RuntimePath
    foreach ($line in Get-Content -LiteralPath $RuntimePath -ErrorAction SilentlyContinue) {
        if ([string]$line -match '^\s*secret:\s*(.*)\s*$') {
            return ([string]$Matches[1]).Trim().Trim("'", '"')
        }
    }
    ''
}

function Invoke-Controller {
    param(
        [Parameter(Mandatory)][string]$Path,
        [ValidateSet('Get', 'Put')][string]$Method = 'Get',
        [object]$Body
    )
    $parameters = @{ Uri = "$ControllerBase$Path"; Method = $Method; TimeoutSec = 15 }
    if ($ControllerHeaders.Count -gt 0) { $parameters.Headers = $ControllerHeaders }
    if ($PSBoundParameters.ContainsKey('Body')) {
        $parameters.ContentType = 'application/json'
        $parameters.Body = ($Body | ConvertTo-Json -Compress)
    }
    Invoke-RestMethod @parameters
}

function Set-ProxyGroup {
    param([Parameter(Mandatory)][string]$Group, [Parameter(Mandatory)][string]$Selection)
    [void](Invoke-Controller -Path ("/proxies/{0}" -f [uri]::EscapeDataString($Group)) -Method Put -Body @{ name = $Selection })
}

function Get-GroupState {
    param([Parameter(Mandatory)][string]$Name)
    $value = Invoke-Controller -Path ("/proxies/{0}" -f [uri]::EscapeDataString($Name))
    [ordered]@{ name = $Name; type = [string]$value.type; now = [string]$value.now; members = @($value.all) }
}

function Invoke-CurlProcess {
    param([Parameter(Mandatory)][string[]]$Arguments)
    $token = [guid]::NewGuid().ToString('N')
    $stdoutPath = Join-Path $LogRoot "curl-$token.stdout.log"
    $stderrPath = Join-Path $LogRoot "curl-$token.stderr.log"
    try {
        $process = Start-Process -FilePath 'curl.exe' -ArgumentList $Arguments -PassThru -Wait -WindowStyle Hidden `
            -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
        $stdoutRaw = if (Test-Path -LiteralPath $stdoutPath) { Get-Content -LiteralPath $stdoutPath -Raw } else { $null }
        $stderrRaw = if (Test-Path -LiteralPath $stderrPath) { Get-Content -LiteralPath $stderrPath -Raw } else { $null }
        $stdout = if ($null -eq $stdoutRaw) { '' } else { ([string]$stdoutRaw).Trim() }
        $stderr = if ($null -eq $stderrRaw) { '' } else { ([string]$stderrRaw).Trim() }
        [ordered]@{ exitCode = $process.ExitCode; stdout = $stdout; error = $stderr }
    } catch {
        [ordered]@{ exitCode = -1; stdout = ''; error = $_.Exception.Message }
    } finally {
        Remove-Item -LiteralPath $stdoutPath, $stderrPath -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-ProxyIpCanary {
    param([int]$Attempts = 3)
    $history = @()
    for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
        $result = Invoke-CurlProcess -Arguments @(
            '--silent', '--show-error', '--connect-timeout', '10', '--max-time', '30',
            '--proxy', "http://127.0.0.1:$MixedPort", 'https://api.ipify.org'
        )
        $pass = $result.exitCode -eq 0 -and $result.stdout -match '^\d{1,3}(\.\d{1,3}){3}$'
        $history += [ordered]@{ attempt = $attempt; ip = $result.stdout; exitCode = $result.exitCode; pass = $pass; error = $result.error }
        if ($pass) { break }
        if ($attempt -lt $Attempts) { Start-Sleep -Milliseconds 800 }
    }
    $last = $history[-1]
    [ordered]@{ ip = $last.ip; exitCode = $last.exitCode; pass = $last.pass; error = $last.error; attempts = $history }
}

function Invoke-HttpCanary {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Url, [string]$ExpectedStatus)
    $result = Invoke-CurlProcess -Arguments @(
        '--silent', '--show-error', '--insecure', '--connect-timeout', '10', '--max-time', '30',
        '--proxy', "http://127.0.0.1:$MixedPort", '--output', 'NUL', '--write-out', '%{http_code}', $Url
    )
    $pass = if ($ExpectedStatus) {
        $result.exitCode -eq 0 -and $result.stdout -ceq $ExpectedStatus
    } else {
        $result.exitCode -eq 0 -and $result.stdout -match '^[1-5][0-9][0-9]$'
    }
    [ordered]@{ name = $Name; status = $result.stdout; exitCode = $result.exitCode; pass = $pass; error = $result.error }
}

function Read-Exact {
    param([Parameter(Mandatory)][IO.Stream]$Stream, [Parameter(Mandatory)][int]$Count)
    $buffer = [byte[]]::new($Count)
    $offset = 0
    while ($offset -lt $Count) {
        $read = $Stream.Read($buffer, $offset, $Count - $offset)
        if ($read -le 0) { throw "Unexpected EOF after $offset of $Count bytes." }
        $offset += $read
    }
    $buffer
}

function Add-SocksAddress {
    param([Parameter(Mandatory)][Collections.Generic.List[byte]]$Buffer, [Parameter(Mandatory)][string]$HostName)
    $address = $null
    if ([Net.IPAddress]::TryParse($HostName, [ref]$address)) {
        $Buffer.Add($(if ($address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) { 0x01 } else { 0x04 }))
        foreach ($value in $address.GetAddressBytes()) { $Buffer.Add($value) }
        return
    }
    $encoded = [Text.Encoding]::ASCII.GetBytes($HostName)
    $Buffer.Add(0x03)
    $Buffer.Add([byte]$encoded.Length)
    foreach ($value in $encoded) { $Buffer.Add($value) }
}

function Open-SocksCommand {
    param([Parameter(Mandatory)][string]$HostName, [Parameter(Mandatory)][int]$Port)
    $client = [Net.Sockets.TcpClient]::new()
    try {
        $pending = $client.BeginConnect('127.0.0.1', $MixedPort, $null, $null)
        if (-not $pending.AsyncWaitHandle.WaitOne(10000)) { throw 'SOCKS proxy connect timeout.' }
        $client.EndConnect($pending)
        $stream = $client.GetStream()
        $stream.ReadTimeout = 15000
        $stream.WriteTimeout = 15000
        $stream.Write([byte[]](0x05, 0x01, 0x00), 0, 3)
        $greeting = Read-Exact -Stream $stream -Count 2
        if ($greeting[0] -ne 0x05 -or $greeting[1] -ne 0x00) { throw 'SOCKS no-auth negotiation failed.' }
        $request = [Collections.Generic.List[byte]]::new()
        foreach ($value in @(0x05, 0x01, 0x00)) { $request.Add([byte]$value) }
        Add-SocksAddress -Buffer $request -HostName $HostName
        $request.Add([byte](($Port -shr 8) -band 255))
        $request.Add([byte]($Port -band 255))
        $bytes = $request.ToArray()
        $stream.Write($bytes, 0, $bytes.Length)
        $header = Read-Exact -Stream $stream -Count 4
        if ($header[0] -ne 0x05 -or $header[1] -ne 0x00) { throw "SOCKS command failed with reply $($header[1])." }
        switch ($header[3]) {
            1 { [void](Read-Exact -Stream $stream -Count 4) }
            3 { $length = (Read-Exact -Stream $stream -Count 1)[0]; [void](Read-Exact -Stream $stream -Count $length) }
            4 { [void](Read-Exact -Stream $stream -Count 16) }
            default { throw "Unsupported SOCKS address type $($header[3])." }
        }
        [void](Read-Exact -Stream $stream -Count 2)
        [pscustomobject]@{ Client = $client; Stream = $stream }
    } catch {
        $client.Dispose()
        throw
    }
}

function Invoke-RdpCanary {
    $connection = $null
    try {
        $connection = Open-SocksCommand -HostName 'desktop.example.invalid' -Port 3389
        [byte[]]$request = @(0x03,0x00,0x00,0x13,0x0e,0xe0,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x08,0x00,0x03,0x00,0x00,0x00)
        $connection.Stream.Write($request, 0, $request.Length)
        $header = Read-Exact -Stream $connection.Stream -Count 4
        $length = (([int]$header[2]) -shl 8) -bor [int]$header[3]
        $body = Read-Exact -Stream $connection.Stream -Count ($length - 4)
        [ordered]@{ name = 'ELITECH RDP'; bytes = $length; pass = ($header[0] -eq 0x03 -and $body[1] -eq 0xd0) }
    } catch {
        [ordered]@{ name = 'ELITECH RDP'; pass = $false; error = $_.Exception.Message }
    } finally {
        if ($connection) { $connection.Client.Dispose() }
    }
}

function Invoke-SshCanary {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$HostName)
    $connection = $null
    try {
        $connection = Open-SocksCommand -HostName $HostName -Port 22
        $bytes = [Collections.Generic.List[byte]]::new()
        while ($bytes.Count -lt 255) {
            $value = $connection.Stream.ReadByte()
            if ($value -lt 0 -or $value -eq 10) { break }
            if ($value -ne 13) { $bytes.Add([byte]$value) }
        }
        $banner = [Text.Encoding]::ASCII.GetString($bytes.ToArray())
        [ordered]@{ name = $Name; protocol = if ($banner.StartsWith('SSH-')) { 'SSH' } else { '' }; pass = $banner.StartsWith('SSH-') }
    } catch {
        [ordered]@{ name = $Name; pass = $false; error = $_.Exception.Message }
    } finally {
        if ($connection) { $connection.Client.Dispose() }
    }
}

function Wait-CvrRuntime {
    param([int]$TimeoutSeconds = 90)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $processes=@(Get-CvrProcesses)
        $ui = @($processes | Where-Object { $_.name -ceq 'clash-verge.exe' -and (Test-SamePath $_.executablePath $UiPath) })
        $allCore=@($processes | Where-Object name -ceq 'verge-mihomo.exe')
        $core = @($allCore | Where-Object { Test-SamePath $_.executablePath $RuntimeCorePath })
        $service=Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
        $mixed = @(Get-NetTCPConnection -LocalPort $MixedPort -State Listen -ErrorAction SilentlyContinue)
        $controller = @(Get-NetTCPConnection -LocalPort $ControllerPort -State Listen -ErrorAction SilentlyContinue)
        $coreOwned=($core.Count -eq 1 -and $allCore.Count -eq 1 -and $service.State -eq 'Running' -and $service.StartName -eq 'LocalSystem' -and $core[0].sessionId -eq 0 -and $core[0].parentPid -eq $service.ProcessId)
        $portsOwned=($core.Count -eq 1 -and $mixed.Count -gt 0 -and $controller.Count -gt 0 -and -not @(@($mixed)+@($controller)|Where-Object OwningProcess -ne $core[0].pid).Count)
        if ($ui.Count -eq 1 -and $coreOwned -and $portsOwned -and (Test-Path -LiteralPath $RuntimePath -PathType Leaf)) {
            Assert-NoReparseAncestors $RuntimePath
            Assert-NoReparseAncestors $RuntimeCorePath
            $executingHash=(Get-FileHash -LiteralPath $RuntimeCorePath).Hash
            if($LabStack -and $executingHash -ine $LabStack.coreSha256){throw 'Executing core hash differs from pinned candidate'}
            return [ordered]@{ ui = $ui[0]; core = $core[0]; mixed = $mixed; controller = $controller; executingCoreHash=$executingHash;coreOwned=$coreOwned }
        }
        Start-Sleep -Seconds 1
    } while ((Get-Date) -lt $deadline)
    $diagnostic=@{at=(Get-Date).ToString('o');uiCount=$ui.Count;coreCount=$allCore.Count;exactCoreCount=$core.Count;coreOwned=$coreOwned;portsOwned=$portsOwned;configExists=(Test-Path -LiteralPath $RuntimePath);approvedLayout=$RuntimeLayout.approved}
    [IO.File]::WriteAllText((Join-Path $LabRoot 'runtime-not-ready.json'),($diagnostic|ConvertTo-Json -Compress))
    throw 'Clash Verge runtime did not become ready within the bounded wait.'
}

function Start-Ui {
    $direct = Invoke-HiddenProcess -Path $UiPath
    try {
        return [ordered]@{ launchMode = 'direct'; process = $direct; runtime = Wait-CvrRuntime -TimeoutSeconds 45 }
    } catch {
        [void](Stop-ExactProcesses -Names @('clash-verge.exe') -AllowedPaths @($UiPath))
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        $action = New-ScheduledTaskAction -Execute $UiPath
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(10)
        $principal = New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Highest
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
        Start-ScheduledTask -TaskName $TaskName
        return [ordered]@{ launchMode = 'interactive-task'; process = $null; runtime = Wait-CvrRuntime -TimeoutSeconds 60 }
    }
}

function Remove-ExactTree {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Expected)
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    if (-not (Test-SamePath $Path $Expected)) { throw 'Refusing unexpected cleanup path.' }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Refusing a reparse-point cleanup path.' }
    Remove-Item -LiteralPath $Path -Recurse -Force
    $true
}

function Remove-CvrUninstallEntries {
    $removed = @()
    foreach ($entry in Get-UninstallEntries) {
        $isOwned = ([string]$entry.installLocation -and (Test-SamePath $entry.installLocation $InstallRoot)) -or
            [string]$entry.uninstallString -match [regex]::Escape($InstallRoot)
        if (-not $isOwned) { continue }
        $providerPath = [string]$entry.key -replace '^Microsoft\.PowerShell\.Core\\Registry::', ''
        if ($providerPath -match '^HKEY_LOCAL_MACHINE\\') { $providerPath = $providerPath -replace '^HKEY_LOCAL_MACHINE\\', 'HKLM:\' }
        if ($providerPath -match '^HKEY_CURRENT_USER\\') { $providerPath = $providerPath -replace '^HKEY_CURRENT_USER\\', 'HKCU:\' }
        Remove-Item -LiteralPath $providerPath -Recurse -Force -ErrorAction SilentlyContinue
        $removed += $providerPath
    }
    $removed
}

$LabStack=$null
$manifest=Join-Path $LabRoot 'input\stack-manifest.json'
if(Test-Path -LiteralPath $manifest){$LabStack=[IO.File]::ReadAllText($manifest)|ConvertFrom-Json}
$RuntimeLayout=Get-LabRuntimeLayout -Stack $LabStack -Sid ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
$RuntimeCorePath=$RuntimeLayout.core
$RuntimePath=$RuntimeLayout.config
if ($Mode -eq 'Library') { return }

if ($Mode -eq 'Snapshot') {
    Get-HostBaseline | ConvertTo-Json -Depth 12 -Compress
    exit 0
}

if ($Mode -eq 'Cleanup') {
    if (-not (Test-Path -LiteralPath $LabRoot)) {
        [ordered]@{ guarded = $false; skipped = $true; reason = 'lab absent'; post = Get-HostBaseline } | ConvertTo-Json -Depth 12 -Compress
        exit 0
    }
    Assert-GuardedLab
    $cleanupStarted = Get-Date
    $stoppedUi = @(Stop-ExactProcesses -Names @('clash-verge.exe') -AllowedPaths @($UiPath))
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

    $serviceHelperExit = $null
    if (Test-Path -LiteralPath $ServiceUninstallPath -PathType Leaf) {
        try { $serviceHelperExit = (Invoke-HiddenProcess -Path $ServiceUninstallPath -Wait).ExitCode } catch { $serviceHelperExit = -1 }
    }
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($service) {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        [void](sc.exe delete $ServiceName)
        $deadline = (Get-Date).AddSeconds(20)
        do { Start-Sleep -Milliseconds 500; $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue } while ($service -and (Get-Date) -lt $deadline)
    }
    $runtimePaths=@($InstalledCorePath,$RuntimeCorePath,(Join-Path $InstallRoot 'resources\clash-verge-service.exe'))
    if($RuntimeLayout.approved){$runtimePaths+='C:\ProgramData\clash-verge-service\bin\clash-verge-service.exe'}
    $stoppedRuntime = @(Stop-ExactProcesses -Names @('verge-mihomo.exe', 'clash-verge-service.exe') -AllowedPaths $runtimePaths)

    $uninstallerExit = $null
    $uninstaller = @(
        'uninstall.exe', 'Uninstall.exe', 'unins000.exe' |
            ForEach-Object { Join-Path $InstallRoot $_ } |
            Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }
    ) | Select-Object -First 1
    if ($uninstaller) {
        try { $uninstallerExit = (Invoke-HiddenProcess -Path $uninstaller -Arguments @('/S') -Wait).ExitCode } catch { $uninstallerExit = -1 }
    }
    Start-Sleep -Seconds 2
    $removedInstall = Remove-ExactTree -Path $InstallRoot -Expected 'C:\Program Files\Clash Verge'
    $removedApp = Remove-ExactTree -Path $AppRoot -Expected (Join-Path $env:APPDATA 'io.github.clash-verge-rev.clash-verge-rev')
    $removedLocalApp = Remove-ExactTree -Path $LocalAppRoot -Expected (Join-Path $env:LOCALAPPDATA 'io.github.clash-verge-rev.clash-verge-rev')

    $shortcutPaths = @(
        (Join-Path ([Environment]::GetFolderPath('Desktop')) 'Clash Verge.lnk'),
        (Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'Clash Verge.lnk'),
        (Join-Path ([Environment]::GetFolderPath('StartMenu')) 'Programs\Clash Verge.lnk'),
        (Join-Path ([Environment]::GetFolderPath('CommonStartMenu')) 'Programs\Clash Verge.lnk')
    )
    foreach ($shortcut in $shortcutPaths) { Remove-Item -LiteralPath $shortcut -Force -ErrorAction SilentlyContinue }
    $removedUninstallEntries = @(Remove-CvrUninstallEntries)
    $runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    foreach ($entry in Get-RunEntries) {
        if ([string]$entry.value -match [regex]::Escape($InstallRoot)) {
            Remove-ItemProperty -LiteralPath $runKey -Name $entry.name -Force -ErrorAction SilentlyContinue
        }
    }

    $labFull = Resolve-NormalizedPath $LabRoot
    if (-not (Test-SamePath $labFull $ExpectedLabRoot)) { throw 'Lab path changed before cleanup.' }
    Remove-Item -LiteralPath $LabRoot -Recurse -Force
    Start-Sleep -Seconds 2
    $post = Get-HostBaseline
    [ordered]@{
        guarded = $true
        skipped = $false
        startedAt = $cleanupStarted.ToString('o')
        finishedAt = (Get-Date).ToString('o')
        stoppedUiPids = $stoppedUi
        stoppedRuntimePids = $stoppedRuntime
        serviceHelperExitCode = $serviceHelperExit
        uninstallerExitCode = $uninstallerExit
        removedInstallTree = $removedInstall
        removedAppTree = $removedApp
        removedLocalAppTree = $removedLocalApp
        removedUninstallEntries = $removedUninstallEntries
        post = $post
        pass = ($post.labAbsent -and $post.footprintAbsent -and $post.mixedPortFree -and $post.controllerPortFree)
    } | ConvertTo-Json -Depth 14 -Compress
    exit 0
}

Assert-GuardedLab
foreach ($required in @(
    @{ path = $InstallerPath; expected = $ExpectedInstallerSha256; label = 'installer' },
    @{ path = $CandidateCorePath; expected = $ExpectedCoreSha256; label = 'custom core' },
    @{ path = $CandidateProfilePath; expected = $ExpectedProfileSha256; label = 'profile' },
    @{ path = $CandidateGeoIpPath; expected = $ExpectedGeoIpSha256; label = 'Country.mmdb' }
)) {
    if ([string]::IsNullOrWhiteSpace([string]$required.expected)) { throw "$($required.label) expected hash is required." }
    [void](Assert-Hash -Path $required.path -Expected $required.expected -Label $required.label)
}
if ([string]::IsNullOrWhiteSpace($ExpectedPrimaryEgress)) { throw 'ExpectedPrimaryEgress is required.' }
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run requires an elevated administrator token.' }
New-Item -ItemType Directory -Force -Path $LogRoot | Out-Null
$startedAt = Get-Date

$installer = Invoke-HiddenProcess -Path $InstallerPath -Arguments @('/S') -Wait
if ($installer.ExitCode -ne 0) { throw "Installer failed with exit code $($installer.ExitCode)." }
$installDeadline = (Get-Date).AddSeconds(60)
do {
    if ((Test-Path -LiteralPath $UiPath -PathType Leaf) -and (Test-Path -LiteralPath $InstalledCorePath -PathType Leaf) -and
        (Test-Path -LiteralPath $ServiceInstallPath -PathType Leaf) -and (Test-Path -LiteralPath $ServiceUninstallPath -PathType Leaf)) { break }
    Start-Sleep -Milliseconds 500
} while ((Get-Date) -lt $installDeadline)
foreach ($path in @($UiPath, $InstalledCorePath, $ServiceInstallPath, $ServiceUninstallPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Stock install is incomplete: $path" }
}

$uiVersionInfo = (Get-Item -LiteralPath $UiPath).VersionInfo
$stockCoreHash = (Get-FileHash -LiteralPath $InstalledCorePath -Algorithm SHA256).Hash
$stockCoreVersion = Invoke-Version $InstalledCorePath
$uiVersionPass = ([string]$uiVersionInfo.FileVersion -match "^$([regex]::Escape($ExpectedUiVersion))(\.|$)" -or
    [string]$uiVersionInfo.ProductVersion -match "^$([regex]::Escape($ExpectedUiVersion))(\.|$)")
$stockCorePass = $stockCoreVersion -match [regex]::Escape($ExpectedStockCoreVersion)
if (-not $uiVersionPass) { throw 'Installed stock UI version does not match the gate contract.' }
if (-not $stockCorePass) { throw 'Bundled stock core version does not match the gate contract.' }

Copy-Item -LiteralPath $InstalledCorePath -Destination $StockCoreBackupPath -Force
[void](Stop-ExactProcesses -Names @('clash-verge.exe', 'verge-mihomo.exe') -AllowedPaths @($UiPath, $InstalledCorePath))
New-Item -ItemType Directory -Force -Path $AppRoot, (Join-Path $AppRoot 'profiles') | Out-Null
$utf8 = [Text.UTF8Encoding]::new($false)
$vergeYaml = @'
app_log_level: info
language: en
clash_core: verge-mihomo
enable_tun_mode: false
enable_system_proxy: false
enable_auto_launch: false
enable_silent_start: true
enable_proxy_guard: false
enable_dns_settings: false
enable_global_hotkey: false
auto_check_update: false
enable_external_controller: true
verge_mixed_port: 7897
'@
[IO.File]::WriteAllText((Join-Path $AppRoot 'verge.yaml'), $vergeYaml, $utf8)
$updated = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$profilesYaml = @"
current: $ProfileUid
items:
- uid: Merge
  type: merge
  name: null
  file: Merge.yaml
  updated: $updated
- uid: Script
  type: script
  name: null
  file: Script.js
  updated: $updated
- uid: $ProfileUid
  type: local
  name: STCVRC userVM gate
  file: $ProfileUid.yaml
  desc: Stock Clash Verge Rev $ExpectedUiVersion with STCVRC $ExpectedStockCoreVersion
  updated: $updated
"@
[IO.File]::WriteAllText((Join-Path $AppRoot 'profiles.yaml'), $profilesYaml, $utf8)
[IO.File]::WriteAllText((Join-Path $AppRoot 'profiles\Merge.yaml'), "# STCVRC userVM gate`n", $utf8)
[IO.File]::WriteAllText((Join-Path $AppRoot 'profiles\Script.js'), "function main(config) { return config; }`n", $utf8)
Copy-Item -LiteralPath $CandidateProfilePath -Destination $ProfilePath -Force
Copy-Item -LiteralPath $CandidateGeoIpPath -Destination (Join-Path $AppRoot 'Country.mmdb') -Force
[void](Assert-Hash -Path $ProfilePath -Expected $ExpectedProfileSha256 -Label 'installed profile')
Copy-Item -LiteralPath $CandidateCorePath -Destination $InstalledCorePath -Force
$installedCustomHash = Assert-Hash -Path $InstalledCorePath -Expected $ExpectedCoreSha256 -Label 'installed custom core'
$customCoreVersion = Invoke-Version $InstalledCorePath
if ($customCoreVersion -notmatch [regex]::Escape($ExpectedCustomCoreToken)) { throw 'Installed custom core version token does not match the gate contract.' }

$serviceInstall = Invoke-HiddenProcess -Path $ServiceInstallPath -Wait
if ($serviceInstall.ExitCode -ne 0) { throw "Service installer failed with exit code $($serviceInstall.ExitCode)." }
$serviceDeadline = (Get-Date).AddSeconds(30)
do {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($service) {
        if ($service.Status -ne 'Running') { Start-Service -Name $ServiceName -ErrorAction SilentlyContinue }
        $service.Refresh()
        if ($service.Status -eq 'Running') { break }
    }
    Start-Sleep -Milliseconds 500
} while ((Get-Date) -lt $serviceDeadline)
$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $service -or $service.Status -ne 'Running') { throw 'Official Clash Verge service did not reach Running.' }

$launch = Start-Ui
$runtime = $launch.runtime
$secret = Get-ControllerSecret
if (-not [string]::IsNullOrWhiteSpace($secret)) { $ControllerHeaders = @{ Authorization = "Bearer $secret" } }
$controllerVersion = Invoke-Controller -Path '/version'
$groups = @('VPS-DEFAULT', 'VPS-AUTO', 'FOREIGN-EGRESS', 'RU-DIRECT', 'LT-ROUTE', 'ELITECH-ROUTE', 'OSEN-ROUTE') |
    ForEach-Object { Get-GroupState $_ }

Set-ProxyGroup -Group 'VPS-DEFAULT' -Selection '4VPS'
Start-Sleep -Seconds 1
$primary = Invoke-ProxyIpCanary
Set-ProxyGroup -Group 'VPS-DEFAULT' -Selection 'VPS-GREEN'
Start-Sleep -Seconds 1
$green = Invoke-ProxyIpCanary
Set-ProxyGroup -Group 'VPS-DEFAULT' -Selection 'FOREIGN-EGRESS'
Set-ProxyGroup -Group 'ELITECH-ROUTE' -Selection 'ELITECH-OPENVPN'
$routes = [ordered]@{
    lt = Invoke-HttpCanary -Name 'LT HTTP' -Url 'http://192.0.2.32/'
    ltGitLab = Invoke-HttpCanary -Name 'LT GitLab' -Url 'http://gitlab-a.example.invalid/'
    elitechGitLab = Invoke-HttpCanary -Name 'ELITECH GitLab' -Url 'http://gitlab-b.example.invalid/'
    elitechRdp = Invoke-RdpCanary
    osenSsh = Invoke-SshCanary -Name 'OSEN SSH' -HostName '192.0.2.78'
    ru = Invoke-HttpCanary -Name 'RU direct' -Url 'https://ya.ru/'
}
$routePass = -not [bool](@($routes.Values) | Where-Object { -not $_.pass })
$primaryPass = $primary.pass -and $primary.ip -ceq $ExpectedPrimaryEgress
$greenPass = $green.pass -and $green.ip -ceq $ExpectedGreenEgress

$runtimeCore = @(Get-CvrProcesses | Where-Object { $_.name -ceq 'verge-mihomo.exe' -and (Test-SamePath $_.executablePath $InstalledCorePath) }) | Select-Object -First 1
$runtimeUi = @(Get-CvrProcesses | Where-Object { $_.name -ceq 'clash-verge.exe' -and (Test-SamePath $_.executablePath $UiPath) }) | Select-Object -First 1
$parent = if ($runtimeCore) { Get-CimInstance Win32_Process -Filter "ProcessId=$($runtimeCore.parentPid)" -ErrorAction SilentlyContinue } else { $null }
$serviceOwnershipPass = (
    $runtimeCore -and $runtimeCore.sessionId -eq 0 -and $runtimeCore.ownerSid -ceq 'S-1-5-18' -and
    $parent -and $parent.Name -ceq 'clash-verge-service.exe'
)
$uiOwnershipPass = $runtimeUi -and $runtimeUi.owner -match '(?i)\\fixtureservice$'
$profilePass = (Get-FileHash -LiteralPath $ProfilePath -Algorithm SHA256).Hash -ceq $ExpectedProfileSha256
$tunAbsentDuringRun = @(
    Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '(?i)clash|mihomo|meta' -or $_.InterfaceDescription -match '(?i)clash|mihomo|meta' }
).Count -eq 0
$internetSettings = Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
$systemProxyDisabledDuringRun = -not $internetSettings -or [int]$internetSettings.ProxyEnable -eq 0

$corePidBeforeUiExit = [int]$runtimeCore.pid
$uiPidsStopped = @(Stop-ExactProcesses -Names @('clash-verge.exe') -AllowedPaths @($UiPath))
Start-Sleep -Seconds 3
$coreAfterUiExit = Get-CimInstance Win32_Process -Filter "ProcessId=$corePidBeforeUiExit" -ErrorAction SilentlyContinue
$serviceAfterUiExit = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
$afterUiExitCanary = Invoke-ProxyIpCanary
$uiExitPass = (
    $uiPidsStopped.Count -ge 1 -and $coreAfterUiExit -and $serviceAfterUiExit.Status -eq 'Running' -and
    $afterUiExitCanary.pass -and $afterUiExitCanary.ip -ceq $ExpectedPrimaryEgress
)

$overallPass = (
    $uiVersionPass -and $stockCorePass -and $installedCustomHash -ceq $ExpectedCoreSha256 -and
    $primaryPass -and $greenPass -and $routePass -and $serviceOwnershipPass -and $uiOwnershipPass -and
    $profilePass -and $tunAbsentDuringRun -and $systemProxyDisabledDuringRun -and $uiExitPass
)
[ordered]@{
    mode = 'Run'
    startedAt = $startedAt.ToString('o')
    finishedAt = (Get-Date).ToString('o')
    installer = [ordered]@{ exitCode = $installer.ExitCode; sha256 = $ExpectedInstallerSha256 }
    stock = [ordered]@{
        uiFileVersion = [string]$uiVersionInfo.FileVersion
        uiProductVersion = [string]$uiVersionInfo.ProductVersion
        uiVersionPass = $uiVersionPass
        bundledCoreSha256 = $stockCoreHash
        bundledCoreVersion = $stockCoreVersion
        bundledCoreVersionPass = $stockCorePass
    }
    customCore = [ordered]@{ sha256 = $installedCustomHash; version = $customCoreVersion; versionPass = $true }
    launchMode = $launch.launchMode
    runtime = [ordered]@{
        ui = $runtimeUi
        core = $runtimeCore
        coreParentName = if ($parent) { [string]$parent.Name } else { $null }
        serviceOwnershipPass = $serviceOwnershipPass
        uiOwnershipPass = $uiOwnershipPass
        mixedPort = $MixedPort
        controllerPort = $ControllerPort
        controllerVersion = [ordered]@{ meta = [bool]$controllerVersion.meta; version = [string]$controllerVersion.version }
        profileUid = $ProfileUid
        profileSha256 = $ExpectedProfileSha256
        profilePass = $profilePass
        tunAbsent = $tunAbsentDuringRun
        systemProxyDisabled = $systemProxyDisabledDuringRun
    }
    groups = $groups
    egress = [ordered]@{
        primary = [ordered]@{ observed = $primary.ip; expected = $ExpectedPrimaryEgress; pass = $primaryPass; attempts = $primary.attempts }
        green = [ordered]@{ observed = $green.ip; expected = $ExpectedGreenEgress; pass = $greenPass; attempts = $green.attempts }
    }
    routes = $routes
    routesPass = $routePass
    uiExit = [ordered]@{
        stoppedUiPids = $uiPidsStopped
        corePidBefore = $corePidBeforeUiExit
        sameCoreStillRunning = [bool]$coreAfterUiExit
        serviceStillRunning = [bool]($serviceAfterUiExit -and $serviceAfterUiExit.Status -eq 'Running')
        egress = $afterUiExitCanary.ip
        pass = $uiExitPass
    }
    overallPass = $overallPass
} | ConvertTo-Json -Depth 14 -Compress
