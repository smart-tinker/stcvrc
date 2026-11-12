param([ValidateSet('seed','exercise','recovery')][string]$Phase = 'exercise')
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

if ($env:GITHUB_ACTIONS -ne 'true' -or $env:GITHUB_REPOSITORY -ne 'smart-tinker/stcvrc') { throw 'Native acceptance is restricted to the disposable public STCVRC GitHub runner.' }
if (-not $env:PR_SOURCE -or -not $env:CUSTOM_CORE -or -not $env:CVR_258_GUI_SHA256 -or -not $env:CVR_2510_GUI_SHA256) { throw 'The exact PR source, fresh custom core, or pinned CVR GUI SHA is missing.' }
$expectedVersion = if ($Phase -in @('seed','recovery')) { '2.5.8' } else { '2.5.10' }
$expectedGuiSha = if ($expectedVersion -eq '2.5.8') { [string]$env:CVR_258_GUI_SHA256 } else { [string]$env:CVR_2510_GUI_SHA256 }
if ($Phase -eq 'exercise' -and $env:CVR_2510_SERVICE_SHA256 -notmatch '^[0-9a-f]{64}$') { throw 'The pinned CVR service SHA is malformed.' }
$manifest = Get-Content -LiteralPath (Join-Path $env:PR_SOURCE 'candidates\cvr-2.5.10\inputs.json') -Raw | ConvertFrom-Json
$coreSha = ([string]$manifest.core.sha256).ToLowerInvariant()
if ($coreSha -ne 'd72784d98a44b90e561c701589c50f53074958d7cef656607ee5be1143b36c87') { throw 'Unexpected fresh STCVRC core identity.' }
if ((Get-FileHash -LiteralPath $env:CUSTOM_CORE -Algorithm SHA256).Hash.ToLowerInvariant() -ne $coreSha) { throw 'The candidate input is not the freshly built pinned core.' }

$serviceName = 'clash_verge_service'
$serviceData = Join-Path $env:ProgramData 'clash-verge-service'
$serviceCore = Join-Path $serviceData 'cores\verge-mihomo.exe'
$expectedServiceExe = Join-Path $serviceData 'bin\clash-verge-service.exe'
$installedCore = Join-Path $env:ProgramFiles 'Clash Verge\verge-mihomo.exe'
$installRoot = Join-Path $env:ProgramFiles 'Clash Verge'
$guiPath = Join-Path $installRoot 'clash-verge.exe'
if (-not (Test-Path -LiteralPath $guiPath -PathType Leaf)) { throw "The verified CVR $expectedVersion GUI is absent from the installed payload." }
if ((Get-FileHash -LiteralPath $guiPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedGuiSha.ToLowerInvariant()) { throw "The installed CVR $expectedVersion GUI SHA256 does not match the pinned extracted payload." }
if ((Get-FileHash -LiteralPath $installedCore -Algorithm SHA256).Hash.ToLowerInvariant() -ne $coreSha) { throw "The installed CVR $expectedVersion core path does not contain the fresh source-built bytes." }
if (Test-Path -LiteralPath $serviceCore -PathType Leaf) {
    if ((Get-FileHash -LiteralPath $serviceCore -Algorithm SHA256).Hash.ToLowerInvariant() -ne $coreSha) { throw 'The service staging path does not contain the fresh source-built core.' }
}
if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) { throw 'Clean-runner precondition failed: a CVR service already exists.' }
$failures = [Collections.Generic.List[string]]::new()
$script:usedPorts = [Collections.Generic.HashSet[int]]::new()
function Add-Failure { param([string]$Message) $failures.Add($Message); Write-Host "ASSERTION FAILED: $Message" -ForegroundColor Red }
function Get-FreeTcpPort {
    do {
        $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
        $listener.Start(); $port = ([Net.IPEndPoint]$listener.LocalEndpoint).Port; $listener.Stop()
    } while (-not $script:usedPorts.Add([int]$port))
    return $port
}
function Get-DefaultRouteSnapshot {
    @(Get-NetRoute -AddressFamily IPv4,IPv6 -ErrorAction Stop |
        Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0', '::/0') } |
        ForEach-Object { "$($_.AddressFamily)|$($_.DestinationPrefix)|$($_.InterfaceIndex)|$($_.NextHop)|$($_.RouteMetric)" } | Sort-Object)
}
function Get-PhysicalDnsSnapshot {
    $physical = @(Get-NetAdapter -Physical -ErrorAction Stop | ForEach-Object { [int]$_.ifIndex })
    @(Get-DnsClientServerAddress -AddressFamily IPv4,IPv6 -ErrorAction Stop |
        Where-Object { $physical -contains [int]$_.InterfaceIndex } |
        ForEach-Object { "$($_.InterfaceIndex)|$($_.AddressFamily)|$(@($_.ServerAddresses) -join ',')" } | Sort-Object)
}
function Assert-SystemRoutesRemainScoped {
    param([string[]]$OriginalDefaults, [string[]]$OriginalDns, [string]$Phase)
    $difference = @(Compare-Object -ReferenceObject $OriginalDefaults -DifferenceObject @(Get-DefaultRouteSnapshot))
    if ($difference.Count) { throw "$Phase changed a system default route: $($difference | Out-String)" }
    $difference = @(Compare-Object -ReferenceObject $OriginalDns -DifferenceObject @(Get-PhysicalDnsSnapshot))
    if ($difference.Count) { throw "$Phase changed DNS servers on a physical adapter: $($difference | Out-String)" }
    $wide = @(Get-NetRoute -AddressFamily IPv4,IPv6 -ErrorAction Stop | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1','::/1','8000::/1') })
    if ($wide.Count) { throw "$Phase installed a broad /1 route that could capture general traffic." }
}
function Assert-FixtureRoute {
    $routes = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '198.18.0.0/16' -ErrorAction SilentlyContinue)
    if (-not $routes.Count) { throw 'The core did not install the explicit synthetic 198.18.0.0/16 route.' }
    $physical = @(Get-NetAdapter -Physical -ErrorAction Stop | ForEach-Object { [int]$_.ifIndex })
    if (-not @($routes | Where-Object { $physical -notcontains [int]$_.InterfaceIndex }).Count) { throw 'Synthetic route is not bound to a non-physical tunnel interface.' }
}
function Receive-CdpMessage {
    $bytes = New-Object byte[] 16384
    $builder = [Text.StringBuilder]::new()
    do {
        $result = $script:cdp.ReceiveAsync([ArraySegment[byte]]::new($bytes), [Threading.CancellationToken]::None).GetAwaiter().GetResult()
        if ($result.MessageType -eq [Net.WebSockets.WebSocketMessageType]::Close) { throw 'WebView2 DevTools websocket closed unexpectedly.' }
        [void]$builder.Append([Text.Encoding]::UTF8.GetString($bytes, 0, $result.Count))
    } while (-not $result.EndOfMessage)
    return ($builder.ToString() | ConvertFrom-Json)
}
function Get-CdpEvaluationError {
    param($Result)
    if ($null -eq $Result) { return $null }
    $detailsProperty = $Result.PSObject.Properties['exceptionDetails']
    if (-not $detailsProperty -or $null -eq $detailsProperty.Value) { return $null }
    $details = $detailsProperty.Value
    $exception = $details.exception
    $exceptionMessage = $null
    if ($exception) {
        $descriptionProperty = $exception.PSObject.Properties['description']
        if ($descriptionProperty -and -not [string]::IsNullOrWhiteSpace([string]$descriptionProperty.Value)) {
            $exceptionMessage = [string]$descriptionProperty.Value
        } else {
            $valueProperty = $exception.PSObject.Properties['value']
            if ($valueProperty) {
                if ($null -eq $valueProperty.Value) {
                    $exceptionMessage = 'null'
                } elseif ($valueProperty.Value -is [string]) {
                    $exceptionMessage = [string]$valueProperty.Value
                } else {
                    $exceptionMessage = ConvertTo-Json -InputObject $valueProperty.Value -Compress -Depth 12
                }
            } else {
                $exceptionMessage = ConvertTo-Json -InputObject $exception -Compress -Depth 12
            }
        }
    } else {
        $exceptionMessage = 'no exception object'
    }
    return "$($details.text); exception=$exceptionMessage"
}
function Test-CdpEvaluationErrorFormatting {
    $primitive = [pscustomobject]@{
        exceptionDetails = [pscustomobject]@{
            text = 'Uncaught (in promise)'
            exception = [pscustomobject]@{ type = 'string'; value = 'primitive fixture rejection' }
        }
    }
    if ((Get-CdpEvaluationError -Result $primitive) -ne 'Uncaught (in promise); exception=primitive fixture rejection') {
        throw 'CDP exception formatting did not preserve a primitive exception.value.'
    }
    $described = [pscustomobject]@{
        exceptionDetails = [pscustomobject]@{
            text = 'Uncaught'
            exception = [pscustomobject]@{ type = 'object'; description = 'Error: fixture rejection' }
        }
    }
    if ((Get-CdpEvaluationError -Result $described) -ne 'Uncaught; exception=Error: fixture rejection') {
        throw 'CDP exception formatting did not preserve an exception.description.'
    }
    if ($null -ne (Get-CdpEvaluationError -Result ([pscustomobject]@{ result = [pscustomobject]@{ value = $true } }))) {
        throw 'CDP exception formatting treated a successful evaluation as an exception.'
    }
}
Test-CdpEvaluationErrorFormatting

function Get-CdpFailureSnapshot {
    param([string]$Command)
    $snapshot = [ordered]@{
        command = $Command
        websocketState = if ($script:cdp) { [string]$script:cdp.State } else { 'missing' }
        gui = $null
        devtools = $null
    }
    try {
        if ($script:guiProcess) {
            $script:guiProcess.Refresh()
            $gui = [ordered]@{
                pid = [int]$script:guiProcess.Id
                alive = (-not [bool]$script:guiProcess.HasExited)
                windowTitle = [string]$script:guiProcess.MainWindowTitle
                windowHandle = [string]$script:guiProcess.MainWindowHandle
            }
            if ($script:guiProcess.HasExited) { $gui.exitCode = [int]$script:guiProcess.ExitCode }
            $process = Get-CimInstance Win32_Process -Filter "ProcessId=$($script:guiProcessId)" -ErrorAction Stop
            if ($process) {
                $gui.path = [string]$process.ExecutablePath
                $gui.parentPid = [int]$process.ParentProcessId
                if ($gui.path -and (Test-Path -LiteralPath $gui.path -PathType Leaf)) {
                    $gui.sha256 = (Get-FileHash -LiteralPath $gui.path -Algorithm SHA256).Hash.ToLowerInvariant()
                }
            }
            $snapshot.gui = $gui
        }
    } catch {
        $snapshot.guiReadError = $_.Exception.Message
    }
    try {
        if ($script:devtoolsPort -gt 0) {
            $pages = @(Invoke-RestMethod -Uri "http://127.0.0.1:$($script:devtoolsPort)/json/list" -TimeoutSec 2)
            $pageTargets = @($pages | Where-Object { $_.type -eq 'page' })
            $snapshot.devtools = [ordered]@{
                available = $true
                pageCount = $pageTargets.Count
                pages = @($pageTargets | ForEach-Object { [ordered]@{ title = [string]$_.title; type = [string]$_.type } })
            }
        }
    } catch {
        $snapshot.devtools = [ordered]@{ available = $false; error = $_.Exception.Message }
    }
    return (ConvertTo-Json -InputObject $snapshot -Compress -Depth 8)
}

function Request-CvrGuiExit {
    if (-not $script:cdp -or $script:cdp.State -ne [Net.WebSockets.WebSocketState]::Open) { throw 'The visible CVR WebView2 command channel is not connected for exit.' }
    if (-not $script:guiProcess -or $script:guiProcessId -le 0) { throw 'The exact CVR GUI process is unavailable for exit verification.' }
    $script:cdpId++
    $expression = "(window.__TAURI_INTERNALS__.invoke('exit_app',{}),'exit-requested')"
    $packet = @{ id=$script:cdpId; method='Runtime.evaluate'; params=@{ expression=$expression; awaitPromise=$false; returnByValue=$true; userGesture=$true } } | ConvertTo-Json -Compress -Depth 8
    $bytes = [Text.Encoding]::UTF8.GetBytes($packet)
    try {
        $null = $script:cdp.SendAsync([ArraySegment[byte]]::new($bytes), [Net.WebSockets.WebSocketMessageType]::Text, $true, [Threading.CancellationToken]::None).GetAwaiter().GetResult()
    } catch {
        $snapshot = Get-CdpFailureSnapshot -Command 'exit_app'
        throw "Could not send CVR exit_app request: $($_.Exception.Message); snapshot=$snapshot"
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(45)
    while ([DateTime]::UtcNow -lt $deadline) {
        $script:guiProcess.Refresh()
        if ($script:guiProcess.HasExited) { break }
        Start-Sleep -Milliseconds 200
    }
    $script:guiProcess.Refresh()
    if (-not $script:guiProcess.HasExited) {
        $snapshot = Get-CdpFailureSnapshot -Command 'exit_app'
        throw "CVR exit_app did not terminate GUI PID $script:guiProcessId within 45 seconds; snapshot=$snapshot"
    }
    $exitCode = [int]$script:guiProcess.ExitCode
    if ($exitCode -ne 0) { throw "CVR exit_app terminated GUI PID $script:guiProcessId with exit code $exitCode." }
    Write-Host "CVR exit_app completed; GUI PID $script:guiProcessId exited with code 0."
    $script:cdp.Dispose()
    $script:cdp = $null
}

function Invoke-CvrCommand {
    param([string]$Command, [hashtable]$Payload = @{})
    if (-not $script:cdp -or $script:cdp.State -ne [Net.WebSockets.WebSocketState]::Open) { throw 'The visible CVR WebView2 command channel is not connected.' }
    $script:cdpId++
    $jsonArgs = ConvertTo-Json -InputObject $Payload -Compress -Depth 20
    $expression = "(async()=>await window.__TAURI_INTERNALS__.invoke('$Command',$jsonArgs))()"
    $packet = @{ id=$script:cdpId; method='Runtime.evaluate'; params=@{ expression=$expression; awaitPromise=$true; returnByValue=$true; userGesture=$true } } | ConvertTo-Json -Compress -Depth 20
    $bytes = [Text.Encoding]::UTF8.GetBytes($packet)
    $null = $script:cdp.SendAsync([ArraySegment[byte]]::new($bytes), [Net.WebSockets.WebSocketMessageType]::Text, $true, [Threading.CancellationToken]::None).GetAwaiter().GetResult()
    while ($true) {
        try {
            $reply = Receive-CdpMessage
        } catch {
            $exceptionType = $_.Exception.GetType().FullName
            $snapshot = Get-CdpFailureSnapshot -Command $Command
            throw "CDP receive failed while awaiting Tauri command '$Command' ($exceptionType): $($_.Exception.Message); snapshot=$snapshot"
        }
        if ($reply.id -ne $script:cdpId) { continue }
        $evaluationError = Get-CdpEvaluationError -Result $reply.result
        if ($null -ne $evaluationError) {
            $detailsJson = ConvertTo-Json -InputObject $reply.result.exceptionDetails -Compress -Depth 12
            throw "CVR Tauri command $Command failed: $evaluationError; details=$detailsJson"
        }
        if ($reply.result.result.PSObject.Properties.Name -contains 'value') { return $reply.result.result.value }
        return $null
    }
}
function Assert-GlobalUiModesOff {
    param([string]$Phase)
    $settings = Invoke-CvrCommand -Command 'get_verge_config'
    foreach ($field in @('enable_tun_mode','enable_system_proxy','enable_auto_launch')) {
        $property = $settings.PSObject.Properties[$field]
        if ($property -and [bool]$property.Value) {
            throw "CVR global mode $field is unexpectedly enabled during $Phase."
        }
    }
    $internetSettingsPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    $internetSettings = Get-ItemProperty -LiteralPath $internetSettingsPath -ErrorAction SilentlyContinue
    $proxyEnableProperty = if ($internetSettings) { $internetSettings.PSObject.Properties['ProxyEnable'] } else { $null }
    if ($proxyEnableProperty) {
        if ([int]$proxyEnableProperty.Value -ne 0) { throw "Windows per-user ProxyEnable is enabled during $Phase." }
        Write-Host "Windows per-user ProxyEnable=0 during $Phase."
    } else {
        $probeUri = [Uri]'http://stcvrc-system-proxy-check.invalid/'
        $webProxy = [Net.WebRequest]::DefaultWebProxy
        if (-not $webProxy -or -not $webProxy.IsBypassed($probeUri)) {
            throw "Windows proxy state is unavailable or enabled during $Phase."
        }
        Write-Host "Windows system proxy resolver reports no proxy during $Phase; ProxyEnable was unavailable."
    }
}

function Invoke-DnsQuery {
    param([string]$Name, [int]$Port)
    $labels = @()
    foreach ($label in $Name.Split('.')) { $encoded = [Text.Encoding]::ASCII.GetBytes($label); $labels += [byte]$encoded.Length; $labels += $encoded }
    $labels += [byte]0
    $query = [byte[]](@(0x12,0x34,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00) + [byte[]]$labels + [byte[]]@(0x00,0x01,0x00,0x01))
    $udp = [Net.Sockets.UdpClient]::new()
    try {
        $udp.Client.ReceiveTimeout = 4000
        $endpoint = [Net.IPEndPoint]::new([Net.IPAddress]::Loopback, $Port)
        [void]$udp.Send($query, $query.Length, $endpoint)
        $reply = $udp.Receive([ref]$endpoint)
    } finally { $udp.Dispose() }
    if ($reply.Length -lt 17 -or (($reply[3] -band 0x0f) -ne 0)) { throw "Invoke-DnsQuery received invalid DNS response for $Name." }
    $answers = ([int]$reply[6] -shl 8) -bor [int]$reply[7]
    $cursor = 12
    while ($cursor -lt $reply.Length -and $reply[$cursor] -ne 0) { $cursor += 1 + [int]$reply[$cursor] }
    $cursor += 5
    for ($i=0; $i -lt $answers -and $cursor+12 -le $reply.Length; $i++) {
        if (($reply[$cursor] -band 0xc0) -eq 0xc0) { $cursor += 2 }
        else { while ($reply[$cursor] -ne 0) { $cursor += 1 + [int]$reply[$cursor] }; $cursor++ }
        if ($cursor+10 -gt $reply.Length) { break }
        $type = ([int]$reply[$cursor] -shl 8) -bor [int]$reply[$cursor+1]
        $cursor += 8
        $length = ([int]$reply[$cursor] -shl 8) -bor [int]$reply[$cursor+1]
        $cursor += 2
        if ($cursor+$length -gt $reply.Length) { break }
        if ($type -eq 1 -and $length -eq 4) {
            $address = [Net.IPAddress]::new([byte[]]$reply[$cursor..($cursor+3)]).ToString()
            if ($address -notmatch '^198\.18\.') { throw "DNS returned non-synthetic answer $address for $Name." }
            return $address
        }
        $cursor += $length
    }
    throw "Core DNS returned no IPv4 answer for $Name."
}
function Invoke-TunHttp {
    param([string]$FakeAddress, [string]$FixtureName, [int]$Port)
    $client = [Net.Sockets.TcpClient]::new()
    try {
        $task = $client.ConnectAsync([Net.IPAddress]::Parse($FakeAddress), $Port)
        if (-not $task.Wait(7000)) { throw "TUN connection timed out for $FixtureName." }
        $stream = $client.GetStream(); $stream.ReadTimeout = 7000; $stream.WriteTimeout = 7000
        $crlf = [string][char]13 + [char]10
        $request = 'GET / HTTP/1.1' + $crlf + "Host: $FixtureName" + $crlf + 'Connection: close' + $crlf + $crlf
        $bytes = [Text.Encoding]::ASCII.GetBytes($request); $stream.Write($bytes, 0, $bytes.Length)
        $reader = [IO.StreamReader]::new($stream, [Text.Encoding]::ASCII, $false, 1024, $true)
        $response = $reader.ReadToEnd()
        if ($response -notmatch ('(?s)^HTTP/1\.[01] 200\b.*\r\n\r\nnative-fixture:' + [regex]::Escape($FixtureName))) { throw "Synthetic HTTP marker mismatch for $FixtureName." }
        return $response
    } finally { $client.Dispose() }
}
function Wait-ServiceReady {
    $deadline = [DateTime]::UtcNow.AddSeconds(45)
    $lastState = $null
    $lastError = $null
    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            $lastState = Invoke-CvrCommand -Command 'get_runtime_state'
            $lastError = $null
            if (([string]$lastState.mode).ToLowerInvariant() -eq 'service' -and
                ([string]$lastState.service).ToLowerInvariant() -eq 'ready' -and
                [bool]$lastState.serviceUsable) { return $lastState }
        } catch { $lastError = $_.Exception.Message }
        Start-Sleep -Milliseconds 700
    }
    $startupError = $null
    try { $startupError = Invoke-CvrCommand -Command 'get_core_startup_error' } catch { $startupError = $_.Exception.Message }
    $stateText = ConvertTo-Json -InputObject $lastState -Compress -Depth 10
    $startupText = ConvertTo-Json -InputObject $startupError -Compress -Depth 10
    throw "get_runtime_state never reached service ready; lastState=$stateText; lastReadError=$lastError; coreStartupError=$startupText"
}
function Assert-LiveServiceIdentity {
    $service = Get-Service -Name $serviceName -ErrorAction Stop
    if ($service.Status -ne 'Running') { throw 'SCM does not report the CVR service running.' }
    $serviceRecord = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    if (-not $serviceRecord -or $serviceRecord.State -ne 'Running') { throw 'CVR SCM service is not running.' }
    $imageMatch = [regex]::Match([string]$serviceRecord.PathName, '^"([^"]+)"|^(\S+)')
    if (-not $imageMatch.Success) { throw "Could not parse the registered service image path: $($serviceRecord.PathName)" }
    $imagePath = if ($imageMatch.Groups[1].Success) { $imageMatch.Groups[1].Value } else { $imageMatch.Groups[2].Value }
    $serviceExe = [IO.Path]::GetFullPath($imagePath)
    $expected = [IO.Path]::GetFullPath($expectedServiceExe)
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals($serviceExe, $expected)) { throw "SCM service image differs from the expected CVR payload path: $serviceExe" }
    if (-not (Test-Path -LiteralPath $serviceExe -PathType Leaf)) { throw "SCM service image is missing: $serviceExe" }
    $serviceHash = (Get-FileHash -LiteralPath $serviceExe -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($serviceHash -ne $env:CVR_2510_SERVICE_SHA256) { throw "SCM service image SHA256 differs from the extracted CVR 2.5.10 payload: $serviceHash" }
}
function Assert-LiveCoreIdentity {
    Assert-LiveServiceIdentity
    $allCores = @(Get-CimInstance Win32_Process -Filter "Name='verge-mihomo.exe'")
    if ($allCores.Count -ne 1) { throw "Expected exactly one live core process; found $($allCores.Count)." }
    $processes = @($allCores | Where-Object { $_.ExecutablePath -and [IO.Path]::GetFullPath($_.ExecutablePath) -eq [IO.Path]::GetFullPath($serviceCore) })
    if ($processes.Count -ne 1) { throw "Expected one live core at the service staging path; found $($processes.Count)." }
    $serviceRecord = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    if (-not $serviceRecord -or $serviceRecord.State -ne 'Running' -or [uint32]$serviceRecord.ProcessId -le 0) { throw 'The registered CVR service has no live process identity.' }
    if ([uint32]$processes[0].ParentProcessId -ne [uint32]$serviceRecord.ProcessId) { throw 'The live core is not a direct child of the registered CVR service process.' }
    if ((Get-FileHash -LiteralPath $processes[0].ExecutablePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $coreSha) { throw 'Live service core SHA256 mismatch.' }
    if (@(Get-CimInstance Win32_Process -Filter "Name='verge-mihomo-alpha.exe'" -ErrorAction SilentlyContinue).Count) { throw 'Alpha core process started during acceptance.' }
}
function Assert-LiveSidecarCoreIdentity {
    $state = Invoke-CvrCommand -Command 'get_runtime_state'
    if (([string]$state.mode).ToLowerInvariant() -ne 'sidecar') { throw "Expected the explicitly isolated sidecar mode, got $($state.mode); snapshot=$(Get-NativeStateSnapshot -Phase 'core identity')." }
    $allCores = @(Get-CimInstance Win32_Process -Filter "Name='verge-mihomo.exe'")
    if ($allCores.Count -ne 1) { throw "Expected exactly one live sidecar core process; found $($allCores.Count)." }
    $path = [IO.Path]::GetFullPath([string]$allCores[0].ExecutablePath)
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals($path,[IO.Path]::GetFullPath($installedCore))) { throw "Recovered/seeded core path differs from the installed custom core: $path" }
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $coreSha) { throw 'Live sidecar core SHA256 mismatch.' }
    if (@(Get-CimInstance Win32_Process -Filter "Name='verge-mihomo-alpha.exe'" -ErrorAction SilentlyContinue).Count) { throw 'Alpha core process started during acceptance.' }
}
function Get-RuntimeYaml { [string](Invoke-CvrCommand -Command 'get_runtime_yaml') }
function Get-NativeStateSnapshot {
    param([string]$Phase)
    $snapshot = [ordered]@{
        phase = $Phase
        currentProfileUid = $null
        fixtureProfiles = @()
        runtimeMode = $null
        runtimeRuleLines = @()
        service = $null
        coreProcesses = @()
    }
    try {
        $profiles = Invoke-CvrCommand -Command 'get_profiles'
        $snapshot.currentProfileUid = [string]$profiles.current
        foreach ($name in @('native-fixture-a','native-fixture-b')) {
            foreach ($item in @($profiles.items | Where-Object { $_.name -eq $name })) {
                $snapshot.fixtureProfiles += [ordered]@{
                    name = [string]$item.name
                    uid = [string]$item.uid
                    selected = @($item.selected | ForEach-Object {
                        [ordered]@{ group = [string]$_.name; now = [string]$_.now }
                    })
                }
            }
        }
    } catch { $snapshot.profilesError = $_.Exception.Message }
    try {
        $state = Invoke-CvrCommand -Command 'get_runtime_state'
        $snapshot.runtimeMode = [string]$state.mode
        if ($state.PSObject.Properties.Name -contains 'status') { $snapshot.runtimeStatus = [string]$state.status }
    } catch { $snapshot.runtimeStateError = $_.Exception.Message }
    try {
        $yaml = Get-RuntimeYaml
        $snapshot.runtimeRuleLines = @($yaml -split '\r?\n' | Where-Object { $_ -match '(^\s*rules:|native-fixture-[ab]\.invalid|native-fixture-[ab])' } | Select-Object -First 20)
    } catch { $snapshot.runtimeYamlError = $_.Exception.Message }
    try {
        $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        $serviceRecord = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue
        if ($svc -or $serviceRecord) {
            $serviceNameValue = if ($serviceRecord) { [string]$serviceRecord.Name } else { [string]$svc.Name }
            $serviceStatus = if ($svc) { [string]$svc.Status } else { $null }
            $serviceState = if ($serviceRecord) { [string]$serviceRecord.State } else { $null }
            $servicePid = if ($serviceRecord) { [int]$serviceRecord.ProcessId } else { 0 }
            $snapshot.service = [ordered]@{
                name = $serviceNameValue
                status = $serviceStatus
                state = $serviceState
                processId = $servicePid
            }
        }
    } catch { $snapshot.serviceError = $_.Exception.Message }
    try {
        foreach ($process in @(Get-CimInstance Win32_Process -Filter "Name='verge-mihomo.exe' OR Name='verge-mihomo-alpha.exe'" -ErrorAction Stop)) {
            $hash = $null
            if ($process.ExecutablePath -and (Test-Path -LiteralPath $process.ExecutablePath -PathType Leaf)) {
                $hash = (Get-FileHash -LiteralPath $process.ExecutablePath -Algorithm SHA256).Hash.ToLowerInvariant()
            }
            $snapshot.coreProcesses += [ordered]@{
                name = [string]$process.Name
                pid = [int]$process.ProcessId
                path = [string]$process.ExecutablePath
                sha256 = $hash
            }
        }
    } catch { $snapshot.coreProcessError = $_.Exception.Message }
    return (ConvertTo-Json -InputObject $snapshot -Compress -Depth 8)
}
function Wait-RuntimeRule {
    param([string]$Rule)
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    while ([DateTime]::UtcNow -lt $deadline) { $yaml=Get-RuntimeYaml; if ($yaml.Contains($Rule)) { return $yaml }; Start-Sleep -Milliseconds 500 }
    throw "Loaded runtime did not contain $Rule."
}
function Add-FixtureProfile {
    param([string]$Name, [string]$AllowName, [string]$RejectName, [int]$DnsPort, [int]$ProfileDnsPort, [int]$ControllerPort, [int]$ProxyPortA, [int]$ProxyPortB)
    $yaml = @"
mode: rule
log-level: info
allow-lan: false
bind-address: 127.0.0.1
external-controller: 127.0.0.1:$ControllerPort
ipv6: false
dns:
  enable: true
  listen: 127.0.0.1:$DnsPort
  ipv6: false
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  default-nameserver:
    - 127.0.0.1
  nameserver:
    - udp://127.0.0.1:$ProfileDnsPort
  proxy-server-nameserver:
    - udp://127.0.0.1:$ProfileDnsPort
  nameserver-policy:
    proxy-fixture.invalid: udp://127.0.0.1:$ProfileDnsPort
proxies:
  - name: fixture-node-a
    type: socks5
    server: 127.0.0.1
    port: $ProxyPortA
  - name: fixture-node-b
    type: socks5
    server: 127.0.0.1
    port: $ProxyPortB
proxy-groups:
  - name: GLOBAL
    type: select
    proxies:
      - fixture-node-a
      - fixture-node-b
tun:
  enable: true
  device: STCVRC-CI
  stack: gvisor
  auto-route: true
  auto-detect-interface: false
  strict-route: false
  route-address:
    - 198.18.0.0/16
rules:
  - DOMAIN-SUFFIX,$AllowName,DIRECT
  - DOMAIN-SUFFIX,$RejectName,REJECT
  - MATCH,GLOBAL
"@
    $item = @{ type='local'; name=$Name; desc='Disposable synthetic CI fixture'; url=$null; option=$null }
    [void](Invoke-CvrCommand -Command 'create_profile' -Payload @{ item=$item; fileData=$yaml })
    $profile = Get-FixtureProfile -Name $Name
    return [string]$profile.uid
}
function Get-FixtureProfile {
    param([string]$Name)
    $profiles = Invoke-CvrCommand -Command 'get_profiles'
    $found = @($profiles.items | Where-Object { $_.name -eq $Name })
    if ($found.Count -ne 1 -or -not $found[0].uid) { throw "Expected one persisted profile named $Name; found $($found.Count)." }
    $yaml = [string](Invoke-CvrCommand -Command 'read_profile_file' -Payload @{ index=[string]$found[0].uid })
    foreach ($required in @('proxy-server-nameserver:', 'nameserver-policy:', 'name: GLOBAL', 'name: fixture-node-a', 'name: fixture-node-b')) {
        if (-not $yaml.Contains($required)) { throw "Persisted $Name profile file is missing $required." }
    }
    return $found[0]
}
function Get-ProfileDnsState {
    param([string]$Uid)
    $verge = Invoke-CvrCommand -Command 'get_verge_config'
    $settings = $verge.profile_dns_settings
    if ($null -eq $settings) { $settings = $verge.profileDnsSettings }
    $entry = if ($settings) { $settings.PSObject.Properties[$Uid] } else { $null }
    if (-not $entry) { throw "CVR did not expose profile-scoped DNS override state for $Uid." }
    return $entry.Value
}
function Set-FixtureDnsOverride {
    param([string]$Uid, [bool]$Enabled, [bool]$Confirm)
    $first = Invoke-CvrCommand -Command 'set_dns_override' -Payload @{ profileUid=$Uid; enabled=$Enabled; confirmation=$null }
    $status = ([string]$first.status).ToLowerInvariant()
    if (-not $Enabled) {
        if ($status -ne 'applied') { throw "Disabling the DNS override returned $status instead of applied." }
        return $null
    }
    if ($status -ne 'confirmation_required' -or [string]$first.source -notmatch '^[0-9a-f]{64}$') {
        throw "Enabling DNS override did not request a source-bound confirmation: $($first | ConvertTo-Json -Compress -Depth 5)"
    }
    $source = [string]$first.source
    if (-not $Confirm) { return $source }
    $confirmed = Invoke-CvrCommand -Command 'set_dns_override' -Payload @{ profileUid=$Uid; enabled=$true; confirmation=$source }
    if (([string]$confirmed.status).ToLowerInvariant() -ne 'applied') { throw "Confirmed DNS override did not apply: $($confirmed | ConvertTo-Json -Compress -Depth 5)" }
    return $source
}
function Assert-ProfileDnsState {
    param([string]$Uid, [bool]$Enabled, [string]$Phase)
    $state = Get-ProfileDnsState -Uid $Uid
    if ([bool]$state.enabled -ne $Enabled) { throw "$Phase expected profile DNS override enabled=$Enabled, got $($state.enabled)." }
}
function Assert-DnsResolver {
    param([string]$Name, [ValidateSet('profile','app')][string]$Resolver)
    $expected = "$Resolver|$($Name.ToLowerInvariant())"
    $deadline = [DateTime]::UtcNow.AddSeconds(4)
    while ([DateTime]::UtcNow -lt $deadline) {
        if (Test-Path -LiteralPath $script:dnsLogPath -PathType Leaf) {
            if (@(Get-Content -LiteralPath $script:dnsLogPath | Where-Object { $_.ToLowerInvariant() -eq $expected }).Count) { return }
        }
        Start-Sleep -Milliseconds 100
    }
    $observed = if (Test-Path -LiteralPath $script:dnsLogPath) { Get-Content -LiteralPath $script:dnsLogPath -Tail 20 } else { @() }
    throw "DNS query $Name did not reach the expected $Resolver resolver; recent resolver log: $($observed -join ' | ')"
}
function Get-GlobalNodeSelection {
    $view = Invoke-CvrCommand -Command 'get_proxy_view'
    if (-not $view.global) { throw 'The active native core did not expose the GLOBAL proxy selector.' }
    return [string]$view.global.now
}
function Assert-FixtureNodeSelection {
    param([string]$ProfileName, [string]$ExpectedNode, [string]$Phase)
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    $actual = $null
    while ([DateTime]::UtcNow -lt $deadline) {
        $actual = Get-GlobalNodeSelection
        if ($actual -eq $ExpectedNode) { break }
        Start-Sleep -Milliseconds 300
    }
    if ($actual -ne $ExpectedNode) { throw "$Phase core selected GLOBAL=$actual, expected $ExpectedNode for $ProfileName; snapshot=$(Get-NativeStateSnapshot -Phase $Phase)." }
    $profile = Get-FixtureProfile -Name $ProfileName
    $matches = @($profile.selected | Where-Object { $_.name -eq 'GLOBAL' })
    if ($matches.Count -ne 1 -or [string]$matches[0].now -ne $ExpectedNode) {
        $persisted = @($profile.selected | ForEach-Object { [ordered]@{ group=[string]$_.name; now=[string]$_.now } } | ConvertTo-Json -Compress -Depth 4)
        throw "$Phase live core selected GLOBAL=$actual but profiles.yaml selected state was $persisted; snapshot=$(Get-NativeStateSnapshot -Phase $Phase)."
    }
}
function Select-FixtureNode {
    param([string]$Node, [string]$ProfileName)
    $selectionResult = Invoke-CvrCommand -Command 'plugin:mihomo|select_node_for_group' -Payload @{ groupName='GLOBAL'; node=$Node }
    $selectionJson = if ($null -eq $selectionResult) { 'null' } else { ConvertTo-Json -InputObject $selectionResult -Compress -Depth 8 }
    Write-Host "select_node_for_group GLOBAL=$Node result=$selectionJson."
    $recordResult = Invoke-CvrCommand -Command 'record_selected_node' -Payload @{ groupName='GLOBAL'; node=$Node }
    $recordJson = if ($null -eq $recordResult) { 'null' } else { ConvertTo-Json -InputObject $recordResult -Compress -Depth 8 }
    Write-Host "record_selected_node GLOBAL=$Node result=$recordJson."
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    while ([DateTime]::UtcNow -lt $deadline) {
        if ((Get-GlobalNodeSelection) -eq $Node) { break }
        Start-Sleep -Milliseconds 300
    }
    Assert-FixtureNodeSelection -ProfileName $ProfileName -ExpectedNode $Node -Phase 'proxy switch'
}
function Select-FixtureProfile {
    param([string]$Uid, [string]$AllowName, [string]$RejectName)
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    $attempt = 0
    $outcome = $null
    $status = $null
    while ($true) {
        $attempt++
        $outcome = Invoke-CvrCommand -Command 'patch_profiles_config' -Payload @{ profiles=@{ current=$Uid } }
        if ($null -eq $outcome -or $outcome -is [array] -or -not ($outcome.PSObject.Properties.Name -contains 'status')) {
            throw "patch_profiles_config uid=$Uid returned an unexpected result shape on attempt $attempt; snapshot=$(Get-NativeStateSnapshot -Phase 'profile selection')."
        }
        $status = ([string]$outcome.status).ToLowerInvariant()
        Write-Host "patch_profiles_config uid=$Uid attempt=$attempt status=$status."
        if ($status -eq 'valid') { break }
        if ($status -ne 'busy') {
            throw "patch_profiles_config uid=$Uid returned non-retryable status=$status on attempt $attempt; snapshot=$(Get-NativeStateSnapshot -Phase 'profile selection')."
        }
        if ([DateTime]::UtcNow -ge $deadline) {
            throw "patch_profiles_config uid=$Uid remained busy for 30 seconds after $attempt attempts; snapshot=$(Get-NativeStateSnapshot -Phase 'profile selection')."
        }
        Start-Sleep -Milliseconds 500
    }
    try {
        $yaml = Wait-RuntimeRule -Rule "DOMAIN-SUFFIX,$AllowName,DIRECT"
        if (-not $yaml.Contains("DOMAIN-SUFFIX,$RejectName,REJECT")) { throw "Loaded profile lacks the reject rule for $RejectName." }
    } catch {
        throw "Profile selection validated (uid=$Uid, attempts=$attempt), but loaded runtime rules were not confirmed: $($_.Exception.Message) snapshot=$(Get-NativeStateSnapshot -Phase 'runtime rule wait')."
    }
}
function Assert-SelectedProfileReady {
    param([string[]]$OriginalDefaults, [string[]]$OriginalDns, [string]$Phase)
    $state = Wait-ServiceReady
    if (-not [bool]$state.tunCapable) { throw 'CVR reports no TUN capability.' }
    Assert-LiveCoreIdentity
    Assert-FixtureRoute
    Assert-SystemRoutesRemainScoped -OriginalDefaults $OriginalDefaults -OriginalDns $OriginalDns -Phase $Phase
}
function Test-FixtureTraffic {
    param([string]$FixtureName,[int]$DnsPort,[int]$HttpPort,[string]$ExpectedResolver)
    $fake=Invoke-DnsQuery -Name $FixtureName -Port $DnsPort
    if ($ExpectedResolver) { Assert-DnsResolver -Name $FixtureName -Resolver $ExpectedResolver }
    [void](Invoke-TunHttp -FakeAddress $fake -FixtureName $FixtureName -Port $HttpPort)
    Write-Host "TUN/DNS fixture passed: $FixtureName -> $fake -> local HTTP; resolver=$ExpectedResolver."
}
function Test-RejectedFixture {
    param(
        [string]$FixtureName,
        [string]$AllowedControlName,
        [int]$DnsPort,
        [int]$HttpPort,
        [string[]]$OriginalDefaults,
        [string[]]$OriginalDns,
        [string]$Phase
    )
    Test-FixtureTraffic -FixtureName $AllowedControlName -DnsPort $DnsPort -HttpPort $HttpPort
    Assert-SelectedProfileReady -OriginalDefaults $OriginalDefaults -OriginalDns $OriginalDns -Phase "$Phase positive control before reject"
    $routeBefore = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '198.18.0.0/16' -ErrorAction Stop |
        ForEach-Object { "$($_.DestinationPrefix)|$($_.InterfaceIndex)|$($_.NextHop)|$($_.RouteMetric)" } | Sort-Object)
    if (-not $routeBefore.Count) { throw "No synthetic route before $Phase reject probe." }

    $expectedRejections = @(
        [System.Net.Sockets.SocketError]::ConnectionRefused,
        [System.Net.Sockets.SocketError]::ConnectionReset,
        [System.Net.Sockets.SocketError]::ConnectionAborted,
        [System.Net.Sockets.SocketError]::NetworkReset
    )
    $fake = Invoke-DnsQuery -Name $FixtureName -Port $DnsPort
    $client = [Net.Sockets.TcpClient]::new()
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $rejection = $null
    $probeFailure = $null
    $responseBytes = 0
    try {
        $connectTask = $client.ConnectAsync([Net.IPAddress]::Parse($fake), $HttpPort)
        if (-not $connectTask.Wait(2000)) { throw "$Phase reject probe timed out during TCP setup." }
        $stream = $client.GetStream()
        $stream.ReadTimeout = 2000
        $stream.WriteTimeout = 2000
        $crlf = [string][char]13 + [char]10
        $request = [Text.Encoding]::ASCII.GetBytes('GET / HTTP/1.1' + $crlf + "Host: $FixtureName" + $crlf + 'Connection: close' + $crlf + $crlf)
        $stream.Write($request, 0, $request.Length)
        $responseBuffer = New-Object byte[] 1
        $responseBytes = $stream.Read($responseBuffer, 0, $responseBuffer.Length)
        if ($responseBytes -eq 0) { $rejection = 'EOF' }
        else { $probeFailure = "$Phase REJECT probe received application response data." }
    } catch [System.AggregateException] {
        $socketException = $_.Exception.GetBaseException()
        if ($socketException -is [System.Net.Sockets.SocketException]) {
            $socketError = [System.Net.Sockets.SocketError]$socketException.SocketErrorCode
            if ($expectedRejections -contains $socketError) { $rejection = $socketError }
            else { $probeFailure = "$Phase REJECT probe returned unclassified socket result: $socketError" }
        } else { $probeFailure = "$Phase REJECT probe failed: $($socketException.GetType().FullName)" }
    } catch [System.IO.IOException] {
        $socketException = $_.Exception.GetBaseException()
        if ($socketException -is [System.Net.Sockets.SocketException]) {
            $socketError = [System.Net.Sockets.SocketError]$socketException.SocketErrorCode
            if ($expectedRejections -contains $socketError) { $rejection = $socketError }
            else { $probeFailure = "$Phase REJECT probe returned unclassified socket result: $socketError" }
        } else { $probeFailure = "$Phase REJECT probe failed: $($socketException.GetType().FullName)" }
    } catch [System.Net.Sockets.SocketException] {
        $socketError = [System.Net.Sockets.SocketError]$_.Exception.SocketErrorCode
        if ($expectedRejections -contains $socketError) { $rejection = $socketError }
        else { $probeFailure = "$Phase REJECT probe returned unclassified socket result: $socketError" }
    } catch {
        $probeFailure = $_.Exception.Message
    } finally {
        $watch.Stop()
        $client.Dispose()
    }
    if (-not $probeFailure -and -not $rejection) { $probeFailure = "$Phase REJECT probe had no classified result." }
    if (-not $probeFailure -and $expectedRejections -notcontains $rejection -and $rejection -ne 'EOF') {
        $probeFailure = "$Phase returned an unclassified REJECT result: $rejection"
    }
    if (-not $probeFailure -and $responseBytes -ne 0) { $probeFailure = "$Phase REJECT probe returned $responseBytes application response bytes." }
    if ($watch.ElapsedMilliseconds -ge 2000) { $probeFailure = "$Phase REJECT response was not quick: $($watch.ElapsedMilliseconds) ms." }

    $phaseFailures = [Collections.Generic.List[string]]::new()
    if ($probeFailure) { $phaseFailures.Add("negative application probe: $probeFailure") }
    try {
        Assert-SelectedProfileReady -OriginalDefaults $OriginalDefaults -OriginalDns $OriginalDns -Phase "$Phase after reject"
        $routeAfter = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '198.18.0.0/16' -ErrorAction Stop |
            ForEach-Object { "$($_.DestinationPrefix)|$($_.InterfaceIndex)|$($_.NextHop)|$($_.RouteMetric)" } | Sort-Object)
        if (@(Compare-Object -ReferenceObject $routeBefore -DifferenceObject $routeAfter).Count) {
            $phaseFailures.Add("$Phase reject probe changed the synthetic route.")
        }
    } catch { $phaseFailures.Add("post-reject service/route check: $($_.Exception.Message)") }
    try {
        Test-FixtureTraffic -FixtureName $AllowedControlName -DnsPort $DnsPort -HttpPort $HttpPort
        Assert-SelectedProfileReady -OriginalDefaults $OriginalDefaults -OriginalDns $OriginalDns -Phase "$Phase positive control after reject"
        $routeAfterControl = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '198.18.0.0/16' -ErrorAction Stop |
            ForEach-Object { "$($_.DestinationPrefix)|$($_.InterfaceIndex)|$($_.NextHop)|$($_.RouteMetric)" } | Sort-Object)
        if (@(Compare-Object -ReferenceObject $routeBefore -DifferenceObject $routeAfterControl).Count) {
            $phaseFailures.Add("$Phase positive control changed the synthetic route.")
        }
    } catch { $phaseFailures.Add("post-reject positive control: $($_.Exception.Message)") }
    if ($phaseFailures.Count) { throw "$Phase REJECT acceptance failed: $($phaseFailures -join ' | ')" }
    Write-Host "$Phase application REJECT returned $rejection with $responseBytes response bytes in $($watch.ElapsedMilliseconds) ms; service/core identity, route and positive control remained valid."
}

$baselineDefaults = @(Get-DefaultRouteSnapshot)
$baselineDns = @(Get-PhysicalDnsSnapshot)
if (@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '198.18.0.0/16' -ErrorAction SilentlyContinue).Count) { throw 'Clean-runner precondition failed: synthetic route already exists.' }
$script:cdp=$null; $script:cdpId=0; $script:guiProcess=$null; $script:guiProcessId=0; $script:devtoolsPort=0; $gui=$null; $server=$null
$devtoolsPort=Get-FreeTcpPort; $script:devtoolsPort=$devtoolsPort; $httpPort=Get-FreeTcpPort; $dnsPort=Get-FreeTcpPort
$profileDnsPort=Get-FreeTcpPort; $appDnsPort=Get-FreeTcpPort
$proxyPortA=Get-FreeTcpPort; $proxyPortB=Get-FreeTcpPort
$script:dnsLogPath=Join-Path $env:RUNNER_TEMP "stcvrc-native-dns-$Phase.log"
if (Test-Path -LiteralPath $script:dnsLogPath) { Remove-Item -LiteralPath $script:dnsLogPath -Force }
$serverPath=Join-Path $env:RUNNER_TEMP 'stcvrc-native-fixture-server.py'
$serverCode=@'
import os, socket, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
HTTP_PORT=int(os.environ["STCVRC_NATIVE_HTTP_PORT"])
PROFILE_DNS_PORT=int(os.environ["STCVRC_NATIVE_PROFILE_DNS_PORT"])
APP_DNS_PORT=int(os.environ["STCVRC_NATIVE_APP_DNS_PORT"])
DNS_LOG=os.environ["STCVRC_NATIVE_DNS_LOG"]
LOG_LOCK=threading.Lock()
class Handler(BaseHTTPRequestHandler):
    protocol_version="HTTP/1.1"
    def do_GET(self):
        host=self.headers.get("Host","").split(":",1)[0]
        body=("native-fixture:"+host).encode("ascii","strict")
        self.send_response(200); self.send_header("Content-Type","text/plain")
        self.send_header("Content-Length",str(len(body))); self.send_header("Connection","close")
        self.end_headers(); self.wfile.write(body)
    def log_message(self,fmt,*args): print("HTTP "+(fmt%args),flush=True)
def dns_server(port,label):
    sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); sock.bind(("127.0.0.1",port))
    while True:
        packet,peer=sock.recvfrom(4096)
        if len(packet)<17: continue
        end=12; labels=[]
        while end<len(packet) and packet[end]!=0:
            length=packet[end]; labels.append(packet[end+1:end+1+length].decode("ascii","replace"))
            end += 1+length
        if end+5>len(packet): continue
        qname=".".join(labels).lower()
        end += 5
        with LOG_LOCK:
            with open(DNS_LOG,"a",encoding="utf-8") as log: log.write(label+"|"+qname+chr(10))
        response=packet[:2]+bytes.fromhex("8180")+packet[4:6]+bytes.fromhex("000100000000")
        response+=packet[12:end]+bytes.fromhex("c00c000100010000000500047f000001")
        sock.sendto(response,peer)
threading.Thread(target=dns_server,args=(PROFILE_DNS_PORT,"profile"),daemon=True).start()
threading.Thread(target=dns_server,args=(APP_DNS_PORT,"app"),daemon=True).start()
HTTPServer(("127.0.0.1",HTTP_PORT),Handler).serve_forever()
'@
[IO.File]::WriteAllText($serverPath,$serverCode,[Text.UTF8Encoding]::new($false))
$env:STCVRC_NATIVE_HTTP_PORT=[string]$httpPort
$env:STCVRC_NATIVE_PROFILE_DNS_PORT=[string]$profileDnsPort
$env:STCVRC_NATIVE_APP_DNS_PORT=[string]$appDnsPort
$env:STCVRC_NATIVE_DNS_LOG=$script:dnsLogPath
$python=(Get-Command python.exe -ErrorAction Stop).Source
$serverArgs=@('-u', ('"' + $serverPath + '"'))
$server=Start-Process -FilePath $python -ArgumentList $serverArgs -PassThru -WindowStyle Hidden
try {
    $deadline=[DateTime]::UtcNow.AddSeconds(10); $serverReady=$false
    while ([DateTime]::UtcNow -lt $deadline) {
        if ($server.HasExited) { throw 'Synthetic fixture server exited before ready.' }
        try { $probe=[Net.Sockets.TcpClient]::new(); $task=$probe.ConnectAsync([Net.IPAddress]::Loopback,$httpPort); if ($task.Wait(300)) { $serverReady=$true; $probe.Dispose(); break }; $probe.Dispose() } catch { Start-Sleep -Milliseconds 100 }
    }
    if (-not $serverReady) { throw 'Synthetic HTTP/DNS server did not become ready.' }
    $env:WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS="--remote-debugging-port=$devtoolsPort"
    $gui=Start-Process -FilePath $guiPath -PassThru -WindowStyle Normal
    $script:guiProcess=$gui; $script:guiProcessId=[int]$gui.Id
    $deadline=[DateTime]::UtcNow.AddSeconds(40); $windowReady=$false
    while ([DateTime]::UtcNow -lt $deadline) {
        $gui.Refresh()
        if ($gui.HasExited) { throw 'Installed CVR GUI exited during startup.' }
        if ($gui.MainWindowHandle -ne [IntPtr]::Zero -and -not [string]::IsNullOrWhiteSpace($gui.MainWindowTitle)) { $windowReady=$true; break }
        Start-Sleep -Milliseconds 500
    }
    if (-not $windowReady) { throw 'Installed CVR GUI did not expose a native window on windows-2022.' }
    Write-Host "Native GUI window shown: $($gui.MainWindowTitle); pid=$($gui.Id)."
    $target=$null; $deadline=[DateTime]::UtcNow.AddSeconds(35)
    while ([DateTime]::UtcNow -lt $deadline) {
        try { $targets=@(Invoke-RestMethod -Uri "http://127.0.0.1:$devtoolsPort/json/list" -TimeoutSec 2); $target=$targets | Where-Object { $_.type -eq 'page' -and $_.webSocketDebuggerUrl } | Select-Object -First 1; if ($target) { break } } catch { Start-Sleep -Milliseconds 500 }
        Start-Sleep -Milliseconds 500
    }
    if (-not $target) { throw 'GUI WebView2 DevTools page was unavailable; real Tauri commands cannot be asserted.' }
    $script:cdp=[Net.WebSockets.ClientWebSocket]::new()
    $null = $script:cdp.ConnectAsync([Uri]$target.webSocketDebuggerUrl,[Threading.CancellationToken]::None).GetAwaiter().GetResult()
    $deadline=[DateTime]::UtcNow.AddSeconds(15); $ipcReady=$false
    while ([DateTime]::UtcNow -lt $deadline) { try { $null=Invoke-CvrCommand -Command 'get_runtime_state'; $ipcReady=$true; break } catch { Start-Sleep -Milliseconds 500 } }
    if (-not $ipcReady) { throw 'Visible GUI did not expose functioning Tauri commands over WebView2.' }

    if ($Phase -eq 'seed') {
        try {
            Assert-GlobalUiModesOff -Phase '2.5.8 profile/config seed'
            $uidA=Add-FixtureProfile -Name 'native-fixture-a' -AllowName 'native-fixture-a.invalid' -RejectName 'native-fixture-b.invalid' -DnsPort $dnsPort -ProfileDnsPort $profileDnsPort -ControllerPort (Get-FreeTcpPort) -ProxyPortA $proxyPortA -ProxyPortB $proxyPortB
            $uidB=Add-FixtureProfile -Name 'native-fixture-b' -AllowName 'native-fixture-b.invalid' -RejectName 'native-fixture-a.invalid' -DnsPort $dnsPort -ProfileDnsPort $profileDnsPort -ControllerPort (Get-FreeTcpPort) -ProxyPortA $proxyPortA -ProxyPortB $proxyPortB
            Select-FixtureProfile -Uid $uidA -AllowName 'native-fixture-a.invalid' -RejectName 'native-fixture-b.invalid'
            Assert-LiveSidecarCoreIdentity
            Select-FixtureNode -Node 'fixture-node-a' -ProfileName 'native-fixture-a'
            Select-FixtureProfile -Uid $uidB -AllowName 'native-fixture-b.invalid' -RejectName 'native-fixture-a.invalid'
            Select-FixtureNode -Node 'fixture-node-b' -ProfileName 'native-fixture-b'
            Select-FixtureProfile -Uid $uidA -AllowName 'native-fixture-a.invalid' -RejectName 'native-fixture-b.invalid'
            Assert-FixtureNodeSelection -ProfileName 'native-fixture-a' -ExpectedNode 'fixture-node-a' -Phase '2.5.8 pre-update seed'
            Write-Host '2.5.8 seeded two valid local profiles and persisted distinct GLOBAL selections before the 2.5.10 update.'
            Request-CvrGuiExit
        } catch { Add-Failure "2.5.8 profile/config seed: $($_.Exception.Message)" }
    } elseif ($Phase -eq 'recovery') {
        try {
            Assert-GlobalUiModesOff -Phase '2.5.8 functional recovery'
            $profiles = Invoke-CvrCommand -Command 'get_profiles'
            $profileA = Get-FixtureProfile -Name 'native-fixture-a'
            $profileB = Get-FixtureProfile -Name 'native-fixture-b'
            if ([string]$profiles.current -ne [string]$profileA.uid) { throw "Recovered CVR current profile is $($profiles.current), expected native-fixture-a ($($profileA.uid))." }
            Select-FixtureProfile -Uid ([string]$profileA.uid) -AllowName 'native-fixture-a.invalid' -RejectName 'native-fixture-b.invalid'
            Assert-LiveSidecarCoreIdentity
            Assert-FixtureNodeSelection -ProfileName 'native-fixture-a' -ExpectedNode 'fixture-node-a' -Phase '2.5.8 recovery'
            Select-FixtureProfile -Uid ([string]$profileB.uid) -AllowName 'native-fixture-b.invalid' -RejectName 'native-fixture-a.invalid'
            Assert-FixtureNodeSelection -ProfileName 'native-fixture-b' -ExpectedNode 'fixture-node-b' -Phase '2.5.8 recovery'
            Select-FixtureProfile -Uid ([string]$profileA.uid) -AllowName 'native-fixture-a.invalid' -RejectName 'native-fixture-b.invalid'
            Assert-FixtureNodeSelection -ProfileName 'native-fixture-a' -ExpectedNode 'fixture-node-a' -Phase '2.5.8 recovery'
            $runtime = Get-RuntimeYaml
            if (-not $runtime.Contains('proxy-server-nameserver:') -or -not $runtime.Contains('nameserver-policy:')) { throw 'Recovered 2.5.8 core did not load the persisted profile DNS configuration.' }
            Write-Host '2.5.8 recovery launched the verified GUI and custom core, loaded preserved profiles/config, and restored each profile GLOBAL selector.'
            Request-CvrGuiExit
        } catch { Add-Failure "2.5.8 functional recovery: $($_.Exception.Message)" }
    } else {
        try {
            $outcome=Invoke-CvrCommand -Command 'install_service'
            if (([string]$outcome.status).ToLowerInvariant() -ne 'installed') { throw "Tauri install_service did not report installed: $($outcome | ConvertTo-Json -Compress -Depth 10)" }
            $deadline=[DateTime]::UtcNow.AddSeconds(30); $svc=$null
            while ([DateTime]::UtcNow -lt $deadline) {
                $svc=Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                if ($svc -and $svc.Status -eq 'Running') { break }
                Start-Sleep -Milliseconds 500
            }
            if (-not $svc -or $svc.Status -ne 'Running') { throw 'Tauri install_service did not start the SCM service.' }
            Assert-LiveServiceIdentity
            Write-Host 'Tauri install_service created and started the verified CVR service.'
        } catch {
            Add-Failure "Tauri service start: $($_.Exception.Message)"
        }

        try {
            Assert-GlobalUiModesOff -Phase '2.5.10 service exercise'
            $profileA=Get-FixtureProfile -Name 'native-fixture-a'
            $profileB=Get-FixtureProfile -Name 'native-fixture-b'
            $uidA=[string]$profileA.uid; $uidB=[string]$profileB.uid
            $profiles=Invoke-CvrCommand -Command 'get_profiles'
            if ([string]$profiles.current -ne $uidA) { throw "The 2.5.10 update did not preserve current profile A: $($profiles.current)." }
            Select-FixtureProfile -Uid $uidA -AllowName 'native-fixture-a.invalid' -RejectName 'native-fixture-b.invalid'
            Assert-FixtureNodeSelection -ProfileName 'native-fixture-a' -ExpectedNode 'fixture-node-a' -Phase '2.5.8 to 2.5.10 update'
            [void](Invoke-CvrCommand -Command 'patch_verge_config' -Payload @{ payload=@{ enable_tun_mode=$true } })
            [void](Invoke-CvrCommand -Command 'restart_core')
            Assert-SelectedProfileReady -OriginalDefaults $baselineDefaults -OriginalDns $baselineDns -Phase 'native TUN service startup'

            $appDns = @{ dns=@{ enable=$true; 'enhanced-mode'='fake-ip'; 'fake-ip-range'='198.18.0.1/16'; 'default-nameserver'=@('127.0.0.1'); nameserver=@("udp://127.0.0.1:$appDnsPort") } }
            [void](Invoke-CvrCommand -Command 'save_dns_config' -Payload @{ dnsConfig=$appDns })
            $dnsFile=[string](Invoke-CvrCommand -Command 'get_dns_config_content')
            if (-not $dnsFile.Contains("127.0.0.1:$appDnsPort")) { throw 'CVR did not persist the synthetic app DNS configuration.' }

            [void](Set-FixtureDnsOverride -Uid $uidA -Enabled $false -Confirm $false)
            Assert-ProfileDnsState -Uid $uidA -Enabled $false -Phase 'profile A DNS off'
            Test-FixtureTraffic -FixtureName 'dns-off.native-fixture-a.invalid' -DnsPort $dnsPort -HttpPort $httpPort -ExpectedResolver 'profile'

            $sourceA=Set-FixtureDnsOverride -Uid $uidA -Enabled $true -Confirm $false
            [void](Set-FixtureDnsOverride -Uid $uidA -Enabled $true -Confirm $true)
            Assert-ProfileDnsState -Uid $uidA -Enabled $true -Phase 'profile A DNS on after confirmation'
            Test-FixtureTraffic -FixtureName 'dns-on.native-fixture-a.invalid' -DnsPort $dnsPort -HttpPort $httpPort -ExpectedResolver 'app'
            [void](Set-FixtureDnsOverride -Uid $uidA -Enabled $false -Confirm $false)
            Assert-ProfileDnsState -Uid $uidA -Enabled $false -Phase 'profile A DNS disabled after enable'
            Test-FixtureTraffic -FixtureName 'dns-off-after-on.native-fixture-a.invalid' -DnsPort $dnsPort -HttpPort $httpPort -ExpectedResolver 'profile'
            $sourceAAfterToggle=Set-FixtureDnsOverride -Uid $uidA -Enabled $true -Confirm $false
            if ($sourceAAfterToggle -ne $sourceA) { throw 'Profile A DNS confirmation digest changed without a source configuration change.' }
            [void](Set-FixtureDnsOverride -Uid $uidA -Enabled $true -Confirm $true)
            Assert-ProfileDnsState -Uid $uidA -Enabled $true -Phase 'profile A DNS re-enabled after toggle'
            Test-FixtureTraffic -FixtureName 'dns-reenabled-after-toggle.native-fixture-a.invalid' -DnsPort $dnsPort -HttpPort $httpPort -ExpectedResolver 'app'
            Write-Host "DNS override confirmation source bound to profile A: $sourceA."

            Select-FixtureProfile -Uid $uidB -AllowName 'native-fixture-b.invalid' -RejectName 'native-fixture-a.invalid'
            Assert-FixtureNodeSelection -ProfileName 'native-fixture-b' -ExpectedNode 'fixture-node-b' -Phase 'profile B restore after update'
            [void](Set-FixtureDnsOverride -Uid $uidB -Enabled $false -Confirm $false)
            $sourceB=Set-FixtureDnsOverride -Uid $uidB -Enabled $true -Confirm $false
            if (-not $sourceB) { throw 'Profile B DNS override did not request its own confirmation.' }
            if ($sourceA -eq $sourceB) { throw 'DNS confirmation source was not bound to the selected profile and source configuration.' }
            Assert-ProfileDnsState -Uid $uidB -Enabled $false -Phase 'profile B independently remains off'
            Test-FixtureTraffic -FixtureName 'dns-off.native-fixture-b.invalid' -DnsPort $dnsPort -HttpPort $httpPort -ExpectedResolver 'profile'
            Test-RejectedFixture -FixtureName 'native-fixture-a.invalid' -AllowedControlName 'native-fixture-b.invalid' -DnsPort $dnsPort -HttpPort $httpPort -OriginalDefaults $baselineDefaults -OriginalDns $baselineDns -Phase 'profile B application reject'

            Select-FixtureProfile -Uid $uidA -AllowName 'native-fixture-a.invalid' -RejectName 'native-fixture-b.invalid'
            Assert-FixtureNodeSelection -ProfileName 'native-fixture-a' -ExpectedNode 'fixture-node-a' -Phase 'switch back to profile A'
            Assert-ProfileDnsState -Uid $uidA -Enabled $true -Phase 'profile A state after switching profiles'
            Test-FixtureTraffic -FixtureName 'dns-reenabled.native-fixture-a.invalid' -DnsPort $dnsPort -HttpPort $httpPort -ExpectedResolver 'app'
            Test-RejectedFixture -FixtureName 'native-fixture-b.invalid' -AllowedControlName 'native-fixture-a.invalid' -DnsPort $dnsPort -HttpPort $httpPort -OriginalDefaults $baselineDefaults -OriginalDns $baselineDns -Phase 'profile A application reject'

            [void](Invoke-CvrCommand -Command 'restart_core')
            Assert-SelectedProfileReady -OriginalDefaults $baselineDefaults -OriginalDns $baselineDns -Phase 'service core restart'
            Assert-FixtureNodeSelection -ProfileName 'native-fixture-a' -ExpectedNode 'fixture-node-a' -Phase 'core restart'
            Assert-ProfileDnsState -Uid $uidA -Enabled $true -Phase 'core restart'
            Test-FixtureTraffic -FixtureName 'dns-restart.native-fixture-a.invalid' -DnsPort $dnsPort -HttpPort $httpPort -ExpectedResolver 'app'
            Write-Host 'DNS override on/off/confirmation, per-profile separation, GLOBAL selector restore, and TUN/DNS/HTTP all passed on the fresh custom core.'
        } catch { Add-Failure "2.5.10 DNS/profile/TUN acceptance: $($_.Exception.Message)" }

        if ($script:cdp.State -eq [Net.WebSockets.WebSocketState]::Open) {
            try {
                [void](Invoke-CvrCommand -Command 'patch_verge_config' -Payload @{ payload=@{ enable_tun_mode=$false } })
                [void](Invoke-CvrCommand -Command 'uninstall_service')
                Request-CvrGuiExit
            } catch { Add-Failure "Tauri runtime cleanup: $($_.Exception.Message)" }
        }
    }
} catch {
    Add-Failure "Native setup or GUI/CDP blocker: $($_.Exception.Message)"
} finally {
    if ($script:cdp) {
        try { if ($script:cdp.State -eq [Net.WebSockets.WebSocketState]::Open) { $script:cdp.CloseAsync([Net.WebSockets.WebSocketCloseStatus]::NormalClosure,'complete',[Threading.CancellationToken]::None).GetAwaiter().GetResult() } }
        catch { Add-Failure "WebView2 cleanup: $($_.Exception.Message)" }
        $script:cdp.Dispose()
    }
    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) { Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue; & sc.exe delete $serviceName | Out-Null }
    if ($gui -and -not $gui.HasExited) { & taskkill.exe /PID $gui.Id /T /F | Out-Null }
    foreach ($name in @('clash-verge','clash-verge-service','verge-mihomo','verge-mihomo-alpha')) { Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue }
    if ($server -and -not $server.HasExited) { Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Seconds 2
    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) { Add-Failure 'Temporary CVR service remained after cleanup.' }
    foreach ($name in @('clash-verge','clash-verge-service','verge-mihomo','verge-mihomo-alpha')) { if (Get-Process -Name $name -ErrorAction SilentlyContinue) { Add-Failure "Temporary process remained: $name" } }
    foreach ($route in @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '198.18.0.0/16' -ErrorAction SilentlyContinue)) { try { $route | Remove-NetRoute -Confirm:$false -ErrorAction Stop } catch { Add-Failure "Could not remove exact synthetic route: $($_.Exception.Message)" } }
    try { Assert-SystemRoutesRemainScoped -OriginalDefaults $baselineDefaults -OriginalDns $baselineDns -Phase 'native cleanup' } catch { Add-Failure $_.Exception.Message }
}
$summary=@(
    '## Bounded native CVR 2.5.10 acceptance',
    '- Requires an actual GUI window and invokes the installed Tauri commands through its WebView2 page.',
    '- Checks ready service mode, SCM service, live core path and SHA against the fresh source build.',
    '- Runs generic synthetic DNS/HTTP fixtures through explicit 198.18.0.0/16 TUN routing and verifies profile A-to-B-to-A reload/recovery.',
    '- Compares system default routes and physical DNS before/after; removes only the exact temporary synthetic route.',
    '- No production profiles, external VPN, secrets, paid runners, Actions cache or artifacts.'
)
if ($failures.Count) { $summary += "- Result: FAIL ($($failures.Count) assertion(s))."; $summary += $failures | ForEach-Object { "- Failure: $_" } }
else { $summary += '- Result: PASS.' }
Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY -Value $summary
if ($failures.Count) { throw "Native Windows acceptance failed: $($failures -join ' | ')" }