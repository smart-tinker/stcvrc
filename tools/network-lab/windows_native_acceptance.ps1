$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

if ($env:GITHUB_ACTIONS -ne 'true' -or $env:GITHUB_REPOSITORY -ne 'smart-tinker/stcvrc') { throw 'Native acceptance is restricted to the disposable public STCVRC GitHub runner.' }
if (-not $env:PR_SOURCE -or -not $env:CUSTOM_CORE -or -not $env:CVR_2510_GUI_SHA256) { throw 'The exact PR source, fresh custom core, or pinned CVR GUI SHA is missing.' }
$manifest = Get-Content -LiteralPath (Join-Path $env:PR_SOURCE 'candidates\cvr-2.5.10\inputs.json') -Raw | ConvertFrom-Json
$coreSha = ([string]$manifest.core.sha256).ToLowerInvariant()
if ($coreSha -ne 'd72784d98a44b90e561c701589c50f53074958d7cef656607ee5be1143b36c87') { throw 'Unexpected fresh STCVRC core identity.' }
if ((Get-FileHash -LiteralPath $env:CUSTOM_CORE -Algorithm SHA256).Hash.ToLowerInvariant() -ne $coreSha) { throw 'The candidate input is not the freshly built pinned core.' }

$version = '1.19.33-STCVRC-candidate-mit-lzo-20261111'
$serviceName = 'clash_verge_service'
$serviceCore = Join-Path $env:ProgramData 'clash-verge-service\cores\verge-mihomo.exe'
$installRoot = Join-Path $env:ProgramFiles 'Clash Verge'
$guiPath = Join-Path $installRoot 'clash-verge.exe'
$helper = Get-ChildItem -LiteralPath $installRoot -Recurse -File -Filter 'clash-verge-service-install.exe' | Select-Object -First 1
if (-not (Test-Path -LiteralPath $guiPath -PathType Leaf) -or -not $helper) { throw 'The verified 2.5.10 GUI or service helper is absent from the installed payload.' }
if ((Get-FileHash -LiteralPath $serviceCore -Algorithm SHA256).Hash.ToLowerInvariant() -ne $coreSha) { throw 'The service staging path does not contain the fresh source-built core.' }
if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) { throw 'Clean-runner precondition failed: a CVR service already exists.' }

$failures = [Collections.Generic.List[string]]::new()
function Add-Failure { param([string]$Message) $failures.Add($Message); Write-Host "ASSERTION FAILED: $Message" -ForegroundColor Red }
function Get-FreeTcpPort {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $listener.Start(); $port = ([Net.IPEndPoint]$listener.LocalEndpoint).Port; $listener.Stop(); return $port
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
function Invoke-CvrCommand {
    param([string]$Command, [hashtable]$Payload = @{})
    if (-not $script:cdp -or $script:cdp.State -ne [Net.WebSockets.WebSocketState]::Open) { throw 'The visible CVR WebView2 command channel is not connected.' }
    $script:cdpId++
    $jsonArgs = ConvertTo-Json -InputObject $Payload -Compress -Depth 20
    $expression = "(async()=>await window.__TAURI_INTERNALS__.invoke('$Command',$jsonArgs))()"
    $packet = @{ id=$script:cdpId; method='Runtime.evaluate'; params=@{ expression=$expression; awaitPromise=$true; returnByValue=$true; userGesture=$true } } | ConvertTo-Json -Compress -Depth 20
    $bytes = [Text.Encoding]::UTF8.GetBytes($packet)
    $script:cdp.SendAsync([ArraySegment[byte]]::new($bytes), [Net.WebSockets.WebSocketMessageType]::Text, $true, [Threading.CancellationToken]::None).GetAwaiter().GetResult()
    while ($true) {
        $reply = Receive-CdpMessage
        if ($reply.id -ne $script:cdpId) { continue }
        if ($reply.result.exceptionDetails) { throw "CVR Tauri command $Command failed: $($reply.result.exceptionDetails.text)" }
        if ($reply.result.result.PSObject.Properties.Name -contains 'value') { return $reply.result.result.value }
        return $null
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
    while ([DateTime]::UtcNow -lt $deadline) {
        $state = Invoke-CvrCommand -Command 'get_runtime_state'
        if (([string]$state.mode).ToLowerInvariant() -eq 'service' -and ([string]$state.service).ToLowerInvariant() -eq 'ready' -and [bool]$state.serviceUsable) { return $state }
        Start-Sleep -Milliseconds 700
    }
    throw 'get_runtime_state did not reach service=ready, mode=service.'
}
function Assert-LiveServiceIdentity {
    $service = Get-Service -Name $serviceName -ErrorAction Stop
    if ($service.Status -ne 'Running') { throw 'SCM does not report the CVR service running.' }
    $serviceRecord = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    if (-not $serviceRecord -or $serviceRecord.State -ne 'Running') { throw 'CVR SCM service is not running.' }
    $serviceExe = [IO.Path]::GetFullPath(([string]$serviceRecord.PathName).Trim('"').Split(' ')[0])
    if (-not $serviceExe.StartsWith([IO.Path]::GetFullPath($installRoot), [StringComparison]::OrdinalIgnoreCase)) { throw "Service image is outside verified install: $serviceExe" }
}
function Assert-LiveCoreIdentity {
    Assert-LiveServiceIdentity
    $processes = @(Get-CimInstance Win32_Process -Filter "Name='verge-mihomo.exe'" | Where-Object { $_.ExecutablePath -and [IO.Path]::GetFullPath($_.ExecutablePath) -eq [IO.Path]::GetFullPath($serviceCore) })
    if ($processes.Count -ne 1) { throw "Expected one live core at the service staging path; found $($processes.Count)." }
    if ((Get-FileHash -LiteralPath $processes[0].ExecutablePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $coreSha) { throw 'Live service core SHA256 mismatch.' }
    if (@(Get-CimInstance Win32_Process -Filter "Name='verge-mihomo-alpha.exe'" -ErrorAction SilentlyContinue).Count) { throw 'Alpha core process started during acceptance.' }
}
function Get-RuntimeYaml { [string](Invoke-CvrCommand -Command 'get_runtime_yaml') }
function Wait-RuntimeRule {
    param([string]$Rule)
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    while ([DateTime]::UtcNow -lt $deadline) { $yaml=Get-RuntimeYaml; if ($yaml.Contains($Rule)) { return $yaml }; Start-Sleep -Milliseconds 500 }
    throw "Loaded runtime did not contain $Rule."
}
function Add-FixtureProfile {
    param([string]$Name, [string]$AllowName, [string]$RejectName, [int]$DnsPort, [int]$UpstreamPort, [int]$ControllerPort)
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
    - udp://127.0.0.1:$UpstreamPort
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
  - DOMAIN,$AllowName,DIRECT
  - DOMAIN,$RejectName,REJECT
  - MATCH,DIRECT
"@
    $item = @{ type='local'; name=$Name; desc='Disposable synthetic CI fixture'; url=$null; option=$null }
    [void](Invoke-CvrCommand -Command 'create_profile' -Payload @{ item=$item; fileData=$yaml })
    $profiles = Invoke-CvrCommand -Command 'get_profiles'
    $found = @($profiles.items | Where-Object { $_.name -eq $Name })
    if ($found.Count -ne 1 -or -not $found[0].uid) { throw "CVR did not persist profile $Name." }
    return [string]$found[0].uid
}
function Select-FixtureProfile {
    param([string]$Uid, [string]$AllowName, [string]$RejectName, [string[]]$OriginalDefaults, [string[]]$OriginalDns)
    [void](Invoke-CvrCommand -Command 'patch_profiles_config' -Payload @{ profiles=@{ current=$Uid } })
    $yaml = Wait-RuntimeRule -Rule "DOMAIN,$AllowName,DIRECT"
    if (-not $yaml.Contains("DOMAIN,$RejectName,REJECT")) { throw "Loaded profile lacks the reject rule for $RejectName." }
    $state = Wait-ServiceReady
    if (-not [bool]$state.tunCapable) { throw 'CVR reports no TUN capability.' }
    Assert-LiveCoreIdentity
    Assert-SystemRoutesRemainScoped -OriginalDefaults $OriginalDefaults -OriginalDns $OriginalDns -Phase $AllowName
}
function Test-FixtureTraffic { param([string]$FixtureName,[int]$DnsPort,[int]$HttpPort); $fake=Invoke-DnsQuery -Name $FixtureName -Port $DnsPort; [void](Invoke-TunHttp -FakeAddress $fake -FixtureName $FixtureName -Port $HttpPort); Write-Host "TUN/DNS fixture passed: $FixtureName -> $fake -> local HTTP." }
function Test-RejectedFixture {
    param([string]$FixtureName,[int]$DnsPort,[int]$HttpPort)
    $fake=Invoke-DnsQuery -Name $FixtureName -Port $DnsPort
    try { [void](Invoke-TunHttp -FakeAddress $fake -FixtureName $FixtureName -Port $HttpPort) }
    catch { Write-Host "Synthetic REJECT rule blocked $FixtureName through the TUN path."; return }
    throw "Synthetic REJECT rule did not block $FixtureName."
}

$baselineDefaults = @(Get-DefaultRouteSnapshot)
$baselineDns = @(Get-PhysicalDnsSnapshot)
if (@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '198.18.0.0/16' -ErrorAction SilentlyContinue).Count) { throw 'Clean-runner precondition failed: synthetic route already exists.' }
$script:cdp=$null; $script:cdpId=0; $gui=$null; $server=$null
$devtoolsPort=Get-FreeTcpPort; $httpPort=Get-FreeTcpPort; $dnsPort=Get-FreeTcpPort; $upstreamDnsPort=Get-FreeTcpPort
$serverPath=Join-Path $env:RUNNER_TEMP 'stcvrc-native-fixture-server.py'
$serverCode=@'
import os, socket, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
HTTP_PORT=int(os.environ["STCVRC_NATIVE_HTTP_PORT"])
DNS_PORT=int(os.environ["STCVRC_NATIVE_DNS_UPSTREAM_PORT"])
class Handler(BaseHTTPRequestHandler):
    protocol_version="HTTP/1.1"
    def do_GET(self):
        host=self.headers.get("Host","").split(":",1)[0]
        body=("native-fixture:"+host).encode("ascii","strict")
        self.send_response(200); self.send_header("Content-Type","text/plain")
        self.send_header("Content-Length",str(len(body))); self.send_header("Connection","close")
        self.end_headers(); self.wfile.write(body)
    def log_message(self,fmt,*args): print("HTTP "+(fmt%args),flush=True)
def dns_server():
    sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); sock.bind(("127.0.0.1",DNS_PORT))
    while True:
        packet,peer=sock.recvfrom(4096)
        if len(packet)<17: continue
        end=12
        while end<len(packet) and packet[end]!=0: end += 1+packet[end]
        if end+5>len(packet): continue
        end += 5
        response=packet[:2]+b"\x81\x80"+packet[4:6]+b"\x00\x01\x00\x00\x00\x00"
        response+=packet[12:end]+b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x05\x00\x04\x7f\x00\x00\x01"
        sock.sendto(response,peer)
threading.Thread(target=dns_server,daemon=True).start()
HTTPServer(("127.0.0.1",HTTP_PORT),Handler).serve_forever()
'@
[IO.File]::WriteAllText($serverPath,$serverCode,[Text.UTF8Encoding]::new($false))
$env:STCVRC_NATIVE_HTTP_PORT=[string]$httpPort; $env:STCVRC_NATIVE_DNS_UPSTREAM_PORT=[string]$upstreamDnsPort
$python=(Get-Command python.exe -ErrorAction Stop).Source
$server=Start-Process -FilePath $python -ArgumentList "-u $serverPath" -PassThru -WindowStyle Hidden
try {
    $deadline=[DateTime]::UtcNow.AddSeconds(10); $serverReady=$false
    while ([DateTime]::UtcNow -lt $deadline) {
        if ($server.HasExited) { throw 'Synthetic fixture server exited before ready.' }
        try { $probe=[Net.Sockets.TcpClient]::new(); $task=$probe.ConnectAsync([Net.IPAddress]::Loopback,$httpPort); if ($task.Wait(300)) { $serverReady=$true; $probe.Dispose(); break }; $probe.Dispose() } catch { Start-Sleep -Milliseconds 100 }
    }
    if (-not $serverReady) { throw 'Synthetic HTTP/DNS server did not become ready.' }
    $env:WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS="--remote-debugging-port=$devtoolsPort"
    $gui=Start-Process -FilePath $guiPath -PassThru -WindowStyle Normal
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
    $script:cdp.ConnectAsync([Uri]$target.webSocketDebuggerUrl,[Threading.CancellationToken]::None).GetAwaiter().GetResult()
    $deadline=[DateTime]::UtcNow.AddSeconds(15); $ipcReady=$false
    while ([DateTime]::UtcNow -lt $deadline) { try { $null=Invoke-CvrCommand -Command 'get_runtime_state'; $ipcReady=$true; break } catch { Start-Sleep -Milliseconds 500 } }
    if (-not $ipcReady) { throw 'Visible GUI did not expose functioning Tauri commands over WebView2.' }

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
        if (-not (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) { $output=& $helper.FullName --install-service 2>&1; if ($LASTEXITCODE -ne 0) { Add-Failure "Service helper fallback failed: $($output -join ' ')" } }
    }

    $uidA=$null; $uidB=$null
    try { $uidA=Add-FixtureProfile -Name 'native-fixture-a' -AllowName 'native-fixture-a.invalid' -RejectName 'native-fixture-b.invalid' -DnsPort $dnsPort -UpstreamPort $upstreamDnsPort -ControllerPort (Get-FreeTcpPort) } catch { Add-Failure "Create fixture A: $($_.Exception.Message)" }
    try { $uidB=Add-FixtureProfile -Name 'native-fixture-b' -AllowName 'native-fixture-b.invalid' -RejectName 'native-fixture-a.invalid' -DnsPort $dnsPort -UpstreamPort $upstreamDnsPort -ControllerPort (Get-FreeTcpPort) } catch { Add-Failure "Create fixture B: $($_.Exception.Message)" }
    if ($uidA) {
        try {
            Select-FixtureProfile -Uid $uidA -AllowName 'native-fixture-a.invalid' -RejectName 'native-fixture-b.invalid' -OriginalDefaults $baselineDefaults -OriginalDns $baselineDns
            [void](Invoke-CvrCommand -Command 'patch_verge_config' -Payload @{ payload=@{ enable_tun_mode=$true; enable_system_proxy=$false; enable_auto_launch=$false } })
            $null=Wait-ServiceReady; Assert-FixtureRoute
            Assert-SystemRoutesRemainScoped -OriginalDefaults $baselineDefaults -OriginalDns $baselineDns -Phase 'TUN fixture A'
            Test-FixtureTraffic -FixtureName 'native-fixture-a.invalid' -DnsPort $dnsPort -HttpPort $httpPort
        } catch { Add-Failure "Fixture A TUN/DNS traffic: $($_.Exception.Message)" }
    }
    if ($uidB) {
        try {
            Select-FixtureProfile -Uid $uidB -AllowName 'native-fixture-b.invalid' -RejectName 'native-fixture-a.invalid' -OriginalDefaults $baselineDefaults -OriginalDns $baselineDns
            Assert-FixtureRoute
            Test-FixtureTraffic -FixtureName 'native-fixture-b.invalid' -DnsPort $dnsPort -HttpPort $httpPort
            Test-RejectedFixture -FixtureName 'native-fixture-a.invalid' -DnsPort $dnsPort -HttpPort $httpPort
        } catch { Add-Failure "Fixture B profile reload: $($_.Exception.Message)" }
    }
    if ($uidA -and $uidB) {
        try {
            Select-FixtureProfile -Uid $uidA -AllowName 'native-fixture-a.invalid' -RejectName 'native-fixture-b.invalid' -OriginalDefaults $baselineDefaults -OriginalDns $baselineDns
            Test-FixtureTraffic -FixtureName 'native-fixture-a.invalid' -DnsPort $dnsPort -HttpPort $httpPort
            Test-RejectedFixture -FixtureName 'native-fixture-b.invalid' -DnsPort $dnsPort -HttpPort $httpPort
            $state=Wait-ServiceReady
            if (([string]$state.mode).ToLowerInvariant() -ne 'service' -or -not [bool]$state.serviceUsable) { throw 'A-to-B-to-A reload did not recover service-ready mode.' }
            Assert-LiveCoreIdentity; Assert-FixtureRoute
            Assert-SystemRoutesRemainScoped -OriginalDefaults $baselineDefaults -OriginalDns $baselineDns -Phase 'A-to-B-to-A recovery'
        } catch { Add-Failure "A-to-B-to-A recovery: $($_.Exception.Message)" }
    }
    if ($script:cdp.State -eq [Net.WebSockets.WebSocketState]::Open) {
        try {
            [void](Invoke-CvrCommand -Command 'patch_verge_config' -Payload @{ payload=@{ enable_tun_mode=$false; enable_system_proxy=$false } })
            [void](Invoke-CvrCommand -Command 'uninstall_service')
            [void](Invoke-CvrCommand -Command 'exit_app')
        } catch { Add-Failure "Tauri runtime cleanup: $($_.Exception.Message)" }
    }
} catch {
    Add-Failure "Native setup or GUI/CDP blocker: $($_.Exception.Message)"
    if (-not (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) {
        try { $output=& $helper.FullName --install-service 2>&1; if ($LASTEXITCODE -ne 0) { Add-Failure "Independent service helper assertion failed: $($output -join ' ')" } } catch { Add-Failure "Independent service helper assertion failed: $($_.Exception.Message)" }
    }
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
