$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$portPlanScript = Join-Path $PSScriptRoot 'windows_native_port_plan.ps1'
$udpPortsScript = Join-Path $PSScriptRoot 'windows_native_udp_ports.py'
if (-not (Test-Path -LiteralPath $portPlanScript -PathType Leaf) -or -not (Test-Path -LiteralPath $udpPortsScript -PathType Leaf)) {
    throw 'Native UDP startup fixture dependency is missing.'
}
. $portPlanScript
$root = Join-Path $env:RUNNER_TEMP ('stcvrc-native-startup-' + [Guid]::NewGuid().ToString('N'))
if (Test-Path -LiteralPath $root) { throw 'Synthetic native startup root unexpectedly exists.' }
New-Item -ItemType Directory -Path $root | Out-Null
$planPath = Join-Path $root 'port-plan.json'
$readyPath = Join-Path $root 'ready.json'
$httpReadyPath = Join-Path $root 'http-ready'
$releasePath = Join-Path $root 'release-udp'
$stopPath = Join-Path $root 'stop'
$childPath = Join-Path $root 'child.py'
$stdoutPath = Join-Path $root 'child.stdout.log'
$stderrPath = Join-Path $root 'child.stderr.log'
$child = $null
$blocker = $null
$probe = $null
$udpProbe = $null
try {
    $env:STCVRC_PORT_PLAN_PATH = $planPath
    $null = Get-StcvrcNativePortPlan -Path $planPath
    $initialPlan = Get-StcvrcNativePortPlan -Path $planPath
    $requestedPort = [int]$initialPlan.profileDnsPort
    $blocker = [Net.Sockets.Socket]::new(
        [Net.Sockets.AddressFamily]::InterNetwork,
        [Net.Sockets.SocketType]::Dgram,
        [Net.Sockets.ProtocolType]::Udp
    )
    $blocker.SetSocketOption(
        [Net.Sockets.SocketOptionLevel]::Socket,
        [Net.Sockets.SocketOptionName]::ExclusiveAddressUse,
        $true
    )
    $blocker.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Loopback, $requestedPort))

    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try { $httpPort = [int]$listener.LocalEndpoint.Port } finally { $listener.Stop() }

    $childCode = @'
import json, os, socket, sys, tempfile, threading, time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
sys.path.insert(0, os.path.dirname(os.environ["STCVRC_NATIVE_UDP_PORTS_SCRIPT"]))
from windows_native_udp_ports import bind_dns_fixture_sockets

ROOT = Path(os.environ["STCVRC_NATIVE_STARTUP_ROOT"])
PLAN = Path(os.environ["STCVRC_NATIVE_PORT_PLAN"])
READY = Path(os.environ["STCVRC_NATIVE_READY_RECEIPT"])
HTTP_READY = Path(os.environ["STCVRC_NATIVE_HTTP_READY"])
RELEASE = Path(os.environ["STCVRC_NATIVE_RELEASE_UDP"])
STOP = Path(os.environ["STCVRC_NATIVE_STOP"])
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"fixture-http-ready"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, fmt, *args):
        pass

server = HTTPServer(("127.0.0.1", int(os.environ["STCVRC_NATIVE_HTTP_PORT"])), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
HTTP_READY.write_text("listening", encoding="ascii")
deadline = time.monotonic() + 10
while not RELEASE.exists():
    if time.monotonic() >= deadline:
        raise TimeoutError("parent did not release the synthetic UDP startup gate")
    time.sleep(0.02)

sockets, collisions = bind_dns_fixture_sockets(PLAN)
if collisions != ("profileDnsPort",):
    raise RuntimeError("forced profile DNS UDP collision was not the only recovered collision")
fields = ("coreDnsPort", "profileDnsPort", "appDnsPort", "subscriptionDnsPort")
persisted = json.loads(PLAN.read_text(encoding="utf-8"))
ports = {name: int(persisted[name]) for name in fields}
for name in ("profileDnsPort", "appDnsPort", "subscriptionDnsPort"):
    actual = int(sockets[name].getsockname()[1])
    if ports[name] != actual:
        raise RuntimeError("persisted plan did not match an actually bound UDP socket")

def echo(sock):
    while True:
        try:
            packet, peer = sock.recvfrom(1024)
            sock.sendto(packet, peer)
        except OSError:
            return
for sock in sockets.values():
    threading.Thread(target=echo, args=(sock,), daemon=True).start()

receipt = {"schemaVersion": 1, **ports, "collisions": list(collisions)}
with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=str(READY.parent), delete=False) as output:
    temporary = Path(output.name)
    json.dump(receipt, output, separators=(",", ":"))
    output.write("\n")
os.replace(temporary, READY)
while not STOP.exists():
    time.sleep(0.02)
server.shutdown()
server.server_close()
for sock in sockets.values():
    sock.close()
'@
    [IO.File]::WriteAllText($childPath, $childCode, [Text.UTF8Encoding]::new($false))
    $env:STCVRC_NATIVE_UDP_PORTS_SCRIPT = $udpPortsScript
    $env:STCVRC_NATIVE_STARTUP_ROOT = $root
    $env:STCVRC_NATIVE_PORT_PLAN = $planPath
    $env:STCVRC_NATIVE_READY_RECEIPT = $readyPath
    $env:STCVRC_NATIVE_HTTP_READY = $httpReadyPath
    $env:STCVRC_NATIVE_RELEASE_UDP = $releasePath
    $env:STCVRC_NATIVE_STOP = $stopPath
    $env:STCVRC_NATIVE_HTTP_PORT = [string]$httpPort
    $python = (Get-Command python.exe -ErrorAction Stop).Source
    $child = Start-Process -FilePath $python -ArgumentList @('-u', ('"' + $childPath + '"')) -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath

    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    while ([DateTime]::UtcNow -lt $deadline -and -not (Test-Path -LiteralPath $httpReadyPath -PathType Leaf)) {
        $child.Refresh()
        if ($child.HasExited) {
            $detail = if (Test-Path -LiteralPath $stderrPath) { Get-Content -LiteralPath $stderrPath -Raw } else { '' }
            throw "Synthetic child exited before its HTTP listener was ready. $detail"
        }
        Start-Sleep -Milliseconds 25
    }
    if (-not (Test-Path -LiteralPath $httpReadyPath -PathType Leaf)) { throw 'Synthetic child HTTP listener did not become ready.' }

    $probe = [Net.Sockets.TcpClient]::new()
    $connect = $probe.ConnectAsync([Net.IPAddress]::Loopback, $httpPort)
    if (-not $connect.Wait(1000) -or -not $probe.Connected) { throw 'Synthetic child HTTP listener did not accept the parent TCP readiness probe.' }
    $probe.Dispose()
    $probe = $null

    if (Test-Path -LiteralPath $readyPath) { throw 'UDP readiness receipt appeared before the parent TCP readiness probe.' }
    $parentPlan = Get-StcvrcNativePortPlan -Path $planPath
    Write-Host 'Observed startup order: HTTP TCP ready; UDP bind and readiness receipt still gated.'

    $waitedForReceipt = $false
    try {
        $null = Wait-StcvrcNativePortPlanReady -PlanPath $planPath -ReceiptPath $readyPath -Process $child -TimeoutSeconds 1
    } catch {
        if ($_.Exception.Message -cne 'Native UDP fixture readiness receipt timed out.') { throw }
        $waitedForReceipt = $true
    }
    if (-not $waitedForReceipt) { throw 'Native parent accepted TCP-only readiness without a UDP receipt.' }
    $stillPendingPlan = Get-StcvrcNativePortPlan -Path $planPath
    foreach ($name in @('coreDnsPort','profileDnsPort','appDnsPort','subscriptionDnsPort')) {
        if ([int]$stillPendingPlan.$name -ne [int]$parentPlan.$name) { throw 'Readiness wait changed the persisted plan before child UDP bind.' }
    }
    Set-Content -LiteralPath $releasePath -Value 'continue' -NoNewline -Encoding ascii

    $finalPlan = Wait-StcvrcNativePortPlanReady -PlanPath $planPath -ReceiptPath $readyPath -Process $child -TimeoutSeconds 10
    $receipt = Get-Content -LiteralPath $readyPath -Raw | ConvertFrom-Json -ErrorAction Stop
    if (@($receipt.collisions).Count -ne 1 -or [string]$receipt.collisions[0] -cne 'profileDnsPort') {
        throw 'Synthetic child did not report the forced profile DNS UDP collision.'
    }
    foreach ($name in @('coreDnsPort','profileDnsPort','appDnsPort','subscriptionDnsPort')) {
        if ([int]$receipt.$name -ne [int]$finalPlan.$name) { throw "Child receipt and persisted plan disagree for $name." }
    }
    if ([int]$parentPlan.profileDnsPort -eq [int]$finalPlan.profileDnsPort) {
        throw 'The forced collision did not demonstrate that the early TCP snapshot was stale.'
    }
    $udpProbe = [Net.Sockets.UdpClient]::new()
    $udpProbe.Client.ReceiveTimeout = 2000
    $payload = [Text.Encoding]::ASCII.GetBytes('udp-readiness-roundtrip')
    $target = [Net.IPEndPoint]::new([Net.IPAddress]::Loopback, [int]$finalPlan.profileDnsPort)
    [void]$udpProbe.Send($payload, $payload.Length, $target)
    $remote = [Net.IPEndPoint]::new([Net.IPAddress]::Any, 0)
    $echo = $udpProbe.Receive([ref]$remote)
    if ([Text.Encoding]::ASCII.GetString($echo) -cne 'udp-readiness-roundtrip') {
        throw 'Bound native UDP fixture did not echo the readiness probe.'
    }
    Write-Host ("Parent waited for UDP receipt and persisted plan: early_profileDnsPort={0}; bound_profileDnsPort={1}; UDP=echo" -f [int]$parentPlan.profileDnsPort,[int]$finalPlan.profileDnsPort)
} finally {
    if ($probe) { $probe.Dispose() }
    if ($udpProbe) { $udpProbe.Dispose() }
    if ($child) {
        $child.Refresh()
        if (-not $child.HasExited) {
            if (-not (Test-Path -LiteralPath $releasePath)) { Set-Content -LiteralPath $releasePath -Value 'continue' -NoNewline -Encoding ascii }
            Set-Content -LiteralPath $stopPath -Value 'stop' -NoNewline -Encoding ascii
            if (-not $child.WaitForExit(5000)) {
                Stop-Process -Id $child.Id -Force -ErrorAction SilentlyContinue
                if (-not $child.WaitForExit(5000)) { throw 'Synthetic UDP startup child did not stop within the cleanup deadline.' }
            }
        }
    }
    if ($blocker) { $blocker.Dispose() }
    if (Test-Path -LiteralPath $root -PathType Container) { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop }
}
