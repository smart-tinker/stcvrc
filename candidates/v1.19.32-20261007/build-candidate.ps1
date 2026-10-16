[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Join-Path $PSScriptRoot '../..'),
    [Parameter(Mandatory = $true)][string]$GoExe,
    [Parameter(Mandatory = $true)][string]$WorkRoot,
    [string]$ModuleCache,
    [string]$BuildCache,
    [switch]$Offline
)

# Review artifact only: no service, profile, TUN, network acceptance or installation.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$SourceCommit = '3d0127d8cc24a6d6c10f7063dad4e0fd97565432'
$SourceTree = 'f5541fdebd99b877619656e54a16f1b3c8a20d03'
$Version = '1.19.32-STCVRC-candidate-20261007'
$BuildTime = '2026-10-07T00:00:00Z'
$ExpectedGoVersion = 'go version go1.26.5 windows/amd64'
$ExpectedGoExeSha256 = 'd6a71e6dc9806cb3f1fcb817d562175c5a7b1505fc3f6638299648e0b9f0f74f'
$ExpectedSha256 = 'b072d09f0754b92cbe737757d2c63111d20ecf00e5d90b534ce2f9492feb9986'
$LdFlags = '-s -w -buildid= -X "github.com/metacubex/mihomo/constant.Version=' + $Version + '" -X "github.com/metacubex/mihomo/constant.BuildTime=' + $BuildTime + '"'

$RepositoryRoot = [IO.Path]::GetFullPath($RepositoryRoot).TrimEnd('\')
$GoExe = [IO.Path]::GetFullPath($GoExe)
$WorkRoot = [IO.Path]::GetFullPath($WorkRoot).TrimEnd('\')
if (-not (Test-Path -LiteralPath $RepositoryRoot -PathType Container)) { throw 'Repository root is missing.' }
if (-not (Test-Path -LiteralPath $GoExe -PathType Leaf)) { throw 'Pinned Go executable is missing.' }
if ((Get-FileHash -LiteralPath $GoExe -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ExpectedGoExeSha256) { throw 'Go executable SHA-256 mismatch.' }
if (Test-Path -LiteralPath $WorkRoot) { throw 'WorkRoot must not exist; use a fresh directory.' }
if ($WorkRoot.StartsWith($RepositoryRoot + '\', [StringComparison]::OrdinalIgnoreCase) -or $WorkRoot -ieq $RepositoryRoot) {
    throw 'WorkRoot must be outside the source repository.'
}
$GitArgs = @('-c', ('safe.directory=' + $RepositoryRoot.Replace('\', '/')), '-C', $RepositoryRoot)
$ResolvedCommit = (& git @GitArgs rev-parse ($SourceCommit + '^{commit}')).Trim()
if ($LASTEXITCODE -ne 0 -or $ResolvedCommit -cne $SourceCommit) { throw 'Pinned public source commit is unavailable.' }
$ResolvedTree = (& git @GitArgs rev-parse ($SourceCommit + '^{tree}')).Trim()
if ($LASTEXITCODE -ne 0 -or $ResolvedTree -cne $SourceTree) { throw 'Pinned public source tree mismatch.' }

New-Item -ItemType Directory -Path $WorkRoot | Out-Null
$SourceRoot = Join-Path $WorkRoot 'source'
$ArchivePath = Join-Path $WorkRoot 'source.zip'
$OutputDirectory = Join-Path $WorkRoot 'out'
$OutputPath = Join-Path $OutputDirectory 'verge-mihomo.exe'
$ReportPath = Join-Path $WorkRoot 'build-report.json'
if (-not $ModuleCache) { $ModuleCache = Join-Path $WorkRoot 'gomodcache' }
$ModuleCache = [IO.Path]::GetFullPath($ModuleCache)
if (-not $BuildCache) { $BuildCache = Join-Path $WorkRoot 'gocache' }
$BuildCache = [IO.Path]::GetFullPath($BuildCache)

# Export the immutable commit, not HEAD or the possibly dirty working directory.
& git @GitArgs archive --format=zip ('--output=' + $ArchivePath) $SourceCommit
if ($LASTEXITCODE -ne 0) { throw 'Pinned source export failed.' }
Add-Type -AssemblyName System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::ExtractToDirectory($ArchivePath, $SourceRoot)
New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
$GoRoot = Split-Path -Parent (Split-Path -Parent $GoExe)
$BuildEnvironment = @{
    APPDATA = (Join-Path $WorkRoot 'appdata')
    LOCALAPPDATA = (Join-Path $WorkRoot 'localappdata')
    GOCACHE = $BuildCache
    GOMODCACHE = $ModuleCache
    GOPATH = (Join-Path $WorkRoot 'gopath')
    GOROOT = $GoRoot
    GOTELEMETRY = 'off'
    GOTELEMETRYDIR = (Join-Path $WorkRoot 'go-telemetry')
    GOENV = 'off'
    GOTOOLCHAIN = 'local'
    GOWORK = 'off'
    GOFLAGS = '-mod=readonly'
    GOEXPERIMENT = ''
    GODEBUG = ''
    GOOS = 'windows'
    GOARCH = 'amd64'
    GOAMD64 = 'v1'
    CGO_ENABLED = '0'
    GOPROXY = 'https://proxy.golang.org,direct'
    GOSUMDB = 'sum.golang.org'
    GOPRIVATE = ''
    GONOPROXY = ''
    GONOSUMDB = ''
}
if ($Offline) {
    $BuildEnvironment.GOPROXY = 'off'
    $BuildEnvironment.GOSUMDB = 'off'
}
$PreviousEnvironment = @{}
foreach ($Name in $BuildEnvironment.Keys) {
    $PreviousEnvironment[$Name] = [Environment]::GetEnvironmentVariable($Name, 'Process')
    [Environment]::SetEnvironmentVariable($Name, $BuildEnvironment[$Name], 'Process')
}
Push-Location $SourceRoot
try {
    $GoVersion = (& $GoExe version).Trim()
    if ($LASTEXITCODE -ne 0 -or $GoVersion -cne $ExpectedGoVersion) { throw ('Pinned Go toolchain version mismatch: ' + $GoVersion) }
    $StartedUtc = [DateTime]::UtcNow.ToString('o')
    & $GoExe build -tags with_gvisor -trimpath -buildvcs=false -ldflags $LdFlags -o $OutputPath .
    if ($LASTEXITCODE -ne 0) { throw ('Go build failed: ' + $LASTEXITCODE) }
    $ActualSha256 = (Get-FileHash -LiteralPath $OutputPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $ActualBytes = (Get-Item -LiteralPath $OutputPath).Length
    # -v exits after version reporting; it does not start the proxy runtime.
    $VersionText = (& $OutputPath -v 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'Built core version readback failed.' }
    $VersionMatches = $VersionText -ceq ('Mihomo Meta ' + $Version + ' windows amd64 with go1.26.5 ' + $BuildTime + [Environment]::NewLine + 'Use tags: with_gvisor')
    $Report = [ordered]@{
        schema = 1
        status = 'review-only; NOT accepted for installation'
        startedUtc = $StartedUtc
        finishedUtc = [DateTime]::UtcNow.ToString('o')
        sourceRepository = 'https://github.com/smart-tinker/stcvrc'
        sourceCommit = $SourceCommit
        sourceTree = $SourceTree
        sourceExport = 'git archive of pinned public commit; HEAD/working tree not used'
        recipeSha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
        go = $GoVersion
        goExeSha256 = $ExpectedGoExeSha256
        goArchive = 'go1.26.5.windows-amd64.zip'
        goArchiveSha256 = '97e6b2a833b6d89f9ff17d25419ac0a7e3b482a044e9ab18cdef834bd834fd38'
        target = 'windows/amd64; GOAMD64=v1; CGO_ENABLED=0'
        flags = @('-tags', 'with_gvisor', '-trimpath', '-buildvcs=false', '-ldflags', $LdFlags, '-mod=readonly')
        version = $VersionText
        output = 'out/verge-mihomo.exe'
        bytes = $ActualBytes
        sha256 = $ActualSha256
        expectedSha256 = $ExpectedSha256
        sha256Matches = ($ActualSha256 -ceq $ExpectedSha256)
        versionMatches = $VersionMatches
        offline = [bool]$Offline
        moduleProxy = $BuildEnvironment.GOPROXY
        moduleSumDb = $BuildEnvironment.GOSUMDB
        testsRun = $false
        runtimeAcceptance = $false
    }
    $Report | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
    if (-not $Report.sha256Matches) { throw ('Candidate output SHA-256 mismatch: ' + $ActualSha256) }
    if (-not $VersionMatches) { throw 'Candidate output version readback mismatch.' }
    $Report
} finally {
    Pop-Location
    foreach ($Name in $PreviousEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($Name, $PreviousEnvironment[$Name], 'Process')
    }
}
