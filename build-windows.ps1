[CmdletBinding()]
param(
    [string]$GoExe = 'go',
    [string]$OutputPath = (Join-Path $PSScriptRoot 'dist\verge-mihomo.exe'),
    [switch]$SkipTests
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$CodeCommit = '9e23508270fed96e346fd4f68447e90401669131'
$ExpectedGoVersion = 'go version go1.26.5 windows/amd64'
$Version = '1.19.29-STCVRC-openvpn-rekey-9e235082'
$BuildTime = '2026-07-20T00:00:00Z'
$ExpectedSha256 = '71195C943BE67017C5646EA2021734BC122FA83C58A408AB6713A2B25CB6B62B'

$GoPath = (Get-Command $GoExe -CommandType Application -ErrorAction Stop).Source
$OutputPath = [IO.Path]::GetFullPath($OutputPath)

$Head = (& git -C $PSScriptRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve the source commit.' }
& git -C $PSScriptRoot merge-base --is-ancestor $CodeCommit $Head
if ($LASTEXITCODE -ne 0) { throw "Required STCVRC code commit is not an ancestor of $Head." }

$UnexpectedChanges = @(
    & git -C $PSScriptRoot diff --name-only "$CodeCommit..$Head" -- . ':(exclude)README.md' ':(exclude)build-windows.ps1'
)
if ($LASTEXITCODE -ne 0 -or $UnexpectedChanges.Count -ne 0) {
    throw "Release source differs from the accepted code commit: $($UnexpectedChanges -join ', ')"
}
$TrackedChanges = @(& git -C $PSScriptRoot status --porcelain --untracked-files=no)
if ($LASTEXITCODE -ne 0 -or $TrackedChanges.Count -ne 0) { throw 'Tracked worktree changes are not allowed.' }

$GoVersion = (& $GoPath version).Trim()
if ($LASTEXITCODE -ne 0 -or $GoVersion -cne $ExpectedGoVersion) {
    throw "Unexpected Go toolchain: $GoVersion"
}

$OutputDirectory = Split-Path -Parent $OutputPath
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null

$PreviousEnvironment = @{}
foreach ($Name in @('GOOS', 'GOARCH', 'GOAMD64', 'CGO_ENABLED', 'GOFLAGS', 'GOTOOLCHAIN')) {
    $PreviousEnvironment[$Name] = [Environment]::GetEnvironmentVariable($Name, 'Process')
}

Push-Location $PSScriptRoot
try {
    $env:GOOS = 'windows'
    $env:GOARCH = 'amd64'
    $env:GOAMD64 = 'v1'
    $env:CGO_ENABLED = '0'
    $env:GOFLAGS = '-mod=readonly'
    $env:GOTOOLCHAIN = 'local'

    if (-not $SkipTests) {
        & $GoPath test -count=1 -timeout 90s ./transport/openvpn ./adapter/outbound
        if ($LASTEXITCODE -ne 0) { throw "Go tests failed with exit code $LASTEXITCODE." }
    }

    $LdFlags = @(
        '-s'
        '-w'
        '-buildid='
        "-X `"github.com/metacubex/mihomo/constant.Version=$Version`""
        "-X `"github.com/metacubex/mihomo/constant.BuildTime=$BuildTime`""
    ) -join ' '

    & $GoPath build -tags with_gvisor -trimpath -buildvcs=false -ldflags $LdFlags -o $OutputPath .
    if ($LASTEXITCODE -ne 0) { throw "Go build failed with exit code $LASTEXITCODE." }

    $ActualSha256 = (Get-FileHash -LiteralPath $OutputPath -Algorithm SHA256).Hash
    if ($ActualSha256 -cne $ExpectedSha256) { throw "Built core SHA-256 mismatch: $ActualSha256" }

    [pscustomobject]@{
        product = 'STCVRC'
        sourceHead = $Head
        codeCommit = $CodeCommit
        go = $GoVersion
        version = $Version
        buildTime = $BuildTime
        output = $OutputPath
        sha256 = $ActualSha256
        testsRun = -not [bool]$SkipTests
    }
} finally {
    Pop-Location
    foreach ($Name in $PreviousEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($Name, $PreviousEnvironment[$Name], 'Process')
    }
}
