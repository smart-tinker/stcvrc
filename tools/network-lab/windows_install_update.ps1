$ErrorActionPreference = 'Stop'

if ($env:GITHUB_ACTIONS -ne 'true' -or $env:GITHUB_REPOSITORY -ne 'smart-tinker/stcvrc') {
    throw 'This installer smoke is allowed only in the public STCVRC GitHub Actions runner.'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'The disposable runner must be elevated for the pinned installer.'
}

$uninstallRelative = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Clash Verge'
$productRelative = 'SOFTWARE\Clash Verge Rev\Clash Verge'
$allowedInstallDirs = @(
    (Join-Path $env:ProgramFiles 'Clash Verge'),
    (Join-Path $env:LOCALAPPDATA 'Clash Verge')
) | ForEach-Object { [IO.Path]::GetFullPath($_).TrimEnd([char]92) }

foreach ($hive in @('HKLM:', 'HKCU:')) {
    foreach ($relative in @($uninstallRelative, $productRelative)) {
        $key = Join-Path $hive $relative
        if (Test-Path -LiteralPath $key) { throw "Refusing a runner with existing CVR registry state: $key" }
    }
}
foreach ($path in $allowedInstallDirs) {
    if (Test-Path -LiteralPath $path) { throw "Refusing an existing CVR install directory: $path" }
}
$serviceData = Join-Path $env:ProgramData 'clash-verge-service'
if (Test-Path -LiteralPath $serviceData) { throw 'Refusing existing Clash Verge service core state.' }
if (Get-Service -Name 'clash_verge_service' -ErrorAction SilentlyContinue) { throw 'Refusing an existing Clash Verge service.' }

function Assert-NoCvrProcesses {
    foreach ($name in @('clash-verge', 'clash-verge-service', 'verge-mihomo', 'verge-mihomo-alpha')) {
        if (Get-Process -Name $name -ErrorAction SilentlyContinue) { throw "Unexpected CVR process is running: $name" }
    }
}
function Assert-NoService {
    if (Get-Service -Name 'clash_verge_service' -ErrorAction SilentlyContinue) { throw 'The installer smoke created or started the CVR service.' }
}
Assert-NoCvrProcesses

$webViewGuid = '{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
$webViewInstalled = $false
foreach ($key in @(
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\$webViewGuid",
    "HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients\$webViewGuid",
    "HKCU:\SOFTWARE\Microsoft\EdgeUpdate\Clients\$webViewGuid"
)) {
    if (Test-Path -LiteralPath $key) {
        $pv = (Get-ItemProperty -LiteralPath $key -Name 'pv' -ErrorAction SilentlyContinue).pv
        if ($pv) { $webViewInstalled = $true; break }
    }
}
if (-not $webViewInstalled) { throw 'Refusing to let NSIS download or install WebView2 on the runner.' }
$vcRuntime = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64' -Name 'Installed' -ErrorAction SilentlyContinue
if ($null -eq $vcRuntime -or [int]$vcRuntime.Installed -ne 1) {
    throw 'Refusing to let NSIS download or install the Visual C++ runtime on the runner.'
}

if (-not $env:APPDATA -or -not $env:PR_SOURCE -or -not $env:CUSTOM_CORE) { throw 'Required runner paths are missing.' }
$profileDirectory = Join-Path $env:APPDATA 'io.github.clash-verge-rev.clash-verge-rev\profiles'
if (Test-Path -LiteralPath (Split-Path -Parent $profileDirectory)) { throw 'Refusing preexisting CVR app data.' }

$manifestPath = Join-Path $env:PR_SOURCE 'candidates\cvr-2.5.10\inputs.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.repository -ne 'clash-verge-rev/clash-verge-rev' -or (@($manifest.releases | ForEach-Object { $_.version }) -join ',') -ne '2.5.8,2.5.10') {
    throw 'Unexpected pinned CVR release pair.'
}
$coreSha = ([string]$manifest.core.sha256).ToLowerInvariant()
if ($coreSha -ne 'd72784d98a44b90e561c701589c50f53074958d7cef656607ee5be1143b36c87') {
    throw 'Unexpected fresh STCVRC core pin.'
}
if (-not (Test-Path -LiteralPath $env:CUSTOM_CORE -PathType Leaf) -or
    (Get-FileHash -LiteralPath $env:CUSTOM_CORE -Algorithm SHA256).Hash.ToLowerInvariant() -ne $coreSha) {
    throw 'Fresh STCVRC core bytes do not match the pinned SHA256.'
}

$installerPaths = @{
    '2.5.8' = $env:CVR_258_INSTALLER
    '2.5.10' = $env:CVR_2510_INSTALLER
}
foreach ($release in $manifest.releases) {
    $installer = $installerPaths[[string]$release.version]
    $asset = $release.assets.installer
    if (-not $installer -or -not (Test-Path -LiteralPath $installer -PathType Leaf)) { throw "Missing pinned CVR $($release.version) installer." }
    if ((Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant() -ne $asset.sha256 -or
        (Get-Item -LiteralPath $installer).Length -ne [long]$asset.size) {
        throw "CVR $($release.version) installer changed after download verification."
    }
}

$profilePath = Join-Path $profileDirectory 'ci-update-preserve.yaml'
[IO.Directory]::CreateDirectory($profileDirectory) | Out-Null
[IO.File]::WriteAllText($profilePath, "synthetic-ci-profile-preserve" + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
$profileSha = (Get-FileHash -LiteralPath $profilePath -Algorithm SHA256).Hash.ToLowerInvariant()

function Get-InstalledCvrDirectory {
    param([string]$ExpectedVersion)
    $records = @()
    foreach ($hive in @('HKLM:', 'HKCU:')) {
        $key = Join-Path $hive $uninstallRelative
        if (Test-Path -LiteralPath $key) {
            $records += Get-ItemProperty -LiteralPath $key
        }
    }
    if ($records.Count -ne 1 -or $records[0].DisplayName -ne 'Clash Verge') {
        throw "Expected one installed Clash Verge product record after $ExpectedVersion setup."
    }
    if ([string]$records[0].DisplayVersion -ne $ExpectedVersion) {
        throw "Expected CVR $ExpectedVersion; got $($records[0].DisplayVersion)."
    }
    $location = ([string]$records[0].InstallLocation).Trim([char]34)
    if (-not $location) { throw 'CVR installer did not register its install location.' }
    $fullPath = [IO.Path]::GetFullPath($location).TrimEnd([char]92)
    if ($allowedInstallDirs -notcontains $fullPath) { throw "Unexpected CVR install location: $fullPath" }
    $guiPath = Join-Path $fullPath 'clash-verge.exe'
    if (-not (Test-Path -LiteralPath $guiPath -PathType Leaf)) {
        throw 'Installed Clash Verge executable is missing.'
    }
    $expectedGuiSha = switch ($ExpectedVersion) {
        '2.5.8' { [string]$env:CVR_258_GUI_SHA256 }
        '2.5.10' { [string]$env:CVR_2510_GUI_SHA256 }
        default { throw "Unsupported CVR GUI pin version: $ExpectedVersion." }
    }
    if ($expectedGuiSha -notmatch '^[0-9a-f]{64}$') { throw "Invalid pinned CVR GUI SHA256 for $ExpectedVersion." }
    $expectedGuiSha = $expectedGuiSha.ToLowerInvariant()
    $installedGuiSha = (Get-FileHash -LiteralPath $guiPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($installedGuiSha -ne $expectedGuiSha) { throw "Installed CVR GUI SHA256 mismatch after $ExpectedVersion." }
    return $fullPath
}

function Invoke-CvrInstaller {
    param([string]$Version, [string[]]$Arguments)
    $installer = $installerPaths[$Version]
    $process = Start-Process -FilePath $installer -ArgumentList $Arguments -Wait -PassThru -WindowStyle Hidden
    if ($process.ExitCode -ne 0) { throw "CVR $Version installer exited with code $($process.ExitCode)." }
    $directory = Get-InstalledCvrDirectory -ExpectedVersion $Version
    Assert-NoService
    Assert-NoCvrProcesses
    return $directory
}

function Assert-ProfilePreserved {
    param([string]$Phase)
    if (-not (Test-Path -LiteralPath $profilePath -PathType Leaf) -or
        (Get-FileHash -LiteralPath $profilePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $profileSha) {
        throw "CVR $Phase did not preserve the synthetic profile marker."
    }
}
function Install-CandidateCore {
    param([string]$InstallDirectory, [string]$Phase)
    $installedCore = Join-Path $InstallDirectory 'verge-mihomo.exe'
    if (-not (Test-Path -LiteralPath $installedCore -PathType Leaf)) { throw "CVR $Phase core path is missing." }
    Copy-Item -LiteralPath $env:CUSTOM_CORE -Destination $installedCore -Force
    if ((Get-FileHash -LiteralPath $installedCore -Algorithm SHA256).Hash.ToLowerInvariant() -ne $coreSha) {
        throw "Fresh candidate core was not restored after $Phase."
    }
    $helpers = @(Get-ChildItem -LiteralPath $InstallDirectory -Recurse -File -Filter 'clash-verge-service-install.exe')
    if ($helpers.Count -ne 1) { throw "Expected one service core-staging helper after $Phase; found $($helpers.Count)." }
    $stageOutput = & $helpers[0].FullName --install-core $installedCore --sha256 $coreSha 2>&1
    $stageExit = $LASTEXITCODE
    if ($stageExit -ne 0) { throw "SHA-pinned core staging failed after $Phase ($stageExit): $($stageOutput -join ' ')" }
    $stagedCore = Join-Path $serviceData 'cores\verge-mihomo.exe'
    if (-not (Test-Path -LiteralPath $stagedCore -PathType Leaf) -or
        (Get-FileHash -LiteralPath $stagedCore -Algorithm SHA256).Hash.ToLowerInvariant() -ne $coreSha) {
        throw "Service helper did not stage the fresh candidate core after $Phase."
    }
}

$processStartSource = 'STCVRC.CvrInstallSmoke.ProcessStart'
Register-CimIndicationEvent -Namespace 'root/cimv2' -Query 'SELECT * FROM Win32_ProcessStartTrace' -SourceIdentifier $processStartSource | Out-Null
$install258 = Invoke-CvrInstaller -Version '2.5.8' -Arguments @('/S', '/P', '/NS')
Install-CandidateCore -InstallDirectory $install258 -Phase '2.5.8 baseline'
$install2510 = Invoke-CvrInstaller -Version '2.5.10' -Arguments @('/S', '/P', '/UPDATE', '/NS')
if ($install258 -ne $install2510) { throw 'CVR update changed the registered install directory.' }
Assert-ProfilePreserved -Phase '2.5.10 update'
Install-CandidateCore -InstallDirectory $install2510 -Phase '2.5.10 update'

$nativeFailure = $null
$nativeScript = Join-Path $env:PR_SOURCE 'tools\network-lab\windows_native_acceptance.ps1'
try {
    & $nativeScript
} catch {
    $nativeFailure = $_.Exception.Message
    Write-Host "Native acceptance reported failure; continuing the independent 2.5.8 recovery check: $nativeFailure" -ForegroundColor Red
}

# The acceptance script normally removes its exact service, process tree and synthetic route.
# Retry cleanup on this disposable runner before invoking the pinned recovery installer.
if (Get-Service -Name 'clash_verge_service' -ErrorAction SilentlyContinue) {
    Stop-Service -Name 'clash_verge_service' -Force -ErrorAction SilentlyContinue
    & sc.exe delete 'clash_verge_service' | Out-Null
}
foreach ($name in @('clash-verge', 'clash-verge-service', 'verge-mihomo', 'verge-mihomo-alpha')) {
    Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Seconds 2

$recoveryFailure = $null
try {
    $installRecovered = Invoke-CvrInstaller -Version '2.5.8' -Arguments @('/S', '/P', '/UPDATE', '/NS')
    if ($installRecovered -ne $install258) { throw 'CVR recovery changed the registered install directory.' }
    Assert-ProfilePreserved -Phase 'recovery'
    Install-CandidateCore -InstallDirectory $installRecovered -Phase 'recovery'
    Assert-NoService
    Assert-NoCvrProcesses
} catch {
    $recoveryFailure = $_.Exception.Message
    Write-Host "Pinned CVR 2.5.8 recovery failed: $recoveryFailure" -ForegroundColor Red
}

Start-Sleep -Milliseconds 250
$processEvents = @(Get-Event -SourceIdentifier $processStartSource -ErrorAction SilentlyContinue)
$processNames = @($processEvents | ForEach-Object { [string]$_.SourceEventArgs.NewEvent.ProcessName })
Unregister-Event -SourceIdentifier $processStartSource -ErrorAction SilentlyContinue
$processEvents | Remove-Event -ErrorAction SilentlyContinue
$alphaStarts = @($processNames | Where-Object { $_ -eq 'verge-mihomo-alpha.exe' } | Sort-Object -Unique)
if ($alphaStarts.Count) {
    $alphaFailure = "Alpha core process started: $($alphaStarts -join ', ')"
    if ($nativeFailure) { $nativeFailure = "$nativeFailure | $alphaFailure" } else { $nativeFailure = $alphaFailure }
}

$summary = @(
    '## Bounded CVR install/update/native acceptance/recovery',
    '- Installed pinned 2.5.8, updated to verified 2.5.10, ran native acceptance on the disposable windows-2022 runner, and attempted pinned recovery to 2.5.8.',
    '- Native acceptance starts the verified GUI and service, applies generic synthetic profiles, checks DNS/TUN traffic and A-to-B-to-A reload, and binds the live core to the fresh build SHA.',
    '- Native checks compare default routes and physical DNS before and after; the synthetic route is limited to 198.18.0.0/16.',
    '- This job does not use production profiles, external VPN endpoints, secrets, paid runners, Actions cache or artifacts.'
)
if ($nativeFailure) { $summary += "- Native acceptance: FAIL — $nativeFailure" } else { $summary += '- Native acceptance: PASS.' }
if ($recoveryFailure) { $summary += "- 2.5.8 recovery: FAIL — $recoveryFailure" } else { $summary += '- 2.5.8 recovery: PASS.' }
Add-Content -Path $env:GITHUB_STEP_SUMMARY -Value $summary
if ($nativeFailure -or $recoveryFailure) { throw "Native acceptance/recovery failed. Native: $nativeFailure; recovery: $recoveryFailure" }
