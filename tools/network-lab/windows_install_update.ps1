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
if ($coreSha -ne 'c00707e061c91fd5bfa5b3a88653597b00ae1ffad39ba33221e5c8cad1eefcbf') {
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
    if (-not (Test-Path -LiteralPath (Join-Path $fullPath 'clash-verge.exe') -PathType Leaf)) {
        throw 'Installed Clash Verge executable is missing.'
    }
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

$profileRoot = Split-Path -Parent $profileDirectory
if (Test-Path -LiteralPath $profileRoot) { throw 'Synthetic CVR app data unexpectedly exists before setup.' }
$install258 = Invoke-CvrInstaller -Version '2.5.8' -Arguments @('/S', '/P', '/NS')
$install2510 = Invoke-CvrInstaller -Version '2.5.10' -Arguments @('/S', '/P', '/UPDATE', '/NS')
if ($install258 -ne $install2510) { throw 'CVR update changed the registered install directory.' }
if (-not (Test-Path -LiteralPath $profilePath -PathType Leaf) -or
    (Get-FileHash -LiteralPath $profilePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $profileSha) {
    throw 'CVR 2.5.10 update did not preserve the synthetic profile marker.'
}

$installedCore = Join-Path $install2510 'verge-mihomo.exe'
if (-not (Test-Path -LiteralPath $installedCore -PathType Leaf)) { throw 'CVR 2.5.10 core path is missing.' }
Copy-Item -LiteralPath $env:CUSTOM_CORE -Destination $installedCore -Force
if ((Get-FileHash -LiteralPath $installedCore -Algorithm SHA256).Hash.ToLowerInvariant() -ne $coreSha) {
    throw 'Fresh candidate core did not replace the installed CVR core bytes.'
}
$helpers = @(Get-ChildItem -LiteralPath $install2510 -Recurse -File -Filter 'clash-verge-service-install.exe')
if ($helpers.Count -ne 1) { throw "Expected one installed service core-staging helper; found $($helpers.Count)." }
$stageOutput = & $helpers[0].FullName --install-core $installedCore --sha256 $coreSha 2>&1
$stageExit = $LASTEXITCODE
if ($stageExit -ne 0) { throw "SHA-pinned core staging failed ($stageExit): $($stageOutput -join ' ')" }
$stagedCore = Join-Path $serviceData 'cores\verge-mihomo.exe'
if (-not (Test-Path -LiteralPath $stagedCore -PathType Leaf) -or
    (Get-FileHash -LiteralPath $stagedCore -Algorithm SHA256).Hash.ToLowerInvariant() -ne $coreSha) {
    throw 'Service helper did not stage the fresh candidate core bytes.'
}
Assert-NoService
Assert-NoCvrProcesses

Add-Content -Path $env:GITHUB_STEP_SUMMARY -Value @(
    '## Bounded CVR Windows install/update smoke',
    '- Pinned 2.5.8 install and 2.5.10 /UPDATE passed on the clean disposable runner.',
    '- Registry versions and the synthetic profile marker were verified.',
    '- Fresh STCVRC core bytes were SHA-checked in the app and service core locations.',
    '- No CVR GUI/core process was launched and no Windows service was created or started.',
    '- NSIS resets TCP settings; the installer helper writes firewall rules. This was the final job step on a disposable runner.'
)
