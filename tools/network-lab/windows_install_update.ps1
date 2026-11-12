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
    $started = [DateTime]::UtcNow
    try {
        $installer = $installerPaths[$Version]
        $process = Start-Process -FilePath $installer -ArgumentList $Arguments -Wait -PassThru -WindowStyle Hidden
        if ($process.ExitCode -ne 0) { throw "CVR $Version installer exited with code $($process.ExitCode)." }
        $directory = Get-InstalledCvrDirectory -ExpectedVersion $Version
        Assert-NoService
        Assert-NoCvrProcesses
        return $directory
    } finally {
        $script:phaseBoundaries.Add([PSCustomObject]@{ phase="installer-$Version"; startUtc=$started; endUtc=[DateTime]::UtcNow })
    }
}

function Install-CandidateCore {
    param([string]$InstallDirectory, [string]$Phase)
    $started = [DateTime]::UtcNow
    try {
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
    } finally {
        $script:phaseBoundaries.Add([PSCustomObject]@{ phase="stage-core-$Phase"; startUtc=$started; endUtc=[DateTime]::UtcNow })
    }
}

$script:nativeIntervals = [Collections.Generic.List[object]]::new()
$script:phaseBoundaries = [Collections.Generic.List[object]]::new()
$script:nativeFailures = [Collections.Generic.List[string]]::new()
$nativeScript = Join-Path $env:PR_SOURCE 'tools\network-lab\windows_native_acceptance.ps1'
function Invoke-NativePhase {
    param([ValidateSet('seed','exercise','recovery')][string]$Phase, [string]$InstallDirectory)
    $installedCore = Join-Path $InstallDirectory 'verge-mihomo.exe'
    $stagedCore = Join-Path $serviceData 'cores\verge-mihomo.exe'
    foreach ($path in @($installedCore,$stagedCore)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or
            (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $coreSha) {
            throw "Refusing native $Phase phase before exact custom core SHA is verified at $path."
        }
    }
    $started = [DateTime]::UtcNow
    $failure = $null
    try {
        & $nativeScript -Phase $Phase
    } catch {
        $failure = $_.Exception.Message
        $script:nativeFailures.Add("$Phase`: $failure")
        Write-Host "Native $Phase phase failed; continuing the bounded recovery sequence: $failure" -ForegroundColor Red
    } finally {
        $ended = [DateTime]::UtcNow
        $script:nativeIntervals.Add([PSCustomObject]@{ phase=$Phase; startUtc=$started; endUtc=$ended })
        $script:phaseBoundaries.Add([PSCustomObject]@{ phase="native-$Phase"; startUtc=$started; endUtc=$ended })
    }
}
$processStartSource = 'STCVRC.CvrInstallSmoke.ProcessStart'
Register-CimIndicationEvent -Namespace 'root/cimv2' -Query 'SELECT * FROM Win32_ProcessStartTrace' -SourceIdentifier $processStartSource | Out-Null
$install258 = Invoke-CvrInstaller -Version '2.5.8' -Arguments @('/S', '/P', '/NS')
Install-CandidateCore -InstallDirectory $install258 -Phase '2.5.8 baseline'
Invoke-NativePhase -Phase seed -InstallDirectory $install258
$install2510 = Invoke-CvrInstaller -Version '2.5.10' -Arguments @('/S', '/P', '/UPDATE', '/NS')
if ($install258 -ne $install2510) { throw 'CVR update changed the registered install directory.' }
Install-CandidateCore -InstallDirectory $install2510 -Phase '2.5.10 update'
Invoke-NativePhase -Phase exercise -InstallDirectory $install2510

# The native phase normally removes its exact service, process tree and synthetic route.
# Repeat cleanup on the disposable runner before the pinned recovery installer.
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
    Install-CandidateCore -InstallDirectory $installRecovered -Phase 'recovery'
    Assert-NoService
    Assert-NoCvrProcesses
    Invoke-NativePhase -Phase recovery -InstallDirectory $installRecovered
} catch {
    $recoveryFailure = $_.Exception.Message
    Write-Host "Pinned CVR 2.5.8 recovery failed: $recoveryFailure" -ForegroundColor Red
}

# WMI indication delivery is asynchronous; drain until stable, with a hard bound.
$drainDeadline = [DateTime]::UtcNow.AddSeconds(8)
$stableSince = [DateTime]::UtcNow
$lastEventCount = -1
while ([DateTime]::UtcNow -lt $drainDeadline) {
    $currentCount = @(Get-Event -SourceIdentifier $processStartSource -ErrorAction SilentlyContinue).Count
    if ($currentCount -ne $lastEventCount) { $lastEventCount=$currentCount; $stableSince=[DateTime]::UtcNow }
    elseif (([DateTime]::UtcNow - $stableSince).TotalSeconds -ge 2) { break }
    Start-Sleep -Milliseconds 100
}
$processEvents = @(Get-Event -SourceIdentifier $processStartSource -ErrorAction SilentlyContinue)
Unregister-Event -SourceIdentifier $processStartSource -ErrorAction SilentlyContinue
$processEvents | Remove-Event -ErrorAction SilentlyContinue
$coreEvents = [Collections.Generic.List[object]]::new()
foreach ($event in $processEvents) {
    $newEvent = $event.SourceEventArgs.NewEvent
    $processName = [string]$newEvent.ProcessName
    if ($processName -notmatch '^(?i:verge-mihomo|verge-mihomo-alpha)\.exe$') { continue }
    $rawTime = $newEvent.TIME_CREATED
    if ($null -eq $rawTime) {
        $script:nativeFailures.Add("Core process start event for $processName had no WMI TIME_CREATED value.")
        continue
    }
    try { $created = [DateTime]::FromFileTimeUtc([Int64]$rawTime) }
    catch { $script:nativeFailures.Add("Could not decode process start time for $processName: $rawTime"); continue }
    $phase = $null
    foreach ($interval in $script:nativeIntervals) {
        if ($created -ge $interval.startUtc -and $created -le $interval.endUtc) { $phase=$interval.phase; break }
    }
    $coreEvents.Add([PSCustomObject]@{ name=$processName; pid=$newEvent.ProcessID; timeUtc=$created; allowedPhase=$phase })
    if ($processName -ieq 'verge-mihomo-alpha.exe') {
        $script:nativeFailures.Add("Forbidden Alpha core process started at $($created.ToString('o')).")
    } elseif (-not $phase) {
        $script:nativeFailures.Add("Core process started outside an exact native acceptance interval: $processName pid=$($newEvent.ProcessID) at $($created.ToString('o')).")
    }
}
foreach ($interval in $script:nativeIntervals) {
    $phaseStarts = @($coreEvents | Where-Object { $_.allowedPhase -eq $interval.phase -and $_.name -ieq 'verge-mihomo.exe' })
    if (-not $phaseStarts.Count) { $script:nativeFailures.Add("No core process-start event was observed inside native phase $($interval.phase); process-start monitoring did not establish coverage.") }
}

$summary = @(
    '## Bounded CVR install/update/native acceptance/recovery',
    '- Exercised valid synthetic profiles, DNS override confirmation/on/off, GLOBAL selector persistence, explicit synthetic TUN traffic, and 2.5.8 recovery on the disposable windows-2022 runner.',
    '- Native core starts were allowed only within phase intervals after the installed and service-staged executable hashes matched the fresh source-built core; every Alpha start is forbidden.',
    '- Default routes and physical DNS are compared before and after; the synthetic route is limited to 198.18.0.0/16.',
    '- No production profiles, external VPN endpoints, secrets, paid runners, Actions cache or artifacts.'
)
foreach ($boundary in $script:phaseBoundaries) { $summary += "- Phase $($boundary.phase): $($boundary.startUtc.ToString('o')) .. $($boundary.endUtc.ToString('o'))." }
foreach ($interval in $script:nativeIntervals) { $summary += "- Allowed native core interval $($interval.phase): $($interval.startUtc.ToString('o')) .. $($interval.endUtc.ToString('o'))." }
foreach ($event in $coreEvents) {
    $eventPhase = if ($event.allowedPhase) { $event.allowedPhase } else { 'none' }
    $summary += "- Core process event $($event.name) pid=$($event.pid) at $($event.timeUtc.ToString('o')); native phase=$eventPhase."
}
if ($script:nativeFailures.Count) { $summary += '- Native/process-start acceptance: FAIL.'; $summary += $script:nativeFailures | ForEach-Object { "- Failure: $_" } }
else { $summary += '- Native/process-start acceptance: PASS.' }
if ($recoveryFailure) { $summary += "- 2.5.8 recovery: FAIL — $recoveryFailure" } else { $summary += '- 2.5.8 recovery: PASS.' }
Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY -Value $summary
if ($script:nativeFailures.Count -or $recoveryFailure) { throw "Native acceptance/recovery failed. Native: $($script:nativeFailures -join ' | '); recovery: $recoveryFailure" }
