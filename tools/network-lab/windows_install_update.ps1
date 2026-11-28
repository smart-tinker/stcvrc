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
. (Join-Path $env:PR_SOURCE 'tools\network-lab\windows_core_preimage_paths.ps1')
. (Join-Path $PSScriptRoot 'windows_core_identity.ps1')
$legacyStateTransactionScript = Join-Path $PSScriptRoot 'windows_legacy_state_transaction.ps1'
if (-not (Test-Path -LiteralPath $legacyStateTransactionScript -PathType Leaf)) { throw 'The shared legacy-state transaction helper is missing.' }
. $legacyStateTransactionScript
$idleBaselineGuardScript = Join-Path $PSScriptRoot 'windows_idle_baseline_guard.ps1'
if (-not (Test-Path -LiteralPath $idleBaselineGuardScript -PathType Leaf)) { throw 'The shared idle-baseline guard helper is missing.' }
. $idleBaselineGuardScript
$idleTransactionScript = Join-Path $PSScriptRoot 'windows_idle_transaction.ps1'
if (-not (Test-Path -LiteralPath $idleTransactionScript -PathType Leaf)) { throw 'The shared idle transaction helper is missing.' }
. $idleTransactionScript
if (-not (Get-Command -Name Assert-CvrIdleBaseline -CommandType Function -ErrorAction SilentlyContinue)) { throw 'The idle-baseline guard function is unavailable in installer scope.' }
$profileDirectory = Join-Path $env:APPDATA 'io.github.clash-verge-rev.clash-verge-rev\profiles'
if (Test-Path -LiteralPath (Split-Path -Parent $profileDirectory)) { throw 'Refusing preexisting CVR app data.' }

$manifestPath = Join-Path $env:PR_SOURCE 'candidates\cvr-2.5.10\inputs.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$script:manifest = $manifest
if ($manifest.repository -ne 'clash-verge-rev/clash-verge-rev' -or (@($manifest.releases | ForEach-Object { $_.version }) -join ',') -ne '2.5.8,2.5.10') {
    throw 'Unexpected pinned CVR release pair.'
}
if (-not $env:STCVRC_BUILD_JSON -or -not (Test-Path -LiteralPath $env:STCVRC_BUILD_JSON -PathType Leaf)) { throw 'Fresh build identity report is missing.' }
$build = Get-Content -LiteralPath $env:STCVRC_BUILD_JSON -Raw | ConvertFrom-Json
$recipeSha = (& git -C $env:PR_SOURCE rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $build.schema_version -ne 1 -or $build.build_host -ne 'windows/amd64' -or $build.recipe_commit -ne $recipeSha) { throw 'Fresh build report does not belong to this Windows recipe.' }
$coreEntries = @($build.artifacts | Where-Object { $_.name -eq 'verge-mihomo.exe' -and $_.target -eq 'windows/amd64' })
if ($coreEntries.Count -ne 1 -or $coreEntries[0].sha256 -notmatch '^[0-9a-f]{64}$' -or [long]$coreEntries[0].size -lt 1) { throw 'Fresh Windows artifact identity is invalid.' }
$coreSha = [string]$coreEntries[0].sha256
$script:coreSha = $coreSha
# windowsNativeCandidate in inputs.json is the historical RC9 pin; validate the fresh RC11 build report here.
if ($build.version -cne '1.19.33-STCVRC-rc.11' -or
    $build.core_source_commit -cne 'a884ad53a3999dd35acab979e0bb040c47f6dbc9' -or
    $build.selected_dependency_versions.'github.com/gobwas/ws' -cne 'v1.5.0' -or
    $build.selected_dependency_versions.'github.com/insomniacslk/dhcp' -cne 'v0.0.0-20260719225207-c76316d4aa82') {
    throw 'Fresh Windows build is not the dependency-updated RC11 candidate.'
}
if (-not (Test-Path -LiteralPath $env:CUSTOM_CORE -PathType Leaf)) { throw 'Fresh STCVRC core is missing.' }
if ((Get-Item -LiteralPath $env:CUSTOM_CORE).Length -ne [long]$coreEntries[0].size) { throw 'Fresh Windows artifact size changed after build.' }
if ((Get-FileHash -LiteralPath $env:CUSTOM_CORE -Algorithm SHA256).Hash.ToLowerInvariant() -ne $coreSha) {
    throw 'Fresh STCVRC core bytes do not match the build report SHA256.'
}
Assert-StcvrcWindowsCoreVersionOutputVectors
$expectedCoreVersion = Get-StcvrcWindowsCoreVersionIdentity -Build $build
$coreVersionLines = @(& $env:CUSTOM_CORE -v 2>&1 | ForEach-Object { [string]$_ })
$coreExit = $LASTEXITCODE
if ($coreExit -ne 0 -or -not (Test-StcvrcWindowsCoreVersionOutput -VersionLines $coreVersionLines -ExpectedIdentity $expectedCoreVersion)) {
    throw "Fresh Windows core version mismatch. Expected [$expectedCoreVersion]; got [$($coreVersionLines -join "`n")]."
}

$installerPaths = @{
    '2.5.8' = $env:CVR_258_INSTALLER
    '2.5.10' = $env:CVR_2510_INSTALLER
}
$script:installerPaths = $installerPaths
foreach ($release in $manifest.releases) {
    $installer = $installerPaths[[string]$release.version]
    $asset = $release.assets.installer
    if (-not $installer -or -not (Test-Path -LiteralPath $installer -PathType Leaf)) { throw "Missing pinned CVR $($release.version) installer." }
    if ((Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant() -ne $asset.sha256 -or
        (Get-Item -LiteralPath $installer).Length -ne [long]$asset.size) {
        throw "CVR $($release.version) installer changed after download verification."
    }
}


function Save-CvrSyntheticStockCore {
    param([string]$InstallDirectory)
    $path = [IO.Path]::GetFullPath((Join-Path $InstallDirectory 'verge-mihomo.exe'))
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'Pinned 2.5.8 stock Program Files core is missing.' }
    $sha = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($sha -ceq $coreSha) { throw 'Synthetic stock Program Files core must differ from the candidate service core.' }
    $acl = Get-Acl -LiteralPath $path
    $backup = Save-CvrCorePreimageBackup -Root $env:RUNNER_TEMP -Label '258-stock' -SourcePath $path -ExpectedSha256 $sha
    return [PSCustomObject]@{
        path = $path
        pathPin = $path
        backup = $backup.backup
        backupPathPin = $backup.backupPathPin
        backupRoot = $backup.backupRoot
        backupSddl = $backup.backupSddl
        backupDirectorySddl = $backup.backupDirectorySddl
        sha256 = $sha
        sddl = $acl.Sddl
        acl = $acl
    }
}

function Set-CvrSyntheticSplitCorePreimage {
    param([string]$InstallDirectory, $StockCore)
    if (-not $StockCore) { throw 'The retained 2.5.8 stock core preimage is missing.' }
    $stockBytes = Get-CvrCorePreimageBackupBytes -Entry $StockCore -Role '2.5.8 stock'
    $programFilesCore = Join-Path $InstallDirectory 'verge-mihomo.exe'
    if ([IO.Path]::GetFullPath([string]$StockCore.path) -ine [IO.Path]::GetFullPath($programFilesCore)) {
        throw 'Signed stock Program Files core path pin changed.'
    }
    $serviceCore = Join-Path $serviceData 'cores\verge-mihomo.exe'
    if (-not (Test-Path -LiteralPath $serviceCore -PathType Leaf) -or
        (Get-FileHash -LiteralPath $serviceCore -Algorithm SHA256).Hash.ToLowerInvariant() -cne $coreSha) {
        throw 'Synthetic service core is not the pinned candidate preimage.'
    }
    [IO.File]::WriteAllBytes($programFilesCore, [byte[]]$stockBytes)
    Set-Acl -LiteralPath $programFilesCore -AclObject $StockCore.acl
    if ((Get-FileHash -LiteralPath $programFilesCore -Algorithm SHA256).Hash.ToLowerInvariant() -cne $StockCore.sha256 -or
        (Get-Acl -LiteralPath $programFilesCore).Sddl -cne $StockCore.sddl) {
        throw 'Could not establish the separate signed-stock Program Files core preimage.'
    }
    if ($StockCore.sha256 -ceq $coreSha) { throw 'Synthetic Program Files and service core preimages are not distinct.' }
}


$script:nativeIntervals = [Collections.Generic.List[object]]::new()
$script:overlayIntervals = [Collections.Generic.List[object]]::new()
$script:phaseBoundaries = [Collections.Generic.List[object]]::new()
$script:nativeFailures = [Collections.Generic.List[string]]::new()
. (Join-Path $PSScriptRoot 'windows_idle_target_runtime.ps1')
$nativeScript = Join-Path $env:PR_SOURCE 'tools\network-lab\windows_native_acceptance.ps1'
$portPlanScript = Join-Path $env:PR_SOURCE 'tools\network-lab\windows_native_port_plan.ps1'
if (-not (Test-Path -LiteralPath $portPlanScript -PathType Leaf) -or -not $env:RUNNER_TEMP) { throw 'Native phase DNS port-plan inputs are missing.' }
. $portPlanScript
$env:STCVRC_NATIVE_PORT_PLAN = Join-Path $env:RUNNER_TEMP 'stcvrc-native-port-plan.json'
if (Test-Path -LiteralPath $env:STCVRC_NATIVE_PORT_PLAN) { throw 'Refusing a preexisting native DNS port plan on the disposable runner.' }
$null = Get-StcvrcNativePortPlan -Path $env:STCVRC_NATIVE_PORT_PLAN
Write-Host 'Created one validated DNS port plan for seed, update, and recovery phases.'
function New-CvrIdleTransactionCapture {
    param(
        [Parameter(Mandatory)][string]$InstallDirectory,
        [Parameter(Mandatory)][object]$CoreShouldBeRunning,
        [Parameter(Mandatory)][string]$TargetIdentity,
        [Parameter(Mandatory)][string]$ExpectedTargetIdentity,
        [Parameter(Mandatory)][hashtable]$ExpectedPins,
        [Parameter(Mandatory)][hashtable]$PinnedFiles,
        [Parameter(Mandatory)][object]$CorePair,
        [Parameter(Mandatory)][object]$LegacyState
    )
    $verifiedDirectory = Get-InstalledCvrDirectory -ExpectedVersion '2.5.8'
    if ([IO.Path]::GetFullPath($verifiedDirectory) -ine [IO.Path]::GetFullPath($InstallDirectory)) {
        throw 'Idle baseline install directory differs from the pinned 2.5.8 directory.'
    }
    if ($CoreShouldBeRunning -isnot [bool] -or $CoreShouldBeRunning) {
        throw 'Idle target capture requires strict false intent.'
    }
    $guiSha = [string]$env:CVR_258_GUI_SHA256
    $guiPath = Join-Path $InstallDirectory 'clash-verge.exe'
    if ($guiSha -notmatch '^[0-9a-f]{64}$' -or
        (Get-FileHash -LiteralPath $guiPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $guiSha.ToLowerInvariant()) {
        throw 'Idle baseline CVR 2.5.8 GUI pin mismatch.'
    }

    Assert-CvrCorePairPreimage -Preimage $CorePair -Phase 'fresh idle capture'
    Assert-CvrLegacyState -Expected $LegacyState -Phase 'fresh idle capture'
    $observation = Get-CvrIdleBaselineObservation -Version '2.5.8' -InstallDirectory $InstallDirectory -CoreShouldBeRunning $CoreShouldBeRunning -ExpectedProgramFilesCoreSha256 ([string]$CorePair.programFiles.sha256) -ExpectedServiceCoreSha256 ([string]$CorePair.service.sha256)
    $capture = [PSCustomObject]@{
        installDirectory = [IO.Path]::GetFullPath($InstallDirectory)
        guiSha256 = $guiSha.ToLowerInvariant()
        targetIdentity = $TargetIdentity
        capturedAtUtc = [DateTime]::UtcNow
        coreShouldBeRunning = $CoreShouldBeRunning
        corePair = $CorePair
        legacyState = $LegacyState
        idleObservation = $observation
        pinnedFiles = $PinnedFiles
    }
    $null = Assert-CvrIdleTargetCapture -Capture $capture -ExpectedTargetIdentity $ExpectedTargetIdentity -ExpectedPins $ExpectedPins
    Assert-CvrCorePairPreimage -Preimage $CorePair -Phase 'fresh idle capture'
    Assert-CvrLegacyState -Expected $LegacyState -Phase 'fresh idle capture'
    return $capture
}

function Restore-CvrIdleTransaction {
    param([Parameter(Mandatory)]$Capture)
    if ($Capture.coreShouldBeRunning -isnot [bool] -or $Capture.coreShouldBeRunning) {
        throw 'Captured idle intent is not the strict false Boolean.'
    }
    Stop-CvrRunnerRuntime
    $guiPath = Join-Path $Capture.installDirectory 'clash-verge.exe'
    $currentGuiSha = if (Test-Path -LiteralPath $guiPath -PathType Leaf) {
        (Get-FileHash -LiteralPath $guiPath -Algorithm SHA256).Hash.ToLowerInvariant()
    } else { '' }
    if ($currentGuiSha -cne $Capture.guiSha256) {
        $restoredDirectory = Invoke-CvrInstaller -Version '2.5.8' -Arguments @('/S', '/P', '/UPDATE', '/NS')
        if ([IO.Path]::GetFullPath($restoredDirectory) -ine $Capture.installDirectory) {
            throw 'Pinned 2.5.8 idle GUI recovery changed the captured install directory.'
        }
        Stop-CvrRunnerRuntime
    }
    $verifiedDirectory = Get-InstalledCvrDirectory -ExpectedVersion '2.5.8'
    if ([IO.Path]::GetFullPath($verifiedDirectory) -ine $Capture.installDirectory) {
        throw 'Pinned 2.5.8 GUI did not return to the captured install directory.'
    }
    Restore-CvrCorePairPreimage -Preimage $Capture.corePair -HelperVersion '2.5.8'
    Restore-CvrLegacyState -State $Capture.legacyState
    $null = Install-CvrIdleService -Version '2.5.8' -InstallDirectory $Capture.installDirectory -ProgramFilesEntry $Capture.corePair.programFiles -CoreEntry $Capture.corePair.service -CoreShouldBeRunning $Capture.coreShouldBeRunning
    Assert-CvrCorePairPreimage -Preimage $Capture.corePair -Phase 'final idle rollback'
    Assert-CvrLegacyState -Expected $Capture.legacyState -Phase 'final idle rollback'
    $observation = Get-CvrIdleBaselineObservation -Version '2.5.8' -InstallDirectory $Capture.installDirectory -CoreShouldBeRunning $Capture.coreShouldBeRunning -ExpectedProgramFilesCoreSha256 $Capture.corePair.programFiles.sha256 -ExpectedServiceCoreSha256 $Capture.corePair.service.sha256
    $null = Assert-CvrIdleBaseline @observation
    return $observation
}

function Invoke-NativePhase {
    param(
        [ValidateSet('seed','exercise','recovery')][string]$Phase,
        [string]$InstallDirectory,
        [string]$ExpectedProgramFilesCoreSha,
        [string]$ExpectedServiceCoreSha,
        [string]$RecoveryServiceCorePreimagePath,
        [string]$TrafficChallenge,
        [string]$TrafficReceiptPath,
        [string[]]$TrafficRequiredProbes,
        [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.List[string]]$NativeFailures,
        [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.List[object]]$NativeIntervals,
        [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.List[object]]$PhaseBoundaries
    )
    $installedCore = Join-Path $InstallDirectory 'verge-mihomo.exe'
    $stagedCore = Join-Path $serviceData 'cores\\verge-mihomo.exe'
    foreach ($target in @(
        [PSCustomObject]@{ path=$installedCore; sha256=$ExpectedProgramFilesCoreSha },
        [PSCustomObject]@{ path=$stagedCore; sha256=$ExpectedServiceCoreSha }
    )) {
        if ($target.sha256 -notmatch '^[0-9a-f]{64}$' -or
            -not (Test-Path -LiteralPath $target.path -PathType Leaf) -or
            (Get-FileHash -LiteralPath $target.path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $target.sha256) {
            throw "Refusing native $Phase phase before its separate original/candidate core SHA is verified."
        }
    }
    $started = [DateTime]::UtcNow
    $failure = $null
    try {
        if ($Phase -eq 'recovery') {
            $null = & $nativeScript -Phase $Phase -ExpectedProgramFilesCoreSha256 $ExpectedProgramFilesCoreSha -ExpectedServiceCoreSha256 $ExpectedServiceCoreSha -RecoveryServiceCorePreimagePath $RecoveryServiceCorePreimagePath
        } elseif ($TrafficChallenge -or $TrafficReceiptPath -or ($TrafficRequiredProbes.Count -gt 0)) {
            if ($Phase -cne 'exercise' -or $TrafficChallenge -notmatch '^[0-9a-f]{32}$' -or
                -not $TrafficReceiptPath -or @($TrafficRequiredProbes).Count -ne 2) {
                throw 'Candidate traffic receipt request is invalid.'
            }
            $null = & $nativeScript -Phase $Phase -ExpectedProgramFilesCoreSha256 $ExpectedProgramFilesCoreSha -ExpectedServiceCoreSha256 $ExpectedServiceCoreSha -TrafficChallenge $TrafficChallenge -TrafficReceiptPath $TrafficReceiptPath -TrafficRequiredProbes $TrafficRequiredProbes
        } else {
            $null = & $nativeScript -Phase $Phase -ExpectedProgramFilesCoreSha256 $ExpectedProgramFilesCoreSha -ExpectedServiceCoreSha256 $ExpectedServiceCoreSha
        }
    } catch {
        $failure = $_.Exception.Message
        $NativeFailures.Add("$Phase`: $failure")
        Write-Host "Native $Phase phase failed; continuing the bounded recovery sequence: $failure" -ForegroundColor Red
    } finally {
        $ended = [DateTime]::UtcNow
        $NativeIntervals.Add([PSCustomObject]@{ phase=$Phase; startUtc=$started; endUtc=$ended })
        $PhaseBoundaries.Add([PSCustomObject]@{ phase="native-$Phase"; startUtc=$started; endUtc=$ended })
    }
}
function Get-CoreStartDecision {
    param([string]$ProcessName, [DateTime]$CreatedUtc, [object[]]$Intervals)
    if ($ProcessName -ieq 'verge-mihomo-alpha.exe') {
        return [PSCustomObject]@{ allowed=$false; phase=$null; reason='alpha-forbidden' }
    }
    foreach ($interval in $Intervals) {
        if ($CreatedUtc -ge $interval.startUtc -and $CreatedUtc -le $interval.endUtc) {
            return [PSCustomObject]@{ allowed=$true; phase=$interval.phase; reason='native-interval' }
        }
    }
    return [PSCustomObject]@{ allowed=$false; phase=$null; reason='outside-native-interval' }
}
function Assert-CoreStartDecisionVectors {
    $now = [DateTime]::UtcNow
    $inside = @([PSCustomObject]@{ phase='fixture'; startUtc=$now.AddSeconds(-1); endUtc=$now.AddSeconds(1) })
    $outside = @([PSCustomObject]@{ phase='fixture'; startUtc=$now.AddSeconds(-3); endUtc=$now.AddSeconds(-2) })
    $vectors = @(
        [PSCustomObject]@{ processName='verge-mihomo.exe'; createdUtc=$now; intervals=$inside; expected=$true; reason='native core inside interval' },
        [PSCustomObject]@{ processName='verge-mihomo.exe'; createdUtc=$now; intervals=$outside; expected=$false; reason='core outside interval' },
        [PSCustomObject]@{ processName='verge-mihomo-alpha.exe'; createdUtc=$now; intervals=$inside; expected=$false; reason='Alpha inside interval' }
    )
    foreach ($vector in $vectors) {
        $decision = Get-CoreStartDecision -ProcessName $vector.processName -CreatedUtc $vector.createdUtc -Intervals $vector.intervals
        if ([bool]$decision.allowed -ne [bool]$vector.expected) {
            throw "Core-start policy self-check failed: $($vector.reason)."
        }
    }
}
Assert-CoreStartDecisionVectors

$processStartSource = 'STCVRC.CvrInstallSmoke.ProcessStart'
Register-CimIndicationEvent -Namespace 'root/cimv2' -Query 'SELECT * FROM Win32_ProcessStartTrace' -SourceIdentifier $processStartSource | Out-Null
$script:legacyStateFixture = New-CvrSyntheticLegacyPreimage
$install258 = Invoke-CvrInstaller -Version '2.5.8' -Arguments @('/S', '/P', '/NS')
$script:installDirectory = $install258
$stockProgramFilesCore = Save-CvrSyntheticStockCore -InstallDirectory $install258
$script:stockProgramFilesCore = $stockProgramFilesCore
$stockHelper = Get-CvrServiceInstallHelper -Version '2.5.8'
if ([IO.Path]::GetFileName([string]$env:CUSTOM_CORE) -cne 'verge-mihomo.exe') { throw 'Fresh source-built core basename does not match the service helper contract.' }
$baselineServiceStageOutput = & $stockHelper.path --install-core $env:CUSTOM_CORE --sha256 $coreSha 2>&1
$baselineServiceStageExit = $LASTEXITCODE
if ($baselineServiceStageExit -ne 0) { throw "Pinned 2.5.8 helper could not stage the source-built baseline service core ($baselineServiceStageExit)." }
Install-CandidateCore -InstallDirectory $install258 -Phase '2.5.8 baseline' -HelperVersion '2.5.8'
Invoke-NativePhase -Phase seed -InstallDirectory $install258 -ExpectedProgramFilesCoreSha $coreSha -ExpectedServiceCoreSha $coreSha -NativeFailures $script:nativeFailures -NativeIntervals $script:nativeIntervals -PhaseBoundaries $script:phaseBoundaries
Set-CvrSyntheticSplitCorePreimage -InstallDirectory $install258 -StockCore $stockProgramFilesCore
Stop-CvrRunnerRuntime
Remove-CvrSyntheticLegacyPreimage -Fixture $script:legacyStateFixture
$script:legacyStateFixture = $null

$script:idleCoreShouldBeRunning = [bool]$false
$script:idleTargetIdentity = [Guid]::NewGuid().ToString('N')
$script:idleLegacyState = Get-CvrLegacyState
$script:idleCorePair = Get-CvrCorePairPreimage -InstallDirectory $install258
$helper258 = Get-CvrServiceInstallHelper -Version '2.5.8'
$helper2510 = Get-CvrServiceInstallHelper -Version '2.5.10'
$release258 = @($manifest.releases | Where-Object { [string]$_.version -ceq '2.5.8' })
$release2510 = @($manifest.releases | Where-Object { [string]$_.version -ceq '2.5.10' })
if ($release258.Count -ne 1 -or $release2510.Count -ne 1) { throw 'Idle target capture release pins are ambiguous.' }
$script:idleExpectedPins = @{
    gui258 = [string]$env:CVR_258_GUI_SHA256
    serviceExe258 = [string]$env:CVR_258_SERVICE_SHA256
    programFilesCore = [string]$script:idleCorePair.programFiles.sha256
    serviceCore = [string]$script:idleCorePair.service.sha256
    candidateCore = [string]$coreSha
    updateInstaller = [string]$release2510[0].assets.installer.sha256
    updateHelper = [string]$helper2510.sha256
    recoveryInstaller = [string]$release258[0].assets.installer.sha256
    recoveryHelper = [string]$helper258.sha256
}
if (-not $env:STCVRC_STAGE_ROOT -or $env:STCVRC_STAGE_MANIFEST_SHA256 -notmatch '^[0-9a-f]{64}$') {
    throw 'Pinned public RC11 stage inputs are missing.'
}
$script:idleStageRoot = [IO.Path]::GetFullPath($env:STCVRC_STAGE_ROOT)
$script:idleStageManifestSha256 = $env:STCVRC_STAGE_MANIFEST_SHA256.ToLowerInvariant()
$stageBinding = Get-CvrIdlePackageStageBinding -StageRoot $script:idleStageRoot -ExpectedStageRoot $script:idleStageRoot -ExpectedPackageManifestSha256 $script:idleStageManifestSha256
try {
    if ($stageBinding.SourceManifestSha256 -cne $script:idleStageManifestSha256) { throw 'Pinned public RC11 stage binding changed.' }
} finally { foreach ($handle in @($stageBinding.OpenFiles)) { if ($handle) { $handle.Dispose() } } }
. (Join-Path $script:idleStageRoot 'tools\network-lab\windows_core_preimage_paths.ps1')
. (Join-Path $script:idleStageRoot 'tools\network-lab\windows_idle_baseline_guard.ps1')
. (Join-Path $script:idleStageRoot 'tools\network-lab\windows_legacy_state_transaction.ps1')
. (Join-Path $script:idleStageRoot 'tools\network-lab\windows_idle_transaction.ps1')
. (Join-Path $script:idleStageRoot 'tools\network-lab\windows_idle_capture_operator.ps1')
. (Join-Path $script:idleStageRoot 'tools\network-lab\windows_idle_preflight_target_operator.ps1')
$script:idlePinnedFiles = @{
    gui258 = (Join-Path $install258 'clash-verge.exe')
    serviceExe258 = (Join-Path $serviceData 'bin\clash-verge-service.exe')
    programFilesCore = [string]$script:idleCorePair.programFiles.path
    serviceCore = [string]$script:idleCorePair.service.path
    candidateCore = (Join-Path $script:idleStageRoot 'payload\verge-mihomo.exe')
    updateInstaller = (Join-Path $script:idleStageRoot 'payload\Clash.Verge_2.5.10_x64-setup.exe')
    updateHelper = (Join-Path $script:idleStageRoot 'payload\cvr-2.5.10\clash-verge-service-install.exe')
    recoveryInstaller = (Join-Path $script:idleStageRoot 'payload\Clash.Verge_2.5.8_x64-setup.exe')
    recoveryHelper = (Join-Path $script:idleStageRoot 'payload\cvr-2.5.8\clash-verge-service-install.exe')
}
$installerPaths = @{
    '2.5.8' = [string]$script:idlePinnedFiles.recoveryInstaller
    '2.5.10' = [string]$script:idlePinnedFiles.updateInstaller
}
$script:installerPaths = $installerPaths
$env:CVR_258_SERVICE_INSTALL_HELPER_PATH = [string]$script:idlePinnedFiles.recoveryHelper
$env:CVR_2510_SERVICE_INSTALL_HELPER_PATH = [string]$script:idlePinnedFiles.updateHelper
try {
    $idleSetupObservation = Install-CvrIdleService -Version '2.5.8' -InstallDirectory $install258 -ProgramFilesEntry $script:idleCorePair.programFiles -CoreEntry $script:idleCorePair.service -CoreShouldBeRunning $script:idleCoreShouldBeRunning
    $null = Assert-CvrIdleBaseline @idleSetupObservation
    Assert-CvrCorePairPreimage -Preimage $script:idleCorePair -Phase 'idle transaction setup'
    Assert-CvrLegacyState -Expected $script:idleLegacyState -Phase 'idle transaction setup'
} catch {
    try {
        Stop-CvrRunnerRuntime
        Restore-CvrCorePairPreimage -Preimage $script:idleCorePair -HelperVersion '2.5.8'
        Restore-CvrLegacyState -State $script:idleLegacyState
        Assert-CvrCorePairPreimage -Preimage $script:idleCorePair -Phase 'idle transaction setup recovery'
        Assert-CvrLegacyState -Expected $script:idleLegacyState -Phase 'idle transaction setup recovery'
    } catch {
        throw 'Idle transaction setup failed and its runner preimages did not verify.'
    }
    throw 'Idle transaction setup failed after restoring its runner preimages.'
}

$targetIdentity = [string]$script:idleTargetIdentity
$captureSeed = [ordered]@{
    Capture = [ordered]@{
        installDirectory = [IO.Path]::GetFullPath($install258)
        guiSha256 = [string]$script:idleExpectedPins.gui258
        targetIdentity = $targetIdentity
        coreShouldBeRunning = [bool]$false
        corePair = $script:idleCorePair
        legacyState = $script:idleLegacyState
        pinnedFiles = $script:idlePinnedFiles
    }
    ExpectedTargetIdentity = $targetIdentity
    ExpectedPins = $script:idleExpectedPins
    Observer = [ordered]@{
        ExpectedOwnerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        ExpectedSessionId = [Diagnostics.Process]::GetCurrentProcess().SessionId
        ExpectedServiceAccountSid = Get-CvrIdleOperatorAccountSid ([string](Get-CimInstance Win32_Service -Filter "Name='clash_verge_service'" -ErrorAction Stop).StartName)
    }
}
$localRoot = Join-Path $script:idleStageRoot 'local'
$seedPath = Join-Path $localRoot 'capture-seed.json'
if (Test-Path -LiteralPath $seedPath) { throw 'Refusing a preexisting Capture seed.' }
$null = [IO.File]::Open($seedPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None).Dispose()
$null = Set-CvrIdleCaptureAcl -Path $seedPath
$seedJson = ConvertTo-Json -InputObject $captureSeed -Depth 16 -Compress -ErrorAction Stop
[IO.File]::WriteAllText($seedPath, $seedJson, [Text.UTF8Encoding]::new($false, $true))
$captureOperatorPath = Join-Path $script:idleStageRoot 'tools\network-lab\windows_idle_capture_operator.ps1'
$captureChild = Invoke-CvrIdleOperatorChild -ScriptPath $captureOperatorPath -Arguments @(
    '-StageRoot',$script:idleStageRoot,
    '-ExpectedPackageManifestSha256',$script:idleStageManifestSha256,
    '-RequestPath',$seedPath,
    '-TimeoutSeconds','90'
) -TimeoutSeconds 180 -WorkingDirectory $script:idleStageRoot
if ($captureChild.ExitCode -ne 0 -or -not [string]::IsNullOrEmpty($captureChild.StdErr)) {
    throw "Packaged Capture/Plan/Preflight child failed (exit=$($captureChild.ExitCode))."
}
$publicCaptureResult = ConvertFrom-Json -InputObject $captureChild.StdOut -ErrorAction Stop
if ([string]$publicCaptureResult.status -cne 'COMPLETE' -or
    [string]$publicCaptureResult.reason -cne 'preflight-complete' -or
    [string]$publicCaptureResult.result -cne 'PASS' -or
    $publicCaptureResult.exitCode -ne 0 -or
    $publicCaptureResult.timedOut -isnot [bool] -or $publicCaptureResult.timedOut -or
    $publicCaptureResult.childStopped -isnot [bool] -or -not $publicCaptureResult.childStopped -or
    $publicCaptureResult.childExitCode -ne 0 -or
    [string]$publicCaptureResult.sourceManifestSha256 -ine $script:idleStageManifestSha256 -or
    [string]$publicCaptureResult.planSha256 -notmatch '^[0-9a-f]{64}$' -or
    [string]$publicCaptureResult.receiptId -notmatch '^[0-9a-f]{32}$') {
    throw 'Packaged Capture/Plan/Preflight returned an incomplete or unbound public result.'
}
Write-Host 'Invoke-CvrIdleCaptureOperator packaged entry passed bounded Capture, Plan, and Preflight.'
$captureDirectories = @(Get-ChildItem -LiteralPath $localRoot -Directory -ErrorAction Stop | Where-Object { $_.Name -match '^capture-idle-[0-9a-f]{32}$' })
$planDirectories = @(Get-ChildItem -LiteralPath $localRoot -Directory -ErrorAction Stop | Where-Object { $_.Name -match '^prepared-idle-[0-9a-f]{32}$' })
if ($captureDirectories.Count -ne 1 -or $planDirectories.Count -ne 1) { throw 'Packaged Capture/Plan output directories are ambiguous.' }
$captureReceiptPath = Join-Path $captureDirectories[0].FullName 'capture.json'
$planPath = Join-Path $planDirectories[0].FullName 'plan.json'
$preflightReceiptPath = Join-Path $localRoot ("preflight-idle-" + [string]$publicCaptureResult.receiptId + '\result.json')

$nativeCallbackContext = [PSCustomObject]@{
    NativeIntervals = $script:nativeIntervals
    PhaseBoundaries = $script:phaseBoundaries
    NativeFailures = $script:nativeFailures
    InstallDirectory = [IO.Path]::GetFullPath([string]$script:installDirectory)
    ServiceData = [IO.Path]::GetFullPath([string]$script:serviceData)
    CandidateGuiSha256 = ([string]$env:CVR_2510_GUI_SHA256).ToLowerInvariant()
    CandidateServiceExeSha256 = ([string]$env:CVR_2510_SERVICE_SHA256).ToLowerInvariant()
}
$candidateTrafficScript = {
    param($request)
    if ($request.challenge -notmatch '^[0-9a-f]{32}$') { throw 'Candidate traffic challenge is invalid.' }
    $expectedInstall = [IO.Path]::GetFullPath([string]$nativeCallbackContext.InstallDirectory)
    $expectedProgramFilesCore = [IO.Path]::GetFullPath((Join-Path $expectedInstall 'verge-mihomo.exe'))
    $expectedServiceCore = [IO.Path]::GetFullPath((Join-Path $nativeCallbackContext.ServiceData 'cores\verge-mihomo.exe'))
    $expectedServiceExe = [IO.Path]::GetFullPath((Join-Path $nativeCallbackContext.ServiceData 'bin\clash-verge-service.exe'))
    if ([IO.Path]::GetFullPath([string]$request.installDirectory) -ine $expectedInstall -or
        [IO.Path]::GetFullPath([string]$request.programFilesCorePath) -ine $expectedProgramFilesCore -or
        [IO.Path]::GetFullPath([string]$request.serviceCorePath) -ine $expectedServiceCore -or
        [string]$request.candidateGuiSha256 -cne [string]$nativeCallbackContext.CandidateGuiSha256 -or
        [string]$request.candidateServiceExeSha256 -cne [string]$nativeCallbackContext.CandidateServiceExeSha256) {
        throw 'Candidate traffic request differs from the pinned native install.'
    }
    foreach ($path in @($expectedProgramFilesCore,$expectedServiceCore)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or
            (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string]$request.candidateCoreSha256) {
            throw 'Candidate traffic request core bytes differ from the pinned native install.'
        }
    }
    if (-not (Test-Path -LiteralPath $expectedServiceExe -PathType Leaf) -or
        (Get-FileHash -LiteralPath $expectedServiceExe -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string]$request.candidateServiceExeSha256) {
        throw 'Candidate traffic request service executable differs from its pin.'
    }
    $receiptPath = Join-Path $env:RUNNER_TEMP ('stcvrc-candidate-traffic-' + [string]$request.challenge + '.json')
    if (Test-Path -LiteralPath $receiptPath) { throw 'Refusing a preexisting candidate traffic receipt.' }
    $stream = [IO.File]::Open($receiptPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $stream.Dispose()
    $null = Set-CvrIdleCaptureAcl -Path $receiptPath
    try {
        $failureCount = $nativeCallbackContext.NativeFailures.Count
        Invoke-NativePhase -Phase exercise -InstallDirectory $request.installDirectory -ExpectedProgramFilesCoreSha $request.candidateCoreSha256 -ExpectedServiceCoreSha $request.candidateCoreSha256 -TrafficChallenge $request.challenge -TrafficReceiptPath $receiptPath -TrafficRequiredProbes $request.requiredProbes -NativeFailures $nativeCallbackContext.NativeFailures -NativeIntervals $nativeCallbackContext.NativeIntervals -PhaseBoundaries $nativeCallbackContext.PhaseBoundaries
        if ($nativeCallbackContext.NativeFailures.Count -gt $failureCount) { throw 'Candidate native traffic acceptance failed.' }
        if (-not (Test-Path -LiteralPath $receiptPath -PathType Leaf)) { throw 'Candidate native traffic receipt was not produced.' }
        return ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($receiptPath, [Text.UTF8Encoding]::new($false, $true))) -ErrorAction Stop
    } finally {
        if (Test-Path -LiteralPath $receiptPath) { Remove-Item -LiteralPath $receiptPath -Force -ErrorAction Stop }
        if (Test-Path -LiteralPath $receiptPath) { throw 'Candidate native traffic receipt cleanup failed.' }
    }
}.GetNewClosure()

$recoveryVerificationScript = {
    param($request)
    $failureCount = $nativeCallbackContext.NativeFailures.Count
    Invoke-NativePhase -Phase recovery -InstallDirectory $request.installDirectory -ExpectedProgramFilesCoreSha $request.expectedProgramFilesCoreSha256 -ExpectedServiceCoreSha $request.expectedServiceCoreSha256 -RecoveryServiceCorePreimagePath $request.recoveryServiceCorePreimagePath -NativeFailures $nativeCallbackContext.NativeFailures -NativeIntervals $nativeCallbackContext.NativeIntervals -PhaseBoundaries $nativeCallbackContext.PhaseBoundaries
    return [bool]($nativeCallbackContext.NativeFailures.Count -eq $failureCount)
}.GetNewClosure()

$targetTransactionResult = Invoke-CvrIdlePreflightTargetAcceptance `
    -CaptureReceiptPath $captureReceiptPath `
    -PlanPath $planPath `
    -PreflightReceiptPath $preflightReceiptPath `
    -ExpectedPlanSha256 ([string]$publicCaptureResult.planSha256) `
    -ExpectedStageRoot $script:idleStageRoot `
    -ExpectedPackageManifestSha256 $script:idleStageManifestSha256 `
    -ExpectedTargetIdentity $targetIdentity `
    -ExpectedPins $script:idleExpectedPins `
    -ExpectedCandidateGuiSha256 $env:CVR_2510_GUI_SHA256 `
    -ExpectedCandidateServiceExeSha256 $env:CVR_2510_SERVICE_SHA256 `
    -RequiredCandidateProbes @('dns','http') `
    -CandidateTrafficScript $candidateTrafficScript `
    -RecoveryVerificationScript $recoveryVerificationScript `
    -NativeFailures $script:nativeFailures `
    -NativeIntervals $script:nativeIntervals `
    -PhaseBoundaries $script:phaseBoundaries
$transactionFailure = $null
$idleRestoreFailure = $null
if ($targetTransactionResult.status -ceq 'PASS' -and $targetTransactionResult.candidateTrafficVerification.status -cne 'PASS') {
    $transactionFailure = 'MissingCandidateTrafficVerification'
} else {
    Write-Host 'Candidate traffic receipt passed identity and probe checks before verified rollback.'
}
if ($targetTransactionResult.actionErrorType) {
    $transactionFailure = [string]$targetTransactionResult.actionErrorType
}
if ($targetTransactionResult.status -eq 'ACTION_FAILED_RESTORED' -and -not $transactionFailure) {
    $transactionFailure = 'MissingActionErrorType'
}
if ($targetTransactionResult.status -eq 'RESTORE_FAILED') {
    $idleRestoreFailure = if ($targetTransactionResult.restoreErrorType) { [string]$targetTransactionResult.restoreErrorType } else { 'MissingRestoreErrorType' }
} elseif ($targetTransactionResult.status -cne 'PASS' -and $targetTransactionResult.status -cne 'ACTION_FAILED_RESTORED') {
    $transactionFailure = [string]$targetTransactionResult.status
}
if ($transactionFailure) { Write-Host "Candidate update/acceptance Action failed: $transactionFailure" -ForegroundColor Red }
if ($idleRestoreFailure) { Write-Host "Captured idle Restore failed: $idleRestoreFailure" -ForegroundColor Red }
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
$coreStartIntervals = $script:nativeIntervals.ToArray() + $script:overlayIntervals.ToArray()
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
    catch { $script:nativeFailures.Add("Could not decode process start time for ${processName}: ${rawTime}"); continue }
    $decision = Get-CoreStartDecision -ProcessName $processName -CreatedUtc $created -Intervals $coreStartIntervals
    $coreEvents.Add([PSCustomObject]@{ name=$processName; pid=$newEvent.ProcessID; timeUtc=$created; allowedPhase=$decision.phase; decision=$decision.reason })
    if (-not $decision.allowed) {
        $script:nativeFailures.Add("Rejected core process start ($($decision.reason)): $processName pid=$($newEvent.ProcessID) at $($created.ToString('o')).")
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
    '- Synthetic NSIS side-effect check ran against the isolated initial preimage; update/recovery transactions captured and restored their actual window-state files, ACLs, and autorun values.',
    '- Public packaged Capture/Plan/Preflight bound owner/session/service identity, idle intent, separate Program Files/service core SHA+ACL preimages, GUI/service executable backups, and legacy files/Run state before Action.',
    '- Candidate acceptance checked the installed Program Files core and the independently pinned service core path/SHA before recovery.',
    '- The shared idle transaction helper restores and verifies captured preimages after the update/recovery action, including when that action fails.',
    '- Updated and exercised the fresh source-built candidate through pinned 2.5.10; verified its post-exercise idle service state before recovery.',
    '- The final recovery restores the captured 2.5.8 GUI, both exact core preimages/ACLs, captured legacy state, and verified idle service state even when update/recovery throws.',
    '- The public runner uses only synthetic acceptance inputs; no private pins/data, production profiles, external VPN endpoints, secrets, paid runners, Actions cache or artifacts.'
)
foreach ($boundary in $script:phaseBoundaries) { $summary += "- Phase $($boundary.phase): $($boundary.startUtc.ToString('o')) .. $($boundary.endUtc.ToString('o'))." }
foreach ($interval in $coreStartIntervals) { $summary += "- Allowed core-start interval $($interval.phase): $($interval.startUtc.ToString('o')) .. $($interval.endUtc.ToString('o'))." }
foreach ($event in $coreEvents) {
    $eventPhase = if ($event.allowedPhase) { $event.allowedPhase } else { 'none' }
    $summary += "- Core process event $($event.name) pid=$($event.pid) at $($event.timeUtc.ToString('o')); native phase=$eventPhase."
}
if ($script:nativeFailures.Count) { $summary += '- Native/process-start acceptance: FAIL.'; $summary += $script:nativeFailures | ForEach-Object { "- Failure: $_" } }
else { $summary += '- Native/process-start acceptance: PASS.' }
if ($script:legacyStateFixture) { Remove-CvrSyntheticLegacyPreimage -Fixture $script:legacyStateFixture }
if ($transactionFailure) { $summary += "- Candidate update/recovery transaction: FAIL — $transactionFailure" } else { $summary += '- Candidate update/recovery transaction: PASS.' }
if ($idleRestoreFailure) { $summary += "- Captured idle baseline restore: FAIL — $idleRestoreFailure" } else { $summary += '- Captured idle baseline restore: PASS.' }
Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY -Value $summary
if ($script:nativeFailures.Count -or $transactionFailure -or $idleRestoreFailure) {
    throw "Native/transaction acceptance failed. Native: $($script:nativeFailures -join ' | '); transaction: $transactionFailure; idle restore: $idleRestoreFailure"
}
