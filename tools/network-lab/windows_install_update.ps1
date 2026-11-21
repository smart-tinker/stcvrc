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
$legacyStateTransactionScript = Join-Path $PSScriptRoot 'windows_legacy_state_transaction.ps1'
if (-not (Test-Path -LiteralPath $legacyStateTransactionScript -PathType Leaf)) { throw 'The shared legacy-state transaction helper is missing.' }
. $legacyStateTransactionScript
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
$nativeCandidate = $manifest.windowsNativeCandidate
if ($nativeCandidate.releaseId -ne 446278043 -or
    $nativeCandidate.tag -cne 'stcvrc-1.19.33-rc.9' -or
    $nativeCandidate.candidate -cne 'STCVRC 1.19.33 RC9' -or
    $nativeCandidate.assetId -ne 751963784 -or
    $nativeCandidate.assetName -cne 'verge-mihomo.exe' -or
    [long]$nativeCandidate.assetSize -ne 60833280 -or
    [long]$coreEntries[0].size -ne [long]$nativeCandidate.assetSize -or
    $coreSha -cne [string]$nativeCandidate.sha256) {
    throw 'Fresh Windows core does not match the exact STCVRC 1.19.33 RC9 release asset pin.'
}
if ((Get-Item -LiteralPath $env:CUSTOM_CORE).Length -ne [long]$coreEntries[0].size) { throw 'Fresh Windows artifact size changed after build.' }
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
    param([string]$Version, [string[]]$Arguments, [switch]$PreserveCorePair)
    return Invoke-CvrStateTransaction -Phase "CVR $Version installer" -HelperVersion $Version -InstallDirectory $script:installDirectory -PreserveCorePair:$PreserveCorePair -Action {
        Invoke-CvrInstallerAction -Version $Version -Arguments $Arguments
    }
}

function Invoke-CvrInstallerAction {
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


function Get-CvrServiceInstallHelper {
    param([ValidateSet('2.5.8','2.5.10')][string]$Version)
    $release = @($script:manifest.releases | Where-Object { $_.version -ceq $Version })
    if ($release.Count -ne 1) { throw "Expected one pinned CVR $Version release." }
    $expected = [string]$release[0].serviceInstallHelperSha256
    if ($expected -notmatch '^[0-9a-f]{64}$') { throw "CVR $Version helper pin is missing or malformed." }
    $suffix = if ($Version -eq '2.5.8') { '258' } else { '2510' }
    $path = [Environment]::GetEnvironmentVariable("CVR_$($suffix)_SERVICE_INSTALL_HELPER_PATH")
    $envSha = [Environment]::GetEnvironmentVariable("CVR_$($suffix)_SERVICE_INSTALL_HELPER_SHA256")
    if (-not $path -or -not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "The extracted CVR $Version service-install helper is missing."
    }
    $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -cne $expected -or $envSha -cne $expected) {
        throw "Extracted CVR $Version helper does not match its installer-derived pin."
    }
    return [PSCustomObject]@{ path=$path; sha256=$expected }
}

function Get-CvrCorePairPreimage {
    param([string]$InstallDirectory)
    Assert-NoService
    Assert-NoCvrProcesses
    $targets = @(
        [PSCustomObject]@{ role='Program Files core'; backupLabel='program-files'; path=(Join-Path $InstallDirectory 'verge-mihomo.exe') },
        [PSCustomObject]@{ role='service core'; backupLabel='service'; path=(Join-Path $serviceData 'cores\verge-mihomo.exe') }
    )
    if ([IO.Path]::GetFullPath($targets[0].path) -ieq [IO.Path]::GetFullPath($targets[1].path)) {
        throw 'Program Files and service core paths are not separate.'
    }
    $records = foreach ($target in $targets) {
        if (-not (Test-Path -LiteralPath $target.path -PathType Leaf)) { throw "Missing $($target.role) before NSIS." }
        $sha = (Get-FileHash -LiteralPath $target.path -Algorithm SHA256).Hash.ToLowerInvariant()
        $acl = Get-Acl -LiteralPath $target.path
        $backup = New-CvrCorePreimageBackupPath -Root $env:RUNNER_TEMP -Label $target.backupLabel
        Copy-Item -LiteralPath $target.path -Destination $backup
        if ((Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash.ToLowerInvariant() -cne $sha) {
            throw "Could not retain $($target.role) preimage."
        }
        [PSCustomObject]@{
            role = $target.role
            path = [IO.Path]::GetFullPath($target.path)
            backup = $backup
            sha256 = $sha
            sddl = $acl.Sddl
            acl = $acl
        }
    }
    return [PSCustomObject]@{ programFiles=$records[0]; service=$records[1] }
}

function Assert-CvrCorePairPreimage {
    param($Preimage, [string]$Phase)
    foreach ($entry in @($Preimage.programFiles, $Preimage.service)) {
        if (-not (Test-Path -LiteralPath $entry.path -PathType Leaf) -or
            (Get-FileHash -LiteralPath $entry.path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry.sha256 -or
            (Get-Acl -LiteralPath $entry.path).Sddl -cne $entry.sddl) {
            throw "CVR $Phase $($entry.role) preimage restore mismatch."
        }
    }
}

function Restore-CvrCorePairPreimage {
    param($Preimage, [ValidateSet('2.5.8','2.5.10')][string]$HelperVersion)
    Assert-NoService
    Assert-NoCvrProcesses
    $failures = [Collections.Generic.List[string]]::new()
    try {
        $entry = $Preimage.programFiles
        Copy-Item -LiteralPath $entry.backup -Destination $entry.path -Force
        Set-Acl -LiteralPath $entry.path -AclObject $entry.acl
        if ((Get-FileHash -LiteralPath $entry.path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry.sha256 -or
            (Get-Acl -LiteralPath $entry.path).Sddl -cne $entry.sddl) {
            throw 'Program Files core hash/ACL mismatch'
        }
    } catch {
        $failures.Add('Program Files core preimage restore failed')
    }
    $serviceRestoreStage = 'preimage path/hash verification'
    $serviceRestoreDiagnostic = ''
    try {
        $entry = $Preimage.service
        if ([IO.Path]::GetFileName([string]$entry.backup) -cne 'verge-mihomo.exe') {
            $serviceRestoreDiagnostic = 'backup basename must be verge-mihomo.exe'
            throw 'service helper input basename mismatch'
        }
        if (-not (Test-Path -LiteralPath $entry.backup -PathType Leaf)) {
            $serviceRestoreDiagnostic = 'backup file missing'
            throw 'service core backup is missing'
        }
        $backupHash = (Get-FileHash -LiteralPath $entry.backup -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($backupHash -cne $entry.sha256) {
            $serviceRestoreDiagnostic = "backup SHA256 expected=$($entry.sha256) actual=$backupHash"
            throw 'service core backup hash mismatch'
        }
        $serviceRestoreStage = 'helper lookup'
        $helper = Get-CvrServiceInstallHelper -Version $HelperVersion
        $serviceRestoreStage = 'helper core restore'
        $output = & $helper.path --install-core $entry.backup --sha256 $entry.sha256 2>&1
        $exitCode = $LASTEXITCODE
        if ($exitCode -ne 0) {
            $serviceRestoreDiagnostic = "helper exit=$exitCode"
            throw "version-pinned helper exit $exitCode"
        }
        $serviceRestoreStage = 'service core content verification'
        if (-not (Test-Path -LiteralPath $entry.path -PathType Leaf)) {
            $serviceRestoreDiagnostic = 'service core destination missing after helper'
            throw 'service core destination missing'
        }
        $restoredHash = (Get-FileHash -LiteralPath $entry.path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($restoredHash -cne $entry.sha256) {
            $serviceRestoreDiagnostic = "content SHA256 expected=$($entry.sha256) actual=$restoredHash"
            throw 'service core hash mismatch'
        }
        $serviceRestoreStage = 'service core ACL restore'
        if ((Get-Acl -LiteralPath $entry.path).Sddl -cne $entry.sddl) {
            Set-Acl -LiteralPath $entry.path -AclObject $entry.acl
        }
        $serviceRestoreStage = 'service core ACL verification'
        $restoredSddl = (Get-Acl -LiteralPath $entry.path).Sddl
        if ($restoredSddl -cne $entry.sddl) {
            $expectedAclHash = Get-CvrStringSha256 -Value $entry.sddl
            $actualAclHash = Get-CvrStringSha256 -Value $restoredSddl
            $serviceRestoreDiagnostic = "ACL SDDL SHA256 expected=$expectedAclHash actual=$actualAclHash"
            throw 'service core ACL mismatch'
        }
    } catch {
        $detail = if ($serviceRestoreDiagnostic) { " ($serviceRestoreDiagnostic)" } else { '' }
        $failures.Add("service core preimage restore failed at $serviceRestoreStage$detail")
    }
    if ($failures.Count) { throw "CVR core rollback was incomplete: $($failures -join '; ')." }
    Assert-CvrCorePairPreimage -Preimage $Preimage -Phase 'rollback'
}


function Save-CvrSyntheticStockCore {
    param([string]$InstallDirectory)
    $path = Join-Path $InstallDirectory 'verge-mihomo.exe'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'Pinned 2.5.8 stock Program Files core is missing.' }
    $sha = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($sha -ceq $coreSha) { throw 'Synthetic stock Program Files core must differ from the candidate service core.' }
    $acl = Get-Acl -LiteralPath $path
    $backup = New-CvrCorePreimageBackupPath -Root $env:RUNNER_TEMP -Label '258-stock'
    if ([IO.Path]::GetFileName($backup) -cne 'verge-mihomo.exe') { throw 'Pinned 2.5.8 helper input basename mismatch.' }
    Copy-Item -LiteralPath $path -Destination $backup
    if ((Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash.ToLowerInvariant() -cne $sha) {
        throw 'Could not retain the pinned 2.5.8 stock Program Files core.'
    }
    return [PSCustomObject]@{ path=$backup; sha256=$sha; sddl=$acl.Sddl; acl=$acl }
}

function Set-CvrSyntheticSplitCorePreimage {
    param([string]$InstallDirectory, $StockCore)
    if (-not $StockCore -or -not (Test-Path -LiteralPath $StockCore.path -PathType Leaf) -or
        (Get-FileHash -LiteralPath $StockCore.path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $StockCore.sha256) {
        throw 'The retained 2.5.8 stock core no longer matches its preimage.'
    }
    $programFilesCore = Join-Path $InstallDirectory 'verge-mihomo.exe'
    $serviceCore = Join-Path $serviceData 'cores\verge-mihomo.exe'
    if (-not (Test-Path -LiteralPath $serviceCore -PathType Leaf) -or
        (Get-FileHash -LiteralPath $serviceCore -Algorithm SHA256).Hash.ToLowerInvariant() -cne $coreSha) {
        throw 'Synthetic service core is not the pinned candidate preimage.'
    }
    Copy-Item -LiteralPath $StockCore.path -Destination $programFilesCore -Force
    Set-Acl -LiteralPath $programFilesCore -AclObject $StockCore.acl
    if ((Get-FileHash -LiteralPath $programFilesCore -Algorithm SHA256).Hash.ToLowerInvariant() -cne $StockCore.sha256 -or
        (Get-Acl -LiteralPath $programFilesCore).Sddl -cne $StockCore.sddl) {
        throw 'Could not establish the separate signed-stock Program Files core preimage.'
    }
    if ($StockCore.sha256 -ceq $coreSha) { throw 'Synthetic Program Files and service core preimages are not distinct.' }
}

function Invoke-CvrOverlayReinstall {
    param([string]$InstallDirectory)
    return Invoke-CvrStateTransaction -Phase 'CVR 2.5.10 overlay' -HelperVersion '2.5.10' -InstallDirectory $InstallDirectory -PreserveCorePair -Action {
        Invoke-CvrOverlayReinstallAction -InstallDirectory $InstallDirectory
    }
}

function Invoke-CvrOverlayReinstallAction {
    param([string]$InstallDirectory)
    $started = [DateTime]::UtcNow
    $guiPath = Join-Path $InstallDirectory 'clash-verge.exe'
    $gui = $null
    $installerProcess = $null
    $overlayInterval = $null
    try {
        if (-not (Test-Path -LiteralPath $guiPath -PathType Leaf)) { throw 'Pinned CVR 2.5.10 GUI is missing before overlay.' }
        $expectedGuiSha = ([string]$env:CVR_2510_GUI_SHA256).ToLowerInvariant()
        $actualGuiSha = (Get-FileHash -LiteralPath $guiPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($expectedGuiSha.Length -ne 64 -or $expectedGuiSha -notmatch '^[0-9a-f]+$' -or $actualGuiSha -ne $expectedGuiSha) {
            throw 'Pinned CVR 2.5.10 GUI SHA256 mismatch before overlay.'
        }

        $overlayInterval = [PSCustomObject]@{ phase='overlay'; startUtc=$started; endUtc=[DateTime]::MaxValue }
        $script:overlayIntervals.Add($overlayInterval)
        $gui = Start-Process -FilePath $guiPath -PassThru
        if (-not (Get-Process -Id $gui.Id -ErrorAction SilentlyContinue)) { throw 'Pinned CVR GUI process exited before overlay started.' }
        $guiRecord = Get-CimInstance Win32_Process -Filter "ProcessId = $($gui.Id)" -ErrorAction SilentlyContinue
        if (-not $guiRecord -or -not $guiRecord.ExecutablePath) { throw 'Could not verify the running CVR GUI executable path.' }
        $actualGuiPath = [IO.Path]::GetFullPath([string]$guiRecord.ExecutablePath).TrimEnd([char]92)
        $expectedGuiPath = [IO.Path]::GetFullPath($guiPath).TrimEnd([char]92)
        if ($actualGuiPath -ine $expectedGuiPath) { throw "Running GUI process did not match the pinned install path: $actualGuiPath" }

        $installerProcess = Start-Process -FilePath $installerPaths['2.5.10'] -ArgumentList @('/S', '/P', '/UPDATE', '/NS') -PassThru -WindowStyle Hidden
        $deadline = [DateTime]::UtcNow.AddSeconds(120)
        $guiExitedDuringOverlay = $false
        while ([DateTime]::UtcNow -lt $deadline) {
            $installerProcess.Refresh()
            $gui.Refresh()
            if ($gui.HasExited) {
                $guiExitTime = $gui.ExitTime.ToUniversalTime()
                $installerProcess.Refresh()
                if ($guiExitTime -ge $installerProcess.StartTime.ToUniversalTime() -and
                    (-not $installerProcess.HasExited -or
                    $guiExitTime -lt $installerProcess.ExitTime.ToUniversalTime())) {
                    $guiExitedDuringOverlay = $true
                }
            }
            if ($installerProcess.HasExited) { break }
            Start-Sleep -Milliseconds 50
        }
        $installerProcess.Refresh()
        $gui.Refresh()
        if ($gui.HasExited -and $installerProcess.HasExited -and
            $gui.ExitTime.ToUniversalTime() -ge $installerProcess.StartTime.ToUniversalTime() -and
            $gui.ExitTime.ToUniversalTime() -lt $installerProcess.ExitTime.ToUniversalTime()) {
            $guiExitedDuringOverlay = $true
        }
        if (-not $installerProcess.HasExited) { throw 'CVR 2.5.10 overlay installer exceeded 120 seconds.' }
        if ($installerProcess.ExitCode -ne 0) { throw "CVR 2.5.10 overlay installer exited with code $($installerProcess.ExitCode)." }
        if (-not $guiExitedDuringOverlay) { throw 'Expected the pinned CVR GUI process to exit during overlay.' }

        $verifiedDirectory = Get-InstalledCvrDirectory -ExpectedVersion '2.5.10'
        if ($verifiedDirectory -ne $InstallDirectory) { throw 'CVR 2.5.10 overlay changed the install directory.' }
        Assert-NoService
        Assert-NoCvrProcesses
        Write-Host 'CVR 2.5.10 overlay completed while the pinned GUI process was running; app exited and installer identity remained valid.'
    } finally {
        if ($installerProcess) {
            try {
                $installerProcess.Refresh()
                if (-not $installerProcess.HasExited) {
                    & taskkill.exe /PID $installerProcess.Id /T /F | Out-Null
                    $installerProcess.Refresh()
                    if (-not $installerProcess.HasExited) { Stop-Process -Id $installerProcess.Id -Force -ErrorAction SilentlyContinue }
                }
            } catch {
                Write-Host "Could not stop overlay installer process $($installerProcess.Id): $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        if ($gui) {
            try {
                $gui.Refresh()
                if (-not $gui.HasExited) {
                    $record = Get-CimInstance Win32_Process -Filter "ProcessId = $($gui.Id)" -ErrorAction SilentlyContinue
                    if ($record.ExecutablePath -and [IO.Path]::GetFullPath([string]$record.ExecutablePath).TrimEnd([char]92) -ieq [IO.Path]::GetFullPath($guiPath).TrimEnd([char]92)) {
                        Stop-Process -Id $gui.Id -Force -ErrorAction SilentlyContinue
                    }
                }
            } catch {
                Write-Host "Could not stop overlay GUI process $($gui.Id): $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        if ($overlayInterval) { $overlayInterval.endUtc = [DateTime]::UtcNow }
        $script:phaseBoundaries.Add([PSCustomObject]@{ phase='overlay-reinstall'; startUtc=$started; endUtc=[DateTime]::UtcNow })
    }
}

function Install-CandidateCore {
    param([string]$InstallDirectory, [string]$Phase, [ValidateSet('2.5.8','2.5.10')][string]$HelperVersion)
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
        $helperPin = Get-CvrServiceInstallHelper -Version $HelperVersion
        if ((Get-FileHash -LiteralPath $helpers[0].FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne $helperPin.sha256) {
            throw "Installed CVR $HelperVersion service helper does not match its extracted installer pin."
        }
        $stageOutput = & $helpers[0].FullName --install-core $installedCore --sha256 $coreSha 2>&1
        $stageExit = $LASTEXITCODE
        if ($stageExit -ne 0) { throw "SHA-pinned core staging failed after $Phase ($stageExit)." }
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
$script:overlayIntervals = [Collections.Generic.List[object]]::new()
$script:phaseBoundaries = [Collections.Generic.List[object]]::new()
$script:nativeFailures = [Collections.Generic.List[string]]::new()
$nativeScript = Join-Path $env:PR_SOURCE 'tools\network-lab\windows_native_acceptance.ps1'
$portPlanScript = Join-Path $env:PR_SOURCE 'tools\network-lab\windows_native_port_plan.ps1'
if (-not (Test-Path -LiteralPath $portPlanScript -PathType Leaf) -or -not $env:RUNNER_TEMP) { throw 'Native phase DNS port-plan inputs are missing.' }
. $portPlanScript
$env:STCVRC_NATIVE_PORT_PLAN = Join-Path $env:RUNNER_TEMP 'stcvrc-native-port-plan.json'
if (Test-Path -LiteralPath $env:STCVRC_NATIVE_PORT_PLAN) { throw 'Refusing a preexisting native DNS port plan on the disposable runner.' }
$null = Get-StcvrcNativePortPlan -Path $env:STCVRC_NATIVE_PORT_PLAN
Write-Host 'Created one validated DNS port plan for seed, update, and recovery phases.'
function Get-CvrIdleBaselineObservation {
    param(
        [ValidateSet('2.5.8','2.5.10')][string]$Version,
        [string]$InstallDirectory,
        [object]$CoreShouldBeRunning,
        [string]$ExpectedProgramFilesCoreSha256,
        [string]$ExpectedServiceCoreSha256
    )
    $expectedGuiSha = if ($Version -eq '2.5.8') { [string]$env:CVR_258_GUI_SHA256 } else { [string]$env:CVR_2510_GUI_SHA256 }
    $expectedServiceExeSha = if ($Version -eq '2.5.8') { [string]$env:CVR_258_SERVICE_SHA256 } else { [string]$env:CVR_2510_SERVICE_SHA256 }
    if ($expectedGuiSha -notmatch '^[0-9a-f]{64}$' -or $expectedServiceExeSha -notmatch '^[0-9a-f]{64}$') {
        throw 'Idle baseline GUI or service executable pin is malformed.'
    }

    $guiPath = [IO.Path]::GetFullPath((Join-Path $InstallDirectory 'clash-verge.exe'))
    $programFilesCore = [IO.Path]::GetFullPath((Join-Path $InstallDirectory 'verge-mihomo.exe'))
    $serviceCore = [IO.Path]::GetFullPath((Join-Path $serviceData 'cores\verge-mihomo.exe'))
    $serviceExe = [IO.Path]::GetFullPath((Join-Path $serviceData 'bin\clash-verge-service.exe'))
    if (-not (Test-Path -LiteralPath $guiPath -PathType Leaf) -or
        (Get-FileHash -LiteralPath $guiPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expectedGuiSha.ToLowerInvariant()) {
        throw 'Idle baseline GUI SHA256 mismatch.'
    }
    if (-not (Test-Path -LiteralPath $programFilesCore -PathType Leaf) -or
        -not (Test-Path -LiteralPath $serviceCore -PathType Leaf)) {
        throw 'Idle baseline core path is missing.'
    }

    $serviceRecord = Get-CimInstance Win32_Service -Filter "Name='clash_verge_service'" -ErrorAction Stop
    $serviceStatus = if ($serviceRecord) { [string]$serviceRecord.State } else { 'Missing' }
    $servicePid = if ($serviceRecord) { [int]$serviceRecord.ProcessId } else { 0 }
    if ($serviceRecord -and ($serviceStatus -cne 'Running' -or $servicePid -le 0)) {
        throw 'Idle baseline service process identity is unavailable.'
    }
    if ($serviceRecord) {
        $serviceExeProcess = Get-CimInstance Win32_Process -Filter "ProcessId=$servicePid" -ErrorAction Stop
        if (-not $serviceExeProcess -or -not $serviceExeProcess.ExecutablePath -or
            [IO.Path]::GetFullPath([string]$serviceExeProcess.ExecutablePath) -ine $serviceExe -or
            (Get-FileHash -LiteralPath $serviceExe -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expectedServiceExeSha.ToLowerInvariant()) {
            throw 'Idle baseline service executable identity mismatch.'
        }
    }

    $programFilesCoreDirectory = [IO.Path]::GetDirectoryName($programFilesCore)
    $serviceCoreDirectory = [IO.Path]::GetDirectoryName($serviceCore)
    $allProcesses = @(Get-CimInstance Win32_Process -Filter "Name='clash-verge.exe' OR Name='clash-verge-service.exe' OR Name='verge-mihomo.exe' OR Name='verge-mihomo-alpha.exe'" -ErrorAction Stop)
    $guiIds = @()
    $coreIds = @()
    foreach ($process in $allProcesses) {
        if (-not $process.ExecutablePath) { throw 'Idle baseline CVR process path is unavailable.' }
        $processPath = [IO.Path]::GetFullPath([string]$process.ExecutablePath)
        if ($process.Name -ieq 'clash-verge.exe') {
            if ($processPath -ine $guiPath) { throw 'Idle baseline found an unowned GUI process.' }
            $guiIds += [int]$process.ProcessId
        } elseif ($process.Name -ieq 'clash-verge-service.exe') {
            if (-not $serviceRecord -or [int]$process.ProcessId -ne $servicePid -or $processPath -ine $serviceExe) {
                throw 'Idle baseline found an unowned service process.'
            }
        } elseif ($process.Name -ieq 'verge-mihomo.exe' -or $process.Name -ieq 'verge-mihomo-alpha.exe') {
            $processDirectory = [IO.Path]::GetDirectoryName($processPath)
            if ($processDirectory -ine $programFilesCoreDirectory -and $processDirectory -ine $serviceCoreDirectory) {
                throw 'Idle baseline found an unowned core process.'
            }
            $coreIds += [int]$process.ProcessId
        } else {
            throw 'Idle baseline found an unrecognized CVR process.'
        }
    }

    $listenerIds = @(
        Get-NetTCPConnection -State Listen -ErrorAction Stop |
            Where-Object { $coreIds -contains [int]$_.OwningProcess } |
            Select-Object -ExpandProperty OwningProcess -Unique |
            ForEach-Object { [int]$_ }
    )
    return @{
        CoreShouldBeRunning = $CoreShouldBeRunning
        OwnedGuiProcessIds = [int[]]$guiIds
        OwnedCoreProcessIds = [int[]]$coreIds
        ControllerListening = [bool]($listenerIds.Count -gt 0)
        OwnedListenerProcessIds = [int[]]$listenerIds
        ServiceStatus = $serviceStatus
        ExpectedProgramFilesCoreSha256 = $ExpectedProgramFilesCoreSha256
        ObservedProgramFilesCoreSha256 = (Get-FileHash -LiteralPath $programFilesCore -Algorithm SHA256).Hash.ToLowerInvariant()
        ExpectedServiceCoreSha256 = $ExpectedServiceCoreSha256
        ObservedServiceCoreSha256 = (Get-FileHash -LiteralPath $serviceCore -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

function Install-CvrIdleService {
    param(
        [ValidateSet('2.5.8','2.5.10')][string]$Version,
        [string]$InstallDirectory,
        [object]$ProgramFilesEntry,
        [object]$CoreEntry,
        [object]$CoreShouldBeRunning
    )
    if (-not (Test-Path -LiteralPath $ProgramFilesEntry.path -PathType Leaf) -or
        (Get-FileHash -LiteralPath $ProgramFilesEntry.path -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string]$ProgramFilesEntry.sha256 -or
        (Get-Acl -LiteralPath $ProgramFilesEntry.path).Sddl -cne [string]$ProgramFilesEntry.sddl) {
        throw 'Idle Program Files core preimage SHA256 or ACL mismatch.'
    }
    if ([IO.Path]::GetFileName([string]$CoreEntry.backup) -cne 'verge-mihomo.exe' -or
        -not (Test-Path -LiteralPath $CoreEntry.backup -PathType Leaf) -or
        (Get-FileHash -LiteralPath $CoreEntry.backup -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string]$CoreEntry.sha256) {
        throw 'Idle service core preimage basename or SHA256 mismatch.'
    }
    if (Get-Service -Name 'clash_verge_service' -ErrorAction SilentlyContinue) {
        throw 'Refusing to replace a preexisting CVR service during idle capture.'
    }
    $helper = Get-CvrServiceInstallHelper -Version $Version
    $helperOutput = & $helper.path --install-service --install-core $CoreEntry.backup --sha256 $CoreEntry.sha256 2>&1
    $helperExit = $LASTEXITCODE
    if ($helperExit -ne 0) { throw "Pinned CVR $Version idle-service helper exited $helperExit." }

    $serviceCore = Join-Path $serviceData 'cores\verge-mihomo.exe'
    if (-not (Test-Path -LiteralPath $serviceCore -PathType Leaf) -or
        (Get-FileHash -LiteralPath $serviceCore -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string]$CoreEntry.sha256) {
        throw 'Pinned helper did not publish the idle service core bytes.'
    }
    if ((Get-Acl -LiteralPath $serviceCore).Sddl -cne [string]$CoreEntry.sddl) {
        Set-Acl -LiteralPath $serviceCore -AclObject $CoreEntry.acl
    }
    if ((Get-Acl -LiteralPath $serviceCore).Sddl -cne [string]$CoreEntry.sddl) {
        throw 'Idle service core ACL did not match the captured preimage.'
    }

    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    $service = $null
    do {
        $service = Get-Service -Name 'clash_verge_service' -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) { break }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    if (-not $service -or $service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running) {
        throw "Pinned CVR $Version helper did not leave the idle service Running."
    }
    if ((Get-FileHash -LiteralPath $ProgramFilesEntry.path -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string]$ProgramFilesEntry.sha256 -or
        (Get-Acl -LiteralPath $ProgramFilesEntry.path).Sddl -cne [string]$ProgramFilesEntry.sddl) {
        throw 'Idle helper changed the captured Program Files core SHA256 or ACL.'
    }
    return (Get-CvrIdleBaselineObservation -Version $Version -InstallDirectory $InstallDirectory -CoreShouldBeRunning $CoreShouldBeRunning -ExpectedProgramFilesCoreSha256 ([string]$ProgramFilesEntry.sha256) -ExpectedServiceCoreSha256 ([string]$CoreEntry.sha256))
}

function Stop-CvrRunnerRuntime {
    $service = Get-Service -Name 'clash_verge_service' -ErrorAction SilentlyContinue
    if ($service) {
        if ($service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
            Stop-Service -Name 'clash_verge_service' -Force -ErrorAction Stop
            $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30))
        }
        $null = & sc.exe delete 'clash_verge_service' 2>&1
    }

    $expectedGui = [IO.Path]::GetFullPath((Join-Path $script:installDirectory 'clash-verge.exe'))
    $expectedServiceExe = [IO.Path]::GetFullPath((Join-Path $serviceData 'bin\clash-verge-service.exe'))
    $expectedCoreDirectories = @(
        [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath((Join-Path $script:installDirectory 'verge-mihomo.exe'))),
        [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath((Join-Path $serviceData 'cores\verge-mihomo.exe')))
    )
    $processes = @(Get-CimInstance Win32_Process -Filter "Name='clash-verge.exe' OR Name='clash-verge-service.exe' OR Name='verge-mihomo.exe' OR Name='verge-mihomo-alpha.exe'" -ErrorAction Stop)
    foreach ($process in $processes) {
        if (-not $process.ExecutablePath) { throw 'Refusing cleanup without a CVR process path.' }
        $path = [IO.Path]::GetFullPath([string]$process.ExecutablePath)
        $owned = if ($process.Name -ieq 'clash-verge.exe') {
            $path -ieq $expectedGui
        } elseif ($process.Name -ieq 'clash-verge-service.exe') {
            $path -ieq $expectedServiceExe
        } elseif ($process.Name -ieq 'verge-mihomo.exe' -or $process.Name -ieq 'verge-mihomo-alpha.exe') {
            [IO.Path]::GetDirectoryName($path) -in $expectedCoreDirectories
        } else { $false }
        if (-not $owned) { throw 'Refusing cleanup of an unowned CVR process.' }
        Stop-Process -Id ([int]$process.ProcessId) -Force -ErrorAction Stop
    }

    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    do {
        $remaining = @(Get-CimInstance Win32_Process -Filter "Name='clash-verge.exe' OR Name='clash-verge-service.exe' OR Name='verge-mihomo.exe' OR Name='verge-mihomo-alpha.exe'" -ErrorAction Stop)
        $service = Get-Service -Name 'clash_verge_service' -ErrorAction SilentlyContinue
        if (-not $remaining.Count -and -not $service) { break }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($remaining.Count -or $service) { throw 'CVR runner runtime did not stop and delete within the bound.' }
    Assert-NoCvrProcesses
}

function New-CvrIdleTransactionCapture {
    param([Parameter(Mandatory)][string]$InstallDirectory)
    Assert-NoService
    Assert-NoCvrProcesses
    $verifiedDirectory = Get-InstalledCvrDirectory -ExpectedVersion '2.5.8'
    if ([IO.Path]::GetFullPath($verifiedDirectory) -ine [IO.Path]::GetFullPath($InstallDirectory)) {
        throw 'Idle baseline install directory differs from the pinned 2.5.8 directory.'
    }
    $guiSha = [string]$env:CVR_258_GUI_SHA256
    $guiPath = Join-Path $InstallDirectory 'clash-verge.exe'
    if ($guiSha -notmatch '^[0-9a-f]{64}$' -or
        (Get-FileHash -LiteralPath $guiPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $guiSha.ToLowerInvariant()) {
        throw 'Idle baseline CVR 2.5.8 GUI pin mismatch.'
    }

    $legacyState = Get-CvrLegacyState
    $corePair = Get-CvrCorePairPreimage -InstallDirectory $InstallDirectory
    $capture = [PSCustomObject]@{
        installDirectory = [IO.Path]::GetFullPath($InstallDirectory)
        guiSha256 = $guiSha.ToLowerInvariant()
        coreShouldBeRunning = [bool]$false
        corePair = $corePair
        legacyState = $legacyState
        idleObservation = $null
    }
    try {
        $observation = Install-CvrIdleService -Version '2.5.8' -InstallDirectory $InstallDirectory -ProgramFilesEntry $corePair.programFiles -CoreEntry $corePair.service -CoreShouldBeRunning $capture.coreShouldBeRunning
        $null = Assert-CvrIdleBaseline @observation
        Assert-CvrCorePairPreimage -Preimage $corePair -Phase 'captured idle baseline'
        Assert-CvrLegacyState -Expected $legacyState -Phase 'captured idle baseline'
        $capture.idleObservation = $observation
    } catch {
        $captureFailure = $_.Exception.Message
        try {
            Stop-CvrRunnerRuntime
            Restore-CvrCorePairPreimage -Preimage $corePair -HelperVersion '2.5.8'
            Restore-CvrLegacyState -State $legacyState
            Assert-CvrCorePairPreimage -Preimage $corePair -Phase 'idle capture rollback'
            Assert-CvrLegacyState -Expected $legacyState -Phase 'idle capture rollback'
        } catch {
            throw "Idle baseline capture failed and its local rollback did not verify: $($_.Exception.Message)"
        }
        throw "Idle baseline capture failed after restoring its preimages: $captureFailure"
    }
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
        [string]$RecoveryServiceCorePreimagePath
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
            & $nativeScript -Phase $Phase -ExpectedProgramFilesCoreSha256 $ExpectedProgramFilesCoreSha -ExpectedServiceCoreSha256 $ExpectedServiceCoreSha -RecoveryServiceCorePreimagePath $RecoveryServiceCorePreimagePath
        } else {
            & $nativeScript -Phase $Phase -ExpectedProgramFilesCoreSha256 $ExpectedProgramFilesCoreSha -ExpectedServiceCoreSha256 $ExpectedServiceCoreSha
        }
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
$stockHelper = Get-CvrServiceInstallHelper -Version '2.5.8'
if ([IO.Path]::GetFileName([string]$env:CUSTOM_CORE) -cne 'verge-mihomo.exe') { throw 'Fresh source-built core basename does not match the service helper contract.' }
$baselineServiceStageOutput = & $stockHelper.path --install-core $env:CUSTOM_CORE --sha256 $coreSha 2>&1
$baselineServiceStageExit = $LASTEXITCODE
if ($baselineServiceStageExit -ne 0) { throw "Pinned 2.5.8 helper could not stage the source-built baseline service core ($baselineServiceStageExit)." }
Install-CandidateCore -InstallDirectory $install258 -Phase '2.5.8 baseline' -HelperVersion '2.5.8'
Invoke-NativePhase -Phase seed -InstallDirectory $install258 -ExpectedProgramFilesCoreSha $coreSha -ExpectedServiceCoreSha $coreSha
Set-CvrSyntheticSplitCorePreimage -InstallDirectory $install258 -StockCore $stockProgramFilesCore
Stop-CvrRunnerRuntime
Remove-CvrSyntheticLegacyPreimage -Fixture $script:legacyStateFixture
$script:legacyStateFixture = $null

$idleBaselineCapture = New-CvrIdleTransactionCapture -InstallDirectory $install258
$originalCorePair = $idleBaselineCapture.corePair
$transactionFailure = $null
$idleRestoreFailure = $null
try {
    Assert-CvrCorePairPreimage -Preimage $originalCorePair -Phase 'captured original 2.5.8 idle core pair'
    if ($originalCorePair.programFiles.sha256 -cne $stockProgramFilesCore.sha256) { throw 'Captured idle Program Files core differs from the pinned 2.5.8 stock preimage.' }
    if ($originalCorePair.programFiles.sha256 -ceq $coreSha) { throw 'Captured idle Program Files core must remain separate from the source-built service core.' }
    if ($originalCorePair.service.sha256 -cne $coreSha) { throw 'Captured idle service core differs from the fresh source-built bytes.' }
    Stop-CvrRunnerRuntime
    $install2510 = Invoke-CvrInstaller -Version '2.5.10' -Arguments @('/S', '/P', '/UPDATE', '/NS') -PreserveCorePair
    if ($install258 -ne $install2510) { throw 'CVR update changed the registered install directory.' }
    Install-CandidateCore -InstallDirectory $install2510 -Phase '2.5.10 update' -HelperVersion '2.5.10'
    Set-CvrSyntheticSplitCorePreimage -InstallDirectory $install2510 -StockCore $stockProgramFilesCore
    Invoke-CvrOverlayReinstall -InstallDirectory $install2510
    Install-CandidateCore -InstallDirectory $install2510 -Phase '2.5.10 overlay' -HelperVersion '2.5.10'
    Invoke-NativePhase -Phase exercise -InstallDirectory $install2510 -ExpectedProgramFilesCoreSha $coreSha -ExpectedServiceCoreSha $coreSha

    Stop-CvrRunnerRuntime
    $candidateCorePair = Get-CvrCorePairPreimage -InstallDirectory $install2510
    if ($candidateCorePair.programFiles.sha256 -cne $coreSha -or $candidateCorePair.service.sha256 -cne $coreSha) {
        throw 'The idle 2.5.10 candidate pair differs from the fresh source-built SHA256.'
    }
    $candidateIdleObservation = Install-CvrIdleService -Version '2.5.10' -InstallDirectory $install2510 -ProgramFilesEntry $candidateCorePair.programFiles -CoreEntry $candidateCorePair.service -CoreShouldBeRunning $false
    $null = Assert-CvrIdleBaseline @candidateIdleObservation
    Stop-CvrRunnerRuntime

    Install-CandidateCore -InstallDirectory $install2510 -Phase '2.5.10 before recovery' -HelperVersion '2.5.10'
    Set-CvrSyntheticSplitCorePreimage -InstallDirectory $install258 -StockCore $stockProgramFilesCore
    $installRecovered = Invoke-CvrInstaller -Version '2.5.8' -Arguments @('/S', '/P', '/UPDATE', '/NS') -PreserveCorePair
    if ($installRecovered -ne $install258) { throw 'CVR recovery changed the registered install directory.' }
    Restore-CvrCorePairPreimage -Preimage $originalCorePair -HelperVersion '2.5.8'
    Assert-CvrCorePairPreimage -Preimage $originalCorePair -Phase 'original pair after recovery'
    Assert-NoService
    Assert-NoCvrProcesses
    Invoke-NativePhase -Phase recovery -InstallDirectory $installRecovered -ExpectedProgramFilesCoreSha $originalCorePair.programFiles.sha256 -ExpectedServiceCoreSha $originalCorePair.service.sha256 -RecoveryServiceCorePreimagePath $originalCorePair.service.backup
    Assert-CvrCorePairPreimage -Preimage $originalCorePair -Phase 'original pair after native recovery'
} catch {
    $transactionFailure = $_.Exception.Message
    Write-Host "Candidate update/recovery transaction failed: $transactionFailure" -ForegroundColor Red
} finally {
    try {
        Restore-CvrIdleTransaction -Capture $idleBaselineCapture | Out-Null
    } catch {
        $idleRestoreFailure = $_.Exception.Message
        Write-Host "Captured idle baseline restore failed: $idleRestoreFailure" -ForegroundColor Red
    }
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
    '- Captured an intentionally idle pinned 2.5.8 baseline after seed, including separate Program Files/service core bytes and ACLs, GUI pin, legacy state, Running service identity, no GUI/core process, and no owned controller listener.',
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
