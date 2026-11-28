# Shared, pin-checked runtime operations used by the packaged idle-target transaction.

function Initialize-CvrIdleTargetRuntime {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedCandidateGuiSha256,
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedCandidateServiceExeSha256,
        [AllowEmptyCollection()][Collections.Generic.List[string]]$NativeFailures,
        [AllowEmptyCollection()][Collections.Generic.List[object]]$NativeIntervals,
        [AllowEmptyCollection()][Collections.Generic.List[object]]$PhaseBoundaries
    )
    $capture = $Context.Capture
    if (-not $capture -or -not $capture.installDirectory -or -not $capture.pinnedFiles -or
        -not $Context.ExpectedPins -or -not $Context.StageRoot) {
        throw 'Verified idle target runtime context is incomplete.'
    }
    $installDirectory = [IO.Path]::GetFullPath([string]$capture.installDirectory).TrimEnd([char]92)
    $allowedInstallDirs = @(
        (Join-Path $env:ProgramFiles 'Clash Verge'),
        (Join-Path $env:LOCALAPPDATA 'Clash Verge')
    ) | ForEach-Object { [IO.Path]::GetFullPath($_).TrimEnd([char]92) }
    if ($allowedInstallDirs -notcontains $installDirectory) { throw 'Captured CVR install directory is outside the stock install allowlist.' }
    $localRoot = [IO.Path]::GetFullPath((Join-Path ([IO.Path]::GetFullPath([string]$Context.StageRoot)) 'local'))
    if ([IO.Path]::GetDirectoryName($localRoot) -ine [IO.Path]::GetFullPath([string]$Context.StageRoot)) {
        throw 'Idle target backup root is outside the verified stage.'
    }
    $installerPaths = @{
        '2.5.8' = [string]$capture.pinnedFiles.recoveryInstaller
        '2.5.10' = [string]$capture.pinnedFiles.updateInstaller
    }
    foreach ($version in @('2.5.8','2.5.10')) {
        $path = [string]$installerPaths[$version]
        if (-not $path -or -not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Pinned CVR $version installer is unavailable in the verified stage." }
    }
    foreach ($name in @('gui258','serviceExe258','programFilesCore','serviceCore','candidateCore','recoveryInstaller','recoveryHelper','updateInstaller','updateHelper')) {
        if (-not $Context.ExpectedPins.Contains($name) -or [string]$Context.ExpectedPins[$name] -notmatch '^[0-9a-f]{64}$') {
            throw 'Verified idle target runtime pin set is incomplete.'
        }
        $path = [string]$capture.pinnedFiles[$name]
        if (-not $path -or -not (Test-Path -LiteralPath $path -PathType Leaf)) {
            if ($name -in @('programFilesCore','serviceCore','gui258','serviceExe258')) { continue }
            throw "Pinned candidate input $name is unavailable in the verified stage."
        }
    }
    $script:uninstallRelative = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Clash Verge'
    $script:productRelative = 'SOFTWARE\Clash Verge Rev\Clash Verge'
    $script:allowedInstallDirs = $allowedInstallDirs
    $script:serviceData = Join-Path $env:ProgramData 'clash-verge-service'
    $script:installDirectory = $installDirectory
    $script:installerPaths = $installerPaths
    $script:coreSha = [string]$Context.ExpectedPins.candidateCore
    $script:idleTargetRuntime = [PSCustomObject]@{
        Context = $Context
        CandidateGuiSha256 = $ExpectedCandidateGuiSha256.ToLowerInvariant()
        CandidateServiceExeSha256 = $ExpectedCandidateServiceExeSha256.ToLowerInvariant()
        BackupRoot = $localRoot
    }
    if ($null -eq $NativeFailures) { $NativeFailures = [Collections.Generic.List[string]]::new() }
    if ($null -eq $NativeIntervals) { $NativeIntervals = [Collections.Generic.List[object]]::new() }
    if ($null -eq $PhaseBoundaries) { $PhaseBoundaries = [Collections.Generic.List[object]]::new() }
    $script:nativeFailures = $NativeFailures
    $script:nativeIntervals = $NativeIntervals
    $script:phaseBoundaries = $PhaseBoundaries
    if ($null -eq $script:overlayIntervals) { $script:overlayIntervals = [Collections.Generic.List[object]]::new() }
    $script:legacyStateFixture = $null
    return [bool]$true
}

function Assert-NoCvrProcesses {
    foreach ($name in @('clash-verge', 'clash-verge-service', 'verge-mihomo', 'verge-mihomo-alpha')) {
        if (Get-Process -Name $name -ErrorAction SilentlyContinue) { throw "Unexpected CVR process is running: $name" }
    }
}

function Assert-NoService {
    if (Get-Service -Name 'clash_verge_service' -ErrorAction SilentlyContinue) { throw 'The CVR service is present where an absent service is required.' }
}

function Get-InstalledCvrDirectory {
    param([string]$ExpectedVersion)
    $records = @()
    foreach ($hive in @('HKLM:', 'HKCU:')) {
        $key = Join-Path $hive $script:uninstallRelative
        if (Test-Path -LiteralPath $key) { $records += Get-ItemProperty -LiteralPath $key }
    }
    if ($records.Count -ne 1 -or $records[0].DisplayName -ne 'Clash Verge') { throw "Expected one installed Clash Verge product record after $ExpectedVersion setup." }
    if ([string]$records[0].DisplayVersion -ne $ExpectedVersion) { throw "Expected CVR $ExpectedVersion; got $($records[0].DisplayVersion)." }
    $location = ([string]$records[0].InstallLocation).Trim([char]34)
    if (-not $location) { throw 'CVR installer did not register its install location.' }
    $fullPath = [IO.Path]::GetFullPath($location).TrimEnd([char]92)
    if ($script:allowedInstallDirs -notcontains $fullPath) { throw "Unexpected CVR install location: $fullPath" }
    $guiPath = Join-Path $fullPath 'clash-verge.exe'
    if (-not (Test-Path -LiteralPath $guiPath -PathType Leaf)) { throw 'Installed Clash Verge executable is missing.' }
    $expectedGuiSha = if ($script:idleTargetRuntime) {
        if ($ExpectedVersion -ceq '2.5.8') { [string]$script:idleTargetRuntime.Context.ExpectedPins.gui258 } else { [string]$script:idleTargetRuntime.CandidateGuiSha256 }
    } else {
        switch ($ExpectedVersion) {
            '2.5.8' { [string]$env:CVR_258_GUI_SHA256 }
            '2.5.10' { [string]$env:CVR_2510_GUI_SHA256 }
            default { throw "Unsupported pinned CVR GUI version: $ExpectedVersion." }
        }
    }
    if ($expectedGuiSha -notmatch '^[0-9a-f]{64}$') { throw "Invalid pinned CVR GUI SHA256 for $ExpectedVersion." }
    $installedGuiSha = (Get-FileHash -LiteralPath $guiPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($installedGuiSha -cne $expectedGuiSha.ToLowerInvariant()) { throw "Installed CVR GUI SHA256 mismatch after $ExpectedVersion." }
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
        $installer = $script:installerPaths[$Version]
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
    if ($script:idleTargetRuntime) {
        $pinName = if ($Version -ceq '2.5.8') { 'recoveryHelper' } else { 'updateHelper' }
        $expected = [string]$script:idleTargetRuntime.Context.ExpectedPins[$pinName]
        $path = [string]$script:idleTargetRuntime.Context.Capture.pinnedFiles[$pinName]
        $runtimeBound = $true
    } else {
        $release = @($script:manifest.releases | Where-Object { $_.version -ceq $Version })
        if ($release.Count -ne 1) { throw "Expected one pinned CVR $Version release." }
        $expected = [string]$release[0].serviceInstallHelperSha256
        if ($expected -notmatch '^[0-9a-f]{64}$') { throw "CVR $Version helper pin is missing or malformed." }
        $suffix = if ($Version -eq '2.5.8') { '258' } else { '2510' }
        $path = [Environment]::GetEnvironmentVariable("CVR_$($suffix)_SERVICE_INSTALL_HELPER_PATH")
        $envSha = [Environment]::GetEnvironmentVariable("CVR_$($suffix)_SERVICE_INSTALL_HELPER_SHA256")
        $runtimeBound = $false
    }
    if (-not $path -or [IO.Path]::GetFileName($path) -cne 'clash-verge-service-install.exe' -or -not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "The extracted CVR $Version service-install helper is missing."
    }
    $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -cne $expected -or (-not $runtimeBound -and $envSha -cne $expected)) { throw "Extracted CVR $Version helper does not match its installer-derived pin." }
    return [PSCustomObject]@{ path=$path; sha256=$expected }
}

function Get-CvrCorePairPreimage {
    param([string]$InstallDirectory, [string]$BackupRoot)
    Assert-NoService
    Assert-NoCvrProcesses
    if (-not $BackupRoot) { $BackupRoot = if ($script:idleTargetRuntime) { [string]$script:idleTargetRuntime.BackupRoot } else { [string]$env:RUNNER_TEMP } }
    if (-not $BackupRoot -or -not (Test-Path -LiteralPath $BackupRoot -PathType Container)) { throw 'Protected core preimage backup root is unavailable.' }
    $targets = @(
        [PSCustomObject]@{ role='Program Files core'; backupLabel='program-files'; path=(Join-Path $InstallDirectory 'verge-mihomo.exe') },
        [PSCustomObject]@{ role='service core'; backupLabel='service'; path=(Join-Path $script:serviceData 'cores\verge-mihomo.exe') }
    )
    if ([IO.Path]::GetFullPath($targets[0].path) -ieq [IO.Path]::GetFullPath($targets[1].path)) { throw 'Program Files and service core paths are not separate.' }
    $records = foreach ($target in $targets) {
        if (-not (Test-Path -LiteralPath $target.path -PathType Leaf)) { throw "Missing $($target.role) before NSIS." }
        $path = [IO.Path]::GetFullPath($target.path)
        $sha = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        $acl = Get-Acl -LiteralPath $path
        $backup = Save-CvrCorePreimageBackup -Root $BackupRoot -Label $target.backupLabel -SourcePath $path -ExpectedSha256 $sha
        [PSCustomObject]@{
            role = $target.role
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

    # Validate both backups before the first live core write.
    $null = Get-CvrCorePreimageBackupBytes -Entry $Preimage.programFiles -Role 'Program Files'
    $null = Get-CvrCorePreimageBackupBytes -Entry $Preimage.service -Role 'service'

    $failures = [Collections.Generic.List[string]]::new()
    try {
        Restore-CvrCoreFilePreimage -Entry $Preimage.programFiles -Role 'Program Files'
    } catch {
        $failures.Add([string]$_.Exception.Message)
    }
    $serviceRestoreStage = 'helper lookup'
    $serviceRestoreDiagnostic = ''
    try {
        $entry = $Preimage.service
        $serviceRestoreStage = 'service core preimage backup verification'
        $null = Get-CvrCorePreimageBackupBytes -Entry $entry -Role 'service'
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
        if (-not $serviceRestoreDiagnostic) {
            $failure = [string]$_.Exception.Message
            $serviceRestoreDiagnostic = if ($failure -match '^service core preimage backup validation failed at ') {
                $failure
            } else {
                "$serviceRestoreStage failed"
            }
        }
        $detail = if ($serviceRestoreDiagnostic) { " ($serviceRestoreDiagnostic)" } else { '' }
        $failures.Add("service core preimage restore failed at $serviceRestoreStage$detail")
    }
    if ($failures.Count) { throw "CVR core rollback was incomplete: $($failures -join '; ')." }
    Assert-CvrCorePairPreimage -Preimage $Preimage -Phase 'rollback'
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
        $expectedGuiSha = if ($script:idleTargetRuntime) { [string]$script:idleTargetRuntime.CandidateGuiSha256 } else { [string]$env:CVR_2510_GUI_SHA256 }
        $expectedGuiSha = $expectedGuiSha.ToLowerInvariant()
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
    param(
        [string]$InstallDirectory,
        [string]$Phase,
        [ValidateSet('2.5.8','2.5.10')][string]$HelperVersion,
        [string]$CorePath,
        [string]$ExpectedSha256
    )
    if (-not $CorePath) { $CorePath = $env:CUSTOM_CORE }
    if (-not $ExpectedSha256) { $ExpectedSha256 = $coreSha }
    if ($ExpectedSha256 -notmatch '^[0-9a-f]{64}$' -or
        -not (Test-Path -LiteralPath $CorePath -PathType Leaf) -or
        (Get-FileHash -LiteralPath $CorePath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ExpectedSha256) {
        throw "CVR $Phase candidate core source does not match its pinned SHA."
    }
    $started = [DateTime]::UtcNow
    try {
        $installedCore = Join-Path $InstallDirectory 'verge-mihomo.exe'
        if (-not (Test-Path -LiteralPath $installedCore -PathType Leaf)) { throw "CVR $Phase core path is missing." }
        Copy-Item -LiteralPath $CorePath -Destination $installedCore -Force
        if ((Get-FileHash -LiteralPath $installedCore -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ExpectedSha256) {
            throw "Pinned candidate core was not restored after $Phase."
        }
        $helpers = @(Get-ChildItem -LiteralPath $InstallDirectory -Recurse -File -Filter 'clash-verge-service-install.exe')
        if ($helpers.Count -ne 1) { throw "Expected one service core-staging helper after $Phase; found $($helpers.Count)." }
        $helperPin = Get-CvrServiceInstallHelper -Version $HelperVersion
        if ((Get-FileHash -LiteralPath $helpers[0].FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne $helperPin.sha256) {
            throw "Installed CVR $HelperVersion service helper does not match its extracted installer pin."
        }
        $null = & $helperPin.path --install-core $installedCore --sha256 $ExpectedSha256 2>&1
        $stageExit = $LASTEXITCODE
        if ($stageExit -ne 0) { throw "SHA-pinned core staging failed after $Phase ($stageExit)." }
        $stagedCore = Join-Path $serviceData 'cores\verge-mihomo.exe'
        if (-not (Test-Path -LiteralPath $stagedCore -PathType Leaf) -or
            (Get-FileHash -LiteralPath $stagedCore -Algorithm SHA256).Hash.ToLowerInvariant() -ne $ExpectedSha256) {
            throw "Service helper did not stage the pinned candidate core after $Phase."
        }
    } finally {
        $script:phaseBoundaries.Add([PSCustomObject]@{ phase="stage-core-$Phase"; startUtc=$started; endUtc=[DateTime]::UtcNow })
    }
}

function Get-CvrIdleBaselineObservation {
    param(
        [ValidateSet('2.5.8','2.5.10')][string]$Version,
        [string]$InstallDirectory,
        [object]$CoreShouldBeRunning,
        [string]$ExpectedProgramFilesCoreSha256,
        [string]$ExpectedServiceCoreSha256
    )
    if ($script:idleTargetRuntime) {
        $expectedGuiSha = if ($Version -ceq '2.5.8') { [string]$script:idleTargetRuntime.Context.ExpectedPins.gui258 } else { [string]$script:idleTargetRuntime.CandidateGuiSha256 }
        $expectedServiceExeSha = if ($Version -ceq '2.5.8') { [string]$script:idleTargetRuntime.Context.ExpectedPins.serviceExe258 } else { [string]$script:idleTargetRuntime.CandidateServiceExeSha256 }
    } else {
        $expectedGuiSha = if ($Version -eq '2.5.8') { [string]$env:CVR_258_GUI_SHA256 } else { [string]$env:CVR_2510_GUI_SHA256 }
        $expectedServiceExeSha = if ($Version -eq '2.5.8') { [string]$env:CVR_258_SERVICE_SHA256 } else { [string]$env:CVR_2510_SERVICE_SHA256 }
    }
    if ($expectedGuiSha -notmatch '^[0-9a-f]{64}$' -or $expectedServiceExeSha -notmatch '^[0-9a-f]{64}$') { throw 'Idle baseline GUI or service executable pin is malformed.' }

    $guiPath = [IO.Path]::GetFullPath((Join-Path $InstallDirectory 'clash-verge.exe'))
    $programFilesCore = [IO.Path]::GetFullPath((Join-Path $InstallDirectory 'verge-mihomo.exe'))
    $serviceCore = [IO.Path]::GetFullPath((Join-Path $script:serviceData 'cores\verge-mihomo.exe'))
    $serviceExe = [IO.Path]::GetFullPath((Join-Path $script:serviceData 'bin\clash-verge-service.exe'))
    if (-not (Test-Path -LiteralPath $guiPath -PathType Leaf) -or
        (Get-FileHash -LiteralPath $guiPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expectedGuiSha.ToLowerInvariant()) {
        throw 'Idle baseline GUI SHA256 mismatch.'
    }
    if (-not (Test-Path -LiteralPath $programFilesCore -PathType Leaf) -or -not (Test-Path -LiteralPath $serviceCore -PathType Leaf)) { throw 'Idle baseline core path is missing.' }

    $serviceRecord = Get-CimInstance Win32_Service -Filter "Name='clash_verge_service'" -ErrorAction Stop
    $serviceStatus = if ($serviceRecord) { [string]$serviceRecord.State } else { 'Missing' }
    $servicePid = if ($serviceRecord) { [int]$serviceRecord.ProcessId } else { 0 }
    if ($serviceRecord -and ($serviceStatus -cne 'Running' -or $servicePid -le 0)) { throw 'Idle baseline service process identity is unavailable.' }
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
            if (-not $serviceRecord -or [int]$process.ProcessId -ne $servicePid -or $processPath -ine $serviceExe) { throw 'Idle baseline found an unowned service process.' }
        } elseif ($process.Name -ieq 'verge-mihomo.exe' -or $process.Name -ieq 'verge-mihomo-alpha.exe') {
            $processDirectory = [IO.Path]::GetDirectoryName($processPath)
            if ($processDirectory -ine $programFilesCoreDirectory -and $processDirectory -ine $serviceCoreDirectory) { throw 'Idle baseline found an unowned core process.' }
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
