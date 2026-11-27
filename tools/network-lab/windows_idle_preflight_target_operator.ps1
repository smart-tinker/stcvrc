$ErrorActionPreference = 'Stop'

function Assert-CvrIdlePackagedCandidateIdentity {
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)]$ActionResult)
    if ([string]$ActionResult.version -cne '2.5.10' -or
        [string]$ActionResult.sourceManifestSha256 -ine [string]$Context.SourceManifestSha256 -or
        [string]$ActionResult.candidateCoreSha256 -ine [string]$Context.ExpectedPins.candidateCore) {
        throw 'Packaged candidate identity does not match the verified stage.'
    }
    return [bool]$true
}

function Assert-CvrIdlePackagedRestoreState {
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)]$Restored)
    $localRoot = Join-Path ([IO.Path]::GetFullPath([string]$Context.StageRoot)) 'local'
    if ($Restored.CoreShouldBeRunning -isnot [bool] -or $Restored.CoreShouldBeRunning) {
        throw 'Restored idle intent differs from the captured strict false baseline.'
    }
    $null = Assert-CvrIdleBaseline @Restored
    Assert-CvrCorePairPreimage -Preimage $Context.Capture.corePair -Phase 'shared idle transaction verification'
    Assert-CvrLegacyState -Expected $Context.Capture.legacyState -Phase 'shared idle transaction verification'
    $null = Assert-CvrIdleRollbackState -Capture $Context.Capture -ExpectedPins $Context.ExpectedPins -ExpectedLocalRoot $localRoot
    return [bool]$true
}

function Invoke-CvrIdleStoppedMutation {
    param(
        [Parameter(Mandatory)][scriptblock]$StopScript,
        [Parameter(Mandatory)][scriptblock]$MutationScript
    )
    try { $null = & $StopScript } catch {
        throw [System.InvalidOperationException]::new('Rollback stopped-state proof failed.')
    }
    & $MutationScript
}

function Invoke-CvrIdlePackagedNativePhase {
    param(
        [Parameter(Mandatory)][ValidateSet('seed','exercise','recovery')][string]$Phase,
        [Parameter(Mandatory)][string]$StageRoot,
        [Parameter(Mandatory)][string]$InstallDirectory,
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedProgramFilesCoreSha,
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedServiceCoreSha,
        [string]$RecoveryServiceCorePreimagePath,
        [Parameter(Mandatory)][System.Collections.Generic.List[string]]$NativeFailures,
        [Parameter(Mandatory)][System.Collections.Generic.List[object]]$NativeIntervals,
        [Parameter(Mandatory)][System.Collections.Generic.List[object]]$PhaseBoundaries
    )
    $installedCore = Join-Path $InstallDirectory 'verge-mihomo.exe'
    $stagedCore = Join-Path $env:ProgramData 'clash-verge-service\cores\verge-mihomo.exe'
    foreach ($target in @(
        [PSCustomObject]@{ path=$installedCore; sha256=$ExpectedProgramFilesCoreSha },
        [PSCustomObject]@{ path=$stagedCore; sha256=$ExpectedServiceCoreSha }
    )) {
        if (-not (Test-Path -LiteralPath $target.path -PathType Leaf) -or
            (Get-FileHash -LiteralPath $target.path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $target.sha256) {
            throw "Refusing native $Phase phase before its separate Program Files/service core SHA is verified."
        }
    }
    $nativeScript = Join-Path ([IO.Path]::GetFullPath($StageRoot)) 'tools\network-lab\windows_native_acceptance.ps1'
    if (-not (Test-Path -LiteralPath $nativeScript -PathType Leaf)) { throw 'The packaged native acceptance script is missing.' }
    $started = [DateTime]::UtcNow
    try {
        if ($Phase -eq 'recovery') {
            & $nativeScript -Phase $Phase -ExpectedProgramFilesCoreSha256 $ExpectedProgramFilesCoreSha -ExpectedServiceCoreSha256 $ExpectedServiceCoreSha -RecoveryServiceCorePreimagePath $RecoveryServiceCorePreimagePath
        } else {
            & $nativeScript -Phase $Phase -ExpectedProgramFilesCoreSha256 $ExpectedProgramFilesCoreSha -ExpectedServiceCoreSha256 $ExpectedServiceCoreSha
        }
    } catch {
        $failure = $_.Exception.Message
        $NativeFailures.Add("$($Phase): $failure")
        Write-Host "Native $Phase phase failed; continuing the bounded recovery sequence: $failure" -ForegroundColor Red
    } finally {
        $ended = [DateTime]::UtcNow
        $NativeIntervals.Add([PSCustomObject]@{ phase=$Phase; startUtc=$started; endUtc=$ended })
        $PhaseBoundaries.Add([PSCustomObject]@{ phase="native-$Phase"; startUtc=$started; endUtc=$ended })
    }
}

function Invoke-CvrIdlePreflightTargetAcceptance {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CaptureReceiptPath,
        [Parameter(Mandatory)][string]$PlanPath,
        [Parameter(Mandatory)][string]$PreflightReceiptPath,
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedPlanSha256,
        [Parameter(Mandatory)][string]$ExpectedStageRoot,
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedPackageManifestSha256,
        [Parameter(Mandatory)][string]$ExpectedTargetIdentity,
        [Parameter(Mandatory)][System.Collections.IDictionary]$ExpectedPins,
        [Parameter(Mandatory)][System.Collections.Generic.List[string]]$NativeFailures,
        [Parameter(Mandatory)][System.Collections.Generic.List[object]]$NativeIntervals,
        [Parameter(Mandatory)][System.Collections.Generic.List[object]]$PhaseBoundaries
    )

$targetTransactionArguments = @{
    CaptureReceiptPath = $captureReceiptPath
    PlanPath = $planPath
    PreflightReceiptPath = $preflightReceiptPath
    ExpectedPlanSha256 = [string]$publicCaptureResult.planSha256
    ExpectedStageRoot = $ExpectedStageRoot
    ExpectedPackageManifestSha256 = $ExpectedPackageManifestSha256
    ExpectedTargetIdentity = $ExpectedTargetIdentity
    ExpectedPins = $ExpectedPins
    RefreshObservationScript = {
        param($capture)
        Get-CvrIdleOperatorFreshObservation -Capture $capture -ExpectedPins $capture.expectedPins
    }
    ActionScript = {
        param($context)
        $capture = $context.Capture
        $installDirectory = [IO.Path]::GetFullPath([string]$capture.installDirectory)
        $candidateCoreSha = [string]$context.ExpectedPins.candidateCore
        if ($capture.coreShouldBeRunning -isnot [bool] -or $capture.coreShouldBeRunning) { throw 'Captured idle intent is not strict false.' }
        $null = Assert-CvrCorePairPreimage -Preimage $capture.corePair -Phase 'before 2.5.10 action'
        if ([string]$capture.corePair.programFiles.sha256 -cne [string]$context.ExpectedPins.programFilesCore -or
            [string]$capture.corePair.service.sha256 -cne [string]$context.ExpectedPins.serviceCore -or
            [string]$capture.corePair.programFiles.sha256 -ceq $candidateCoreSha -or
            [string]$capture.corePair.service.sha256 -cne $candidateCoreSha) {
            throw 'Captured 2.5.8 Program Files and service core SHA pins do not match their separate preimages.'
        }
        $sourceCore = [string]$capture.pinnedFiles.candidateCore
        if ((Get-FileHash -LiteralPath $sourceCore -Algorithm SHA256).Hash.ToLowerInvariant() -cne $candidateCoreSha) {
            throw 'Staged candidate core changed after packaged Capture/Preflight.'
        }
        $null = Stop-CvrRunnerRuntime
        $install2510 = Invoke-CvrInstaller -Version '2.5.10' -Arguments @('/S','/P','/UPDATE','/NS') -PreserveCorePair
        if ([IO.Path]::GetFullPath($install2510) -ine $installDirectory) { throw 'CVR 2.5.10 update changed the captured install directory.' }
        $null = Install-CandidateCore -InstallDirectory $install2510 -Phase '2.5.10 update' -HelperVersion '2.5.10' -CorePath $sourceCore -ExpectedSha256 $candidateCoreSha
        $null = Set-CvrSyntheticSplitCorePreimage -InstallDirectory $install2510 -StockCore $capture.corePair.programFiles
        $null = Invoke-CvrOverlayReinstall -InstallDirectory $install2510
        $null = Install-CandidateCore -InstallDirectory $install2510 -Phase '2.5.10 overlay' -HelperVersion '2.5.10' -CorePath $sourceCore -ExpectedSha256 $candidateCoreSha
        $nativeFailureCountBeforeExercise = $NativeFailures.Count
        $null = Invoke-CvrIdlePackagedNativePhase -Phase exercise -StageRoot $ExpectedStageRoot -InstallDirectory $install2510 -ExpectedProgramFilesCoreSha $candidateCoreSha -ExpectedServiceCoreSha $candidateCoreSha -NativeFailures $NativeFailures -NativeIntervals $NativeIntervals -PhaseBoundaries $PhaseBoundaries
        return [PSCustomObject]@{ version='2.5.10'; sourceManifestSha256=[string]$context.SourceManifestSha256; candidateCoreSha256=$candidateCoreSha; nativeFailureCountBeforeExercise=$nativeFailureCountBeforeExercise }
    }
    CandidateCheckScript = {
        param($context,$actionResult)
        $null = Assert-CvrIdlePackagedCandidateIdentity -Context $context -ActionResult $actionResult
        $capture = $context.Capture
        $installDirectory = [IO.Path]::GetFullPath([string]$capture.installDirectory)
        $candidateCoreSha = [string]$context.ExpectedPins.candidateCore
        $programFilesCore = [IO.Path]::GetFullPath((Join-Path $installDirectory 'verge-mihomo.exe'))
        $serviceCore = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'clash-verge-service\cores\verge-mihomo.exe'))
        $null = Stop-CvrRunnerRuntime
        foreach ($entry in @(
            [PSCustomObject]@{ path=$programFilesCore; expected=$candidateCoreSha },
            [PSCustomObject]@{ path=$serviceCore; expected=$candidateCoreSha }
        )) {
            if (-not (Test-Path -LiteralPath $entry.path -PathType Leaf) -or
                (([int](Get-Item -LiteralPath $entry.path -Force -ErrorAction Stop).Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0) -or
                (Get-FileHash -LiteralPath $entry.path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry.expected) {
                throw 'Candidate 2.5.10 Program Files or service core differs from its pinned SHA.'
            }
        }
        if ([IO.Path]::GetFullPath($programFilesCore) -ieq [IO.Path]::GetFullPath($serviceCore)) { throw 'Candidate Program Files and service core paths are not separate.' }
        if ($NativeFailures.Count -gt [int]$actionResult.nativeFailureCountBeforeExercise) { throw 'Candidate native exercise did not pass its acceptance checks.' }
        $candidateCorePair = Get-CvrCorePairPreimage -InstallDirectory $installDirectory
        if ($candidateCorePair.programFiles.sha256 -cne $candidateCoreSha -or $candidateCorePair.service.sha256 -cne $candidateCoreSha) {
            throw 'Candidate 2.5.10 core pair did not retain both separately verified candidate SHA values.'
        }
        $candidateIdleObservation = Install-CvrIdleService -Version '2.5.10' -InstallDirectory $installDirectory -ProgramFilesEntry $candidateCorePair.programFiles -CoreEntry $candidateCorePair.service -CoreShouldBeRunning $false
        $null = Assert-CvrIdleBaseline @candidateIdleObservation
        $null = Stop-CvrRunnerRuntime
        return [bool]$true
    }
    RestoreScript = {
        param($context,$actionResult)
        $capture = $context.Capture
        $localRoot = Join-Path ([IO.Path]::GetFullPath([string]$context.StageRoot)) 'local'
        $installDirectory = [IO.Path]::GetFullPath([string]$capture.installDirectory)
        $expectedServiceExecutableDirectory = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'clash-verge-service\bin'))
        $restoreErrors = [Collections.Generic.List[string]]::new()
        $restoreState = [PSCustomObject]@{ nativeRecoveryErrorType=$null }

        $installRestore = {
            try {
                $installRecovered = Invoke-CvrInstaller -Version '2.5.8' -Arguments @('/S','/P','/UPDATE','/NS') -PreserveCorePair
                if ([IO.Path]::GetFullPath($installRecovered) -ine $installDirectory) { throw 'install-directory' }
            } catch { $restoreErrors.Add('installer:' + $_.Exception.GetBaseException().GetType().Name) }
        }.GetNewClosure()
        $null = Invoke-CvrIdleStoppedMutation -StopScript { Stop-CvrRunnerRuntime } -MutationScript $installRestore

        $preimageRestore = {
            try {
                $null = Restore-CvrIdleFilePreimage -Entry $capture.rollbackState.gui -Role 'gui' -ExpectedPath ([string]$capture.pinnedFiles.gui258) -ExpectedLocalRoot $localRoot -ExpectedDirectory $installDirectory -ExpectedSha256 ([string]$context.ExpectedPins.gui258)
            } catch { $restoreErrors.Add('gui-preimage:' + $_.Exception.GetBaseException().GetType().Name) }
            try {
                $null = Restore-CvrIdleFilePreimage -Entry $capture.rollbackState.serviceExe -Role 'service-exe' -ExpectedPath ([string]$capture.pinnedFiles.serviceExe258) -ExpectedLocalRoot $localRoot -ExpectedDirectory $expectedServiceExecutableDirectory -ExpectedSha256 ([string]$context.ExpectedPins.serviceExe258)
            } catch { $restoreErrors.Add('service-exe-preimage:' + $_.Exception.GetBaseException().GetType().Name) }
            try { $null = Restore-CvrCorePairPreimage -Preimage $capture.corePair -HelperVersion '2.5.8' } catch { $restoreErrors.Add('core-pair-preimage:' + $_.Exception.GetBaseException().GetType().Name) }
            try { $null = Restore-CvrLegacyState -State $capture.legacyState } catch { $restoreErrors.Add('legacy-preimage:' + $_.Exception.GetBaseException().GetType().Name) }

            if ($restoreErrors.Count -eq 0) {
                try {
                    $null = Assert-CvrCorePairPreimage -Preimage $capture.corePair -Phase 'before native 2.5.8 rollback acceptance'
                    $null = Assert-CvrLegacyState -Expected $capture.legacyState -Phase 'before native 2.5.8 rollback acceptance'
                    $null = Assert-CvrIdleRollbackState -Capture $capture -ExpectedPins $context.ExpectedPins -ExpectedLocalRoot $localRoot
                    $null = Assert-NoService
                    $null = Assert-NoCvrProcesses
                    $failureCount = $NativeFailures.Count
                    $null = Invoke-CvrIdlePackagedNativePhase -Phase recovery -StageRoot $ExpectedStageRoot -InstallDirectory $installDirectory -ExpectedProgramFilesCoreSha $capture.corePair.programFiles.sha256 -ExpectedServiceCoreSha $capture.corePair.service.sha256 -RecoveryServiceCorePreimagePath $capture.corePair.service.backup -NativeFailures $NativeFailures -NativeIntervals $NativeIntervals -PhaseBoundaries $PhaseBoundaries
                    if ($NativeFailures.Count -gt $failureCount) { throw 'NativeAcceptanceFailure' }
                } catch { $restoreState.nativeRecoveryErrorType = $_.Exception.GetBaseException().GetType().Name }
            } else {
                $restoreState.nativeRecoveryErrorType = 'PreimageRestoreIncomplete'
            }
        }.GetNewClosure()
        $null = Invoke-CvrIdleStoppedMutation -StopScript { Stop-CvrRunnerRuntime } -MutationScript $preimageRestore

        $finalRestore = {
            try {
                $null = Restore-CvrIdleFilePreimage -Entry $capture.rollbackState.gui -Role 'gui' -ExpectedPath ([string]$capture.pinnedFiles.gui258) -ExpectedLocalRoot $localRoot -ExpectedDirectory $installDirectory -ExpectedSha256 ([string]$context.ExpectedPins.gui258)
            } catch { $restoreErrors.Add('gui-final:' + $_.Exception.GetBaseException().GetType().Name) }
            try {
                $null = Restore-CvrIdleFilePreimage -Entry $capture.rollbackState.serviceExe -Role 'service-exe' -ExpectedPath ([string]$capture.pinnedFiles.serviceExe258) -ExpectedLocalRoot $localRoot -ExpectedDirectory $expectedServiceExecutableDirectory -ExpectedSha256 ([string]$context.ExpectedPins.serviceExe258)
            } catch { $restoreErrors.Add('service-exe-final:' + $_.Exception.GetBaseException().GetType().Name) }
            try { $null = Restore-CvrCorePairPreimage -Preimage $capture.corePair -HelperVersion '2.5.8' } catch { $restoreErrors.Add('core-pair-final:' + $_.Exception.GetBaseException().GetType().Name) }
            try { $null = Restore-CvrLegacyState -State $capture.legacyState } catch { $restoreErrors.Add('legacy-final:' + $_.Exception.GetBaseException().GetType().Name) }
            try {
                $null = Install-CvrIdleService -Version '2.5.8' -InstallDirectory $installDirectory -ProgramFilesEntry $capture.corePair.programFiles -CoreEntry $capture.corePair.service -CoreShouldBeRunning $false
            } catch { $restoreErrors.Add('idle-service-final:' + $_.Exception.GetBaseException().GetType().Name) }

            try { $null = Assert-CvrCorePairPreimage -Preimage $capture.corePair -Phase 'final idle rollback' } catch { $restoreErrors.Add('core-pair-verify:' + $_.Exception.GetBaseException().GetType().Name) }
            try { $null = Assert-CvrLegacyState -Expected $capture.legacyState -Phase 'final idle rollback' } catch { $restoreErrors.Add('legacy-verify:' + $_.Exception.GetBaseException().GetType().Name) }
            try { $null = Assert-CvrIdleRollbackState -Capture $capture -ExpectedPins $context.ExpectedPins -ExpectedLocalRoot $localRoot } catch { $restoreErrors.Add('file-preimage-verify:' + $_.Exception.GetBaseException().GetType().Name) }
            $restored = $null
            try {
                $restored = Get-CvrIdleBaselineObservation -Version '2.5.8' -InstallDirectory $installDirectory -CoreShouldBeRunning $false -ExpectedProgramFilesCoreSha256 $capture.corePair.programFiles.sha256 -ExpectedServiceCoreSha256 $capture.corePair.service.sha256
                $null = Assert-CvrIdleBaseline @restored
            } catch { $restoreErrors.Add('idle-baseline-verify:' + $_.Exception.GetBaseException().GetType().Name) }
            if ($restoreState.nativeRecoveryErrorType) { $restoreErrors.Add('native-2.5.8:' + $restoreState.nativeRecoveryErrorType) }
            if ($restoreErrors.Count) { throw ('RestoreVerificationFailure:' + ($restoreErrors -join ',')) }
            return $restored
        }.GetNewClosure()
        return Invoke-CvrIdleStoppedMutation -StopScript { Stop-CvrRunnerRuntime } -MutationScript $finalRestore
    }
    VerifyScript = {
        param($context,$restored,$actionResult)
        return Assert-CvrIdlePackagedRestoreState -Context $context -Restored $restored
    }
$targetTransactionResult = Invoke-CvrIdlePreflightTargetTransaction @targetTransactionArguments

    return $targetTransactionResult
}
