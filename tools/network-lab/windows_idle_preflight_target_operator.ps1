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

function Assert-CvrIdleCandidateTrafficVerification {
    param(
        [Parameter(Mandatory)][object]$Verification,
        [Parameter(Mandatory)][object]$Request,
        [Parameter(Mandatory)][DateTime]$StartedUtc,
        [Parameter(Mandatory)][DateTime]$CompletedUtc
    )
    if ($StartedUtc.Kind -ne [DateTimeKind]::Utc -or $CompletedUtc.Kind -ne [DateTimeKind]::Utc -or
        $CompletedUtc -lt $StartedUtc) { throw 'Candidate traffic verification interval is invalid.' }
    if ([string]$Request.challenge -notmatch '^[0-9a-f]{32}$' -or
        [string]$Request.candidateCoreSha256 -notmatch '^[0-9a-f]{64}$' -or
        [string]$Request.candidateGuiSha256 -notmatch '^[0-9a-f]{64}$' -or
        [string]$Request.candidateServiceExeSha256 -notmatch '^[0-9a-f]{64}$') {
        throw 'Candidate traffic request identity is incomplete.'
    }
    $schema = $Verification.PSObject.Properties['schemaVersion']
    $status = $Verification.PSObject.Properties['status']
    $candidateGui = $Verification.PSObject.Properties['candidateGuiSha256']
    $candidateServiceExe = $Verification.PSObject.Properties['candidateServiceExeSha256']
    if (-not $schema -or ($schema.Value -isnot [int] -and $schema.Value -isnot [long]) -or
        [long]$schema.Value -ne 1 -or -not $status -or [string]$status.Value -cne 'PASS' -or
        [string]$Verification.challenge -cne [string]$Request.challenge -or
        [string]$Verification.candidateCoreSha256 -cne [string]$Request.candidateCoreSha256 -or
        -not $candidateGui -or [string]$candidateGui.Value -cne [string]$Request.candidateGuiSha256 -or
        -not $candidateServiceExe -or [string]$candidateServiceExe.Value -cne [string]$Request.candidateServiceExeSha256) {
        throw 'Candidate traffic verification receipt is missing or does not bind to this candidate.'
    }
    $required = @($Request.requiredProbes)
    if (-not $required.Count -or @($required | Where-Object { $_ -cnotin @('dns','http','https','udp') }).Count) {
        throw 'Candidate traffic request contains a noncanonical probe name.'
    }
    $probes = @($Verification.probes)
    if ($required.Count -lt 1 -or $probes.Count -ne $required.Count) {
        throw 'Candidate traffic verification did not cover every approved probe.'
    }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $processIds = [Collections.Generic.List[int]]::new()
    foreach ($probe in $probes) {
        $protocolProperty = $probe.PSObject.Properties['protocol']
        $passedProperty = $probe.PSObject.Properties['passed']
        $timeProperty = $probe.PSObject.Properties['observedAtUtcMs']
        $pidProperty = $probe.PSObject.Properties['processId']
        $hashProperty = $probe.PSObject.Properties['coreSha256']
        $observedAtUtc = $null
        if ($timeProperty -and ($timeProperty.Value -is [int] -or $timeProperty.Value -is [long]) -and [long]$timeProperty.Value -gt 0) {
            try { $observedAtUtc = [DateTimeOffset]::FromUnixTimeMilliseconds([long]$timeProperty.Value).UtcDateTime } catch {
                throw 'Candidate traffic probe observation time is invalid.'
            }
        }
        if (-not $protocolProperty -or $protocolProperty.Value -isnot [string] -or
            $required -cnotcontains [string]$protocolProperty.Value -or
            -not $seen.Add([string]$protocolProperty.Value) -or
            -not $passedProperty -or $passedProperty.Value -isnot [bool] -or -not $passedProperty.Value -or
            -not $observedAtUtc -or $observedAtUtc -lt $StartedUtc -or $observedAtUtc -gt $CompletedUtc -or
            -not $pidProperty -or ($pidProperty.Value -isnot [int] -and $pidProperty.Value -isnot [long]) -or [long]$pidProperty.Value -le 0 -or
            -not $hashProperty -or [string]$hashProperty.Value -cne [string]$Request.candidateCoreSha256) {
            throw 'Candidate traffic probe evidence is incomplete or does not match the candidate.'
        }
        if ($processIds.Count -and $processIds[0] -ne [int]$pidProperty.Value) {
            throw 'Candidate traffic probes were not served by one stable candidate core process.'
        }
        $processIds.Add([int]$pidProperty.Value)
    }
    foreach ($protocol in $required) {
        if (-not $seen.Contains([string]$protocol)) { throw 'Candidate traffic verification omitted an approved probe.' }
    }
    return [PSCustomObject]@{
        status = 'PASS'
        protocols = [string[]]$required
        processIds = [int[]]$processIds.ToArray()
        candidateCoreSha256 = [string]$Request.candidateCoreSha256
        candidateGuiSha256 = [string]$Request.candidateGuiSha256
        candidateServiceExeSha256 = [string]$Request.candidateServiceExeSha256
        verifiedAtUtc = $CompletedUtc
    }
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
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedCandidateGuiSha256,
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedCandidateServiceExeSha256,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][ValidateSet('dns','http','https','udp')][string[]]$RequiredCandidateProbes,
        [Parameter(Mandatory)][scriptblock]$CandidateTrafficScript,
        [Parameter(Mandatory)][scriptblock]$RecoveryVerificationScript,
        [AllowEmptyCollection()][Collections.Generic.List[string]]$NativeFailures,
        [AllowEmptyCollection()][Collections.Generic.List[object]]$NativeIntervals,
        [AllowEmptyCollection()][Collections.Generic.List[object]]$PhaseBoundaries
    )
    if (@($RequiredCandidateProbes | Where-Object { $_ -cnotin @('dns','http','https','udp') }).Count -or
        @($RequiredCandidateProbes | Select-Object -Unique).Count -ne $RequiredCandidateProbes.Count) {
        throw 'Approved candidate probe names must be canonical and unique.'
    }
    if ($null -eq $NativeFailures) { $NativeFailures = [Collections.Generic.List[string]]::new() }
    if ($null -eq $NativeIntervals) { $NativeIntervals = [Collections.Generic.List[object]]::new() }
    if ($null -eq $PhaseBoundaries) { $PhaseBoundaries = [Collections.Generic.List[object]]::new() }

    $stageRoot = [IO.Path]::GetFullPath($ExpectedStageRoot)
    $binding = Get-CvrIdlePackageStageBinding -StageRoot $stageRoot -ExpectedStageRoot $stageRoot -ExpectedPackageManifestSha256 $ExpectedPackageManifestSha256
    try {
        if ($binding.SourceManifestSha256 -ine $ExpectedPackageManifestSha256) { throw 'Verified target operator stage binding changed.' }
        $manifestPath = Join-Path $stageRoot 'source-manifest.json'
        $manifest = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($manifestPath, [Text.UTF8Encoding]::new($false, $true))) -ErrorAction Stop
        foreach ($name in @(
            'windows_core_preimage_paths.ps1',
            'windows_idle_baseline_guard.ps1',
            'windows_legacy_state_transaction.ps1',
            'windows_idle_transaction.ps1',
            'windows_idle_capture_operator.ps1',
            'windows_idle_preflight_package_writer.ps1',
            'windows_idle_preflight.ps1',
            'windows_idle_target_runtime.ps1'
        )) {
            $relative = 'tools/network-lab/' + $name
            if (@($manifest.files | Where-Object { [string]$_.path -ceq $relative }).Count -ne 1) {
                throw 'Verified target operator dependency is absent or duplicated in the source manifest.'
            }
            $path = Join-Path $stageRoot ('tools\network-lab\' + $name)
            $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
            if ($item.PSIsContainer -or (([int]$item.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0)) {
                throw 'Verified target operator dependency is not a regular stage file.'
            }
            . $path
        }

    $runtimeLists = [PSCustomObject]@{
        NativeFailures = $NativeFailures
        NativeIntervals = $NativeIntervals
        PhaseBoundaries = $PhaseBoundaries
    }
    $expectedPins = [ordered]@{}
    foreach ($pinName in $ExpectedPins.Keys) { $expectedPins[$pinName] = [string]$ExpectedPins[$pinName] }
    $candidateGuiSha = $ExpectedCandidateGuiSha256.ToLowerInvariant()
    $candidateServiceExeSha = $ExpectedCandidateServiceExeSha256.ToLowerInvariant()
    $refreshPins = $expectedPins
    $candidateTrafficScript = $CandidateTrafficScript
    $recoveryVerificationScript = $RecoveryVerificationScript
    $requiredCandidateProbes = [string[]]$RequiredCandidateProbes
    $trafficSummary = [PSCustomObject]@{
        value = [PSCustomObject]@{ status='NOT_RUN'; protocols=@(); processIds=@(); candidateCoreSha256=$null; candidateGuiSha256=$null; candidateServiceExeSha256=$null; verifiedAtUtc=$null }
    }

    $targetTransactionArguments = @{
        CaptureReceiptPath = $CaptureReceiptPath
        PlanPath = $PlanPath
        PreflightReceiptPath = $PreflightReceiptPath
        ExpectedPlanSha256 = $ExpectedPlanSha256
        ExpectedStageRoot = $stageRoot
        ExpectedPackageManifestSha256 = $ExpectedPackageManifestSha256
        ExpectedTargetIdentity = $ExpectedTargetIdentity
        ExpectedPins = $expectedPins
        RefreshObservationScript = {
            param($capture)
            Get-CvrIdleOperatorFreshObservation -Capture $capture -ExpectedPins $refreshPins
        }.GetNewClosure()
        ActionScript = {
            param($context)
            $null = Initialize-CvrIdleTargetRuntime -Context $context -ExpectedCandidateGuiSha256 $candidateGuiSha -ExpectedCandidateServiceExeSha256 $candidateServiceExeSha -NativeFailures $runtimeLists.NativeFailures -NativeIntervals $runtimeLists.NativeIntervals -PhaseBoundaries $runtimeLists.PhaseBoundaries
            $capture = $context.Capture
            $installDirectory = [IO.Path]::GetFullPath([string]$capture.installDirectory)
            $candidateCoreSha = [string]$context.ExpectedPins.candidateCore
            if ($capture.coreShouldBeRunning -isnot [bool] -or $capture.coreShouldBeRunning) { throw 'Captured idle intent is not strict false.' }
            $null = Assert-CvrCorePairPreimage -Preimage $capture.corePair -Phase 'before 2.5.10 action'
            if ([string]$capture.corePair.programFiles.sha256 -cne [string]$context.ExpectedPins.programFilesCore -or
                [string]$capture.corePair.service.sha256 -cne [string]$context.ExpectedPins.serviceCore) {
                throw 'Captured 2.5.8 Program Files or service core SHA does not match its independent preimage pin.'
            }
            $sourceCore = [string]$capture.pinnedFiles.candidateCore
            if ((Get-FileHash -LiteralPath $sourceCore -Algorithm SHA256).Hash.ToLowerInvariant() -cne $candidateCoreSha) {
                throw 'Staged candidate core changed after packaged Capture/Preflight.'
            }
            $null = Stop-CvrRunnerRuntime
            $install2510 = Invoke-CvrInstaller -Version '2.5.10' -Arguments @('/S','/P','/UPDATE','/NS') -PreserveCorePair
            if ([IO.Path]::GetFullPath($install2510) -ine $installDirectory) { throw 'CVR 2.5.10 update changed the captured install directory.' }
            $null = Install-CandidateCore -InstallDirectory $install2510 -Phase '2.5.10 update' -HelperVersion '2.5.10' -CorePath $sourceCore -ExpectedSha256 $candidateCoreSha
            $null = Invoke-CvrOverlayReinstall -InstallDirectory $install2510
            $null = Install-CandidateCore -InstallDirectory $install2510 -Phase '2.5.10 overlay' -HelperVersion '2.5.10' -CorePath $sourceCore -ExpectedSha256 $candidateCoreSha

            $trafficChallenge = [Guid]::NewGuid().ToString('N')
            $trafficRequest = [PSCustomObject]@{
                challenge = $trafficChallenge
                installDirectory = $install2510
                candidateCoreSha256 = $candidateCoreSha
                candidateGuiSha256 = $candidateGuiSha
                candidateServiceExeSha256 = $candidateServiceExeSha
                programFilesCorePath = [IO.Path]::GetFullPath((Join-Path $install2510 'verge-mihomo.exe'))
                serviceCorePath = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'clash-verge-service\cores\verge-mihomo.exe'))
                requiredProbes = $requiredCandidateProbes
            }
            $callbackRequest = [PSCustomObject]@{
                challenge = [string]$trafficRequest.challenge
                installDirectory = [string]$trafficRequest.installDirectory
                candidateCoreSha256 = [string]$trafficRequest.candidateCoreSha256
                candidateGuiSha256 = [string]$trafficRequest.candidateGuiSha256
                candidateServiceExeSha256 = [string]$trafficRequest.candidateServiceExeSha256
                programFilesCorePath = [string]$trafficRequest.programFilesCorePath
                serviceCorePath = [string]$trafficRequest.serviceCorePath
                requiredProbes = [string[]]@($trafficRequest.requiredProbes)
            }
            $trafficStartedUtc = [DateTime]::UtcNow
            $trafficVerification = $null
            try { $trafficVerification = & $candidateTrafficScript $callbackRequest }
            finally { $trafficCompletedUtc = [DateTime]::UtcNow }
            return [PSCustomObject]@{
                version = '2.5.10'
                sourceManifestSha256 = [string]$context.SourceManifestSha256
                candidateCoreSha256 = $candidateCoreSha
                trafficChallenge = $trafficChallenge
                trafficRequest = $trafficRequest
                trafficVerification = $trafficVerification
                trafficStartedUtc = $trafficStartedUtc
                trafficCompletedUtc = $trafficCompletedUtc
            }
        }.GetNewClosure()
        CandidateCheckScript = {
            param($context,$actionResult)
            $null = Initialize-CvrIdleTargetRuntime -Context $context -ExpectedCandidateGuiSha256 $candidateGuiSha -ExpectedCandidateServiceExeSha256 $candidateServiceExeSha -NativeFailures $runtimeLists.NativeFailures -NativeIntervals $runtimeLists.NativeIntervals -PhaseBoundaries $runtimeLists.PhaseBoundaries
            $null = Assert-CvrIdlePackagedCandidateIdentity -Context $context -ActionResult $actionResult
            $trafficSummary.value = Assert-CvrIdleCandidateTrafficVerification -Verification $actionResult.trafficVerification -Request $actionResult.trafficRequest -StartedUtc $actionResult.trafficStartedUtc -CompletedUtc $actionResult.trafficCompletedUtc
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
            $candidateCorePair = Get-CvrCorePairPreimage -InstallDirectory $installDirectory -BackupRoot (Join-Path $context.StageRoot 'local')
            if ($candidateCorePair.programFiles.sha256 -cne $candidateCoreSha -or $candidateCorePair.service.sha256 -cne $candidateCoreSha) {
                throw 'Candidate 2.5.10 core pair did not retain both separately verified candidate SHA values.'
            }
            $candidateIdleObservation = Install-CvrIdleService -Version '2.5.10' -InstallDirectory $installDirectory -ProgramFilesEntry $candidateCorePair.programFiles -CoreEntry $candidateCorePair.service -CoreShouldBeRunning $false
            $null = Assert-CvrIdleBaseline @candidateIdleObservation
            $null = Stop-CvrRunnerRuntime
            return [bool]$true
        }.GetNewClosure()
        RestoreScript = {
            param($context,$actionResult)
            $null = Initialize-CvrIdleTargetRuntime -Context $context -ExpectedCandidateGuiSha256 $candidateGuiSha -ExpectedCandidateServiceExeSha256 $candidateServiceExeSha -NativeFailures $runtimeLists.NativeFailures -NativeIntervals $runtimeLists.NativeIntervals -PhaseBoundaries $runtimeLists.PhaseBoundaries
            $capture = $context.Capture
            $localRoot = Join-Path ([IO.Path]::GetFullPath([string]$context.StageRoot)) 'local'
            $installDirectory = [IO.Path]::GetFullPath([string]$capture.installDirectory)
            $expectedServiceExecutableDirectory = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'clash-verge-service\bin'))
            $restoreErrors = [Collections.Generic.List[string]]::new()
            $restoreState = [PSCustomObject]@{ recoveryVerificationErrorType=$null }
            $stopScript = { Stop-CvrRunnerRuntime }.GetNewClosure()

            $installRestore = {
                try {
                    $installRecovered = Invoke-CvrInstaller -Version '2.5.8' -Arguments @('/S','/P','/UPDATE','/NS') -PreserveCorePair
                    if ([IO.Path]::GetFullPath($installRecovered) -ine $installDirectory) { throw 'install-directory' }
                } catch { $restoreErrors.Add('installer:' + $_.Exception.GetBaseException().GetType().Name) }
            }.GetNewClosure()
            $null = Invoke-CvrIdleStoppedMutation -StopScript $stopScript -MutationScript $installRestore

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
                        $recoveryRequest = [PSCustomObject]@{
                            installDirectory = [string]$installDirectory
                            expectedProgramFilesCoreSha256 = [string]$capture.corePair.programFiles.sha256
                            expectedServiceCoreSha256 = [string]$capture.corePair.service.sha256
                            recoveryServiceCorePreimagePath = [string]$capture.corePair.service.backup
                        }
                        $recoveryVerified = & $recoveryVerificationScript $recoveryRequest
                        if ($recoveryVerified -isnot [bool] -or -not $recoveryVerified) { throw 'Recovery acceptance callback did not pass.' }
                    } catch { $restoreState.recoveryVerificationErrorType = $_.Exception.GetBaseException().GetType().Name }
                } else {
                    $restoreState.recoveryVerificationErrorType = 'PreimageRestoreIncomplete'
                }
            }.GetNewClosure()
            $null = Invoke-CvrIdleStoppedMutation -StopScript $stopScript -MutationScript $preimageRestore

            $finalRestore = {
                try {
                    $null = Restore-CvrIdleFilePreimage -Entry $capture.rollbackState.gui -Role 'gui' -ExpectedPath ([string]$capture.pinnedFiles.gui258) -ExpectedLocalRoot $localRoot -ExpectedDirectory $installDirectory -ExpectedSha256 ([string]$context.ExpectedPins.gui258)
                } catch { $restoreErrors.Add('gui-final:' + $_.Exception.GetBaseException().GetType().Name) }
                try {
                    $null = Restore-CvrIdleFilePreimage -Entry $capture.rollbackState.serviceExe -Role 'service-exe' -ExpectedPath ([string]$capture.pinnedFiles.serviceExe258) -ExpectedLocalRoot $localRoot -ExpectedDirectory $expectedServiceExecutableDirectory -ExpectedSha256 ([string]$context.ExpectedPins.serviceExe258)
                } catch { $restoreErrors.Add('service-exe-final:' + $_.Exception.GetBaseException().GetType().Name) }
                try { $null = Restore-CvrCorePairPreimage -Preimage $capture.corePair -HelperVersion '2.5.8' } catch { $restoreErrors.Add('core-pair-final:' + $_.Exception.GetBaseException().GetType().Name) }
                try { $null = Restore-CvrLegacyState -State $capture.legacyState } catch { $restoreErrors.Add('legacy-final:' + $_.Exception.GetBaseException().GetType().Name) }
                $serviceRestoreReady = $true
                try {
                    $verifiedDirectory = Get-InstalledCvrDirectory -ExpectedVersion '2.5.8'
                    if ([IO.Path]::GetFullPath($verifiedDirectory) -ine $installDirectory) { throw 'install-directory' }
                    $null = Assert-CvrCorePairPreimage -Preimage $capture.corePair -Phase 'before restored idle service'
                    $null = Assert-CvrLegacyState -Expected $capture.legacyState -Phase 'before restored idle service'
                    $null = Assert-CvrIdleRollbackState -Capture $capture -ExpectedPins $context.ExpectedPins -ExpectedLocalRoot $localRoot
                } catch {
                    $serviceRestoreReady = $false
                    $restoreErrors.Add('idle-service-precondition:' + $_.Exception.GetBaseException().GetType().Name)
                }
                if ($serviceRestoreReady) {
                    try {
                        $null = Install-CvrIdleService -Version '2.5.8' -InstallDirectory $installDirectory -ProgramFilesEntry $capture.corePair.programFiles -CoreEntry $capture.corePair.service -CoreShouldBeRunning $false
                    } catch { $restoreErrors.Add('idle-service-final:' + $_.Exception.GetBaseException().GetType().Name) }
                }

                try { $null = Assert-CvrCorePairPreimage -Preimage $capture.corePair -Phase 'final idle rollback' } catch { $restoreErrors.Add('core-pair-verify:' + $_.Exception.GetBaseException().GetType().Name) }
                try { $null = Assert-CvrLegacyState -Expected $capture.legacyState -Phase 'final idle rollback' } catch { $restoreErrors.Add('legacy-verify:' + $_.Exception.GetBaseException().GetType().Name) }
                try { $null = Assert-CvrIdleRollbackState -Capture $capture -ExpectedPins $context.ExpectedPins -ExpectedLocalRoot $localRoot } catch { $restoreErrors.Add('file-preimage-verify:' + $_.Exception.GetBaseException().GetType().Name) }
                $restored = $null
                try {
                    $restored = Get-CvrIdleBaselineObservation -Version '2.5.8' -InstallDirectory $installDirectory -CoreShouldBeRunning $false -ExpectedProgramFilesCoreSha256 $capture.corePair.programFiles.sha256 -ExpectedServiceCoreSha256 $capture.corePair.service.sha256
                    $null = Assert-CvrIdleBaseline @restored
                } catch { $restoreErrors.Add('idle-baseline-verify:' + $_.Exception.GetBaseException().GetType().Name) }
                if ($restoreState.recoveryVerificationErrorType) { $restoreErrors.Add('recovery-verification:' + $restoreState.recoveryVerificationErrorType) }
                if ($restoreErrors.Count) { throw ('RestoreVerificationFailure:' + ($restoreErrors -join ',')) }
                return $restored
            }.GetNewClosure()
            return Invoke-CvrIdleStoppedMutation -StopScript $stopScript -MutationScript $finalRestore
        }.GetNewClosure()
        VerifyScript = {
            param($context,$restored,$actionResult)
            return Assert-CvrIdlePackagedRestoreState -Context $context -Restored $restored
        }.GetNewClosure()
    }
    $targetTransactionResult = Invoke-CvrIdlePreflightTargetTransaction @targetTransactionArguments
    return [PSCustomObject]@{
        status = [string]$targetTransactionResult.status
        actionErrorType = $targetTransactionResult.actionErrorType
        restoreErrorType = $targetTransactionResult.restoreErrorType
        candidateTrafficVerification = $trafficSummary.value
    }
    } finally {
        foreach ($handle in @($binding.OpenFiles)) { if ($handle) { $handle.Dispose() } }
    }
}
