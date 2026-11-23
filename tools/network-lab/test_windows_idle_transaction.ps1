$ErrorActionPreference = 'Stop'
$modulePath = Join-Path $PSScriptRoot 'windows_idle_transaction.ps1'
if (-not (Test-Path -LiteralPath $modulePath -PathType Leaf)) {
    throw 'Expected behavior RED: shared idle transaction module is missing.'
}
. $modulePath
$corePreimagePathScript = Join-Path $PSScriptRoot 'windows_core_preimage_paths.ps1'
if (-not (Test-Path -LiteralPath $corePreimagePathScript -PathType Leaf)) {
    throw 'Shared core preimage restore helper is missing.'
}
. $corePreimagePathScript
. (Join-Path $PSScriptRoot 'windows_idle_baseline_guard.ps1')

$script:nativeCalls = 0
function Start-Service { $script:nativeCalls++; throw 'unexpected-native-service-call' }
function Stop-Service { $script:nativeCalls++; throw 'unexpected-native-service-call' }
function Restart-Service { $script:nativeCalls++; throw 'unexpected-native-service-call' }
function Set-Service { $script:nativeCalls++; throw 'unexpected-native-service-call' }
function Start-Process { $script:nativeCalls++; throw 'unexpected-native-process-call' }
function Stop-Process { $script:nativeCalls++; throw 'unexpected-native-process-call' }
function Start-ScheduledTask { $script:nativeCalls++; throw 'unexpected-native-task-call' }
function Register-ScheduledTask { $script:nativeCalls++; throw 'unexpected-native-task-call' }
function Set-ScheduledTask { $script:nativeCalls++; throw 'unexpected-native-task-call' }
function Unregister-ScheduledTask { $script:nativeCalls++; throw 'unexpected-native-task-call' }
function Enable-ScheduledTask { $script:nativeCalls++; throw 'unexpected-native-task-call' }
function Disable-ScheduledTask { $script:nativeCalls++; throw 'unexpected-native-task-call' }
function netsh { $script:nativeCalls++; throw 'unexpected-native-network-call' }
$script:targetCaptureOutcomes = [Collections.Generic.List[object]]::new()

function Assert-IdleTransaction([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}
function Assert-IdleTransactionOrder([string[]]$Expected) {
    $actual = @($script:idleTransactionEvents.ToArray())
    if (($actual -join ',') -cne ($Expected -join ',')) {
        throw 'Shared idle transaction callback order did not match.'
    }
}
function New-IdleTransactionCapture($Intent, [int[]]$OwnedGuiProcessIds = @()) {
    [PSCustomObject]@{
        coreShouldBeRunning = $Intent
        idleObservation = @{
            CoreShouldBeRunning = $Intent
            OwnedGuiProcessIds = $OwnedGuiProcessIds
            OwnedCoreProcessIds = [int[]]@()
            ControllerListening = [bool]$false
            OwnedListenerProcessIds = [int[]]@()
            ServiceStatus = 'Running'
            ExpectedProgramFilesCoreSha256 = ('a' * 64)
            ObservedProgramFilesCoreSha256 = ('a' * 64)
            ExpectedServiceCoreSha256 = ('b' * 64)
            ObservedServiceCoreSha256 = ('b' * 64)
        }
    }
}

$script:idleTransactionEvents = [Collections.Generic.List[string]]::new()
$success = Invoke-CvrIdleTransaction -CaptureScript { $script:idleTransactionEvents.Add('capture'); New-IdleTransactionCapture $false } -ActionScript { param($capture) $script:idleTransactionEvents.Add('action'); 'candidate' } -RestoreScript { param($capture) $script:idleTransactionEvents.Add('restore'); 'baseline' } -VerifyScript { param($capture,$restored) $script:idleTransactionEvents.Add('verify'); ($capture.coreShouldBeRunning -ceq $false -and $restored -ceq 'baseline') }
Assert-IdleTransactionOrder @('capture','action','restore','verify')
Assert-IdleTransaction ($success.ActionFailure -eq $null -and $success.RestoreFailure -eq $null) 'Successful transaction reported a failure.'

$script:idleTransactionEvents.Clear()
$idleGuardFailure = $null
try {
    $null = Invoke-CvrIdleTransaction -CaptureScript { $script:idleTransactionEvents.Add('capture'); New-IdleTransactionCapture $false ([int[]]@(501)) } -ActionScript { param($capture) $script:idleTransactionEvents.Add('action') } -RestoreScript { param($capture) $script:idleTransactionEvents.Add('restore') } -VerifyScript { param($capture,$restored) $script:idleTransactionEvents.Add('verify'); $true }
} catch { $idleGuardFailure = $_.Exception.Message }
Assert-IdleTransaction ($idleGuardFailure -ceq 'Idle baseline has owned GUI processes.') 'Invalid idle observation reached the candidate action.'
Assert-IdleTransactionOrder @('capture')

$script:idleTransactionEvents.Clear()
$actionException = $null
try {
    $failure = Invoke-CvrIdleTransaction -CaptureScript { $script:idleTransactionEvents.Add('capture'); New-IdleTransactionCapture $false } -ActionScript { param($capture) $script:idleTransactionEvents.Add('action'); throw 'synthetic-action-failure' } -RestoreScript { param($capture) $script:idleTransactionEvents.Add('restore'); 'baseline' } -VerifyScript { param($capture,$restored) $script:idleTransactionEvents.Add('verify'); $true }
} catch {
    $actionException = $_.Exception.Message
}
if ($actionException -or $script:idleTransactionEvents -notcontains 'restore') {
    throw 'Expected behavior RED: rollback callback was skipped after action failure.'
}
Assert-IdleTransaction ($failure.ActionFailure -ceq 'synthetic-action-failure') 'Action failure was not retained.'
Assert-IdleTransaction ($failure.RestoreFailure -eq $null) 'Successful rollback was reported as failed.'
Assert-IdleTransactionOrder @('capture','action','restore','verify')

$script:idleTransactionEvents.Clear()
$restoreFailure = Invoke-CvrIdleTransaction -CaptureScript { $script:idleTransactionEvents.Add('capture'); New-IdleTransactionCapture $false } -ActionScript { param($capture) $script:idleTransactionEvents.Add('action'); 'candidate' } -RestoreScript { param($capture) $script:idleTransactionEvents.Add('restore'); throw 'synthetic-restore-failure' } -VerifyScript { param($capture,$restored) $script:idleTransactionEvents.Add('verify'); $true }
Assert-IdleTransaction ($restoreFailure.ActionFailure -eq $null) 'Successful action was reported as failed.'
Assert-IdleTransaction ($restoreFailure.RestoreFailure -ceq 'synthetic-restore-failure') 'Restore failure was not retained.'
Assert-IdleTransactionOrder @('capture','action','restore')

$script:idleTransactionEvents.Clear()
$verifyFailure = Invoke-CvrIdleTransaction -CaptureScript { $script:idleTransactionEvents.Add('capture'); New-IdleTransactionCapture $false } -ActionScript { param($capture) $script:idleTransactionEvents.Add('action'); 'candidate' } -RestoreScript { param($capture) $script:idleTransactionEvents.Add('restore'); 'baseline' } -VerifyScript { param($capture,$restored) $script:idleTransactionEvents.Add('verify'); $false }
Assert-IdleTransaction ($verifyFailure.RestoreFailure -ceq 'Idle transaction restore verification did not pass.') 'False restore verification was accepted.'

$script:idleTransactionEvents.Clear()
$intentMutation = Invoke-CvrIdleTransaction -CaptureScript {
    $script:idleTransactionEvents.Add('capture')
    New-IdleTransactionCapture $false
} -ActionScript {
    param($capture)
    $script:idleTransactionEvents.Add('action')
    $capture.coreShouldBeRunning = [bool]$true
    $capture.idleObservation.CoreShouldBeRunning = [bool]$true
    'candidate'
} -RestoreScript {
    param($capture)
    $script:idleTransactionEvents.Add('restore')
    if ($capture.coreShouldBeRunning -isnot [bool] -or $capture.coreShouldBeRunning -or
        $capture.idleObservation.CoreShouldBeRunning -isnot [bool] -or $capture.idleObservation.CoreShouldBeRunning) {
        throw 'rollback did not receive strict false intent'
    }
    'baseline'
} -VerifyScript {
    param($capture, $restored)
    $script:idleTransactionEvents.Add('verify')
    ($capture.coreShouldBeRunning -is [bool] -and -not $capture.coreShouldBeRunning -and
        $capture.idleObservation.CoreShouldBeRunning -is [bool] -and
        -not $capture.idleObservation.CoreShouldBeRunning -and
        $restored -ceq 'baseline')
}
Assert-IdleTransaction ($intentMutation.ActionFailure -ceq 'Action callback changed captured strict false intent.') 'Action intent mutation was not rejected.'
Assert-IdleTransaction ($intentMutation.RestoreFailure -eq $null) 'Rollback did not receive the original strict false intent.'
Assert-IdleTransactionOrder @('capture','action','restore','verify')
Assert-IdleTransaction ($script:nativeCalls -eq 0) 'Idle intent recovery invoked a native service or process action.'
Assert-IdleTransactionOrder @('capture','action','restore','verify')

foreach ($invalidIntent in @($true,0)) {
    $script:idleTransactionEvents.Clear()
    $rejected = $false
    try {
        $null = Invoke-CvrIdleTransaction -CaptureScript { $script:idleTransactionEvents.Add('capture'); New-IdleTransactionCapture $invalidIntent } -ActionScript { param($capture) $script:idleTransactionEvents.Add('action') } -RestoreScript { param($capture) $script:idleTransactionEvents.Add('restore') } -VerifyScript { param($capture,$restored) $script:idleTransactionEvents.Add('verify'); $true }
    } catch { $rejected = $_.Exception.Message -ceq 'Idle transaction requires a captured strict false intent.' }
    Assert-IdleTransaction $rejected 'Non-false or coerced idle intent was accepted.'
    Assert-IdleTransactionOrder @('capture')
}


function Assert-IdleTargetCaptureRejected([string]$Case, [string]$ExpectedMessage, [string]$ExpectedIdentity, [System.Collections.IDictionary]$Pins) {
    $rejected = $false
    try {
        $null = Assert-CvrIdleTargetCapture -Capture $targetCapture -ExpectedTargetIdentity $ExpectedIdentity -ExpectedPins $Pins
    } catch {
        if ($_.Exception.Message -cne $ExpectedMessage) { throw "Idle target capture guard returned an unexpected message for $Case." }
        $rejected = $true
    }
    Assert-IdleTransaction $rejected "$Case drift was accepted."
    $script:targetCaptureOutcomes.Add([pscustomobject]@{case=$Case;result='rejected'})
}

$targetCaptureRoot = Join-Path ([IO.Path]::GetTempPath()) ('stcvrc-idle-target-capture-' + [Guid]::NewGuid().ToString('N'))
if (Test-Path -LiteralPath $targetCaptureRoot) { throw 'Idle target capture fixture path unexpectedly exists.' }
$null = New-Item -ItemType Directory -Path $targetCaptureRoot
$programFilesFixtureRoot = $null
$serviceFixtureRoot = $null
$ownsProgramFilesFixtureRoot = $false
$ownsServiceFixtureRoot = $false
try {
    if ([string]::IsNullOrWhiteSpace($env:ProgramFiles) -or [string]::IsNullOrWhiteSpace($env:ProgramData)) {
        throw 'Synthetic core fixture roots are unavailable.'
    }
    $programFilesFixtureRoot = Join-Path $env:ProgramFiles ('stcvrc-idle-program-files-' + [Guid]::NewGuid().ToString('N'))
    $serviceFixtureRoot = Join-Path $env:ProgramData ('stcvrc-idle-service-' + [Guid]::NewGuid().ToString('N'))
    if ((Test-Path -LiteralPath $programFilesFixtureRoot) -or (Test-Path -LiteralPath $serviceFixtureRoot)) {
        throw 'Synthetic core fixture path unexpectedly exists.'
    }
    $null = New-Item -ItemType Directory -Path $programFilesFixtureRoot -ErrorAction Stop
    $ownsProgramFilesFixtureRoot = $true
    $null = New-Item -ItemType Directory -Path $serviceFixtureRoot -ErrorAction Stop
    $ownsServiceFixtureRoot = $true
    $pinPath = Join-Path $targetCaptureRoot 'pinned-input.bin'
    [IO.File]::WriteAllBytes($pinPath, [byte[]](7, 2, 5, 10))
    $pinSha = (Get-FileHash -LiteralPath $pinPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $syntheticPinPaths = @{
        candidateCore = Join-Path $targetCaptureRoot 'candidate-core.synthetic'
        updateInstaller = Join-Path $targetCaptureRoot 'update-installer.synthetic'
        updateHelper = Join-Path $targetCaptureRoot 'update-helper.synthetic'
        recoveryInstaller = Join-Path $targetCaptureRoot 'recovery-installer.synthetic'
        recoveryHelper = Join-Path $targetCaptureRoot 'recovery-helper.synthetic'
    }
    [IO.File]::WriteAllBytes($syntheticPinPaths.candidateCore, [byte[]](1, 19, 33, 9))
    [IO.File]::WriteAllBytes($syntheticPinPaths.updateInstaller, [byte[]](2, 5, 10, 2))
    [IO.File]::WriteAllBytes($syntheticPinPaths.updateHelper, [byte[]](2, 7, 7, 2))
    [IO.File]::WriteAllBytes($syntheticPinPaths.recoveryInstaller, [byte[]](2, 5, 8, 2))
    [IO.File]::WriteAllBytes($syntheticPinPaths.recoveryHelper, [byte[]](2, 7, 6, 2))
    $syntheticPinHashes = @{}
    foreach ($name in @('candidateCore', 'updateInstaller', 'updateHelper', 'recoveryInstaller', 'recoveryHelper')) {
        $syntheticPinHashes[$name] = (Get-FileHash -LiteralPath $syntheticPinPaths[$name] -Algorithm SHA256).Hash.ToLowerInvariant()
    }

    $programFilesPath = Join-Path $programFilesFixtureRoot 'verge-mihomo.exe'
    $serviceCorePath = Join-Path $serviceFixtureRoot 'verge-mihomo.exe'
    $programFilesBackup = Join-Path $targetCaptureRoot 'program-files-preimage.exe'
    $serviceBackupDirectory = Join-Path $targetCaptureRoot 'service-preimage'
    $null = New-Item -ItemType Directory -Path $serviceBackupDirectory
    $serviceBackup = Join-Path $serviceBackupDirectory 'verge-mihomo.exe'
    [IO.File]::WriteAllBytes($programFilesPath, [byte[]](2, 5, 8, 1))
    [IO.File]::WriteAllBytes($serviceCorePath, [byte[]](1, 1, 9, 3))
    $programFilesBytes = [IO.File]::ReadAllBytes($programFilesPath)
    $serviceBytes = [IO.File]::ReadAllBytes($serviceCorePath)
    [IO.File]::WriteAllBytes($programFilesBackup, $programFilesBytes)
    [IO.File]::WriteAllBytes($serviceBackup, $serviceBytes)
    $programFilesSha = (Get-FileHash -LiteralPath $programFilesPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $serviceSha = (Get-FileHash -LiteralPath $serviceCorePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $programFilesAcl = Get-Acl -LiteralPath $programFilesPath
    $serviceAcl = Get-Acl -LiteralPath $serviceCorePath

    $expectedPins = @{
        gui258 = $pinSha
        serviceExe258 = $pinSha
        programFilesCore = $programFilesSha
        serviceCore = $serviceSha
        candidateCore = $syntheticPinHashes.candidateCore
        updateInstaller = $syntheticPinHashes.updateInstaller
        updateHelper = $syntheticPinHashes.updateHelper
        recoveryInstaller = $syntheticPinHashes.recoveryInstaller
        recoveryHelper = $syntheticPinHashes.recoveryHelper
    }
    $pinnedFiles = @{
        gui258 = $pinPath
        serviceExe258 = $pinPath
        programFilesCore = $programFilesPath
        serviceCore = $serviceCorePath
        candidateCore = $syntheticPinPaths.candidateCore
        updateInstaller = $syntheticPinPaths.updateInstaller
        updateHelper = $syntheticPinPaths.updateHelper
        recoveryInstaller = $syntheticPinPaths.recoveryInstaller
        recoveryHelper = $syntheticPinPaths.recoveryHelper
    }
    $targetIdentity = [Guid]::NewGuid().ToString('N')
    $targetCapture = [PSCustomObject]@{
        targetIdentity = $targetIdentity
        capturedAtUtc = [DateTime]::UtcNow
        coreShouldBeRunning = [bool]$false
        idleObservation = @{
            CoreShouldBeRunning = [bool]$false
            OwnedGuiProcessIds = [int[]]@()
            OwnedCoreProcessIds = [int[]]@()
            ControllerListening = [bool]$false
            OwnedListenerProcessIds = [int[]]@()
            ServiceStatus = 'Running'
            ExpectedProgramFilesCoreSha256 = $programFilesSha
            ObservedProgramFilesCoreSha256 = $programFilesSha
            ExpectedServiceCoreSha256 = $serviceSha
            ObservedServiceCoreSha256 = $serviceSha
        }
        pinnedFiles = $pinnedFiles
        corePair = @{
            programFiles = [PSCustomObject]@{
                path = $programFilesPath
                backup = $programFilesBackup
                sha256 = $programFilesSha
                sddl = $programFilesAcl.Sddl
                acl = $programFilesAcl
            }
            service = [PSCustomObject]@{
                path = $serviceCorePath
                backup = $serviceBackup
                sha256 = $serviceSha
                sddl = $serviceAcl.Sddl
                acl = $serviceAcl
            }
        }
    }

    $acceptedTargetCapture = $false
    try {
        $acceptedTargetCapture = (Assert-CvrIdleTargetCapture -Capture $targetCapture -ExpectedTargetIdentity $targetIdentity -ExpectedPins $expectedPins) -ceq $true
    } catch {}
    Assert-IdleTransaction $acceptedTargetCapture 'Valid fresh idle target capture was rejected.'
    Assert-IdleTransaction ($acceptedTargetCapture -is [bool]) 'Idle target capture did not return a strict Boolean.'
    $script:targetCaptureOutcomes.Add([pscustomobject]@{case='fresh-idle-capture-with-distinct-2.5.8-and-2.5.10-pins';result='accepted'})
    if ($expectedPins.recoveryInstaller -ceq $expectedPins.updateInstaller -or $expectedPins.recoveryHelper -ceq $expectedPins.updateHelper) { throw 'Synthetic old and new pins must be distinct.' }

    $savedUpdateInstallerPath = $targetCapture.pinnedFiles.updateInstaller
    $targetCapture.pinnedFiles.updateInstaller = $targetCapture.pinnedFiles.recoveryInstaller
    $script:idleTransactionEvents.Clear()
    $targetPinDriftFailure = $null
    try {
        $null = Invoke-CvrIdleTargetTransaction -CaptureScript {
            $script:idleTransactionEvents.Add('capture')
            $targetCapture
        } -ExpectedTargetIdentity $targetIdentity -ExpectedPins $expectedPins -ActionScript {
            param($capture)
            $script:idleTransactionEvents.Add('candidate-apply')
            'candidate'
        } -RestoreScript {
            param($capture)
            $script:idleTransactionEvents.Add('rollback')
            'baseline'
        } -VerifyScript {
            param($capture, $restored)
            $script:idleTransactionEvents.Add('verify')
            $true
        }
    } catch { $targetPinDriftFailure = $_.Exception.Message }
    $targetCapture.pinnedFiles.updateInstaller = $savedUpdateInstallerPath
    Assert-IdleTransaction ($targetPinDriftFailure -ceq 'Idle target pinned input verification failed.') 'Target pin drift was not rejected.'
    Assert-IdleTransactionOrder @('capture')

    $candidateCoreSha = $expectedPins.candidateCore
    $script:syntheticRuntime = @{
        intent = [bool]$false
        coreRunning = [bool]$false
        controllerListening = [bool]$false
        serviceStatus = 'Running'
        serviceCorePath = [IO.Path]::GetFullPath($serviceCorePath)
        serviceCoreSha256 = $serviceSha
    }
    $script:idleTransactionEvents.Clear()
    $idleTargetTransaction = Invoke-CvrIdleTargetTransaction -CaptureScript {
        $script:idleTransactionEvents.Add('capture')
        $targetCapture
    } -ExpectedTargetIdentity $targetIdentity -ExpectedPins $expectedPins -ActionScript {
        param($capture)
        $script:idleTransactionEvents.Add('candidate-apply')
        $candidateBytes = [IO.File]::ReadAllBytes($capture.pinnedFiles.candidateCore)
        $coreEntries = @($capture.corePair.programFiles, $capture.corePair.service)
        foreach ($entry in $coreEntries) {
            [IO.File]::WriteAllBytes($entry.path, $candidateBytes)
            $candidateAcl = Get-Acl -LiteralPath $entry.path -ErrorAction Stop
            $candidateAcl.SetAccessRuleProtection((-not [bool]$entry.acl.AreAccessRulesProtected), $true)
            Set-Acl -LiteralPath $entry.path -AclObject $candidateAcl -ErrorAction Stop
            if ((Get-Acl -LiteralPath $entry.path -ErrorAction Stop).Sddl -ceq $entry.sddl -or
                (Get-FileHash -LiteralPath $entry.path -Algorithm SHA256 -ErrorAction Stop).Hash -ine $candidateCoreSha) {
                throw 'Synthetic candidate core pair did not match its pin or change its ACL.'
            }
        }
        $script:syntheticRuntime.serviceCoreSha256 = (Get-FileHash -LiteralPath $capture.corePair.service.path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        if ($script:syntheticRuntime.serviceCorePath -cne [IO.Path]::GetFullPath($capture.corePair.service.path) -or
            $script:syntheticRuntime.serviceCoreSha256 -cne $candidateCoreSha -or
            $script:syntheticRuntime.intent -isnot [bool] -or $script:syntheticRuntime.intent -or
            $script:syntheticRuntime.coreRunning -or
            $script:syntheticRuntime.controllerListening -or
            $script:syntheticRuntime.serviceStatus -cne [string]$capture.idleObservation.ServiceStatus) {
            throw 'Synthetic idle candidate acceptance failed.'
        }
        $script:idleTransactionEvents.Add('candidate-accepted')
        'candidate-accepted'
    } -RestoreScript {
        param($capture)
        $script:idleTransactionEvents.Add('rollback')
        foreach ($pair in @(
            [PSCustomObject]@{ name = 'Program Files'; entry = $capture.corePair.programFiles },
            [PSCustomObject]@{ name = 'service'; entry = $capture.corePair.service }
        )) {
            Restore-CvrCoreFilePreimage -Entry $pair.entry -Role $pair.name
        }
        $script:syntheticRuntime.serviceCorePath = [IO.Path]::GetFullPath($capture.corePair.service.path)
        $script:syntheticRuntime.serviceCoreSha256 = [string]$capture.corePair.service.sha256
        'baseline-restored'
    } -VerifyScript {
        param($capture, $restored)
        $script:idleTransactionEvents.Add('verify')
        if ($restored -cne 'baseline-restored') { throw 'Synthetic rollback callback result mismatch.' }
        foreach ($pair in @(
            [PSCustomObject]@{ name = 'Program Files'; entry = $capture.corePair.programFiles },
            [PSCustomObject]@{ name = 'service'; entry = $capture.corePair.service }
        )) {
            $actualSha = (Get-FileHash -LiteralPath $pair.entry.path -Algorithm SHA256 -ErrorAction Stop).Hash
            if ($actualSha -ine [string]$pair.entry.sha256) {
                throw "Synthetic rollback $($pair.name) core SHA256 mismatch."
            }
            $actualSddl = (Get-Acl -LiteralPath $pair.entry.path -ErrorAction Stop).Sddl
            if ($actualSddl -cne [string]$pair.entry.sddl) {
                throw "Synthetic rollback $($pair.name) core ACL mismatch."
            }
        }
        if ($script:syntheticRuntime.intent -isnot [bool] -or $script:syntheticRuntime.intent) {
            throw 'Synthetic rollback did not preserve false intent.'
        }
        if ($script:syntheticRuntime.coreRunning) { throw 'Synthetic rollback left the core running.' }
        if ($script:syntheticRuntime.controllerListening) { throw 'Synthetic rollback left the controller listening.' }
        if ($script:syntheticRuntime.serviceStatus -cne [string]$capture.idleObservation.ServiceStatus) {
            throw 'Synthetic rollback service status mismatch.'
        }
        if ($script:syntheticRuntime.serviceCoreSha256 -cne [string]$capture.corePair.service.sha256) {
            throw 'Synthetic rollback service core SHA256 mismatch.'
        }
        return [bool]$true
    }
    if ($idleTargetTransaction.ActionFailure -or $idleTargetTransaction.RestoreFailure) {
        throw ("Synthetic idle transaction failed. ActionFailure={0}; RestoreFailure={1}" -f
            [string]$idleTargetTransaction.ActionFailure,
            [string]$idleTargetTransaction.RestoreFailure)
    }
    if ($idleTargetTransaction.ActionResult -cne 'candidate-accepted') {
        throw 'Synthetic candidate acceptance marker was not returned.'
    }
    Assert-IdleTransactionOrder @('capture','candidate-apply','candidate-accepted','rollback','verify')
    Assert-IdleTransaction ($script:syntheticRuntime.intent -ceq [bool]$false -and
        -not $script:syntheticRuntime.coreRunning -and
        -not $script:syntheticRuntime.controllerListening) 'Synthetic rollback did not restore the idle false-intent state.'
    Assert-IdleTransaction ($script:nativeCalls -eq 0) 'Idle candidate transaction invoked a native service or process action.'

    $script:idleTransactionEvents.Clear()
    $partialCandidateFailure = Invoke-CvrIdleTargetTransaction -CaptureScript {
        $script:idleTransactionEvents.Add('capture')
        $targetCapture
    } -ExpectedTargetIdentity $targetIdentity -ExpectedPins $expectedPins -ActionScript {
        param($capture)
        $script:idleTransactionEvents.Add('candidate-partial')
        $candidateBytes = [IO.File]::ReadAllBytes($capture.pinnedFiles.candidateCore)
        [IO.File]::WriteAllBytes($capture.corePair.programFiles.path, $candidateBytes)
        $partialAcl = Get-Acl -LiteralPath $capture.corePair.programFiles.path -ErrorAction Stop
        $partialAcl.SetAccessRuleProtection((-not [bool]$capture.corePair.programFiles.acl.AreAccessRulesProtected), $true)
        Set-Acl -LiteralPath $capture.corePair.programFiles.path -AclObject $partialAcl -ErrorAction Stop
        throw 'synthetic-partial-candidate-failure'
    } -RestoreScript {
        param($capture)
        $script:idleTransactionEvents.Add('rollback')
        Restore-CvrCoreFilePreimage -Entry $capture.corePair.programFiles -Role 'Program Files'
        Restore-CvrCoreFilePreimage -Entry $capture.corePair.service -Role 'service'
        $script:syntheticRuntime.serviceCoreSha256 = [string]$capture.corePair.service.sha256
        'baseline-restored'
    } -VerifyScript {
        param($capture, $restored)
        $script:idleTransactionEvents.Add('verify')
        if ($restored -cne 'baseline-restored') { throw 'Synthetic partial rollback callback result mismatch.' }
        foreach ($pair in @(
            [PSCustomObject]@{ name = 'Program Files'; entry = $capture.corePair.programFiles },
            [PSCustomObject]@{ name = 'service'; entry = $capture.corePair.service }
        )) {
            if ((Get-FileHash -LiteralPath $pair.entry.path -Algorithm SHA256 -ErrorAction Stop).Hash -ine [string]$pair.entry.sha256 -or
                (Get-Acl -LiteralPath $pair.entry.path -ErrorAction Stop).Sddl -cne [string]$pair.entry.sddl) {
                throw "Synthetic partial rollback $($pair.name) preimage mismatch."
            }
        }
        if ($script:syntheticRuntime.intent -isnot [bool] -or $script:syntheticRuntime.intent -or
            $script:syntheticRuntime.coreRunning -or $script:syntheticRuntime.controllerListening -or
            $script:syntheticRuntime.serviceStatus -cne [string]$capture.idleObservation.ServiceStatus) {
            throw 'Synthetic partial rollback changed idle runtime state.'
        }
        return [bool]$true
    }
    Assert-IdleTransaction ($partialCandidateFailure.ActionFailure -ceq 'synthetic-partial-candidate-failure') 'Partial candidate failure was not retained.'
    Assert-IdleTransaction ($partialCandidateFailure.RestoreFailure -eq $null) 'Partial candidate rollback failed.'
    Assert-IdleTransactionOrder @('capture','candidate-partial','rollback','verify')
    Assert-IdleTransaction ($script:nativeCalls -eq 0) 'Partial idle rollback invoked a native service or process action.'
    $script:targetCaptureOutcomes.Add([pscustomobject]@{case='synthetic-idle-partial-write-rollback';result='restored'})

    $script:targetCaptureOutcomes.Add([pscustomobject]@{case='synthetic-idle-apply-accept-rollback';result='accepted';candidateCoreSha256=$candidateCoreSha})
    $script:idleTransactionReceipt = [pscustomobject]@{
        candidateCoreSha256 = $candidateCoreSha
        restoredProgramFilesCoreSha256 = (Get-FileHash -LiteralPath $programFilesPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        restoredServiceCoreSha256 = (Get-FileHash -LiteralPath $serviceCorePath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        finalIntent = [bool]$script:syntheticRuntime.intent
        finalCoreRunning = [bool]$script:syntheticRuntime.coreRunning
        finalControllerListening = [bool]$script:syntheticRuntime.controllerListening
    }

    Assert-IdleTargetCaptureRejected 'target identity' 'Idle target identity does not match the expected target.' 'different-target' $expectedPins

    $savedTime = $targetCapture.capturedAtUtc
    $targetCapture.capturedAtUtc = [DateTime]::UtcNow.AddMinutes(-6)
    Assert-IdleTargetCaptureRejected 'stale capture' 'Idle target capture timestamp is missing, stale, or not UTC.' $targetIdentity $expectedPins
    $targetCapture.capturedAtUtc = $savedTime

    $targetCapture.coreShouldBeRunning = 0
    Assert-IdleTargetCaptureRejected 'non-Boolean owner intent' 'Idle target capture requires strict false intent.' $targetIdentity $expectedPins
    $targetCapture.coreShouldBeRunning = [bool]$true
    Assert-IdleTargetCaptureRejected 'running owner intent' 'Idle target capture requires strict false intent.' $targetIdentity $expectedPins
    $targetCapture.coreShouldBeRunning = [bool]$false

    $targetCapture.idleObservation.OwnedGuiProcessIds = [int[]]@(101)
    Assert-IdleTargetCaptureRejected 'owned GUI process' 'Idle baseline has owned GUI processes.' $targetIdentity $expectedPins
    $targetCapture.idleObservation.OwnedGuiProcessIds = [int[]]@()
    $targetCapture.idleObservation.OwnedCoreProcessIds = [int[]]@(202)
    Assert-IdleTargetCaptureRejected 'owned core process' 'Idle baseline has owned core processes.' $targetIdentity $expectedPins
    $targetCapture.idleObservation.OwnedCoreProcessIds = [int[]]@()
    $targetCapture.idleObservation.ControllerListening = [bool]$true
    Assert-IdleTargetCaptureRejected 'controller listener' 'Idle baseline controller listener is present.' $targetIdentity $expectedPins
    $targetCapture.idleObservation.ControllerListening = [bool]$false
    $targetCapture.idleObservation.OwnedListenerProcessIds = [int[]]@(303)
    Assert-IdleTargetCaptureRejected 'owned listener' 'Idle baseline has owned listeners.' $targetIdentity $expectedPins
    $targetCapture.idleObservation.OwnedListenerProcessIds = [int[]]@()

    $savedInstallerPin = $expectedPins.updateInstaller
    $expectedPins.updateInstaller = ('0' * 64)
    Assert-IdleTargetCaptureRejected 'update installer pin drift' 'Idle target pinned input verification failed.' $targetIdentity $expectedPins
    $expectedPins.updateInstaller = $savedInstallerPin

    foreach ($pinName in @('updateInstaller', 'recoveryInstaller')) {
        $pinPathToDrift = $pinnedFiles[$pinName]
        $pinBytesBeforeDrift = [IO.File]::ReadAllBytes($pinPathToDrift)
        [IO.File]::WriteAllBytes($pinPathToDrift, [byte[]](0, 255, 0, 1))
        Assert-IdleTargetCaptureRejected "$pinName bytes drift" 'Idle target pinned input verification failed.' $targetIdentity $expectedPins
        [IO.File]::WriteAllBytes($pinPathToDrift, $pinBytesBeforeDrift)
    }

    $savedRecoveryHelperPin = $expectedPins.recoveryHelper
    $savedRecoveryHelperPath = $pinnedFiles.recoveryHelper
    $null = $expectedPins.Remove('recoveryHelper')
    $null = $pinnedFiles.Remove('recoveryHelper')
    Assert-IdleTargetCaptureRejected 'missing rollback helper pin' 'Idle target pin set is incomplete.' $targetIdentity $expectedPins
    $expectedPins.recoveryHelper = $savedRecoveryHelperPin
    $pinnedFiles.recoveryHelper = $savedRecoveryHelperPath

    $savedServiceBackup = $targetCapture.corePair.service.backup
    $targetCapture.corePair.service.backup = $programFilesBackup
    Assert-IdleTargetCaptureRejected 'aliased core preimages' 'Idle target core preimage verification failed.' $targetIdentity $expectedPins
    $targetCapture.corePair.service.backup = $savedServiceBackup

    [IO.File]::WriteAllBytes($serviceBackup, [byte[]](4, 3, 2))
    Assert-IdleTargetCaptureRejected 'changed service preimage bytes' 'Idle target core preimage verification failed.' $targetIdentity $expectedPins
    [IO.File]::WriteAllBytes($serviceBackup, $serviceBytes)

    $savedSddl = $targetCapture.corePair.programFiles.sddl
    $targetCapture.corePair.programFiles.sddl = 'unreviewed'
    Assert-IdleTargetCaptureRejected 'changed Program Files ACL preimage' 'Idle target core preimage verification failed.' $targetIdentity $expectedPins
    $targetCapture.corePair.programFiles.sddl = $savedSddl


# Public idle Preflight capture contract.
if (-not (Get-Command -Name Save-CvrIdlePreflightCapture -CommandType Function -ErrorAction SilentlyContinue)) {
    throw 'Idle Preflight capture writer is missing.'
}

$preflightPackageRoot = Join-Path $targetCaptureRoot 'preflight-package'
$preflightLocalRoot = Join-Path $preflightPackageRoot 'local'
$null = New-Item -ItemType Directory -Path $preflightPackageRoot -ErrorAction Stop
Set-CvrIdleCaptureAcl -Path $preflightPackageRoot -Directory
$null = New-Item -ItemType Directory -Path $preflightLocalRoot -ErrorAction Stop
Set-CvrIdleCaptureAcl -Path $preflightLocalRoot -Directory
$captureMarkerPath = Join-Path (Join-Path $preflightLocalRoot 'capture') 'keep.txt'
$preparedMarkerPath = Join-Path (Join-Path $preflightLocalRoot 'prepared') 'keep.txt'
$null = New-Item -ItemType Directory -Path (Split-Path -Parent $captureMarkerPath) -Force
$null = New-Item -ItemType Directory -Path (Split-Path -Parent $preparedMarkerPath) -Force
[IO.File]::WriteAllText($captureMarkerPath, 'preserve-capture')
[IO.File]::WriteAllText($preparedMarkerPath, 'preserve-prepared')

$protectedPackageAcl = Get-Acl -LiteralPath $preflightPackageRoot
$unprotectedPackageAcl = Get-Acl -LiteralPath $preflightPackageRoot
$unprotectedPackageAcl.SetAccessRuleProtection($false, $true)
Set-Acl -LiteralPath $preflightPackageRoot -AclObject $unprotectedPackageAcl -ErrorAction Stop
$beforeUnprotectedPackageCaptureCount = @(Get-ChildItem -LiteralPath $preflightLocalRoot -Directory -Filter 'capture-idle-*').Count
$unprotectedPackageRejected = $false
try {
    $null = Save-CvrIdlePreflightCapture -Capture $targetCapture -ExpectedTargetIdentity $targetIdentity -ExpectedPins $expectedPins -PackageRoot $preflightPackageRoot
} catch {
    $unprotectedPackageRejected = $_.Exception.Message -ceq 'Idle Preflight package root is not protected.'
}
$afterUnprotectedPackageCaptureCount = @(Get-ChildItem -LiteralPath $preflightLocalRoot -Directory -Filter 'capture-idle-*').Count
Set-Acl -LiteralPath $preflightPackageRoot -AclObject $protectedPackageAcl -ErrorAction Stop
$null = Assert-CvrIdleCaptureAcl -Path $preflightPackageRoot -Directory
if (-not $unprotectedPackageRejected -or $afterUnprotectedPackageCaptureCount -ne $beforeUnprotectedPackageCaptureCount) {
    throw 'Unprotected idle Preflight package root was accepted or wrote output.'
}

$targetCapture | Add-Member -NotePropertyName profileMarker -NotePropertyValue 'synthetic-profile-marker'
$targetCapture.idleObservation.ControllerListening = [bool]$true
$beforeRejectedCaptureCount = @(Get-ChildItem -LiteralPath $preflightLocalRoot -Directory -Filter 'capture-idle-*').Count
$rejectedSave = $false
try {
    $null = Save-CvrIdlePreflightCapture -Capture $targetCapture -ExpectedTargetIdentity $targetIdentity -ExpectedPins $expectedPins -PackageRoot $preflightPackageRoot
} catch {
    $rejectedSave = $_.Exception.Message -ceq 'Idle baseline controller listener is present.'
}
$targetCapture.idleObservation.ControllerListening = [bool]$false
$afterRejectedCaptureCount = @(Get-ChildItem -LiteralPath $preflightLocalRoot -Directory -Filter 'capture-idle-*').Count
if (-not $rejectedSave -or $afterRejectedCaptureCount -ne $beforeRejectedCaptureCount) {
    throw 'Rejected idle Preflight created a capture directory.'
}

$preflight = Save-CvrIdlePreflightCapture -Capture $targetCapture -ExpectedTargetIdentity $targetIdentity -ExpectedPins $expectedPins -PackageRoot $preflightPackageRoot
$preflightAgain = Save-CvrIdlePreflightCapture -Capture $targetCapture -ExpectedTargetIdentity $targetIdentity -ExpectedPins $expectedPins -PackageRoot $preflightPackageRoot
$preflightDirectory = [IO.Path]::GetFullPath($preflight.CaptureDirectory)
$preflightLocal = [IO.Path]::GetFullPath($preflightLocalRoot)
if ([IO.Path]::GetDirectoryName($preflightDirectory) -ine $preflightLocal -or
    [IO.Path]::GetFileName($preflightDirectory) -notmatch '^capture-idle-[0-9a-f]{32}$' -or
    $preflightDirectory -ceq [IO.Path]::GetFullPath((Join-Path $preflightLocalRoot 'capture')) -or
    $preflightDirectory -ceq [IO.Path]::GetFullPath((Join-Path $preflightLocalRoot 'prepared'))) {
    throw 'Idle Preflight capture was not written to a unique protected sibling.'
}
if ($preflight.CaptureDirectory -ceq $preflightAgain.CaptureDirectory) {
    throw 'Repeated idle Preflight capture reused an existing output directory.'
}
if (-not (Test-Path -LiteralPath $preflight.ReceiptPath -PathType Leaf)) {
    throw 'Idle Preflight receipt file is missing.'
}
if (-not (Get-Acl -LiteralPath $preflight.CaptureDirectory).AreAccessRulesProtected -or
    -not (Get-Acl -LiteralPath $preflight.ReceiptPath).AreAccessRulesProtected) {
    throw 'Idle Preflight capture ACL is not protected.'
}
$receiptText = [IO.File]::ReadAllText($preflight.ReceiptPath)
$receipt = $receiptText | ConvertFrom-Json
$receiptFailures = [Collections.Generic.List[string]]::new()
if ($receipt.coreShouldBeRunning -isnot [bool] -or $receipt.coreShouldBeRunning) { $receiptFailures.Add('strict-false-intent') }
if ($receipt.targetIdentity -cne $targetIdentity) { $receiptFailures.Add('target-identity') }
$receiptPinNames = @($receipt.expectedPins.PSObject.Properties | ForEach-Object { $_.Name })
$expectedPinNames = @('gui258', 'serviceExe258', 'programFilesCore', 'serviceCore', 'candidateCore', 'updateInstaller', 'updateHelper', 'recoveryInstaller', 'recoveryHelper')
$receiptPinNamesText = @($receiptPinNames | Sort-Object -CaseSensitive) -join '|'
$expectedPinNamesText = @($expectedPinNames | Sort-Object -CaseSensitive) -join '|'
if ($receiptPinNames.Count -ne 9 -or $receiptPinNamesText -cne $expectedPinNamesText) {
    $receiptFailures.Add("expected-pin-fields:$($receiptPinNames.Count):$($receiptPinNames -join ',')")
}
if ($receipt.idleObservation.ServiceStatus -cne 'Running') { $receiptFailures.Add('service-status') }
if ([IO.Path]::GetFileName($receipt.corePair.service.backup) -cne 'verge-mihomo.exe') { $receiptFailures.Add('service-backup-basename') }
if ($receiptText.Contains('synthetic-profile-marker')) { $receiptFailures.Add('non-allowlisted-profile-marker') }
if ($receiptFailures.Count) {
    throw "Idle Preflight receipt contract failed: $($receiptFailures -join ', ')."
}
if ([IO.File]::ReadAllText($captureMarkerPath) -cne 'preserve-capture' -or
    [IO.File]::ReadAllText($preparedMarkerPath) -cne 'preserve-prepared') {
    throw 'Idle Preflight modified the existing capture or prepared sibling.'
}
$script:saveCaptureParameters = (Get-Command Save-CvrIdlePreflightCapture).Parameters.Keys
if ($script:saveCaptureParameters -contains 'ActionScript' -or
    $script:saveCaptureParameters -contains 'RestoreScript') {
    throw 'Read-only idle Preflight adapter must not accept transaction callbacks.'
}

# Public idle Preflight prepared-plan contract.
if (-not (Get-Command -Name Save-CvrIdlePreflightPlan -CommandType Function -ErrorAction SilentlyContinue)) {
    throw 'Expected behavior RED: guarded unique idle preflight plan writer is missing.'
}

$beforePreparedPlanCount = @(Get-ChildItem -LiteralPath $preflightLocalRoot -Directory -Filter 'prepared-idle-*').Count
$preparedPlan = Save-CvrIdlePreflightPlan -Capture $targetCapture -CaptureDirectory $preflight.CaptureDirectory -ReceiptPath $preflight.ReceiptPath -ExpectedTargetIdentity $targetIdentity -ExpectedPins $expectedPins -PackageRoot $preflightPackageRoot
$preparedPlanAgain = Save-CvrIdlePreflightPlan -Capture $targetCapture -CaptureDirectory $preflight.CaptureDirectory -ReceiptPath $preflight.ReceiptPath -ExpectedTargetIdentity $targetIdentity -ExpectedPins $expectedPins -PackageRoot $preflightPackageRoot
$preparedDirectory = [IO.Path]::GetFullPath($preparedPlan.PreparedDirectory)
$preparedAgainDirectory = [IO.Path]::GetFullPath($preparedPlanAgain.PreparedDirectory)
if ([IO.Path]::GetDirectoryName($preparedDirectory) -ine $preflightLocal -or
    [IO.Path]::GetFileName($preparedDirectory) -notmatch '^prepared-idle-[0-9a-f]{32}

if ($script:nativeCalls -ne 0) { throw 'Idle capture fixture reached a native action tripwire.' }
$fixtureSha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
[pscustomobject]@{
    pass = $true
    fixtureSha256 = $fixtureSha256
    targetCaptureOutcomes = @($script:targetCaptureOutcomes.ToArray())
    idleTransaction = $script:idleTransactionReceipt
    measuredNativeCalls = $script:nativeCalls
} | ConvertTo-Json -Depth 5 -Compress | Write-Host

} finally {
    if ($ownsServiceFixtureRoot) { Remove-Item -LiteralPath $serviceFixtureRoot -Recurse -Force -ErrorAction Stop }
    if ($ownsProgramFilesFixtureRoot) { Remove-Item -LiteralPath $programFilesFixtureRoot -Recurse -Force -ErrorAction Stop }
    Remove-Item -LiteralPath $targetCaptureRoot -Recurse -Force -ErrorAction Stop
}
 -or
    $preparedDirectory -ceq [IO.Path]::GetFullPath((Join-Path $preflightLocalRoot 'prepared')) -or
    $preparedDirectory -ceq $preflightDirectory -or
    $preparedAgainDirectory -ceq $preparedDirectory -or
    @(Get-ChildItem -LiteralPath $preflightLocalRoot -Directory -Filter 'prepared-idle-*').Count -ne ($beforePreparedPlanCount + 2)) {
    throw 'Idle Preflight plan was not written to unique protected siblings.'
}
if (-not (Test-Path -LiteralPath $preparedPlan.PlanPath -PathType Leaf) -or
    [IO.Path]::GetFileName($preparedPlan.PlanPath) -cne 'plan.json' -or
    (Get-FileHash -LiteralPath $preparedPlan.PlanPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string]$preparedPlan.PlanSha256 -or
    -not (Get-Acl -LiteralPath $preparedDirectory).AreAccessRulesProtected -or
    -not (Get-Acl -LiteralPath $preparedPlan.PlanPath).AreAccessRulesProtected) {
    throw 'Idle Preflight plan is missing or not hash-bound and protected.'
}
$planText = [IO.File]::ReadAllText($preparedPlan.PlanPath)
$plan = $planText | ConvertFrom-Json
$planFailures = [Collections.Generic.List[string]]::new()
if ($plan.coreShouldBeRunning -isnot [bool] -or $plan.coreShouldBeRunning) { $planFailures.Add('strict-false-intent') }
if ($plan.targetIdentity -cne $targetIdentity) { $planFailures.Add('target-identity') }
if ([IO.Path]::GetFullPath([string]$plan.captureDirectory) -cne $preflightDirectory) { $planFailures.Add('capture-directory-binding') }
if ([IO.Path]::GetFullPath([string]$plan.captureReceiptPath) -cne [IO.Path]::GetFullPath($preflight.ReceiptPath)) { $planFailures.Add('capture-receipt-binding') }
if ([string]$plan.captureReceiptSha256 -cne (Get-FileHash -LiteralPath $preflight.ReceiptPath -Algorithm SHA256).Hash.ToLowerInvariant()) { $planFailures.Add('capture-receipt-hash') }
$planPinNames = @($plan.expectedPins.PSObject.Properties | ForEach-Object { $_.Name })
if ($planPinNames.Count -ne $expectedPinNames.Count -or (@($planPinNames | Sort-Object -CaseSensitive) -join '|') -cne $expectedPinNamesText) {
    $planFailures.Add('exact-pin-fields')
}
$planPinnedFileNames = @($plan.pinnedFiles.PSObject.Properties | ForEach-Object { $_.Name })
if ($planPinnedFileNames.Count -ne $expectedPinNames.Count -or (@($planPinnedFileNames | Sort-Object -CaseSensitive) -join '|') -cne $expectedPinNamesText) {
    $planFailures.Add('exact-pinned-file-fields')
}
foreach ($pinName in $expectedPinNames) {
    if ([string]$plan.expectedPins.$pinName -cne [string]$expectedPins[$pinName] -or
        [string]$plan.pinnedFiles.$pinName -cne [string]$pinnedFiles[$pinName]) {
        $planFailures.Add("pin-binding:$pinName")
    }
}
if ($plan.idleObservation.ControllerListening -isnot [bool] -or $plan.idleObservation.ControllerListening -or
    @($plan.idleObservation.OwnedGuiProcessIds).Count -ne 0 -or
    @($plan.idleObservation.OwnedCoreProcessIds).Count -ne 0 -or
    @($plan.idleObservation.OwnedListenerProcessIds).Count -ne 0) {
    $planFailures.Add('idle-observation')
}
if ([string]$plan.corePair.programFiles.sha256 -cne $programFilesSha -or
    [string]$plan.corePair.programFiles.sddl -cne [string]$programFilesAcl.Sddl -or
    [string]$plan.corePair.service.sha256 -cne $serviceSha -or
    [string]$plan.corePair.service.sddl -cne [string]$serviceAcl.Sddl -or
    [IO.Path]::GetFileName([string]$plan.corePair.service.backup) -cne 'verge-mihomo.exe') {
    $planFailures.Add('core-pair-preimage')
}
if ($planText.Contains('synthetic-profile-marker')) { $planFailures.Add('non-allowlisted-profile-marker') }
if ($planFailures.Count) { throw 'Idle Preflight plan contract failed.' }

$beforeRejectedPlanCount = @(Get-ChildItem -LiteralPath $preflightLocalRoot -Directory -Filter 'prepared-idle-*').Count
$targetCapture.idleObservation.ControllerListening = [bool]$true
$rejectedPlanForListener = $false
try {
    $null = Save-CvrIdlePreflightPlan -Capture $targetCapture -CaptureDirectory $preflight.CaptureDirectory -ReceiptPath $preflight.ReceiptPath -ExpectedTargetIdentity $targetIdentity -ExpectedPins $expectedPins -PackageRoot $preflightPackageRoot
} catch {
    $rejectedPlanForListener = $_.Exception.Message -ceq 'Idle baseline controller listener is present.'
}
$targetCapture.idleObservation.ControllerListening = [bool]$false
if (-not $rejectedPlanForListener -or
    @(Get-ChildItem -LiteralPath $preflightLocalRoot -Directory -Filter 'prepared-idle-*').Count -ne $beforeRejectedPlanCount) {
    throw 'Idle Preflight plan accepted controller drift or wrote output after rejection.'
}

$receiptBeforePlanDrift = [IO.File]::ReadAllText($preflight.ReceiptPath)
$receiptForPlanDrift = $receiptBeforePlanDrift | ConvertFrom-Json
$receiptForPlanDrift.targetIdentity = [Guid]::NewGuid().ToString('N')
[IO.File]::WriteAllText($preflight.ReceiptPath, (ConvertTo-Json -InputObject $receiptForPlanDrift -Depth 8 -Compress), [Text.UTF8Encoding]::new($false))
$rejectedPlanForReceiptDrift = $false
try {
    $null = Save-CvrIdlePreflightPlan -Capture $targetCapture -CaptureDirectory $preflight.CaptureDirectory -ReceiptPath $preflight.ReceiptPath -ExpectedTargetIdentity $targetIdentity -ExpectedPins $expectedPins -PackageRoot $preflightPackageRoot
} catch {
    $rejectedPlanForReceiptDrift = $_.Exception.Message -ceq 'Idle Preflight capture receipt does not match the supplied capture.'
} finally {
    [IO.File]::WriteAllText($preflight.ReceiptPath, $receiptBeforePlanDrift, [Text.UTF8Encoding]::new($false))
}
if (-not $rejectedPlanForReceiptDrift -or
    @(Get-ChildItem -LiteralPath $preflightLocalRoot -Directory -Filter 'prepared-idle-*').Count -ne $beforeRejectedPlanCount) {
    throw 'Idle Preflight plan accepted a drifted capture receipt or wrote output after rejection.'
}
if ([IO.File]::ReadAllText($captureMarkerPath) -cne 'preserve-capture' -or
    [IO.File]::ReadAllText($preparedMarkerPath) -cne 'preserve-prepared') {
    throw 'Idle Preflight plan modified an existing capture or prepared sibling.'
}

$targetCapture.PSObject.Properties.Remove('profileMarker')

if ($script:nativeCalls -ne 0) { throw 'Idle capture fixture reached a native action tripwire.' }
$fixtureSha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
[pscustomobject]@{
    pass = $true
    fixtureSha256 = $fixtureSha256
    targetCaptureOutcomes = @($script:targetCaptureOutcomes.ToArray())
    idleTransaction = $script:idleTransactionReceipt
    measuredNativeCalls = $script:nativeCalls
} | ConvertTo-Json -Depth 5 -Compress | Write-Host

} finally {
    if ($ownsServiceFixtureRoot) { Remove-Item -LiteralPath $serviceFixtureRoot -Recurse -Force -ErrorAction Stop }
    if ($ownsProgramFilesFixtureRoot) { Remove-Item -LiteralPath $programFilesFixtureRoot -Recurse -Force -ErrorAction Stop }
    Remove-Item -LiteralPath $targetCaptureRoot -Recurse -Force -ErrorAction Stop
}
