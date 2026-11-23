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
function Write-IdleProtectedBackup([string]$Path, [byte[]]$Bytes) {
    $directory = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Path))
    $null = Set-CvrIdleCaptureAcl -Path $directory -Directory
    [IO.File]::WriteAllBytes($Path, [byte[]]@())
    $null = Set-CvrIdleCaptureAcl -Path $Path
    [IO.File]::WriteAllBytes($Path, $Bytes)
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
    $programFilesBackup = New-CvrCorePreimageBackupPath -Root $targetCaptureRoot -Label 'program-files'
    $serviceBackup = New-CvrCorePreimageBackupPath -Root $targetCaptureRoot -Label 'service'
    [IO.File]::WriteAllBytes($programFilesPath, [byte[]](2, 5, 8, 1))
    [IO.File]::WriteAllBytes($serviceCorePath, [byte[]](1, 1, 9, 3))
    $programFilesBytes = [IO.File]::ReadAllBytes($programFilesPath)
    $serviceBytes = [IO.File]::ReadAllBytes($serviceCorePath)
    Write-IdleProtectedBackup -Path $programFilesBackup -Bytes $programFilesBytes
    Write-IdleProtectedBackup -Path $serviceBackup -Bytes $serviceBytes
    $programFilesSha = (Get-FileHash -LiteralPath $programFilesPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $serviceSha = (Get-FileHash -LiteralPath $serviceCorePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $programFilesAcl = Get-Acl -LiteralPath $programFilesPath
    $serviceAcl = Get-Acl -LiteralPath $serviceCorePath
    $programFilesBackupAcl = Get-Acl -LiteralPath $programFilesBackup
    $serviceBackupAcl = Get-Acl -LiteralPath $serviceBackup
    $programFilesBackupDirectoryAcl = Get-Acl -LiteralPath ([IO.Path]::GetDirectoryName($programFilesBackup))
    $serviceBackupDirectoryAcl = Get-Acl -LiteralPath ([IO.Path]::GetDirectoryName($serviceBackup))

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
                pathPin = $programFilesPath
                backup = $programFilesBackup
                backupPathPin = $programFilesBackup
                backupRoot = $targetCaptureRoot
                backupSddl = $programFilesBackupAcl.Sddl
                backupDirectorySddl = $programFilesBackupDirectoryAcl.Sddl
                sha256 = $programFilesSha
                sddl = $programFilesAcl.Sddl
                acl = $programFilesAcl
            }
            service = [PSCustomObject]@{
                path = $serviceCorePath
                pathPin = $serviceCorePath
                backup = $serviceBackup
                backupPathPin = $serviceBackup
                backupRoot = $targetCaptureRoot
                backupSddl = $serviceBackupAcl.Sddl
                backupDirectorySddl = $serviceBackupDirectoryAcl.Sddl
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

    $beforeServiceBackupDriftProgramFiles = [Convert]::ToBase64String([IO.File]::ReadAllBytes($programFilesPath))
    $beforeServiceBackupDriftService = [Convert]::ToBase64String([IO.File]::ReadAllBytes($serviceCorePath))
    $beforeServiceBackupDriftProgramFilesSddl = (Get-Acl -LiteralPath $programFilesPath).Sddl
    $beforeServiceBackupDriftServiceSddl = (Get-Acl -LiteralPath $serviceCorePath).Sddl
    try {
        [IO.File]::WriteAllBytes($serviceBackup, [byte[]](4, 3, 2))
        $changedServiceSha = (Get-FileHash -LiteralPath $serviceBackup -Algorithm SHA256).Hash.ToLowerInvariant()
        Assert-IdleTargetCaptureRejected 'changed service preimage bytes' "Idle target core preimage verification failed: service core preimage backup validation failed at backup SHA256 (SHA256 expected=$serviceSha actual=$changedServiceSha)." $targetIdentity $expectedPins
    } finally {
        [IO.File]::WriteAllBytes($serviceBackup, $serviceBytes)
    }
    if ([Convert]::ToBase64String([IO.File]::ReadAllBytes($programFilesPath)) -cne $beforeServiceBackupDriftProgramFiles -or
        [Convert]::ToBase64String([IO.File]::ReadAllBytes($serviceCorePath)) -cne $beforeServiceBackupDriftService -or
        (Get-Acl -LiteralPath $programFilesPath).Sddl -cne $beforeServiceBackupDriftProgramFilesSddl -or
        (Get-Acl -LiteralPath $serviceCorePath).Sddl -cne $beforeServiceBackupDriftServiceSddl) {
        throw 'Changed service backup bytes altered a live core or ACL before rejection.'
    }

    $savedSddl = $targetCapture.corePair.programFiles.sddl
    $targetCapture.corePair.programFiles.sddl = 'unreviewed'
    Assert-IdleTargetCaptureRejected 'changed Program Files ACL preimage' 'Idle target core preimage verification failed.' $targetIdentity $expectedPins
    $targetCapture.corePair.programFiles.sddl = $savedSddl



    # The pair path must bind to its pinned file even when an alternate has exact pinned bytes and ACL.
    $preimageGuardFailures = [Collections.Generic.List[string]]::new()
    foreach ($case in @(
        [PSCustomObject]@{ label='Program Files'; pin='programFilesCore'; entry=$targetCapture.corePair.programFiles; originalPath=$programFilesPath; acl=$programFilesAcl; alternateName='program-files-alternate' },
        [PSCustomObject]@{ label='service'; pin='serviceCore'; entry=$targetCapture.corePair.service; originalPath=$serviceCorePath; acl=$serviceAcl; alternateName='service-alternate' }
    )) {
        $alternatePath = Join-Path ([IO.Path]::GetDirectoryName($case.originalPath)) ($case.alternateName + '-' + [Guid]::NewGuid().ToString('N') + '.exe')
        [IO.File]::WriteAllBytes($alternatePath, [IO.File]::ReadAllBytes($case.originalPath))
        Set-Acl -LiteralPath $alternatePath -AclObject $case.acl
        $alternateSha = (Get-FileHash -LiteralPath $alternatePath -Algorithm SHA256).Hash.ToLowerInvariant()
        $alternateSddl = (Get-Acl -LiteralPath $alternatePath).Sddl
        if ([IO.Path]::GetFullPath($alternatePath) -ieq [IO.Path]::GetFullPath([string]$pinnedFiles[$case.pin]) -or
            $alternateSha -cne [string]$expectedPins[$case.pin] -or
            $alternateSddl -cne [string]$case.entry.sddl) {
            throw 'Alternate live-core fixture did not preserve exact pinned bytes and ACL.'
        }
        $beforeProgramFiles = [Convert]::ToBase64String([IO.File]::ReadAllBytes($programFilesPath))
        $beforeService = [Convert]::ToBase64String([IO.File]::ReadAllBytes($serviceCorePath))
        $beforeProgramFilesSddl = (Get-Acl -LiteralPath $programFilesPath).Sddl
        $beforeServiceSddl = (Get-Acl -LiteralPath $serviceCorePath).Sddl
        $script:wrongCorePathActionCalled = $false
        $rejected = $false
        $case.entry.path = $alternatePath
        try {
            $null = Invoke-CvrIdleTargetTransaction -CaptureScript { $targetCapture } -ExpectedTargetIdentity $targetIdentity -ExpectedPins $expectedPins -ActionScript {
                $script:wrongCorePathActionCalled = $true
            } -RestoreScript { 'restored' } -VerifyScript { param($capture, $restored) $true }
        } catch {
            if ($_.Exception.Message -like 'Idle target core preimage verification failed*') {
                $rejected = $true
            } else {
                $preimageGuardFailures.Add("$($case.label) alternate path returned an unexpected guard error.")
            }
        } finally {
            $case.entry.path = $case.originalPath
        }
        if (-not $rejected) { $preimageGuardFailures.Add("$($case.label) same-byte alternate path was accepted.") }
        if ($script:wrongCorePathActionCalled) { $preimageGuardFailures.Add("$($case.label) alternate path reached the transaction action.") }
        if ([Convert]::ToBase64String([IO.File]::ReadAllBytes($programFilesPath)) -cne $beforeProgramFiles -or
            [Convert]::ToBase64String([IO.File]::ReadAllBytes($serviceCorePath)) -cne $beforeService -or
            (Get-Acl -LiteralPath $programFilesPath).Sddl -cne $beforeProgramFilesSddl -or
            (Get-Acl -LiteralPath $serviceCorePath).Sddl -cne $beforeServiceSddl) {
            $preimageGuardFailures.Add("$($case.label) alternate path changed a pinned live core.")
        }
        Remove-Item -LiteralPath $alternatePath -Force -ErrorAction Stop
    }

    # An alternate backup with exact pinned bytes and ACL still is not the pinned restore source.
    $alternateProgramFilesBackup = New-CvrCorePreimageBackupPath -Root $targetCaptureRoot -Label 'program-files'
    Write-IdleProtectedBackup -Path $alternateProgramFilesBackup -Bytes $programFilesBytes
    $alternateBackupSha = (Get-FileHash -LiteralPath $alternateProgramFilesBackup -Algorithm SHA256).Hash.ToLowerInvariant()
    $alternateBackupSddl = (Get-Acl -LiteralPath $alternateProgramFilesBackup).Sddl
    $alternateBackupDirectorySddl = (Get-Acl -LiteralPath ([IO.Path]::GetDirectoryName($alternateProgramFilesBackup))).Sddl
    if ([IO.Path]::GetFullPath($alternateProgramFilesBackup) -ieq [IO.Path]::GetFullPath([string]$targetCapture.corePair.programFiles.backupPathPin) -or
        $alternateBackupSha -cne [string]$expectedPins.programFilesCore -or
        $alternateBackupSddl -cne [string]$targetCapture.corePair.programFiles.backupSddl -or
        $alternateBackupDirectorySddl -cne [string]$targetCapture.corePair.programFiles.backupDirectorySddl) {
        throw 'Alternate backup fixture did not preserve exact pinned bytes and ACL.'
    }
    $null = Assert-CvrIdleCaptureAcl -Path $alternateProgramFilesBackup
    $null = Assert-CvrIdleCaptureAcl -Path ([IO.Path]::GetDirectoryName($alternateProgramFilesBackup)) -Directory
    $programFilesEntry = $targetCapture.corePair.programFiles
    $originalProgramFilesBackupPath = $programFilesEntry.backup
    $liveMarker = [byte[]](0x91, 0x82, 0x73, 0x64)
    $alternateBackupRejected = $false
    try {
        [IO.File]::WriteAllBytes($programFilesPath, $liveMarker)
        $liveBeforeRestore = [Convert]::ToBase64String([IO.File]::ReadAllBytes($programFilesPath))
        $programFilesEntry.backup = $alternateProgramFilesBackup
        try {
            Restore-CvrCoreFilePreimage -Entry $programFilesEntry -Role 'Program Files'
        } catch {
            $alternateBackupRejected = $_.Exception.Message -like 'Program Files core preimage backup validation failed at *'
        }
        if (-not $alternateBackupRejected) { $preimageGuardFailures.Add('same-byte alternate backup path was accepted.') }
        if ([Convert]::ToBase64String([IO.File]::ReadAllBytes($programFilesPath)) -cne $liveBeforeRestore) {
            $preimageGuardFailures.Add('same-byte alternate backup changed the live core before rejection.')
        }
    } finally {
        $programFilesEntry.backup = $originalProgramFilesBackupPath
        [IO.File]::WriteAllBytes($programFilesPath, $programFilesBytes)
        Set-Acl -LiteralPath $programFilesPath -AclObject $programFilesAcl
        Remove-Item -LiteralPath ([IO.Path]::GetDirectoryName($alternateProgramFilesBackup)) -Recurse -Force -ErrorAction Stop
    }

    # A bad backup must be rejected before Restore writes to the live core.
    $liveMarker = [byte[]](0x91, 0x82, 0x73, 0x64)
    $originalProgramFilesBackup = [IO.File]::ReadAllBytes($programFilesBackup)
    $tamperedBackupRejected = $false
    try {
        [IO.File]::WriteAllBytes($programFilesPath, $liveMarker)
        [IO.File]::WriteAllBytes($programFilesBackup, [byte[]](0x11, 0x22, 0x33))
        $liveBeforeRestore = [Convert]::ToBase64String([IO.File]::ReadAllBytes($programFilesPath))
        try {
            Restore-CvrCoreFilePreimage -Entry $targetCapture.corePair.programFiles -Role 'Program Files'
        } catch {
            $tamperedBackupRejected = $_.Exception.Message -like 'Program Files core preimage backup validation failed at *'
        }
        if (-not $tamperedBackupRejected) { $preimageGuardFailures.Add('tampered backup bytes were not rejected before restore.') }
        if ([Convert]::ToBase64String([IO.File]::ReadAllBytes($programFilesPath)) -cne $liveBeforeRestore) {
            $preimageGuardFailures.Add('tampered backup bytes changed the live core before rejection.')
        }
    } finally {
        [IO.File]::WriteAllBytes($programFilesBackup, $originalProgramFilesBackup)
        [IO.File]::WriteAllBytes($programFilesPath, $programFilesBytes)
        Set-Acl -LiteralPath $programFilesPath -AclObject $programFilesAcl
    }

    # A broadened backup ACL is also rejected before its bytes can replace the live core.
    $originalProgramFilesBackupAcl = Get-Acl -LiteralPath $programFilesBackup
    $tamperedBackupAclRejected = $false
    try {
        [IO.File]::WriteAllBytes($programFilesPath, $liveMarker)
        $invalidBackupAcl = Get-Acl -LiteralPath $programFilesBackup
        $usersSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
        $usersRule = [Security.AccessControl.FileSystemAccessRule]::new(
            $usersSid,
            [Security.AccessControl.FileSystemRights]::Modify,
            [Security.AccessControl.AccessControlType]::Allow
        )
        $null = $invalidBackupAcl.AddAccessRule($usersRule)
        Set-Acl -LiteralPath $programFilesBackup -AclObject $invalidBackupAcl
        $liveBeforeRestore = [Convert]::ToBase64String([IO.File]::ReadAllBytes($programFilesPath))
        try {
            Restore-CvrCoreFilePreimage -Entry $targetCapture.corePair.programFiles -Role 'Program Files'
        } catch {
            $tamperedBackupAclRejected = $_.Exception.Message -like 'Program Files core preimage backup validation failed at *'
        }
        if (-not $tamperedBackupAclRejected) { $preimageGuardFailures.Add('unprotected backup ACL was not rejected before restore.') }
        if ([Convert]::ToBase64String([IO.File]::ReadAllBytes($programFilesPath)) -cne $liveBeforeRestore) {
            $preimageGuardFailures.Add('unprotected backup ACL changed the live core before rejection.')
        }
    } finally {
        Set-Acl -LiteralPath $programFilesBackup -AclObject $originalProgramFilesBackupAcl
        [IO.File]::WriteAllBytes($programFilesPath, $programFilesBytes)
        Set-Acl -LiteralPath $programFilesPath -AclObject $programFilesAcl
    }
    Assert-IdleTransaction ($preimageGuardFailures.Count -eq 0) ("Core preimage security guard failed: " + ($preimageGuardFailures -join '; '))
    $script:targetCaptureOutcomes.Add([pscustomobject]@{case='core-path-binding-and-prewrite-backup-validation';result='rejected-with-live-bytes-preserved'})

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

# Synthetic package identity input for the package-to-stage capture contract.
$stageFilesRoot = Join-Path $preflightPackageRoot 'scripts'
$null = New-Item -ItemType Directory -Path $stageFilesRoot -ErrorAction Stop
$stageInputPath = Join-Path $stageFilesRoot 'capture-adapter.ps1'
[IO.File]::WriteAllText($stageInputPath, 'synthetic-stage-input', [Text.UTF8Encoding]::new($false))
$stageManifestPath = Join-Path $preflightPackageRoot 'source-manifest.json'
$stageManifest = [ordered]@{
    schemaVersion = 1
    scope = 'synthetic package-stage contract'
    files = @([ordered]@{
        path = 'scripts/capture-adapter.ps1'
        sha256 = (Get-FileHash -LiteralPath $stageInputPath -Algorithm SHA256).Hash.ToLowerInvariant()
    })
}
[IO.File]::WriteAllText(
    $stageManifestPath,
    (ConvertTo-Json -InputObject $stageManifest -Depth 4 -Compress),
    [Text.UTF8Encoding]::new($false)
)
$expectedPackageManifestSha256 = (Get-FileHash -LiteralPath $stageManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
$expectedStageRoot = [IO.Path]::GetFullPath($preflightPackageRoot)

$beforeUnboundStageCaptureCount = @(Get-ChildItem -LiteralPath $preflightLocalRoot -Directory -Filter 'capture-idle-*').Count
$unboundStageCaptureRejected = $false
try {
    $null = Save-CvrIdlePreflightCapture -Capture $targetCapture -ExpectedTargetIdentity $targetIdentity -ExpectedPins $expectedPins -PackageRoot $preflightPackageRoot
} catch {
    $unboundStageCaptureRejected = $true
}
$afterUnboundStageCaptureCount = @(Get-ChildItem -LiteralPath $preflightLocalRoot -Directory -Filter 'capture-idle-*').Count
if (-not $unboundStageCaptureRejected -or $afterUnboundStageCaptureCount -ne $beforeUnboundStageCaptureCount) {
    throw 'Idle capture accepted a staged package without its external manifest pin.'
}


function Assert-CvrIdleStageCaptureRejected {
    param(
        [string]$CaseName,
        [string]$StageRoot,
        [string]$ManifestSha256
    )
    $before = @(Get-ChildItem -LiteralPath $preflightLocalRoot -Directory -Filter 'capture-idle-*').Count
    $rejected = $false
    try {
        $null = Save-CvrIdlePreflightCapture -Capture $targetCapture -ExpectedTargetIdentity $targetIdentity -ExpectedPins $expectedPins -PackageRoot $preflightPackageRoot -ExpectedStageRoot $StageRoot -ExpectedPackageManifestSha256 $ManifestSha256
    } catch {
        $rejected = $_.Exception.Message -ceq 'Idle package stage binding failed.'
    }
    $after = @(Get-ChildItem -LiteralPath $preflightLocalRoot -Directory -Filter 'capture-idle-*').Count
    Assert-IdleTransaction ($rejected -and $after -eq $before) ("Idle capture accepted stage-binding case: " + $CaseName)
}

Assert-CvrIdleStageCaptureRejected -CaseName 'stage-path' -StageRoot ([IO.Path]::GetFullPath((Join-Path $targetCaptureRoot 'different-stage'))) -ManifestSha256 $expectedPackageManifestSha256
Assert-CvrIdleStageCaptureRejected -CaseName 'manifest-pin' -StageRoot $expectedStageRoot -ManifestSha256 '0000000000000000000000000000000000000000000000000000000000000000'

$stageInputBytes = [IO.File]::ReadAllBytes($stageInputPath)
try {
    [IO.File]::WriteAllText($stageInputPath, 'synthetic-stage-drift', [Text.UTF8Encoding]::new($false))
    Assert-CvrIdleStageCaptureRejected -CaseName 'listed-file-drift' -StageRoot $expectedStageRoot -ManifestSha256 $expectedPackageManifestSha256
} finally {
    [IO.File]::WriteAllBytes($stageInputPath, $stageInputBytes)
}

$stageManifestBytes = [IO.File]::ReadAllBytes($stageManifestPath)
$stageEscapePath = Join-Path $targetCaptureRoot 'stage-escape.txt'
[IO.File]::WriteAllText($stageEscapePath, 'synthetic-stage-escape', [Text.UTF8Encoding]::new($false))
$traversalManifest = [ordered]@{
    schemaVersion = 1
    scope = 'synthetic package-stage traversal rejection'
    files = @([ordered]@{
        path = '../stage-escape.txt'
        sha256 = (Get-FileHash -LiteralPath $stageEscapePath -Algorithm SHA256).Hash.ToLowerInvariant()
    })
}
try {
    [IO.File]::WriteAllText($stageManifestPath, (ConvertTo-Json -InputObject $traversalManifest -Depth 4 -Compress), [Text.UTF8Encoding]::new($false))
    $traversalManifestSha256 = (Get-FileHash -LiteralPath $stageManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Assert-CvrIdleStageCaptureRejected -CaseName 'manifest-traversal' -StageRoot $expectedStageRoot -ManifestSha256 $traversalManifestSha256
    $traversalManifest.files[0]['path'] = '.. /stage-escape.txt'
    [IO.File]::WriteAllText($stageManifestPath, (ConvertTo-Json -InputObject $traversalManifest -Depth 4 -Compress), [Text.UTF8Encoding]::new($false))
    $traversalManifestSha256 = (Get-FileHash -LiteralPath $stageManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Assert-CvrIdleStageCaptureRejected -CaseName 'manifest-traversal-dot-space' -StageRoot $expectedStageRoot -ManifestSha256 $traversalManifestSha256
} finally {
    [IO.File]::WriteAllBytes($stageManifestPath, $stageManifestBytes)
    Remove-Item -LiteralPath $stageEscapePath -Force -ErrorAction Stop
}

$protectedPackageAcl = Get-Acl -LiteralPath $preflightPackageRoot
$unprotectedPackageAcl = Get-Acl -LiteralPath $preflightPackageRoot
$unprotectedPackageAcl.SetAccessRuleProtection($false, $true)
Set-Acl -LiteralPath $preflightPackageRoot -AclObject $unprotectedPackageAcl -ErrorAction Stop
$beforeUnprotectedPackageCaptureCount = @(Get-ChildItem -LiteralPath $preflightLocalRoot -Directory -Filter 'capture-idle-*').Count
$unprotectedPackageRejected = $false
try {
    $null = Save-CvrIdlePreflightCapture -Capture $targetCapture -ExpectedTargetIdentity $targetIdentity -ExpectedPins $expectedPins -PackageRoot $preflightPackageRoot -ExpectedStageRoot $expectedStageRoot -ExpectedPackageManifestSha256 $expectedPackageManifestSha256
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
    $null = Save-CvrIdlePreflightCapture -Capture $targetCapture -ExpectedTargetIdentity $targetIdentity -ExpectedPins $expectedPins -PackageRoot $preflightPackageRoot -ExpectedStageRoot $expectedStageRoot -ExpectedPackageManifestSha256 $expectedPackageManifestSha256
} catch {
    $rejectedSave = $_.Exception.Message -ceq 'Idle baseline controller listener is present.'
}
$targetCapture.idleObservation.ControllerListening = [bool]$false
$afterRejectedCaptureCount = @(Get-ChildItem -LiteralPath $preflightLocalRoot -Directory -Filter 'capture-idle-*').Count
if (-not $rejectedSave -or $afterRejectedCaptureCount -ne $beforeRejectedCaptureCount) {
    throw 'Rejected idle Preflight created a capture directory.'
}

$preflight = Save-CvrIdlePreflightCapture -Capture $targetCapture -ExpectedTargetIdentity $targetIdentity -ExpectedPins $expectedPins -PackageRoot $preflightPackageRoot -ExpectedStageRoot $expectedStageRoot -ExpectedPackageManifestSha256 $expectedPackageManifestSha256
$preflightAgain = Save-CvrIdlePreflightCapture -Capture $targetCapture -ExpectedTargetIdentity $targetIdentity -ExpectedPins $expectedPins -PackageRoot $preflightPackageRoot -ExpectedStageRoot $expectedStageRoot -ExpectedPackageManifestSha256 $expectedPackageManifestSha256
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
if ([IO.Path]::GetFullPath([string]$receipt.packageStageBinding.stageRoot) -cne $expectedStageRoot -or [string]$receipt.packageStageBinding.sourceManifestSha256 -cne $expectedPackageManifestSha256) { $receiptFailures.Add('package-stage-binding') }
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
$stageInputBytesBeforePlan = [IO.File]::ReadAllBytes($stageInputPath)
$rejectedPlanForStageDrift = $false
try {
    [IO.File]::WriteAllText($stageInputPath, 'synthetic-stage-drift-before-plan', [Text.UTF8Encoding]::new($false))
    try {
        $null = Save-CvrIdlePreflightPlan -Capture $targetCapture -CaptureDirectory $preflight.CaptureDirectory -ReceiptPath $preflight.ReceiptPath -ExpectedTargetIdentity $targetIdentity -ExpectedPins $expectedPins -PackageRoot $preflightPackageRoot -ExpectedStageRoot $expectedStageRoot -ExpectedPackageManifestSha256 $expectedPackageManifestSha256
    } catch {
        $rejectedPlanForStageDrift = $_.Exception.Message -ceq 'Idle package stage binding failed.'
    }
} finally {
    [IO.File]::WriteAllBytes($stageInputPath, $stageInputBytesBeforePlan)
}
Assert-IdleTransaction ($rejectedPlanForStageDrift -and @(Get-ChildItem -LiteralPath $preflightLocalRoot -Directory -Filter 'prepared-idle-*').Count -eq $beforePreparedPlanCount) 'Idle Preflight plan accepted staged package drift or wrote output.'

$preparedPlan = Save-CvrIdlePreflightPlan -Capture $targetCapture -CaptureDirectory $preflight.CaptureDirectory -ReceiptPath $preflight.ReceiptPath -ExpectedTargetIdentity $targetIdentity -ExpectedPins $expectedPins -PackageRoot $preflightPackageRoot -ExpectedStageRoot $expectedStageRoot -ExpectedPackageManifestSha256 $expectedPackageManifestSha256
$preparedPlanAgain = Save-CvrIdlePreflightPlan -Capture $targetCapture -CaptureDirectory $preflight.CaptureDirectory -ReceiptPath $preflight.ReceiptPath -ExpectedTargetIdentity $targetIdentity -ExpectedPins $expectedPins -PackageRoot $preflightPackageRoot -ExpectedStageRoot $expectedStageRoot -ExpectedPackageManifestSha256 $expectedPackageManifestSha256
$preparedDirectory = [IO.Path]::GetFullPath($preparedPlan.PreparedDirectory)
$preparedAgainDirectory = [IO.Path]::GetFullPath($preparedPlanAgain.PreparedDirectory)
$uniquePreparedOutput = (
    [IO.Path]::GetDirectoryName($preparedDirectory) -ieq $preflightLocal -and
    [IO.Path]::GetFileName($preparedDirectory) -match '^prepared-idle-[0-9a-f]{32}$' -and
    $preparedDirectory -ine [IO.Path]::GetFullPath((Join-Path $preflightLocalRoot 'prepared')) -and
    $preparedDirectory -ine $preflightDirectory -and
    $preparedAgainDirectory -ine $preparedDirectory -and
    @(Get-ChildItem -LiteralPath $preflightLocalRoot -Directory -Filter 'prepared-idle-*').Count -eq ($beforePreparedPlanCount + 2)
)
Assert-IdleTransaction $uniquePreparedOutput 'Idle Preflight plans did not use unique siblings.'

$planText = [IO.File]::ReadAllText($preparedPlan.PlanPath)
$plan = $planText | ConvertFrom-Json
$planPinNames = @($plan.expectedPins.PSObject.Properties | ForEach-Object { $_.Name })
$planFileNames = @($plan.pinnedFiles.PSObject.Properties | ForEach-Object { $_.Name })
$planPinsMatch = (
    $planPinNames.Count -eq $expectedPinNames.Count -and
    (@($planPinNames | Sort-Object -CaseSensitive) -join '|') -ceq $expectedPinNamesText -and
    $planFileNames.Count -eq $expectedPinNames.Count -and
    (@($planFileNames | Sort-Object -CaseSensitive) -join '|') -ceq $expectedPinNamesText
)
foreach ($pinName in $expectedPinNames) {
    if ([string]$plan.expectedPins.$pinName -cne [string]$expectedPins[$pinName] -or
        [string]$plan.pinnedFiles.$pinName -cne [string]$pinnedFiles[$pinName]) {
        $planPinsMatch = $false
    }
}
$planBindingAndBaselineMatch = (
    $plan.coreShouldBeRunning -is [bool] -and -not $plan.coreShouldBeRunning -and
    $plan.targetIdentity -ceq $targetIdentity -and
    [IO.Path]::GetFullPath([string]$plan.packageStageBinding.stageRoot) -ceq $expectedStageRoot -and
    [string]$plan.packageStageBinding.sourceManifestSha256 -ceq $expectedPackageManifestSha256 -and
    [IO.Path]::GetFullPath([string]$plan.captureDirectory) -ceq $preflightDirectory -and
    [IO.Path]::GetFullPath([string]$plan.captureReceiptPath) -ceq [IO.Path]::GetFullPath($preflight.ReceiptPath) -and
    [string]$plan.captureReceiptSha256 -ceq (Get-FileHash -LiteralPath $preflight.ReceiptPath -Algorithm SHA256).Hash.ToLowerInvariant() -and
    $plan.idleObservation.CoreShouldBeRunning -is [bool] -and -not $plan.idleObservation.CoreShouldBeRunning -and
    $plan.idleObservation.ControllerListening -is [bool] -and -not $plan.idleObservation.ControllerListening -and
    [string]$plan.idleObservation.ServiceStatus -ceq 'Running' -and
    [string]$plan.idleObservation.ExpectedProgramFilesCoreSha256 -ceq $programFilesSha -and
    [string]$plan.idleObservation.ObservedProgramFilesCoreSha256 -ceq $programFilesSha -and
    [string]$plan.idleObservation.ExpectedServiceCoreSha256 -ceq $serviceSha -and
    [string]$plan.idleObservation.ObservedServiceCoreSha256 -ceq $serviceSha -and
    @($plan.idleObservation.OwnedGuiProcessIds).Count -eq 0 -and
    @($plan.idleObservation.OwnedCoreProcessIds).Count -eq 0 -and
    @($plan.idleObservation.OwnedListenerProcessIds).Count -eq 0 -and
    [string]$plan.corePair.programFiles.sha256 -ceq $programFilesSha -and
    [string]$plan.corePair.programFiles.sddl -ceq [string]$programFilesAcl.Sddl -and
    [string]$plan.corePair.service.sha256 -ceq $serviceSha -and
    [string]$plan.corePair.service.sddl -ceq [string]$serviceAcl.Sddl -and
    [IO.Path]::GetFileName([string]$plan.corePair.service.backup) -ceq 'verge-mihomo.exe' -and
    -not $planText.Contains('synthetic-profile-marker') -and
    [IO.Path]::GetFileName($preparedPlan.PlanPath) -ceq 'plan.json' -and
    (Get-FileHash -LiteralPath $preparedPlan.PlanPath -Algorithm SHA256).Hash.ToLowerInvariant() -ceq [string]$preparedPlan.PlanSha256 -and
    (Get-Acl -LiteralPath $preparedDirectory).AreAccessRulesProtected -and
    (Get-Acl -LiteralPath $preparedPlan.PlanPath).AreAccessRulesProtected
)
Assert-IdleTransaction ($planPinsMatch -and $planBindingAndBaselineMatch) 'Idle Preflight plan binding, baseline, pins, ACL or allowlist failed.'

$beforeRejectedPlanCount = @(Get-ChildItem -LiteralPath $preflightLocalRoot -Directory -Filter 'prepared-idle-*').Count
$targetCapture.idleObservation.ControllerListening = [bool]$true
$rejectedPlanForListener = $false
try {
    $null = Save-CvrIdlePreflightPlan -Capture $targetCapture -CaptureDirectory $preflight.CaptureDirectory -ReceiptPath $preflight.ReceiptPath -ExpectedTargetIdentity $targetIdentity -ExpectedPins $expectedPins -PackageRoot $preflightPackageRoot -ExpectedStageRoot $expectedStageRoot -ExpectedPackageManifestSha256 $expectedPackageManifestSha256
} catch {
    $rejectedPlanForListener = $_.Exception.Message -ceq 'Idle baseline controller listener is present.'
} finally {
    $targetCapture.idleObservation.ControllerListening = [bool]$false
}
Assert-IdleTransaction ($rejectedPlanForListener -and @(Get-ChildItem -LiteralPath $preflightLocalRoot -Directory -Filter 'prepared-idle-*').Count -eq $beforeRejectedPlanCount) 'Idle Preflight plan accepted listener drift or wrote output after rejection.'

$receiptBeforePlanDrift = [IO.File]::ReadAllText($preflight.ReceiptPath)
$receiptForPlanDrift = $receiptBeforePlanDrift | ConvertFrom-Json
$receiptForPlanDrift.targetIdentity = [Guid]::NewGuid().ToString('N')
[IO.File]::WriteAllText($preflight.ReceiptPath, (ConvertTo-Json -InputObject $receiptForPlanDrift -Depth 8 -Compress), [Text.UTF8Encoding]::new($false))
$rejectedPlanForReceiptDrift = $false
try {
    $null = Save-CvrIdlePreflightPlan -Capture $targetCapture -CaptureDirectory $preflight.CaptureDirectory -ReceiptPath $preflight.ReceiptPath -ExpectedTargetIdentity $targetIdentity -ExpectedPins $expectedPins -PackageRoot $preflightPackageRoot -ExpectedStageRoot $expectedStageRoot -ExpectedPackageManifestSha256 $expectedPackageManifestSha256
} catch {
    $rejectedPlanForReceiptDrift = $_.Exception.Message -ceq 'Idle Preflight capture receipt does not match the supplied capture.'
} finally {
    [IO.File]::WriteAllText($preflight.ReceiptPath, $receiptBeforePlanDrift, [Text.UTF8Encoding]::new($false))
}
Assert-IdleTransaction ($rejectedPlanForReceiptDrift -and @(Get-ChildItem -LiteralPath $preflightLocalRoot -Directory -Filter 'prepared-idle-*').Count -eq $beforeRejectedPlanCount) 'Idle Preflight plan accepted receipt drift or wrote output after rejection.'
Assert-IdleTransaction ([IO.File]::ReadAllText($captureMarkerPath) -ceq 'preserve-capture' -and [IO.File]::ReadAllText($preparedMarkerPath) -ceq 'preserve-prepared') 'Idle Preflight plan modified existing fixed siblings.'

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
