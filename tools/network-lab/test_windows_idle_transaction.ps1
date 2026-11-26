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

$script:packageStageBindingOriginal = (Get-Command -Name Get-CvrIdlePackageStageBinding -CommandType Function).ScriptBlock
$script:stageMutationTargets = @()
$script:stageMutationResults = @{}
function Get-CvrIdlePackageStageBinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$StageRoot,
        [Parameter(Mandatory = $true)][string]$ExpectedStageRoot,
        [Parameter(Mandatory = $true)][string]$ExpectedPackageManifestSha256
    )
    $binding = & $script:packageStageBindingOriginal @PSBoundParameters
    foreach ($target in @($script:stageMutationTargets)) {
        $tempPath = Join-Path ([IO.Path]::GetDirectoryName([string]$target.Path)) ([IO.Path]::GetFileName([string]$target.Path) + '.race-' + [Guid]::NewGuid().ToString('N'))
        [IO.File]::WriteAllBytes($tempPath, [byte[]]$target.Bytes)
        $replaceException = $null
        $writeException = $null
        $replaced = $false
        $wrote = $false
        $backupPath = $tempPath + '.backup'
        try { [IO.File]::Replace($tempPath, [string]$target.Path, $backupPath); $replaced = $true } catch { $replaceException = $_.Exception.GetBaseException().GetType().FullName }
        try { [IO.File]::WriteAllBytes([string]$target.Path, [byte[]]$target.Bytes); $wrote = $true } catch { $writeException = $_.Exception.GetBaseException().GetType().FullName }
        if (Test-Path -LiteralPath $tempPath) { Remove-Item -LiteralPath $tempPath -Force -ErrorAction Stop }
        if (Test-Path -LiteralPath $backupPath) { Remove-Item -LiteralPath $backupPath -Force -ErrorAction Stop }
        $script:stageMutationResults[[string]$target.Name] = [PSCustomObject]@{
            Replaced = $replaced
            Wrote = $wrote
            ReplaceIOException = $replaceException -ceq 'System.IO.IOException'
            WriteIOException = $writeException -ceq 'System.IO.IOException'
        }
    }
    return $binding
}

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

$targetCaptureRoot = Join-Path ([IO.Path]::GetTempPath()) ('stcvrc-idle-target-capture-' + [char]0x03BB + [Guid]::NewGuid().ToString('N'))
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
$null = Set-CvrIdleCaptureAcl -Path $stageFilesRoot -Directory
$stageInputPath = Join-Path $stageFilesRoot 'capture-adapter.ps1'
[IO.File]::WriteAllBytes($stageInputPath, [byte[]]@())
$null = Set-CvrIdleCaptureAcl -Path $stageInputPath
[IO.File]::WriteAllText($stageInputPath, 'synthetic-stage-input', [Text.UTF8Encoding]::new($false))
$stageManifestPath = Join-Path $preflightPackageRoot 'source-manifest.json'
[IO.File]::WriteAllBytes($stageManifestPath, [byte[]]@())
$null = Set-CvrIdleCaptureAcl -Path $stageManifestPath
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

function Invoke-CvrIdleStageAclCase {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][ValidateSet('Capture','Plan')][string]$WriterMode
    )
    $filter = if ($WriterMode -ceq 'Capture') { 'capture-idle-*' } else { 'prepared-idle-*' }
    $before = @(Get-ChildItem -LiteralPath $preflightLocalRoot -Directory -Filter $filter -ErrorAction Stop | ForEach-Object { $_.FullName })
    $originalAcl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $untrustedAcl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $untrustedSid = [Security.Principal.SecurityIdentifier]::new('S-1-1-0')
    $untrustedRule = [Security.AccessControl.FileSystemAccessRule]::new(
        $untrustedSid,
        [Security.AccessControl.FileSystemRights]::Modify,
        [Security.AccessControl.AccessControlType]::Allow
    )
    $null = $untrustedAcl.AddAccessRule($untrustedRule)
    Set-Acl -LiteralPath $Path -AclObject $untrustedAcl -ErrorAction Stop
    $failure = $null
    try {
        if ($WriterMode -ceq 'Capture') {
            $null = Save-CvrIdlePreflightCapture -Capture $targetCapture -ExpectedTargetIdentity $targetIdentity -ExpectedPins $expectedPins -PackageRoot $preflightPackageRoot -ExpectedStageRoot $expectedStageRoot -ExpectedPackageManifestSha256 $expectedPackageManifestSha256
        } else {
            $null = Save-CvrIdlePreflightPlan -Capture $targetCapture -CaptureDirectory $preflight.CaptureDirectory -ReceiptPath $preflight.ReceiptPath -ExpectedTargetIdentity $targetIdentity -ExpectedPins $expectedPins -PackageRoot $preflightPackageRoot -ExpectedStageRoot $expectedStageRoot -ExpectedPackageManifestSha256 $expectedPackageManifestSha256
        }
    } catch {
        $failure = $_.Exception.Message
    } finally {
        Set-Acl -LiteralPath $Path -AclObject $originalAcl -ErrorAction Stop
    }
    $after = @(Get-ChildItem -LiteralPath $preflightLocalRoot -Directory -Filter $filter -ErrorAction Stop)
    $created = @($after | Where-Object { $before -notcontains $_.FullName })
    $rejectedWithoutOutput = $failure -ceq 'Idle package stage binding failed.' -and $created.Count -eq 0
    foreach ($directory in $created) {
        Remove-Item -LiteralPath $directory.FullName -Recurse -Force -ErrorAction Stop
    }
    return [bool]$rejectedWithoutOutput
}

function Invoke-CvrIdleStageBoundaryCase {
    param([Parameter(Mandatory = $true)][ValidateSet('Capture','Plan')][string]$WriterMode)
    $manifestBefore = [IO.File]::ReadAllBytes($stageManifestPath)
    $entryBefore = [IO.File]::ReadAllBytes($stageInputPath)
    $manifestAclBefore = Get-Acl -LiteralPath $stageManifestPath
    $entryAclBefore = Get-Acl -LiteralPath $stageInputPath
    $manifestReplacement = [ordered]@{
        schemaVersion = 1
        scope = 'synthetic package-stage boundary mutation'
        files = @([ordered]@{
            path = 'scripts/capture-adapter.ps1'
            sha256 = (Get-FileHash -LiteralPath $stageInputPath -Algorithm SHA256).Hash.ToLowerInvariant()
        })
    }
    $script:stageMutationResults = @{}
    $script:stageMutationTargets = @(
        [PSCustomObject]@{
            Name = 'manifest'
            Path = $stageManifestPath
            Bytes = [Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-Json -InputObject $manifestReplacement -Depth 4 -Compress))
        },
        [PSCustomObject]@{
            Name = 'entry'
            Path = $stageInputPath
            Bytes = [Text.UTF8Encoding]::new($false).GetBytes('synthetic-stage-boundary-mutation')
        }
    )
    $filter = if ($WriterMode -ceq 'Capture') { 'capture-idle-*' } else { 'prepared-idle-*' }
    $before = @(Get-ChildItem -LiteralPath $preflightLocalRoot -Directory -Filter $filter -ErrorAction Stop | ForEach-Object { $_.FullName })
    $output = $null
    $failure = $null
    try {
        if ($WriterMode -ceq 'Capture') {
            $output = Save-CvrIdlePreflightCapture -Capture $targetCapture -ExpectedTargetIdentity $targetIdentity -ExpectedPins $expectedPins -PackageRoot $preflightPackageRoot -ExpectedStageRoot $expectedStageRoot -ExpectedPackageManifestSha256 $expectedPackageManifestSha256
        } else {
            $output = Save-CvrIdlePreflightPlan -Capture $targetCapture -CaptureDirectory $preflight.CaptureDirectory -ReceiptPath $preflight.ReceiptPath -ExpectedTargetIdentity $targetIdentity -ExpectedPins $expectedPins -PackageRoot $preflightPackageRoot -ExpectedStageRoot $expectedStageRoot -ExpectedPackageManifestSha256 $expectedPackageManifestSha256
        }
    } catch {
        $failure = $_.Exception.Message
    } finally {
        $script:stageMutationTargets = @()
        [IO.File]::WriteAllBytes($stageManifestPath, $manifestBefore)
        [IO.File]::WriteAllBytes($stageInputPath, $entryBefore)
        Set-Acl -LiteralPath $stageManifestPath -AclObject $manifestAclBefore -ErrorAction Stop
        Set-Acl -LiteralPath $stageInputPath -AclObject $entryAclBefore -ErrorAction Stop
    }
    $after = @(Get-ChildItem -LiteralPath $preflightLocalRoot -Directory -Filter $filter -ErrorAction Stop)
    $created = @($after | Where-Object { $before -notcontains $_.FullName })
    $bindingMatches = $false
    if ($output) {
        $outputPath = if ($WriterMode -ceq 'Capture') { $output.ReceiptPath } else { $output.PlanPath }
        $outputBinding = [IO.File]::ReadAllText($outputPath) | ConvertFrom-Json -ErrorAction Stop
        $bindingMatches = [IO.Path]::GetFullPath([string]$outputBinding.packageStageBinding.stageRoot) -ceq $expectedStageRoot -and
            [string]$outputBinding.packageStageBinding.sourceManifestSha256 -ceq $expectedPackageManifestSha256
    }
    $mutationBlocked = $script:stageMutationResults.Count -eq 2
    foreach ($name in @('manifest','entry')) {
        $result = $script:stageMutationResults[$name]
        if (-not $result -or $result.Replaced -or $result.Wrote -or
            -not $result.ReplaceIOException -or -not $result.WriteIOException) {
            $mutationBlocked = $false
        }
    }
    $safe = $mutationBlocked -and $null -eq $failure -and $output -and $bindingMatches -and $created.Count -eq 1
    foreach ($directory in $created) {
        Remove-Item -LiteralPath $directory.FullName -Recurse -Force -ErrorAction Stop
    }
    return [bool]$safe
}

$stageManifestAclCaptureSafe = Invoke-CvrIdleStageAclCase -Path $stageManifestPath -WriterMode Capture

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

# Exercise unsafe paths with a valid no-digit staged entry and externally pinned manifest.
$stageBoundaryInputPath = Join-Path $stageFilesRoot 'adapter.txt'
[IO.File]::WriteAllBytes($stageBoundaryInputPath, [byte[]]@())
$null = Set-CvrIdleCaptureAcl -Path $stageBoundaryInputPath
[IO.File]::WriteAllText($stageBoundaryInputPath, 'synthetic-stage-path-input', [Text.UTF8Encoding]::new($false))
$stageBoundaryInputSha256 = (Get-FileHash -LiteralPath $stageBoundaryInputPath -Algorithm SHA256).Hash.ToLowerInvariant()
$stageManifestBytesForPathCases = [IO.File]::ReadAllBytes($stageManifestPath)
$stageManifestAclForPathCases = Get-Acl -LiteralPath $stageManifestPath -ErrorAction Stop
try {
    $stagePathRejectionCases = @(
        [PSCustomObject]@{ Name = 'rooted'; Path = $stageBoundaryInputPath },
        [PSCustomObject]@{ Name = 'backslash'; Path = 'scripts\adapter.txt' },
        [PSCustomObject]@{ Name = 'colon'; Path = 'scripts/adapter.txt:stream' },
        [PSCustomObject]@{ Name = 'control'; Path = ('scripts/' + [char]0x1f + 'adapter.txt') }
    )
    foreach ($case in $stagePathRejectionCases) {
        $candidateManifest = [ordered]@{
            schemaVersion = 1
            scope = 'synthetic package-stage path rejection'
            files = @([ordered]@{ path = [string]$case.Path; sha256 = $stageBoundaryInputSha256 })
        }
        [IO.File]::WriteAllText($stageManifestPath, (ConvertTo-Json -InputObject $candidateManifest -Depth 4 -Compress), [Text.UTF8Encoding]::new($false))
        $candidateManifestSha256 = (Get-FileHash -LiteralPath $stageManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
        Assert-CvrIdleStageCaptureRejected -CaseName ("manifest-" + $case.Name) -StageRoot $expectedStageRoot -ManifestSha256 $candidateManifestSha256
    }

    [IO.File]::WriteAllBytes($stageManifestPath, $stageManifestBytesForPathCases)
    Set-Acl -LiteralPath $stageManifestPath -AclObject $stageManifestAclForPathCases -ErrorAction Stop

    $digitPathBinding = $null
    $digitPathFailure = $null
    try {
        $digitPathBinding = Get-CvrIdlePackageStageBinding -StageRoot $expectedStageRoot -ExpectedStageRoot $expectedStageRoot -ExpectedPackageManifestSha256 $expectedPackageManifestSha256
    } catch {
        $digitPathFailure = $_.Exception.Message
    }
    $digitPathAccepted = $null -eq $digitPathFailure -and $digitPathBinding -and
        $digitPathBinding.StageRoot -ceq $expectedStageRoot -and
        $digitPathBinding.SourceManifestSha256 -ceq $expectedPackageManifestSha256
    if ($digitPathBinding) {
        foreach ($handle in @($digitPathBinding.OpenFiles)) {
            if ($handle) { $handle.Dispose() }
        }
    }
    Assert-IdleTransaction ([bool]$digitPathAccepted) 'Valid digit-containing relative stage path was rejected.'
} finally {
    [IO.File]::WriteAllBytes($stageManifestPath, $stageManifestBytesForPathCases)
    Set-Acl -LiteralPath $stageManifestPath -AclObject $stageManifestAclForPathCases -ErrorAction Stop
    Remove-Item -LiteralPath $stageBoundaryInputPath -Force -ErrorAction Stop
}

$preflight = Save-CvrIdlePreflightCapture -Capture $targetCapture -ExpectedTargetIdentity $targetIdentity -ExpectedPins $expectedPins -PackageRoot $preflightPackageRoot -ExpectedStageRoot $expectedStageRoot -ExpectedPackageManifestSha256 $expectedPackageManifestSha256
$stageEntryAclPlanSafe = Invoke-CvrIdleStageAclCase -Path $stageInputPath -WriterMode Plan
$stageBoundaryCaptureSafe = Invoke-CvrIdleStageBoundaryCase -WriterMode Capture
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

$stageBoundaryPlanSafe = Invoke-CvrIdleStageBoundaryCase -WriterMode Plan
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


# Reproduce the prepared Capture caller's pre-binding argument set, then exercise
# one data-free entrypoint for both Capture and Plan.
$legacyCaptureArguments = @{
    Capture = $targetCapture
    ExpectedTargetIdentity = $targetIdentity
    ExpectedPins = $expectedPins
    PackageRoot = $preflightPackageRoot
}
$legacyCaptureCount = @(Get-ChildItem -LiteralPath $preflightLocalRoot -Directory -Filter 'capture-idle-*' -ErrorAction Stop).Count
$legacyCaptureErrorId = $null
try {
    $null = Save-CvrIdlePreflightCapture @legacyCaptureArguments
} catch {
    $legacyCaptureErrorId = [string]$_.FullyQualifiedErrorId
}
$legacyCaptureCountAfter = @(Get-ChildItem -LiteralPath $preflightLocalRoot -Directory -Filter 'capture-idle-*' -ErrorAction Stop).Count
Assert-IdleTransaction ($legacyCaptureErrorId -like '*MissingMandatoryParameter*' -and $legacyCaptureCountAfter -eq $legacyCaptureCount) 'The prepared Capture caller must supply the external stage root and manifest digest before writing.'
Write-Host 'Legacy Capture caller arguments rejected before output: missing external stage identity.'

$portableCaptureArguments = @{
    Mode = 'Capture'
    Capture = $targetCapture
    ExpectedTargetIdentity = $targetIdentity
    ExpectedPins = $expectedPins
    PackageRoot = $preflightPackageRoot
    ExpectedStageRoot = $expectedStageRoot
    ExpectedPackageManifestSha256 = $expectedPackageManifestSha256
}
$portableCapture = $null
$portableCaptureErrorId = $null
try {
    $portableCapture = Invoke-CvrIdlePreflightPackageWriter @portableCaptureArguments
} catch {
    $portableCaptureErrorId = [string]$_.FullyQualifiedErrorId
}
Assert-IdleTransaction ($null -eq $portableCaptureErrorId -and $null -ne $portableCapture) 'The shared portable Capture entrypoint did not produce a bound capture.'

$portablePlanArguments = @{
    Mode = 'Plan'
    Capture = $targetCapture
    CaptureDirectory = $portableCapture.CaptureDirectory
    ReceiptPath = $portableCapture.ReceiptPath
    ExpectedTargetIdentity = $targetIdentity
    ExpectedPins = $expectedPins
    PackageRoot = $preflightPackageRoot
    ExpectedStageRoot = $expectedStageRoot
    ExpectedPackageManifestSha256 = $expectedPackageManifestSha256
}
$portablePlanErrorId = $null
$portablePlan = $null
try {
    $portablePlan = Invoke-CvrIdlePreflightPackageWriter @portablePlanArguments
} catch {
    $portablePlanErrorId = [string]$_.FullyQualifiedErrorId
}
Assert-IdleTransaction ($null -eq $portablePlanErrorId -and $null -ne $portablePlan) 'The shared portable Plan entrypoint did not produce a bound plan.'

$portableCaptureRecord = [IO.File]::ReadAllText($portableCapture.ReceiptPath) | ConvertFrom-Json -ErrorAction Stop
$portablePlanRecord = [IO.File]::ReadAllText($portablePlan.PlanPath) | ConvertFrom-Json -ErrorAction Stop
$portableCaptureBound = [IO.Path]::GetFullPath([string]$portableCaptureRecord.packageStageBinding.stageRoot) -ceq $expectedStageRoot -and
    [string]$portableCaptureRecord.packageStageBinding.sourceManifestSha256 -ceq $expectedPackageManifestSha256
$portablePlanBound = [IO.Path]::GetFullPath([string]$portablePlanRecord.packageStageBinding.stageRoot) -ceq $expectedStageRoot -and
    [string]$portablePlanRecord.packageStageBinding.sourceManifestSha256 -ceq $expectedPackageManifestSha256
Assert-IdleTransaction ($portableCaptureBound -and $portablePlanBound) 'Capture or Plan did not persist the independently supplied stage identity.'

function Assert-CvrIdlePortableWriterRejects {
    param(
        [Parameter(Mandatory = $true)][string]$CaseName,
        [Parameter(Mandatory = $true)][hashtable]$Arguments,
        [Parameter(Mandatory = $true)][ValidateSet('capture-idle-*','prepared-idle-*')][string]$OutputFilter
    )
    $before = @(Get-ChildItem -LiteralPath $preflightLocalRoot -Directory -Filter $OutputFilter -ErrorAction Stop).Count
    $rejected = $false
    try {
        $null = Invoke-CvrIdlePreflightPackageWriter @Arguments
    } catch {
        $rejected = $true
    }
    $after = @(Get-ChildItem -LiteralPath $preflightLocalRoot -Directory -Filter $OutputFilter -ErrorAction Stop).Count
    Assert-IdleTransaction ($rejected -and $after -eq $before) ("Portable " + $CaseName + " entrypoint did not reject before output.")
}

$missingCaptureStageRoot = $portableCaptureArguments.Clone()
$null = $missingCaptureStageRoot.Remove('ExpectedStageRoot')
Assert-CvrIdlePortableWriterRejects -CaseName 'Capture missing stage root' -Arguments $missingCaptureStageRoot -OutputFilter 'capture-idle-*'
$missingCaptureManifestPin = $portableCaptureArguments.Clone()
$null = $missingCaptureManifestPin.Remove('ExpectedPackageManifestSha256')
Assert-CvrIdlePortableWriterRejects -CaseName 'Capture missing manifest digest' -Arguments $missingCaptureManifestPin -OutputFilter 'capture-idle-*'
$wrongCaptureStageRoot = $portableCaptureArguments.Clone()
$wrongCaptureStageRoot['ExpectedStageRoot'] = Join-Path $targetCaptureRoot 'different-stage'
Assert-CvrIdlePortableWriterRejects -CaseName 'Capture wrong stage root' -Arguments $wrongCaptureStageRoot -OutputFilter 'capture-idle-*'
$wrongCaptureManifestPin = $portableCaptureArguments.Clone()
$wrongCaptureManifestPin['ExpectedPackageManifestSha256'] = '0000000000000000000000000000000000000000000000000000000000000000'
Assert-CvrIdlePortableWriterRejects -CaseName 'Capture wrong manifest digest' -Arguments $wrongCaptureManifestPin -OutputFilter 'capture-idle-*'

$missingPlanStageRoot = $portablePlanArguments.Clone()
$null = $missingPlanStageRoot.Remove('ExpectedStageRoot')
Assert-CvrIdlePortableWriterRejects -CaseName 'Plan missing stage root' -Arguments $missingPlanStageRoot -OutputFilter 'prepared-idle-*'
$missingPlanManifestPin = $portablePlanArguments.Clone()
$null = $missingPlanManifestPin.Remove('ExpectedPackageManifestSha256')
Assert-CvrIdlePortableWriterRejects -CaseName 'Plan missing manifest digest' -Arguments $missingPlanManifestPin -OutputFilter 'prepared-idle-*'
$wrongPlanStageRoot = $portablePlanArguments.Clone()
$wrongPlanStageRoot['ExpectedStageRoot'] = Join-Path $targetCaptureRoot 'different-stage'
Assert-CvrIdlePortableWriterRejects -CaseName 'Plan wrong stage root' -Arguments $wrongPlanStageRoot -OutputFilter 'prepared-idle-*'
$wrongPlanManifestPin = $portablePlanArguments.Clone()
$wrongPlanManifestPin['ExpectedPackageManifestSha256'] = '0000000000000000000000000000000000000000000000000000000000000000'
Assert-CvrIdlePortableWriterRejects -CaseName 'Plan wrong manifest digest' -Arguments $wrongPlanManifestPin -OutputFilter 'prepared-idle-*'

$script:targetCaptureOutcomes.Add([pscustomobject]@{
    case = 'portable-capture-plan-stage-binding'
    result = 'bound-identity-and-rejected-missing-or-mismatched-inputs-before-output'
})

$packageWriterCliPath = Join-Path $PSScriptRoot 'windows_idle_preflight_package_writer.ps1'
if (-not (Test-Path -LiteralPath $packageWriterCliPath -PathType Leaf)) {
    throw 'Expected behavior RED: executable Capture and Plan package writer is missing.'
}

function Quote-CvrPackageWriterArgument([string]$Value) {
    if ($Value.Contains('"')) { throw 'Unsafe synthetic package-writer argument.' }
    return '"' + $Value + '"'
}

function Invoke-CvrPackageWriterCli([string]$CaseName, [hashtable]$Arguments) {
    $caseLabel = $CaseName -replace '[^A-Za-z0-9-]', '-'
    $timeoutSeconds = if ($Arguments.ContainsKey('TimeoutSeconds')) { [int]$Arguments.TimeoutSeconds } else { 45 }
    if ($timeoutSeconds -lt 10 -or $timeoutSeconds -gt 60) { throw 'Invalid synthetic process timeout.' }
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $workBudgetMilliseconds = ($timeoutSeconds - 5) * 1000
    $process = $null
    $started = $false
    $stdoutTask = $null
    $stderrTask = $null
    $state = 'failure'
    $stage = 'request-serialize'
    $callDirectory = $null
    $childStopped = $true
    $stdout = ''
    $stderr = ''
    $workerStdOut = ''

    function Get-CvrPackageWriterWorkerMarkers([string]$MarkerText) {
        $lastStage = 'request-serialize'
        $pattern = '^package-writer case=' + [regex]::Escape($caseLabel) + ' stage=([a-z-]+)(?: (?:exit=[0-9]+|child-stopped=(?:True|False)))?$'
        foreach ($line in [regex]::Split([string]$MarkerText, '\r?\n')) {
            if ($line -match $pattern) {
                Write-Host $line
                $markerStage = $Matches[1]
                if ($markerStage -match '^(?:before|after)-(.+)$') { $lastStage = $Matches[1] }
                else { $lastStage = $markerStage }
            }
        }
        return $lastStage
    }

    try {
        $request = $Arguments.Request
        if ($request -isnot [System.Collections.IDictionary]) { throw 'Invalid synthetic package-writer request.' }
        $syntheticRequest = -not $request.Contains('Capture')
        $pinnedFilesBase64 = ''
        if (-not $syntheticRequest) {
            $pinNames = @(
                'gui258', 'serviceExe258', 'programFilesCore', 'serviceCore',
                'candidateCore', 'updateInstaller', 'updateHelper',
                'recoveryInstaller', 'recoveryHelper'
            )
            $encodedPaths = [Collections.Generic.List[string]]::new()
            foreach ($pinName in $pinNames) {
                $pathValue = [string]$request.Capture.pinnedFiles[$pinName]
                $pathBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($pathValue)
                $encodedPaths.Add([Convert]::ToBase64String($pathBytes))
            }
            $pinnedFilesBase64 = [string]::Join(',', $encodedPaths.ToArray())
        }

        $callDirectory = Join-Path $targetCaptureRoot ('package-writer-call-' + [Guid]::NewGuid().ToString('N'))
        $null = [IO.Directory]::CreateDirectory($callDirectory)
        $workerPath = Join-Path $PSScriptRoot 'windows_idle_preflight_package_writer_call.ps1'
        $writerPath = if ($Arguments.ContainsKey('ScriptPath')) { [string]$Arguments.ScriptPath } else { $packageWriterCliPath }
        $powershell51 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $commandLineParts = @(
            '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'RemoteSigned',
            '-File', (Quote-CvrPackageWriterArgument $workerPath),
            '-Mode', (Quote-CvrPackageWriterArgument ([string]$Arguments.Mode)),
            '-CaseName', (Quote-CvrPackageWriterArgument $caseLabel),
            '-WriterScriptPath', (Quote-CvrPackageWriterArgument $writerPath),
            '-CaptureSourceReceiptPath', (Quote-CvrPackageWriterArgument ([string]$preflight.ReceiptPath)),
            '-ExpectedTargetIdentity', (Quote-CvrPackageWriterArgument ([string]$request.ExpectedTargetIdentity)),
            '-PackageRoot', (Quote-CvrPackageWriterArgument ([string]$request.PackageRoot)),
            '-CallDirectory', (Quote-CvrPackageWriterArgument $callDirectory)
        )
        if (-not $syntheticRequest) {
            $commandLineParts += @('-PinnedFilePathsBase64', (Quote-CvrPackageWriterArgument $pinnedFilesBase64))
        } else {
            $commandLineParts += '-SyntheticRequest'
        }
        if ($request.Contains('ExpectedStageRoot')) {
            $commandLineParts += @('-HasExpectedStageRoot', '-ExpectedStageRoot', (Quote-CvrPackageWriterArgument ([string]$request.ExpectedStageRoot)))
        }
        if ($request.Contains('ExpectedPackageManifestSha256')) {
            $commandLineParts += @('-HasExpectedPackageManifestSha256', '-ExpectedPackageManifestSha256', (Quote-CvrPackageWriterArgument ([string]$request.ExpectedPackageManifestSha256)))
        }
        if ([string]$Arguments.Mode -eq 'Plan') {
            $commandLineParts += @(
                '-CaptureDirectory', (Quote-CvrPackageWriterArgument ([string]$request.CaptureDirectory)),
                '-PlanReceiptPath', (Quote-CvrPackageWriterArgument ([string]$request.ReceiptPath))
            )
        }
        if ($Arguments.ContainsKey('SyntheticSerializationDelaySeconds')) {
            $commandLineParts += @('-SyntheticSerializationDelaySeconds', (Quote-CvrPackageWriterArgument ([string]$Arguments.SyntheticSerializationDelaySeconds)))
        }
        if ($Arguments.ContainsKey('SyntheticWaitBeforeWriterPidWrite') -and $Arguments.SyntheticWaitBeforeWriterPidWrite) {
            $commandLineParts += '-SyntheticWaitBeforeWriterPidWrite'
        }

        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = $powershell51
        $startInfo.Arguments = $commandLineParts -join ' '
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $startInfo.StandardOutputEncoding = [Text.UTF8Encoding]::new($false, $true)
        $startInfo.StandardErrorEncoding = [Text.UTF8Encoding]::new($false, $true)
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $startInfo

        $stage = 'worker-start'
        if (-not $process.Start()) { throw 'package-writer call worker failed to start' }
        $started = $true
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()

        $stage = 'request-serialize'
        $remainingMilliseconds = [int][Math]::Max(1, ($workBudgetMilliseconds - $timer.ElapsedMilliseconds))
        if (-not $process.WaitForExit($remainingMilliseconds)) {
            $state = 'timeout'
            throw 'package-writer call deadline'
        }

        $stage = 'stdout-read'
        $remainingMilliseconds = [int][Math]::Max(1, ($timeoutSeconds * 1000 - $timer.ElapsedMilliseconds))
        if (-not $stdoutTask.Wait($remainingMilliseconds)) {
            $state = 'timeout'
            throw 'package-writer call stdout deadline'
        }
        $workerStdOut = $stdoutTask.GetAwaiter().GetResult()
        $stage = Get-CvrPackageWriterWorkerMarkers $workerStdOut

        $stage = 'stderr-read'
        $remainingMilliseconds = [int][Math]::Max(1, ($timeoutSeconds * 1000 - $timer.ElapsedMilliseconds))
        if (-not $stderrTask.Wait($remainingMilliseconds)) {
            $state = 'timeout'
            throw 'package-writer call stderr deadline'
        }
        $null = $stderrTask.GetAwaiter().GetResult()

        $statusPath = Join-Path $callDirectory 'result.txt'
        $stdoutPath = Join-Path $callDirectory 'writer.stdout'
        $stderrPath = Join-Path $callDirectory 'writer.stderr'
        if (-not (Test-Path -LiteralPath $statusPath -PathType Leaf)) { throw 'package-writer call returned no result' }
        $statusFields = @{}
        foreach ($line in [IO.File]::ReadAllLines($statusPath, [Text.UTF8Encoding]::new($false, $true))) {
            $separator = $line.IndexOf('=')
            if ($separator -gt 0) { $statusFields[$line.Substring(0, $separator)] = $line.Substring($separator + 1) }
        }
        foreach ($requiredField in @('State', 'Stage', 'ExitCode', 'ChildStopped')) {
            if (-not $statusFields.ContainsKey($requiredField)) { throw 'package-writer call result was incomplete' }
        }
        $state = [string]$statusFields.State
        $stage = [string]$statusFields.Stage
        $exitCode = [int]$statusFields.ExitCode
        $childStopped = [bool]::Parse([string]$statusFields.ChildStopped)
        foreach ($outputPath in @($stdoutPath, $stderrPath)) {
            if (-not (Test-Path -LiteralPath $outputPath -PathType Leaf) -or (Get-Item -LiteralPath $outputPath).Length -gt 65536) {
                throw 'package-writer call output exceeded the fixture limit'
            }
        }
        $encoding = [Text.UTF8Encoding]::new($false, $true)
        $stdout = [IO.File]::ReadAllText($stdoutPath, $encoding)
        $stderr = [IO.File]::ReadAllText($stderrPath, $encoding)
        return [PSCustomObject]@{
            State = $state
            Stage = $stage
            ExitCode = $exitCode
            StdOut = $stdout
            StdErr = $stderr
            ChildStopped = $childStopped
            ElapsedMilliseconds = [int]$timer.ElapsedMilliseconds
            CallDirectory = $callDirectory
        }
    } catch {
        $failedStage = $stage
        if ($state -ne 'timeout') { $state = 'failure' }
        Write-Host ('package-writer case=' + $caseLabel + ' stage=before-cleanup')
        $treeKillSucceeded = $false
        if ($started -and $process -and -not $process.HasExited) {
            $taskkill = $null
            try {
                $killInfo = New-Object System.Diagnostics.ProcessStartInfo
                $killInfo.FileName = Join-Path $env:SystemRoot 'System32\taskkill.exe'
                $killInfo.Arguments = '/PID ' + [string]$process.Id + ' /T /F'
                $killInfo.UseShellExecute = $false
                $killInfo.CreateNoWindow = $true
                $killInfo.RedirectStandardOutput = $true
                $killInfo.RedirectStandardError = $true
                $taskkill = New-Object System.Diagnostics.Process
                $taskkill.StartInfo = $killInfo
                if ($taskkill.Start()) {
                    $killOutTask = $taskkill.StandardOutput.ReadToEndAsync()
                    $killErrTask = $taskkill.StandardError.ReadToEndAsync()
                    $killWait = [int][Math]::Max(0, [Math]::Min(2000, ($timeoutSeconds * 1000 - $timer.ElapsedMilliseconds)))
                    if ($killWait -gt 0 -and $taskkill.WaitForExit($killWait)) {
                        $treeKillSucceeded = ($taskkill.ExitCode -eq 0)
                    } elseif (-not $taskkill.HasExited) {
                        try { $taskkill.Kill() } catch {}
                    }
                    $remainingKillRead = [int][Math]::Max(0, ($timeoutSeconds * 1000 - $timer.ElapsedMilliseconds))
                    if ($killOutTask -and $remainingKillRead -gt 0) { try { $null = $killOutTask.Wait($remainingKillRead) } catch {} }
                    if ($killErrTask -and $remainingKillRead -gt 0) { try { $null = $killErrTask.Wait($remainingKillRead) } catch {} }
                }
            } catch {}
            if ($taskkill) { $taskkill.Dispose() }
            $remainingMilliseconds = [int][Math]::Max(0, ($timeoutSeconds * 1000 - $timer.ElapsedMilliseconds))
            if (-not $process.HasExited -and $remainingMilliseconds -gt 0) {
                try { $null = $process.WaitForExit($remainingMilliseconds) } catch {}
            }
            if (-not $process.HasExited) {
                try { $process.Kill() } catch {}
                $remainingMilliseconds = [int][Math]::Max(0, ($timeoutSeconds * 1000 - $timer.ElapsedMilliseconds))
                if ($remainingMilliseconds -gt 0) { try { $null = $process.WaitForExit($remainingMilliseconds) } catch {} }
            }
        }

        if ($stdoutTask -and -not $stdoutTask.IsCompleted) {
            $remainingMilliseconds = [int][Math]::Max(0, ($timeoutSeconds * 1000 - $timer.ElapsedMilliseconds))
            if ($remainingMilliseconds -gt 0) { try { $null = $stdoutTask.Wait($remainingMilliseconds) } catch {} }
        }
        if ($stderrTask -and -not $stderrTask.IsCompleted) {
            $remainingMilliseconds = [int][Math]::Max(0, ($timeoutSeconds * 1000 - $timer.ElapsedMilliseconds))
            if ($remainingMilliseconds -gt 0) { try { $null = $stderrTask.Wait($remainingMilliseconds) } catch {} }
        }
        if ($stdoutTask -and $stdoutTask.IsCompleted) {
            try { $workerStdOut = $stdoutTask.GetAwaiter().GetResult() } catch {}
        }
        $markerStage = Get-CvrPackageWriterWorkerMarkers $workerStdOut
        if ($failedStage -in @('request-serialize', 'worker-start')) { $failedStage = $markerStage }

        $supervisorStopped = -not $started
        if ($started -and $process) { try { $supervisorStopped = [bool]$process.HasExited } catch { $supervisorStopped = $false } }
        $writerChildStopped = $supervisorStopped
        $writerPidPath = if ($callDirectory) { Join-Path $callDirectory 'writer.pid' } else { $null }
        if ($writerChildStopped -and $writerPidPath -and (Test-Path -LiteralPath $writerPidPath -PathType Leaf)) {
            try {
                $pidParts = [IO.File]::ReadAllText($writerPidPath).Split('|')
                if ($pidParts.Count -ne 2) { $writerChildStopped = $false }
                else {
                    $recordedPid = [int]$pidParts[0]
                    $recordedStart = [long]$pidParts[1]
                    try {
                        $candidateProcess = [Diagnostics.Process]::GetProcessById($recordedPid)
                        $writerChildStopped = ($candidateProcess.StartTime.ToUniversalTime().Ticks -ne $recordedStart)
                        $candidateProcess.Dispose()
                    } catch [ArgumentException] {
                        $writerChildStopped = $true
                    } catch {
                        $writerChildStopped = $false
                    }
                }
            } catch {
                $writerChildStopped = $false
            }
        } elseif ($started -and $supervisorStopped -and $writerPidPath -and -not (Test-Path -LiteralPath $writerPidPath -PathType Leaf)) {
            $writerChildStopped = $treeKillSucceeded
        }
        $childStopped = $supervisorStopped -and $writerChildStopped
        Write-Host ('package-writer case=' + $caseLabel + ' stage=after-cleanup child-stopped=' + $childStopped)
        $exitCode = $null
        if ($started -and $process -and $process.HasExited) { $exitCode = [int]$process.ExitCode }
        return [PSCustomObject]@{
            State = $state
            Stage = $failedStage
            ExitCode = $exitCode
            StdOut = ''
            StdErr = ''
            ChildStopped = $childStopped
            ElapsedMilliseconds = [int]$timer.ElapsedMilliseconds
            CallDirectory = $callDirectory
        }
    } finally {
        $supervisorExitedForCleanup = -not $started
        if ($started -and $process) {
            try { $supervisorExitedForCleanup = [bool]$process.HasExited } catch { $supervisorExitedForCleanup = $false }
        }
        if ($callDirectory -and $childStopped -and $supervisorExitedForCleanup -and (Test-Path -LiteralPath $callDirectory -PathType Container)) {
            try {
                Remove-Item -LiteralPath $callDirectory -Recurse -Force -ErrorAction Stop
            } catch {
                $cleanupException = $_.Exception.GetBaseException()
                $cleanupHResult = '0x{0:X8}' -f [int]$cleanupException.HResult
                Write-Host ('package-writer case=' + $caseLabel + ' stage=call-directory-cleanup error-type=' + $cleanupException.GetType().FullName + ' hresult=' + $cleanupHResult)
            }
        } elseif ($callDirectory -and $childStopped) {
            Write-Host ('package-writer case=' + $caseLabel + ' stage=call-directory-cleanup skipped=supervisor-not-exited')
        }
        if ($process) { $process.Dispose() }
    }
}

function Get-CvrPackageWriterOutputCount([string]$Mode) {
    $filter = if ($Mode -eq 'Capture') { 'capture-idle-*' } else { 'prepared-idle-*' }
    return @(Get-ChildItem -LiteralPath $preflightLocalRoot -Directory -Filter $filter -ErrorAction Stop).Count
}

function Get-CvrPackageWriterDiagnostic([string]$StdErr) {
    $diagnostic = ([string]$StdErr).Trim()
    if ($diagnostic -match '^Idle Preflight package writer failed \(stage=[a-z-]+ shape=(?:unread|empty|object|partial) type=[A-Za-z0-9_.+]+ line=[0-9]+\)\.$') {
        return $Matches[0]
    }
    return 'unclassified child failure'
}

function Assert-CvrPackageWriterCliRejects([string]$CaseName, [hashtable]$Arguments) {
    $before = Get-CvrPackageWriterOutputCount ([string]$Arguments.Mode)
    $result = Invoke-CvrPackageWriterCli -CaseName $CaseName -Arguments $Arguments
    $after = Get-CvrPackageWriterOutputCount ([string]$Arguments.Mode)
    $diagnostic = Get-CvrPackageWriterDiagnostic $result.StdErr
    $writerGuardRejected = $diagnostic -match '^Idle Preflight package writer failed \(stage=invoke-writer '
    Assert-IdleTransaction (
        $result.State -ceq 'completed' -and $result.ExitCode -ne 0 -and $result.ChildStopped -and
        [string]::IsNullOrEmpty($result.StdOut) -and $after -eq $before -and $writerGuardRejected
    ) ("Package writer CLI " + $CaseName + " did not reach the guard or wrote output.")
}

# Serialize the persisted capture data, not live FileSecurity objects returned by Get-Acl.
$packageWriterCorePair = [ordered]@{}
foreach ($coreRole in @('programFiles', 'service')) {
    $entry = $targetCapture.corePair[$coreRole]
    $packageWriterCorePair[$coreRole] = [ordered]@{
        path = [string]$entry.path
        pathPin = [string]$entry.pathPin
        backup = [string]$entry.backup
        backupPathPin = [string]$entry.backupPathPin
        backupRoot = [string]$entry.backupRoot
        backupSddl = [string]$entry.backupSddl
        backupDirectorySddl = [string]$entry.backupDirectorySddl
        sha256 = [string]$entry.sha256
        sddl = [string]$entry.sddl
        acl = [ordered]@{ Sddl = [string]$entry.acl.Sddl }
    }
}
$packageWriterCapture = [ordered]@{
    targetIdentity = [string]$targetCapture.targetIdentity
    capturedAtUtc = $targetCapture.capturedAtUtc.ToString('o')
    coreShouldBeRunning = [bool]$targetCapture.coreShouldBeRunning
    idleObservation = $targetCapture.idleObservation
    pinnedFiles = $targetCapture.pinnedFiles
    corePair = $packageWriterCorePair
}

$validCaptureCliArguments = @{
    Mode = 'Capture'
    Request = @{
        Capture = $packageWriterCapture
        ExpectedTargetIdentity = $targetIdentity
        ExpectedPins = $expectedPins
        PackageRoot = $preflightPackageRoot
        ExpectedStageRoot = $expectedStageRoot
        ExpectedPackageManifestSha256 = $expectedPackageManifestSha256
    }
}
$captureCliBefore = Get-CvrPackageWriterOutputCount 'Capture'
$captureCliResult = Invoke-CvrPackageWriterCli -CaseName 'capture-valid' -Arguments $validCaptureCliArguments
Assert-IdleTransaction ($captureCliResult.State -ceq 'completed' -and $captureCliResult.ExitCode -eq 0 -and $captureCliResult.ChildStopped) ("The actual Capture package-writer command failed: " + (Get-CvrPackageWriterDiagnostic $captureCliResult.StdErr))
$captureCli = $captureCliResult.StdOut | ConvertFrom-Json -ErrorAction Stop
$captureCliReceipt = [IO.File]::ReadAllText($captureCli.ReceiptPath) | ConvertFrom-Json -ErrorAction Stop
Assert-IdleTransaction (
    (Get-CvrPackageWriterOutputCount 'Capture') -eq ($captureCliBefore + 1) -and
    [IO.Path]::GetFullPath([string]$captureCliReceipt.packageStageBinding.stageRoot) -ceq $expectedStageRoot -and
    [string]$captureCliReceipt.packageStageBinding.sourceManifestSha256 -ceq $expectedPackageManifestSha256
) 'The actual Capture command did not write a stage-bound receipt.'

$validPlanCliArguments = @{
    Mode = 'Plan'
    Request = @{
        Capture = $packageWriterCapture
        CaptureDirectory = [string]$captureCli.CaptureDirectory
        ReceiptPath = [string]$captureCli.ReceiptPath
        ExpectedTargetIdentity = $targetIdentity
        ExpectedPins = $expectedPins
        PackageRoot = $preflightPackageRoot
        ExpectedStageRoot = $expectedStageRoot
        ExpectedPackageManifestSha256 = $expectedPackageManifestSha256
    }
}
$planCliBefore = Get-CvrPackageWriterOutputCount 'Plan'
$planCliResult = Invoke-CvrPackageWriterCli -CaseName 'plan-valid' -Arguments $validPlanCliArguments
Assert-IdleTransaction ($planCliResult.State -ceq 'completed' -and $planCliResult.ExitCode -eq 0 -and $planCliResult.ChildStopped) ("The actual Plan package-writer command failed: " + (Get-CvrPackageWriterDiagnostic $planCliResult.StdErr))
$planCli = $planCliResult.StdOut | ConvertFrom-Json -ErrorAction Stop
$planCliRecord = [IO.File]::ReadAllText($planCli.PlanPath) | ConvertFrom-Json -ErrorAction Stop
$planCliSha256 = (Get-FileHash -LiteralPath $planCli.PlanPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
Assert-IdleTransaction (
    (Get-CvrPackageWriterOutputCount 'Plan') -eq ($planCliBefore + 1) -and
    [IO.Path]::GetFullPath([string]$planCliRecord.packageStageBinding.stageRoot) -ceq $expectedStageRoot -and
    [string]$planCliRecord.packageStageBinding.sourceManifestSha256 -ceq $expectedPackageManifestSha256 -and
    [string]$planCli.PlanSha256 -ceq $planCliSha256
) 'The actual Plan command did not write a stage-bound plan.'

foreach ($mode in @('Capture', 'Plan')) {
    $validArguments = if ($mode -eq 'Capture') { $validCaptureCliArguments.Clone() } else { $validPlanCliArguments.Clone() }

    $missingRoot = $validArguments.Clone()
    $missingRoot['Request'] = $validArguments['Request'].Clone()
    $null = $missingRoot['Request'].Remove('ExpectedStageRoot')
    Assert-CvrPackageWriterCliRejects ($mode + ' missing expected stage root') $missingRoot

    $missingDigest = $validArguments.Clone()
    $missingDigest['Request'] = $validArguments['Request'].Clone()
    $null = $missingDigest['Request'].Remove('ExpectedPackageManifestSha256')
    Assert-CvrPackageWriterCliRejects ($mode + ' missing external manifest digest') $missingDigest

    $wrongRoot = $validArguments.Clone()
    $wrongRoot['Request'] = $validArguments['Request'].Clone()
    $wrongRoot['Request']['ExpectedStageRoot'] = Join-Path $targetCaptureRoot 'different-stage'
    Assert-CvrPackageWriterCliRejects ($mode + ' wrong expected stage root') $wrongRoot

    $wrongDigest = $validArguments.Clone()
    $wrongDigest['Request'] = $validArguments['Request'].Clone()
    $wrongDigest['Request']['ExpectedPackageManifestSha256'] = ('0' * 64)
    Assert-CvrPackageWriterCliRejects ($mode + ' wrong external manifest digest') $wrongDigest
}


# The whole-call timeout must include request serialization, before a writer child exists.
$slowSerializationResult = Invoke-CvrPackageWriterCli -CaseName 'serialization-stall' -Arguments @{
    Mode = 'Capture'
    TimeoutSeconds = 10
    SyntheticSerializationDelaySeconds = 15
    Request = @{ synthetic = $true }
}
Assert-IdleTransaction (
    $slowSerializationResult.State -ceq 'timeout' -and
    $slowSerializationResult.Stage -ceq 'request-serialize' -and
    $slowSerializationResult.ChildStopped -and
    $slowSerializationResult.ElapsedMilliseconds -le 15000
) 'Synchronous request serialization exceeded the whole-call deadline.'

$pidGapWriterPath = Join-Path $targetCaptureRoot 'synthetic-writer-pid-gap.ps1'
$pidGapIdentityPath = Join-Path $targetCaptureRoot 'synthetic-writer-ready.txt'
$pidGapWriterLines = @(
    'param([string]$Mode)'
    '$writer = [Diagnostics.Process]::GetCurrentProcess()'
    '$identity = [string]$PID + ''|'' + [string]$writer.StartTime.ToUniversalTime().Ticks'
    '[IO.File]::WriteAllText((Join-Path $PSScriptRoot ''synthetic-writer-ready.txt''), $identity, [Text.UTF8Encoding]::new($false))'
    '$writer.Dispose()'
    '$null = [Console]::In.ReadLine()'
    'Start-Sleep -Seconds 60'
)
[IO.File]::WriteAllLines($pidGapWriterPath, [string[]]$pidGapWriterLines, [Text.UTF8Encoding]::new($false))
$pidGapResult = $null
$pidGapProcess = $null
$pidGapStartTicks = 0L
$pidGapWriterStopped = $false
try {
    $beforePidGapCaptureCount = Get-CvrPackageWriterOutputCount 'Capture'
    $pidGapResult = Invoke-CvrPackageWriterCli -CaseName 'writer-start-before-pid' -Arguments @{
        Mode = 'Capture'
        ScriptPath = $pidGapWriterPath
        TimeoutSeconds = 15
        SyntheticWaitBeforeWriterPidWrite = $true
        Request = @{ synthetic = $true }
    }
    $readyDeadline = [DateTime]::UtcNow.AddSeconds(5)
    while (-not (Test-Path -LiteralPath $pidGapIdentityPath -PathType Leaf) -and [DateTime]::UtcNow -lt $readyDeadline) { Start-Sleep -Milliseconds 10 }
    Assert-IdleTransaction (Test-Path -LiteralPath $pidGapIdentityPath -PathType Leaf) 'Synthetic writer did not reach the start-before-pid window.'
    $identityParts = [IO.File]::ReadAllText($pidGapIdentityPath, [Text.UTF8Encoding]::new($false, $true)).Split('|')
    if ($identityParts.Count -ne 3 -or $identityParts[2] -cne 'writer-pid-absent') { throw 'Synthetic writer PID-gap receipt was invalid.' }
    $pidGapStartTicks = [long]$identityParts[1]
    try {
        $pidGapProcess = [Diagnostics.Process]::GetProcessById([int]$identityParts[0])
        $pidGapProcess.Refresh()
        if ($pidGapProcess.HasExited) { $pidGapWriterStopped = $true }
        else { $pidGapWriterStopped = ($pidGapProcess.StartTime.ToUniversalTime().Ticks -ne $pidGapStartTicks) }
    } catch [ArgumentException] {
        $pidGapWriterStopped = $true
    } catch {
        $pidGapWriterStopped = $false
    }
    $pidGapCallDirectoryRemoved = $pidGapResult.CallDirectory -and -not (Test-Path -LiteralPath $pidGapResult.CallDirectory -PathType Container)
    $pidGapDiagnostic = 'state={0} stage={1} child-stopped={2} writer-stopped={3} pid-absent={4} call-directory-present={5} elapsed-ms={6}.' -f @(
        [string]$pidGapResult.State,
        [string]$pidGapResult.Stage,
        [string]$pidGapResult.ChildStopped,
        [string]$pidGapWriterStopped,
        [string]$true,
        [string](-not $pidGapCallDirectoryRemoved),
        [string]$pidGapResult.ElapsedMilliseconds
    )
    Assert-IdleTransaction (
        $pidGapResult.State -ceq 'timeout' -and
        $pidGapResult.Stage -ceq 'writer-pid' -and
        $pidGapResult.ChildStopped -and
        $pidGapWriterStopped -and
        $pidGapCallDirectoryRemoved -and
        $pidGapResult.ElapsedMilliseconds -le 16000 -and
        [string]::IsNullOrEmpty($pidGapResult.StdOut) -and
        (Get-CvrPackageWriterOutputCount 'Capture') -eq $beforePidGapCaptureCount
    ) ('Writer PID gap cleanup was not proven: ' + $pidGapDiagnostic)
} finally {
    if ($pidGapProcess) {
        try {
            $pidGapProcess.Refresh()
            if (-not $pidGapProcess.HasExited -and $pidGapProcess.StartTime.ToUniversalTime().Ticks -eq $pidGapStartTicks) {
                $pidGapProcess.Kill()
                if (-not $pidGapProcess.WaitForExit(5000)) { throw 'Synthetic writer cleanup exceeded its deadline.' }
            }
        } finally { $pidGapProcess.Dispose() }
    }
    if ($pidGapResult -and $pidGapResult.CallDirectory -and (Test-Path -LiteralPath $pidGapResult.CallDirectory -PathType Container)) {
        Remove-Item -LiteralPath $pidGapResult.CallDirectory -Recurse -Force -ErrorAction Stop
    }
    if (Test-Path -LiteralPath $pidGapIdentityPath -PathType Leaf) { Remove-Item -LiteralPath $pidGapIdentityPath -Force -ErrorAction Stop }
}
$script:targetCaptureOutcomes.Add([pscustomobject]@{
    case = 'powershell51-writer-start-before-pid'
    result = 'absent writer PID receipt is followed by verified process-tree cleanup against the synthetic PID and start time'
})

$delayedWriterPath = Join-Path $targetCaptureRoot 'synthetic-delayed-writer.ps1'
$delayedWriterLines = @(
    'param([string]$Mode)'
    '$null = [Console]::In.ReadLine()'
    'Start-Sleep -Seconds 60'
)
[IO.File]::WriteAllLines($delayedWriterPath, [string[]]$delayedWriterLines, [Text.UTF8Encoding]::new($false))
$beforeDelayedWriterCount = Get-CvrPackageWriterOutputCount 'Capture'
$delayedWriterResult = Invoke-CvrPackageWriterCli -CaseName 'delayed-synthetic' -Arguments @{
    Mode = 'Capture'
    ScriptPath = $delayedWriterPath
    TimeoutSeconds = 15
    Request = @{ synthetic = $true }
}
Assert-IdleTransaction (
    $delayedWriterResult.State -ceq 'timeout' -and
    $delayedWriterResult.Stage -ceq 'process-wait' -and
    $delayedWriterResult.ChildStopped -and
    $delayedWriterResult.ElapsedMilliseconds -le 20000 -and
    [string]::IsNullOrEmpty($delayedWriterResult.StdOut) -and
    (Get-CvrPackageWriterOutputCount 'Capture') -eq $beforeDelayedWriterCount
) 'A delayed synthetic package writer was not bounded and reaped before output.'


$script:targetCaptureOutcomes.Add([pscustomobject]@{
    case = 'powershell51-package-writer-timeout'
    result = 'delayed child timed out in process-wait and was reaped before output'
})

$script:targetCaptureOutcomes.Add([pscustomobject]@{
    case = 'powershell51-package-writer-cli'
    result = 'capture-and-plan-bound-with-eight-fail-closed-rejections-before-output'
})

$stageBindingFailures = [Collections.Generic.List[string]]::new()
if (-not $stageManifestAclCaptureSafe) { $stageBindingFailures.Add('manifest-acl-capture') }
if (-not $stageEntryAclPlanSafe) { $stageBindingFailures.Add('entry-acl-plan') }
if (-not $stageBoundaryCaptureSafe) { $stageBindingFailures.Add('capture-validation-write-mutation') }
if (-not $stageBoundaryPlanSafe) { $stageBindingFailures.Add('plan-validation-write-mutation') }
if ($stageBindingFailures.Count) {
    throw ("Idle package-stage race/ACL contract failed: " + ($stageBindingFailures -join ',') + '.')
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
