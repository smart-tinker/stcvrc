$ErrorActionPreference = 'Stop'
$modulePath = Join-Path $PSScriptRoot 'windows_idle_transaction.ps1'
if (-not (Test-Path -LiteralPath $modulePath -PathType Leaf)) {
    throw 'Expected behavior RED: shared idle transaction module is missing.'
}
. $modulePath

function Assert-IdleTransaction([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}
function Assert-IdleTransactionOrder([string[]]$Expected) {
    $actual = @($script:idleTransactionEvents.ToArray())
    if (($actual -join ',') -cne ($Expected -join ',')) {
        throw 'Shared idle transaction callback order did not match.'
    }
}
function New-IdleTransactionCapture($Intent) {
    [PSCustomObject]@{ coreShouldBeRunning = $Intent }
}

$script:idleTransactionEvents = [Collections.Generic.List[string]]::new()
$success = Invoke-CvrIdleTransaction -CaptureScript { $script:idleTransactionEvents.Add('capture'); New-IdleTransactionCapture $false } -ActionScript { param($capture) $script:idleTransactionEvents.Add('action'); 'candidate' } -RestoreScript { param($capture) $script:idleTransactionEvents.Add('restore'); 'baseline' } -VerifyScript { param($capture,$restored) $script:idleTransactionEvents.Add('verify'); ($capture.coreShouldBeRunning -ceq $false -and $restored -ceq 'baseline') }
Assert-IdleTransactionOrder @('capture','action','restore','verify')
Assert-IdleTransaction ($success.ActionFailure -eq $null -and $success.RestoreFailure -eq $null) 'Successful transaction reported a failure.'

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


. (Join-Path $PSScriptRoot 'windows_idle_baseline_guard.ps1')

function Assert-IdleTargetCaptureRejected([string]$Case, [string]$ExpectedMessage, [string]$ExpectedIdentity, [System.Collections.IDictionary]$Pins) {
    $rejected = $false
    try {
        $null = Assert-CvrIdleTargetCapture -Capture $targetCapture -ExpectedTargetIdentity $ExpectedIdentity -ExpectedPins $Pins
    } catch {
        if ($_.Exception.Message -cne $ExpectedMessage) { throw "Idle target capture guard returned an unexpected message for $Case." }
        $rejected = $true
    }
    Assert-IdleTransaction $rejected "$Case drift was accepted."
}

$targetCaptureRoot = Join-Path ([IO.Path]::GetTempPath()) ('stcvrc-idle-target-capture-' + [Guid]::NewGuid().ToString('N'))
if (Test-Path -LiteralPath $targetCaptureRoot) { throw 'Idle target capture fixture path unexpectedly exists.' }
$null = New-Item -ItemType Directory -Path $targetCaptureRoot
try {
    $pinPath = Join-Path $targetCaptureRoot 'pinned-input.bin'
    [IO.File]::WriteAllBytes($pinPath, [byte[]](7, 2, 5, 10))
    $pinSha = (Get-FileHash -LiteralPath $pinPath -Algorithm SHA256).Hash.ToLowerInvariant()

    $programFilesPath = Join-Path $targetCaptureRoot 'program-files-core.exe'
    $serviceCorePath = Join-Path $targetCaptureRoot 'service-core.exe'
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
        candidateCore = $pinSha
        updateInstaller = $pinSha
        updateHelper = $pinSha
        recoveryInstaller = $pinSha
        recoveryHelper = $pinSha
    }
    $pinnedFiles = @{
        gui258 = $pinPath
        serviceExe258 = $pinPath
        programFilesCore = $programFilesPath
        serviceCore = $serviceCorePath
        candidateCore = $pinPath
        updateInstaller = $pinPath
        updateHelper = $pinPath
        recoveryInstaller = $pinPath
        recoveryHelper = $pinPath
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
} finally {
    Remove-Item -LiteralPath $targetCaptureRoot -Recurse -Force -ErrorAction Stop
}


# Expected behavior RED: the public idle-only Preflight capture adapter is missing.
if (-not (Get-Command -Name Save-CvrIdlePreflightCapture -CommandType Function -ErrorAction SilentlyContinue)) {
    throw 'Expected behavior RED: validated idle Preflight capture writer is missing.'
}

$preflightPackageRoot = Join-Path $targetCaptureRoot 'preflight-package'
$preflightLocalRoot = Join-Path $preflightPackageRoot 'local'
$null = New-Item -ItemType Directory -Path $preflightLocalRoot -Force
Set-CvrIdleCaptureAcl -Path $preflightLocalRoot -Directory
$captureMarkerPath = Join-Path (Join-Path $preflightLocalRoot 'capture') 'keep.txt'
$preparedMarkerPath = Join-Path (Join-Path $preflightLocalRoot 'prepared') 'keep.txt'
$null = New-Item -ItemType Directory -Path (Split-Path -Parent $captureMarkerPath) -Force
$null = New-Item -ItemType Directory -Path (Split-Path -Parent $preparedMarkerPath) -Force
[IO.File]::WriteAllText($captureMarkerPath, 'preserve-capture')
[IO.File]::WriteAllText($preparedMarkerPath, 'preserve-prepared')
$targetCapture.profileMarker = 'synthetic-profile-marker'

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
if ($receipt.coreShouldBeRunning -isnot [bool] -or $receipt.coreShouldBeRunning -or
    $receipt.targetIdentity -cne $targetIdentity -or
    $receipt.expectedPins.PSObject.Properties.Count -ne 9 -or
    $receipt.idleObservation.ServiceStatus -cne 'Running' -or
    [IO.Path]::GetFileName($receipt.corePair.service.backup) -cne 'verge-mihomo.exe' -or
    $receiptText.Contains('synthetic-profile-marker')) {
    throw 'Idle Preflight receipt did not preserve the validated allowlisted capture contract.'
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
$targetCapture.PSObject.Properties.Remove('profileMarker')

Write-Host 'Shared idle transaction behavior checks passed.'
