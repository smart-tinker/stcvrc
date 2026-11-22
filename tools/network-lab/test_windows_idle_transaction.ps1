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
    [IO.File]::WriteAllBytes($programFilesBackup, [IO.File]::ReadAllBytes($programFilesPath))
    [IO.File]::WriteAllBytes($serviceBackup, [IO.File]::ReadAllBytes($serviceCorePath))
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
    Assert-IdleTransaction $acceptedTargetCapture 'Expected behavior RED: the complete fresh idle target capture was not accepted.'
} finally {
    Remove-Item -LiteralPath $targetCaptureRoot -Recurse -Force -ErrorAction Stop
}

Write-Host 'Shared idle transaction behavior checks passed.'
