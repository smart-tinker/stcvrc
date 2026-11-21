function Invoke-CvrIdleTransaction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][scriptblock]$CaptureScript,
        [Parameter(Mandatory = $true)][scriptblock]$ActionScript,
        [Parameter(Mandatory = $true)][scriptblock]$RestoreScript,
        [Parameter(Mandatory = $true)][scriptblock]$VerifyScript
    )

    $capturedBaseline = & $CaptureScript
    $intent = $capturedBaseline.PSObject.Properties['coreShouldBeRunning']
    if (-not $intent -or $intent.Value -isnot [bool] -or $intent.Value) {
        throw 'Idle transaction requires a captured strict false intent.'
    }

    $actionResult = $null
    $actionFailure = $null
    try { $actionResult = & $ActionScript $capturedBaseline }
    catch {
        $actionFailure = $_.Exception.Message
        if (-not $actionFailure) { $actionFailure = 'Action callback failed without a message.' }
    }

    $restoreResult = $null
    $restoreFailure = $null
    try { $restoreResult = & $RestoreScript $capturedBaseline }
    catch {
        $restoreFailure = $_.Exception.Message
        if (-not $restoreFailure) { $restoreFailure = 'Restore callback failed without a message.' }
    }

    if ($null -eq $restoreFailure) {
        try {
            $verified = & $VerifyScript $capturedBaseline $restoreResult
            if ($verified -isnot [bool] -or -not $verified) {
                throw 'Idle transaction restore verification did not pass.'
            }
        } catch {
            $restoreFailure = $_.Exception.Message
            if (-not $restoreFailure) { $restoreFailure = 'Restore verification failed without a message.' }
        }
    }

    return [PSCustomObject]@{
        Capture = $capturedBaseline
        ActionResult = $actionResult
        ActionFailure = $actionFailure
        RestoreFailure = $restoreFailure
    }
}
