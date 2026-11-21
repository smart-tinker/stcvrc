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

    # RED baseline: action errors escape before restoration.
    $actionResult = & $ActionScript $capturedBaseline
    $restoreResult = & $RestoreScript $capturedBaseline
    $verified = & $VerifyScript $capturedBaseline $restoreResult
    if ($verified -isnot [bool] -or -not $verified) {
        throw 'Idle transaction restore verification did not pass.'
    }

    return [PSCustomObject]@{
        Capture = $capturedBaseline
        ActionResult = $actionResult
        ActionFailure = $null
        RestoreFailure = $null
    }
}
