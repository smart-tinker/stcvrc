function Invoke-CvrIdleTransaction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Capture,
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [Parameter(Mandatory = $true)][scriptblock]$Restore,
        [Parameter(Mandatory = $true)][scriptblock]$Verify
    )

    $capture = & $Capture
    $intent = $capture.PSObject.Properties['coreShouldBeRunning']
    if (-not $intent -or $intent.Value -isnot [bool] -or $intent.Value) {
        throw 'Idle transaction requires a captured strict false intent.'
    }

    # RED baseline: action errors escape before restoration.
    $actionResult = & $Action $capture
    $restoreResult = & $Restore $capture
    $verified = & $Verify $capture $restoreResult
    if ($verified -isnot [bool] -or -not $verified) {
        throw 'Idle transaction restore verification did not pass.'
    }

    return [PSCustomObject]@{
        Capture = $capture
        ActionResult = $actionResult
        ActionFailure = $null
        RestoreFailure = $null
    }
}
