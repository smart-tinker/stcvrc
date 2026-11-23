# Caller supplies fresh, owner-scoped observations; this helper does not collect or mutate them.
function Assert-CvrIdleBaseline {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$CoreShouldBeRunning,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [int[]]$OwnedGuiProcessIds,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [int[]]$OwnedCoreProcessIds,

        [Parameter(Mandatory = $true)]
        [object]$ControllerListening,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [int[]]$OwnedListenerProcessIds,

        [Parameter(Mandatory = $true)]
        [string]$ServiceStatus,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedProgramFilesCoreSha256,

        [Parameter(Mandatory = $true)]
        [string]$ObservedProgramFilesCoreSha256,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedServiceCoreSha256,

        [Parameter(Mandatory = $true)]
        [string]$ObservedServiceCoreSha256
    )

    if ($CoreShouldBeRunning -isnot [bool] -or $ControllerListening -isnot [bool]) {
        throw 'Idle baseline Boolean observations must be strict Booleans.'
    }
    if ($CoreShouldBeRunning) { throw 'Idle baseline intent must be false.' }
    if ($OwnedGuiProcessIds.Count -gt 0) { throw 'Idle baseline has owned GUI processes.' }
    if ($OwnedCoreProcessIds.Count -gt 0) { throw 'Idle baseline has owned core processes.' }
    if ($ControllerListening) { throw 'Idle baseline controller listener is present.' }
    if ($OwnedListenerProcessIds.Count -gt 0) { throw 'Idle baseline has owned listeners.' }
    if ($ServiceStatus -cne 'Running') { throw 'Idle baseline service is not Running.' }

    $sha256Pattern = '^[0-9a-fA-F]{64}$'
    if ($ExpectedProgramFilesCoreSha256 -notmatch $sha256Pattern -or
        $ObservedProgramFilesCoreSha256 -notmatch $sha256Pattern) {
        throw 'Idle baseline Program Files core SHA256 is malformed.'
    }
    if ($ExpectedProgramFilesCoreSha256 -ine $ObservedProgramFilesCoreSha256) {
        throw 'Idle baseline Program Files core SHA256 mismatch.'
    }
    if ($ExpectedServiceCoreSha256 -notmatch $sha256Pattern -or
        $ObservedServiceCoreSha256 -notmatch $sha256Pattern) {
        throw 'Idle baseline service core SHA256 is malformed.'
    }
    if ($ExpectedServiceCoreSha256 -ine $ObservedServiceCoreSha256) {
        throw 'Idle baseline service core SHA256 mismatch.'
    }

    return $true
}

function Assert-CvrRequiredSourcePins {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$Index,

        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$RequiredPins
    )

    $sha256Pattern = '^[0-9a-fA-F]{64}$'
    foreach ($path in $RequiredPins.Keys) {
        if (-not $Index.Contains($path)) {
            throw 'Required source manifest helper is missing.'
        }
        $expected = [string]$RequiredPins[$path]
        $actual = [string]$Index[$path]
        if ($expected -notmatch $sha256Pattern -or
            $actual -notmatch $sha256Pattern -or
            $actual -ine $expected) {
            throw 'Required source manifest helper pin mismatch.'
        }
    }
    return $true
}
