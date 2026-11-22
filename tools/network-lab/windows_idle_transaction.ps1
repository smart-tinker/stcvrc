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


function Assert-CvrIdleTargetCapture {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$Capture,
        [Parameter(Mandatory = $true)][string]$ExpectedTargetIdentity,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$ExpectedPins
    )

    $identity = $Capture.PSObject.Properties['targetIdentity']
    $capturedAt = $Capture.PSObject.Properties['capturedAtUtc']
    $intent = $Capture.PSObject.Properties['coreShouldBeRunning']
    $observationProperty = $Capture.PSObject.Properties['idleObservation']
    if (-not $identity -or $identity.Value -isnot [string] -or
        [string]::IsNullOrWhiteSpace($ExpectedTargetIdentity) -or
        $identity.Value -cne $ExpectedTargetIdentity) {
        throw 'Idle target identity does not match the expected target.'
    }
    if (-not $capturedAt -or $capturedAt.Value -isnot [DateTime] -or
        $capturedAt.Value.Kind -ne [DateTimeKind]::Utc) {
        throw 'Idle target capture timestamp is missing, stale, or not UTC.'
    }
    $captureAge = [DateTime]::UtcNow - $capturedAt.Value
    if ($captureAge.TotalSeconds -lt 0 -or $captureAge.TotalMinutes -gt 5) {
        throw 'Idle target capture timestamp is missing, stale, or not UTC.'
    }
    if (-not $intent -or $intent.Value -isnot [bool] -or $intent.Value) {
        throw 'Idle target capture requires strict false intent.'
    }
    if (-not $observationProperty -or $observationProperty.Value -isnot [System.Collections.IDictionary]) {
        throw 'Idle target baseline observation is incomplete.'
    }
    $observation = $observationProperty.Value
    if (-not $observation.Contains('CoreShouldBeRunning') -or
        $observation.CoreShouldBeRunning -isnot [bool] -or
        $observation.CoreShouldBeRunning -cne $intent.Value) {
        throw 'Idle target capture requires strict false intent.'
    }
    if (-not (Get-Command Assert-CvrIdleBaseline -ErrorAction SilentlyContinue)) {
        throw 'Idle target baseline guard is unavailable.'
    }
    $null = Assert-CvrIdleBaseline @observation

    $requiredPinNames = @(
        'gui258', 'serviceExe258', 'programFilesCore', 'serviceCore',
        'candidateCore', 'updateInstaller', 'updateHelper',
        'recoveryInstaller', 'recoveryHelper'
    )
    $pinnedFilesProperty = $Capture.PSObject.Properties['pinnedFiles']
    if (-not $pinnedFilesProperty -or
        $pinnedFilesProperty.Value -isnot [System.Collections.IDictionary] -or
        $ExpectedPins.Count -ne $requiredPinNames.Count -or
        $pinnedFilesProperty.Value.Count -ne $requiredPinNames.Count) {
        throw 'Idle target pin set is incomplete.'
    }
    $pinnedFiles = $pinnedFilesProperty.Value
    foreach ($pinName in $requiredPinNames) {
        if (-not $ExpectedPins.Contains($pinName) -or -not $pinnedFiles.Contains($pinName)) {
            throw 'Idle target pin set is incomplete.'
        }
        $expected = $ExpectedPins[$pinName]
        $path = $pinnedFiles[$pinName]
        if ($expected -isnot [string] -or $expected -notmatch '^[0-9a-fA-F]{64}$' -or
            $path -isnot [string] -or [string]::IsNullOrWhiteSpace($path)) {
            throw 'Idle target pin set is incomplete.'
        }
        try {
            if (-not (Test-Path -LiteralPath $path -PathType Leaf -ErrorAction Stop)) {
                throw 'missing'
            }
            $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash
        } catch {
            throw 'Idle target pinned input verification failed.'
        }
        if ($actual -notmatch '^[0-9a-fA-F]{64}$' -or $actual -ine $expected) {
            throw 'Idle target pinned input verification failed.'
        }
    }

    $corePairProperty = $Capture.PSObject.Properties['corePair']
    if (-not $corePairProperty -or -not $corePairProperty.Value) {
        throw 'Idle target core preimage verification failed.'
    }
    $pair = $corePairProperty.Value
    if (-not $pair.programFiles -or -not $pair.service) {
        throw 'Idle target core preimage verification failed.'
    }
    $paths = @{}
    foreach ($entryInfo in @(
        [PSCustomObject]@{ entry = $pair.programFiles; pin = 'programFilesCore'; service = $false },
        [PSCustomObject]@{ entry = $pair.service; pin = 'serviceCore'; service = $true }
    )) {
        try {
            $entry = $entryInfo.entry
            $pathProperty = $entry.PSObject.Properties['path']
            $backupProperty = $entry.PSObject.Properties['backup']
            $shaProperty = $entry.PSObject.Properties['sha256']
            $sddlProperty = $entry.PSObject.Properties['sddl']
            $aclProperty = $entry.PSObject.Properties['acl']
            if (-not $pathProperty -or -not $backupProperty -or -not $shaProperty -or
                -not $sddlProperty -or -not $aclProperty -or
                $pathProperty.Value -isnot [string] -or $backupProperty.Value -isnot [string] -or
                $shaProperty.Value -isnot [string] -or $shaProperty.Value -notmatch '^[0-9a-fA-F]{64}$' -or
                $sddlProperty.Value -isnot [string] -or [string]::IsNullOrWhiteSpace($sddlProperty.Value) -or
                -not $aclProperty.Value -or [string]$aclProperty.Value.Sddl -cne [string]$sddlProperty.Value -or
                -not $ExpectedPins.Contains($entryInfo.pin) -or
                [string]$ExpectedPins[$entryInfo.pin] -ine [string]$shaProperty.Value) {
                throw 'invalid'
            }
            $livePath = [IO.Path]::GetFullPath([string]$pathProperty.Value)
            $backupPath = [IO.Path]::GetFullPath([string]$backupProperty.Value)
            if ($paths.ContainsKey($livePath) -or $paths.ContainsKey($backupPath)) {
                throw 'aliased'
            }
            $paths[$livePath] = $true
            $paths[$backupPath] = $true
            if ($entryInfo.service -and [IO.Path]::GetFileName($backupPath) -cne 'verge-mihomo.exe') {
                throw 'basename'
            }
            if (-not (Test-Path -LiteralPath $livePath -PathType Leaf -ErrorAction Stop) -or
                -not (Test-Path -LiteralPath $backupPath -PathType Leaf -ErrorAction Stop)) {
                throw 'missing'
            }
            $liveHash = (Get-FileHash -LiteralPath $livePath -Algorithm SHA256 -ErrorAction Stop).Hash
            $backupHash = (Get-FileHash -LiteralPath $backupPath -Algorithm SHA256 -ErrorAction Stop).Hash
            $liveSddl = (Get-Acl -LiteralPath $livePath -ErrorAction Stop).Sddl
            if ($liveHash -ine [string]$shaProperty.Value -or
                $backupHash -ine [string]$shaProperty.Value -or
                $liveSddl -cne [string]$sddlProperty.Value) {
                throw 'drift'
            }
        } catch {
            throw 'Idle target core preimage verification failed.'
        }
    }
    return $true
}
