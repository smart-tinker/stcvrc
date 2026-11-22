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


function Assert-CvrIdleCaptureAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$Directory
    )

    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ((([int]$item.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0) -or
            [bool]$item.PSIsContainer -ne [bool]$Directory) {
            throw 'invalid'
        }
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $ownerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
        if (-not $ownerSid -or -not $acl.AreAccessRulesProtected -or
            $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $ownerSid.Value) {
            throw 'invalid'
        }

        $expectedSids = @{}
        $expectedSids[$ownerSid.Value] = $true
        $expectedSids['S-1-5-18'] = $true
        $expectedSids['S-1-5-32-544'] = $true
        $rules = @($acl.Access)
        if ($rules.Count -ne $expectedSids.Count) { throw 'invalid' }
        $expectedInheritance = if ($Directory) { 3 } else { 0 }
        $seenSids = @{}
        foreach ($rule in $rules) {
            $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
            if (-not $expectedSids.ContainsKey($sid) -or $seenSids.ContainsKey($sid) -or
                $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
                $rule.IsInherited -or
                [int]$rule.FileSystemRights -ne [int][Security.AccessControl.FileSystemRights]::FullControl -or
                [int]$rule.InheritanceFlags -ne $expectedInheritance -or
                [int]$rule.PropagationFlags -ne 0) {
                throw 'invalid'
            }
            $seenSids[$sid] = $true
        }
        return $true
    } catch {
        throw 'Idle capture ACL validation failed.'
    }
}

function Set-CvrIdleCaptureAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$Directory
    )

    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ((([int]$item.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0) -or
            [bool]$item.PSIsContainer -ne [bool]$Directory) {
            throw 'invalid'
        }
        if ($Directory) {
            if (@(Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop).Count -ne 0) {
                throw 'nonempty'
            }
        } elseif ($item.Length -ne 0) {
            throw 'nonempty'
        }

        $ownerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
        if (-not $ownerSid) { throw 'owner' }
        $security = if ($Directory) {
            New-Object System.Security.AccessControl.DirectorySecurity
        } else {
            New-Object System.Security.AccessControl.FileSecurity
        }
        $security.SetAccessRuleProtection($true, $false)
        $security.SetOwner($ownerSid)
        $accessSids = @{}
        $accessSids[$ownerSid.Value] = $true
        $accessSids['S-1-5-18'] = $true
        $accessSids['S-1-5-32-544'] = $true
        $inheritance = [Security.AccessControl.InheritanceFlags]::None
        if ($Directory) {
            $inheritance = [Security.AccessControl.InheritanceFlags](
                [int][Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                [int][Security.AccessControl.InheritanceFlags]::ObjectInherit
            )
        }
        foreach ($sidValue in $accessSids.Keys) {
            $sid = [Security.Principal.SecurityIdentifier]::new([string]$sidValue)
            $rule = [Security.AccessControl.FileSystemAccessRule]::new(
                $sid,
                [Security.AccessControl.FileSystemRights]::FullControl,
                $inheritance,
                [Security.AccessControl.PropagationFlags]::None,
                [Security.AccessControl.AccessControlType]::Allow
            )
            $null = $security.AddAccessRule($rule)
        }
        Set-Acl -LiteralPath $Path -AclObject $security -ErrorAction Stop
        $null = Assert-CvrIdleCaptureAcl -Path $Path -Directory:$Directory
    } catch {
        throw 'Idle capture ACL setup failed.'
    }
}

function Save-CvrIdlePreflightCapture {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$Capture,
        [Parameter(Mandatory = $true)][string]$ExpectedTargetIdentity,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$ExpectedPins,
        [Parameter(Mandatory = $true)][string]$PackageRoot
    )

    $null = Assert-CvrIdleTargetCapture -Capture $Capture -ExpectedTargetIdentity $ExpectedTargetIdentity -ExpectedPins $ExpectedPins
    try {
        $packagePath = [IO.Path]::GetFullPath($PackageRoot)
        $localPath = [IO.Path]::GetFullPath((Join-Path $packagePath 'local'))
        $packageItem = Get-Item -LiteralPath $packagePath -Force -ErrorAction Stop
        $localItem = Get-Item -LiteralPath $localPath -Force -ErrorAction Stop
        if (-not $packageItem.PSIsContainer -or -not $localItem.PSIsContainer -or
            [IO.Path]::GetDirectoryName($localPath) -ine $packagePath -or
            (([int]$packageItem.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0) -or
            (([int]$localItem.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw 'invalid'
        }
        $null = Assert-CvrIdleCaptureAcl -Path $localPath -Directory
    } catch {
        throw 'Idle Preflight package root is not protected.'
    }

    $pinNames = @(
        'gui258', 'serviceExe258', 'programFilesCore', 'serviceCore',
        'candidateCore', 'updateInstaller', 'updateHelper',
        'recoveryInstaller', 'recoveryHelper'
    )
    $storedPins = [ordered]@{}
    foreach ($pinName in $pinNames) {
        $storedPins[$pinName] = [string]$ExpectedPins[$pinName]
    }
    $observation = $Capture.idleObservation
    $storedObservation = [ordered]@{
        CoreShouldBeRunning = [bool]$observation.CoreShouldBeRunning
        OwnedGuiProcessIds = @($observation.OwnedGuiProcessIds)
        OwnedCoreProcessIds = @($observation.OwnedCoreProcessIds)
        ControllerListening = [bool]$observation.ControllerListening
        OwnedListenerProcessIds = @($observation.OwnedListenerProcessIds)
        ServiceStatus = [string]$observation.ServiceStatus
        ExpectedProgramFilesCoreSha256 = [string]$observation.ExpectedProgramFilesCoreSha256
        ObservedProgramFilesCoreSha256 = [string]$observation.ObservedProgramFilesCoreSha256
        ExpectedServiceCoreSha256 = [string]$observation.ExpectedServiceCoreSha256
        ObservedServiceCoreSha256 = [string]$observation.ObservedServiceCoreSha256
    }
    $programFiles = $Capture.corePair.programFiles
    $serviceCore = $Capture.corePair.service
    $receipt = [ordered]@{
        targetIdentity = [string]$Capture.targetIdentity
        capturedAtUtc = $Capture.capturedAtUtc.ToString('o')
        coreShouldBeRunning = [bool]$Capture.coreShouldBeRunning
        expectedPins = $storedPins
        idleObservation = $storedObservation
        corePair = [ordered]@{
            programFiles = [ordered]@{
                path = [string]$programFiles.path
                backup = [string]$programFiles.backup
                sha256 = [string]$programFiles.sha256
                sddl = [string]$programFiles.sddl
            }
            service = [ordered]@{
                path = [string]$serviceCore.path
                backup = [string]$serviceCore.backup
                sha256 = [string]$serviceCore.sha256
                sddl = [string]$serviceCore.sddl
            }
        }
    }
    $receiptBytes = [Text.UTF8Encoding]::new($false).GetBytes(
        (ConvertTo-Json -InputObject $receipt -Depth 8 -Compress -ErrorAction Stop)
    )

    $captureDirectory = Join-Path $localPath ('capture-idle-' + [Guid]::NewGuid().ToString('N'))
    $createdDirectory = $false
    try {
        if (Test-Path -LiteralPath $captureDirectory) { throw 'exists' }
        $null = New-Item -ItemType Directory -Path $captureDirectory -ErrorAction Stop
        $createdDirectory = $true
        $null = Set-CvrIdleCaptureAcl -Path $captureDirectory -Directory

        $receiptPath = Join-Path $captureDirectory 'capture.json'
        $stream = [IO.File]::Open(
            $receiptPath,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None
        )
        $stream.Dispose()
        $null = Set-CvrIdleCaptureAcl -Path $receiptPath
        $stream = [IO.File]::Open(
            $receiptPath,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None
        )
        try {
            $stream.Write($receiptBytes, 0, $receiptBytes.Length)
            $stream.Flush()
        } finally {
            $stream.Dispose()
        }
        return [PSCustomObject]@{
            CaptureDirectory = $captureDirectory
            ReceiptPath = $receiptPath
        }
    } catch {
        if ($createdDirectory) {
            Remove-Item -LiteralPath $captureDirectory -Recurse -Force -ErrorAction SilentlyContinue
        }
        throw 'Idle Preflight capture could not be written.'
    }
}
