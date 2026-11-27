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
    $observationProperty = $capturedBaseline.PSObject.Properties['idleObservation']
    if (-not $observationProperty -or $observationProperty.Value -isnot [System.Collections.IDictionary]) {
        throw 'Idle transaction requires a captured idle observation.'
    }
    if (-not (Get-Command -Name Assert-CvrIdleBaseline -CommandType Function -ErrorAction SilentlyContinue)) {
        throw 'Idle transaction baseline guard is unavailable.'
    }
    $observation = $observationProperty.Value
    $null = Assert-CvrIdleBaseline @observation

    $actionResult = $null
    $actionFailure = $null
    try { $actionResult = & $ActionScript $capturedBaseline }
    catch {
        $actionFailure = $_.Exception.Message
        if (-not $actionFailure) { $actionFailure = 'Action callback failed without a message.' }
    }

    $intentAfterAction = $capturedBaseline.PSObject.Properties['coreShouldBeRunning']
    $observationAfterAction = $capturedBaseline.PSObject.Properties['idleObservation']
    $observationIntentAfterAction = $null
    if ($observationAfterAction -and
        $observationAfterAction.Value -is [System.Collections.IDictionary] -and
        $observationAfterAction.Value.Contains('CoreShouldBeRunning')) {
        $observationIntentAfterAction = $observationAfterAction.Value['CoreShouldBeRunning']
    }
    if (-not $intentAfterAction -or
        $intentAfterAction.Value -isnot [bool] -or
        $intentAfterAction.Value -or
        $observationIntentAfterAction -isnot [bool] -or
        $observationIntentAfterAction) {
        if ($null -eq $actionFailure) {
            $actionFailure = 'Action callback changed captured strict false intent.'
        }
        $null = $capturedBaseline | Add-Member -MemberType NoteProperty -Name 'coreShouldBeRunning' -Value ([bool]$false) -Force
        $observation['CoreShouldBeRunning'] = [bool]$false
        $null = $capturedBaseline | Add-Member -MemberType NoteProperty -Name 'idleObservation' -Value $observation -Force
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
        [PSCustomObject]@{ entry = $pair.programFiles; pin = 'programFilesCore'; role = 'Program Files' },
        [PSCustomObject]@{ entry = $pair.service; pin = 'serviceCore'; role = 'service' }
    )) {
        try {
            $entry = $entryInfo.entry
            $pathProperty = $entry.PSObject.Properties['path']
            $pathPinProperty = $entry.PSObject.Properties['pathPin']
            $backupProperty = $entry.PSObject.Properties['backup']
            $backupPathPinProperty = $entry.PSObject.Properties['backupPathPin']
            $backupRootProperty = $entry.PSObject.Properties['backupRoot']
            $backupSddlProperty = $entry.PSObject.Properties['backupSddl']
            $backupDirectorySddlProperty = $entry.PSObject.Properties['backupDirectorySddl']
            $shaProperty = $entry.PSObject.Properties['sha256']
            $sddlProperty = $entry.PSObject.Properties['sddl']
            $aclProperty = $entry.PSObject.Properties['acl']
            if (-not $pathProperty -or -not $pathPinProperty -or -not $backupProperty -or
                -not $backupPathPinProperty -or -not $backupRootProperty -or
                -not $backupSddlProperty -or -not $backupDirectorySddlProperty -or
                -not $shaProperty -or -not $sddlProperty -or -not $aclProperty -or
                $pathProperty.Value -isnot [string] -or $pathPinProperty.Value -isnot [string] -or
                $backupProperty.Value -isnot [string] -or $backupPathPinProperty.Value -isnot [string] -or
                $backupRootProperty.Value -isnot [string] -or
                $backupSddlProperty.Value -isnot [string] -or $backupDirectorySddlProperty.Value -isnot [string] -or
                $shaProperty.Value -isnot [string] -or $shaProperty.Value -notmatch '^[0-9a-fA-F]{64}$' -or
                $sddlProperty.Value -isnot [string] -or [string]::IsNullOrWhiteSpace($sddlProperty.Value) -or
                -not $aclProperty.Value -or [string]$aclProperty.Value.Sddl -cne [string]$sddlProperty.Value -or
                -not $ExpectedPins.Contains($entryInfo.pin) -or
                [string]$ExpectedPins[$entryInfo.pin] -ine [string]$shaProperty.Value) {
                throw 'invalid'
            }
            $livePath = [IO.Path]::GetFullPath([string]$pathProperty.Value)
            $pinnedPath = [IO.Path]::GetFullPath([string]$pinnedFiles[$entryInfo.pin])
            if ($livePath -ine $pinnedPath -or [IO.Path]::GetFullPath([string]$pathPinProperty.Value) -ine $pinnedPath) {
                throw 'path pin'
            }
            $backupPath = [IO.Path]::GetFullPath([string]$backupProperty.Value)
            if ($paths.ContainsKey($livePath) -or $paths.ContainsKey($backupPath)) {
                throw 'aliased'
            }
            $paths[$livePath] = $true
            $paths[$backupPath] = $true
            if (-not (Test-Path -LiteralPath $livePath -PathType Leaf -ErrorAction Stop)) {
                throw 'missing live core'
            }
            $null = Get-CvrCorePreimageBackupBytes -Entry $entry -Role $entryInfo.role
            $liveHash = (Get-FileHash -LiteralPath $livePath -Algorithm SHA256 -ErrorAction Stop).Hash
            $liveSddl = (Get-Acl -LiteralPath $livePath -ErrorAction Stop).Sddl
            if ($liveHash -ine [string]$shaProperty.Value -or
                $liveSddl -cne [string]$sddlProperty.Value) {
                throw 'live core drift'
            }
        } catch {
            $failure = [string]$_.Exception.Message
            if ($failure -match '^(Program Files|service) core preimage backup validation failed at ') {
                throw "Idle target core preimage verification failed: $failure"
            }
            throw 'Idle target core preimage verification failed.'
        }
    }

    return $true
}


function Invoke-CvrIdleTargetTransaction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][scriptblock]$CaptureScript,
        [Parameter(Mandatory = $true)][string]$ExpectedTargetIdentity,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$ExpectedPins,
        [Parameter(Mandatory = $true)][scriptblock]$ActionScript,
        [Parameter(Mandatory = $true)][scriptblock]$RestoreScript,
        [Parameter(Mandatory = $true)][scriptblock]$VerifyScript
    )

    $capturedBaseline = & $CaptureScript
    $targetCaptureValid = Assert-CvrIdleTargetCapture -Capture $capturedBaseline -ExpectedTargetIdentity $ExpectedTargetIdentity -ExpectedPins $ExpectedPins
    if ($targetCaptureValid -isnot [bool] -or -not $targetCaptureValid) {
        throw 'Idle target capture validation did not pass.'
    }
    $validatedCapture = $capturedBaseline
    $validatedCaptureScript = { $validatedCapture }
    $validatedCaptureScript = $validatedCaptureScript.GetNewClosure()

    $transaction = Invoke-CvrIdleTransaction -CaptureScript $validatedCaptureScript -ActionScript $ActionScript -RestoreScript $RestoreScript -VerifyScript $VerifyScript
    return $transaction
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

function Get-CvrIdlePackageStageBinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$StageRoot,
        [Parameter(Mandatory = $true)][string]$ExpectedStageRoot,
        [Parameter(Mandatory = $true)][string]$ExpectedPackageManifestSha256
    )

    $openFiles = [Collections.Generic.List[IO.FileStream]]::new()
    try {
        if (-not [IO.Path]::IsPathRooted($StageRoot) -or
            -not [IO.Path]::IsPathRooted($ExpectedStageRoot) -or
            $ExpectedPackageManifestSha256 -notmatch '^[0-9a-fA-F]{64}$') {
            throw 'invalid'
        }
        $stagePath = [IO.Path]::GetFullPath($StageRoot)
        if ($stagePath -ine [IO.Path]::GetFullPath($ExpectedStageRoot)) { throw 'stage path' }
        $stageItem = Get-Item -LiteralPath $stagePath -Force -ErrorAction Stop
        if (-not $stageItem.PSIsContainer -or
            (([int]$stageItem.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw 'stage root'
        }
        try {
            $null = Assert-CvrIdleCaptureAcl -Path $stagePath -Directory
        } catch {
            throw 'Idle Preflight package root is not protected.'
        }

        $manifestPath = Join-Path $stagePath 'source-manifest.json'
        $manifestItem = Get-Item -LiteralPath $manifestPath -Force -ErrorAction Stop
        if ($manifestItem.PSIsContainer -or
            (([int]$manifestItem.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw 'manifest'
        }
        $null = Assert-CvrIdleCaptureAcl -Path $manifestPath
        $manifestStream = [IO.File]::Open(
            $manifestPath,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read
        )
        $null = $openFiles.Add($manifestStream)
        $manifestMemory = [IO.MemoryStream]::new()
        try {
            $manifestStream.CopyTo($manifestMemory)
            $manifestBytes = $manifestMemory.ToArray()
        } finally {
            $manifestMemory.Dispose()
        }
        $manifestHasher = [Security.Cryptography.SHA256]::Create()
        try {
            $manifestSha256 = ([BitConverter]::ToString($manifestHasher.ComputeHash($manifestBytes))).Replace('-', '').ToLowerInvariant()
        } finally {
            $manifestHasher.Dispose()
        }
        if ($manifestSha256 -ine $ExpectedPackageManifestSha256) { throw 'manifest pin' }

        $manifestText = [Text.UTF8Encoding]::new($false, $true).GetString($manifestBytes)
        if ($manifestText.Length -gt 0 -and $manifestText[0] -eq [char]0xFEFF) {
            $manifestText = $manifestText.Substring(1)
        }
        $manifest = ConvertFrom-Json -InputObject $manifestText -ErrorAction Stop
        if ([int]$manifest.schemaVersion -ne 1 -or @($manifest.files).Count -eq 0) {
            throw 'manifest schema'
        }
        $seenPaths = @{}
        foreach ($entry in @($manifest.files)) {
            $pathProperty = $entry.PSObject.Properties['path']
            $shaProperty = $entry.PSObject.Properties['sha256']
            if (-not $pathProperty -or $pathProperty.Value -isnot [string] -or
                -not $shaProperty -or $shaProperty.Value -isnot [string] -or
                $shaProperty.Value -notmatch '^[0-9a-fA-F]{64}$') {
                throw 'manifest entry'
            }
            $relativePath = [string]$pathProperty.Value
            if ([IO.Path]::IsPathRooted($relativePath) -or
                $relativePath -match '[\\:\x00-\x1f]' -or
                $relativePath.StartsWith('/')) {
                throw 'manifest path'
            }
            $segments = $relativePath.Split([char]'/')
            if ($segments.Count -eq 0) { throw 'manifest path' }
            foreach ($segment in $segments) {
                if ([string]::IsNullOrWhiteSpace($segment) -or $segment -ceq '.' -or $segment -ceq '..' -or $segment -match '[. ]$') {
                    throw 'manifest path'
                }
            }
            if ($seenPaths.ContainsKey($relativePath)) { throw 'duplicate path' }
            $seenPaths[$relativePath] = $true

            $currentPath = $stagePath
            for ($index = 0; $index -lt $segments.Count; $index++) {
                $currentPath = Join-Path $currentPath $segments[$index]
                $item = Get-Item -LiteralPath $currentPath -Force -ErrorAction Stop
                if ((([int]$item.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0) -or
                    ($index -lt ($segments.Count - 1) -and -not $item.PSIsContainer) -or
                    ($index -eq ($segments.Count - 1) -and $item.PSIsContainer)) {
                    throw 'staged path'
                }
                if ($index -lt ($segments.Count - 1)) {
                    $null = Assert-CvrIdleCaptureAcl -Path $currentPath -Directory
                } else {
                    $null = Assert-CvrIdleCaptureAcl -Path $currentPath
                    $entryStream = [IO.File]::Open(
                        $currentPath,
                        [IO.FileMode]::Open,
                        [IO.FileAccess]::Read,
                        [IO.FileShare]::Read
                    )
                    $null = $openFiles.Add($entryStream)
                    $entryHasher = [Security.Cryptography.SHA256]::Create()
                    try {
                        $actualSha256 = ([BitConverter]::ToString($entryHasher.ComputeHash($entryStream))).Replace('-', '').ToLowerInvariant()
                    } finally {
                        $entryHasher.Dispose()
                    }
                    if ($actualSha256 -ine [string]$shaProperty.Value) { throw 'staged hash' }
                }
            }
        }
        return [PSCustomObject]@{
            StageRoot = $stagePath
            SourceManifestSha256 = $manifestSha256
            OpenFiles = $openFiles.ToArray()
        }
    } catch {
        $failure = $_.Exception.Message
        foreach ($handle in $openFiles) {
            if ($handle) {
                try { $handle.Dispose() } catch { }
            }
        }
        if ($failure -ceq 'Idle Preflight package root is not protected.') {
            throw 'Idle Preflight package root is not protected.'
        }
        throw 'Idle package stage binding failed.'
    }
}

function Save-CvrIdlePreflightCapture {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$Capture,
        [Parameter(Mandatory = $true)][string]$ExpectedTargetIdentity,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$ExpectedPins,
        [Parameter(Mandatory = $true)][string]$PackageRoot,
        [Parameter(Mandatory = $true)][string]$ExpectedStageRoot,
        [Parameter(Mandatory = $true)][string]$ExpectedPackageManifestSha256
    )

    $null = Assert-CvrIdleTargetCapture -Capture $Capture -ExpectedTargetIdentity $ExpectedTargetIdentity -ExpectedPins $ExpectedPins
    $null = Assert-CvrIdleRollbackState -Capture $Capture -ExpectedPins $ExpectedPins -ExpectedLocalRoot ([IO.Path]::GetFullPath((Join-Path $PackageRoot 'local')))
    $packageStageBinding = Get-CvrIdlePackageStageBinding -StageRoot $PackageRoot -ExpectedStageRoot $ExpectedStageRoot -ExpectedPackageManifestSha256 $ExpectedPackageManifestSha256
    try {
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
        $null = Assert-CvrIdleCaptureAcl -Path $packagePath -Directory
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
    $storedPinnedFiles = [ordered]@{}
    foreach ($pinName in $pinNames) {
        $storedPins[$pinName] = [string]$ExpectedPins[$pinName]
        $storedPinnedFiles[$pinName] = [string]$Capture.pinnedFiles[$pinName]
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
        packageStageBinding = [ordered]@{
            stageRoot = [string]$packageStageBinding.StageRoot
            sourceManifestSha256 = [string]$packageStageBinding.SourceManifestSha256
        }
        capturedAtUtc = $Capture.capturedAtUtc.ToString('o')
        coreShouldBeRunning = [bool]$Capture.coreShouldBeRunning
        expectedPins = $storedPins
        pinnedFiles = $storedPinnedFiles
        rollbackState = $Capture.rollbackState
        idleObservation = $storedObservation
        corePair = [ordered]@{
            programFiles = [ordered]@{
                path = [string]$programFiles.path
                pathPin = [string]$programFiles.pathPin
                backup = [string]$programFiles.backup
                backupPathPin = [string]$programFiles.backupPathPin
                backupRoot = [string]$programFiles.backupRoot
                backupSddl = [string]$programFiles.backupSddl
                backupDirectorySddl = [string]$programFiles.backupDirectorySddl
                sha256 = [string]$programFiles.sha256
                sddl = [string]$programFiles.sddl
            }
            service = [ordered]@{
                path = [string]$serviceCore.path
                pathPin = [string]$serviceCore.pathPin
                backup = [string]$serviceCore.backup
                backupPathPin = [string]$serviceCore.backupPathPin
                backupRoot = [string]$serviceCore.backupRoot
                backupSddl = [string]$serviceCore.backupSddl
                backupDirectorySddl = [string]$serviceCore.backupDirectorySddl
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
    } finally {
        foreach ($handle in @($packageStageBinding.OpenFiles)) {
            if ($handle) { $handle.Dispose() }
        }
    }
}

function Save-CvrIdlePreflightPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$Capture,
        [Parameter(Mandatory = $true)][string]$CaptureDirectory,
        [Parameter(Mandatory = $true)][string]$ReceiptPath,
        [Parameter(Mandatory = $true)][string]$ExpectedTargetIdentity,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$ExpectedPins,
        [Parameter(Mandatory = $true)][string]$PackageRoot,
        [Parameter(Mandatory = $true)][string]$ExpectedStageRoot,
        [Parameter(Mandatory = $true)][string]$ExpectedPackageManifestSha256
    )

    $null = Assert-CvrIdleTargetCapture -Capture $Capture -ExpectedTargetIdentity $ExpectedTargetIdentity -ExpectedPins $ExpectedPins
    $null = Assert-CvrIdleRollbackState -Capture $Capture -ExpectedPins $ExpectedPins -ExpectedLocalRoot ([IO.Path]::GetFullPath((Join-Path $PackageRoot 'local')))
    $packageStageBinding = Get-CvrIdlePackageStageBinding -StageRoot $PackageRoot -ExpectedStageRoot $ExpectedStageRoot -ExpectedPackageManifestSha256 $ExpectedPackageManifestSha256
    try {

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
    $storedCorePair = [ordered]@{
        programFiles = [ordered]@{
            path = [string]$programFiles.path
            pathPin = [string]$programFiles.pathPin
            backup = [string]$programFiles.backup
            backupPathPin = [string]$programFiles.backupPathPin
            backupRoot = [string]$programFiles.backupRoot
            backupSddl = [string]$programFiles.backupSddl
            backupDirectorySddl = [string]$programFiles.backupDirectorySddl
            sha256 = [string]$programFiles.sha256
            sddl = [string]$programFiles.sddl
        }
        service = [ordered]@{
            path = [string]$serviceCore.path
            pathPin = [string]$serviceCore.pathPin
            backup = [string]$serviceCore.backup
            backupPathPin = [string]$serviceCore.backupPathPin
            backupRoot = [string]$serviceCore.backupRoot
            backupSddl = [string]$serviceCore.backupSddl
            backupDirectorySddl = [string]$serviceCore.backupDirectorySddl
            sha256 = [string]$serviceCore.sha256
            sddl = [string]$serviceCore.sddl
        }
    }
    $storedPinnedFiles = [ordered]@{}
    foreach ($pinName in $pinNames) {
        $storedPinnedFiles[$pinName] = [string]$Capture.pinnedFiles[$pinName]
    }
    $expectedReceipt = [ordered]@{
        targetIdentity = [string]$Capture.targetIdentity
        packageStageBinding = [ordered]@{
            stageRoot = [string]$packageStageBinding.StageRoot
            sourceManifestSha256 = [string]$packageStageBinding.SourceManifestSha256
        }
        capturedAtUtc = $Capture.capturedAtUtc.ToString('o')
        coreShouldBeRunning = [bool]$Capture.coreShouldBeRunning
        expectedPins = $storedPins
        pinnedFiles = $storedPinnedFiles
        rollbackState = $Capture.rollbackState
        idleObservation = $storedObservation
        corePair = $storedCorePair
    }
    $expectedReceiptText = ConvertTo-Json -InputObject $expectedReceipt -Depth 8 -Compress -ErrorAction Stop

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
        $null = Assert-CvrIdleCaptureAcl -Path $packagePath -Directory
        $null = Assert-CvrIdleCaptureAcl -Path $localPath -Directory
    } catch {
        throw 'Idle Preflight package root is not protected.'
    }

    $receiptStream = $null
    try {
        $capturePath = [IO.Path]::GetFullPath($CaptureDirectory)
        $receiptFullPath = [IO.Path]::GetFullPath($ReceiptPath)
        $expectedReceiptPath = [IO.Path]::GetFullPath((Join-Path $capturePath 'capture.json'))
        if ([IO.Path]::GetDirectoryName($capturePath) -ine $localPath -or
            [IO.Path]::GetFileName($capturePath) -notmatch '^capture-idle-[0-9a-f]{32}$' -or
            $receiptFullPath -ine $expectedReceiptPath -or
            -not (Test-Path -LiteralPath $receiptFullPath -PathType Leaf -ErrorAction Stop)) {
            throw 'invalid'
        }
        $null = Assert-CvrIdleCaptureAcl -Path $capturePath -Directory
        $null = Assert-CvrIdleCaptureAcl -Path $receiptFullPath
        $receiptStream = [IO.File]::Open($receiptFullPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        $receiptMemory = New-Object IO.MemoryStream
        try {
            $receiptStream.CopyTo($receiptMemory)
            $receiptBytes = $receiptMemory.ToArray()
        } finally {
            $receiptMemory.Dispose()
        }
        $actualReceiptText = [Text.UTF8Encoding]::new($false, $true).GetString($receiptBytes)
        if ($actualReceiptText -cne $expectedReceiptText) {
            throw 'mismatch'
        }
        $receiptHasher = [Security.Cryptography.SHA256]::Create()
        try {
            $captureReceiptSha256 = ([BitConverter]::ToString($receiptHasher.ComputeHash($receiptBytes))).Replace('-', '').ToLowerInvariant()
        } finally {
            $receiptHasher.Dispose()
        }
        if ($captureReceiptSha256 -notmatch '^[0-9a-f]{64}$') { throw 'hash' }
    } catch {
        if ($receiptStream) {
            $receiptStream.Dispose()
            $receiptStream = $null
        }
        throw 'Idle Preflight capture receipt does not match the supplied capture.'
    }

    try {
        $plan = $expectedReceipt
        $plan['pinnedFiles'] = $storedPinnedFiles
        $plan['captureDirectory'] = $capturePath
        $plan['captureReceiptPath'] = $receiptFullPath
        $plan['captureReceiptSha256'] = $captureReceiptSha256
        $planBytes = [Text.UTF8Encoding]::new($false).GetBytes(
            (ConvertTo-Json -InputObject $plan -Depth 8 -Compress -ErrorAction Stop)
        )
        $preparedDirectory = Join-Path $localPath ('prepared-idle-' + [Guid]::NewGuid().ToString('N'))
        $createdDirectory = $false
        try {
            if (Test-Path -LiteralPath $preparedDirectory) { throw 'exists' }
            $null = New-Item -ItemType Directory -Path $preparedDirectory -ErrorAction Stop
            $createdDirectory = $true
            $null = Set-CvrIdleCaptureAcl -Path $preparedDirectory -Directory

            $planPath = Join-Path $preparedDirectory 'plan.json'
            $stream = [IO.File]::Open(
                $planPath,
                [IO.FileMode]::CreateNew,
                [IO.FileAccess]::Write,
                [IO.FileShare]::None
            )
            $stream.Dispose()
            $null = Set-CvrIdleCaptureAcl -Path $planPath
            $stream = [IO.File]::Open(
                $planPath,
                [IO.FileMode]::Open,
                [IO.FileAccess]::Write,
                [IO.FileShare]::None
            )
            try {
                $stream.Write($planBytes, 0, $planBytes.Length)
                $stream.Flush()
            } finally {
                $stream.Dispose()
            }

            if ((Get-FileHash -LiteralPath $receiptFullPath -Algorithm SHA256 -ErrorAction Stop).Hash -ine $captureReceiptSha256) {
                throw 'receipt-drift'
            }
            $planSha256 = (Get-FileHash -LiteralPath $planPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
            return [PSCustomObject]@{
                PreparedDirectory = $preparedDirectory
                PlanPath = $planPath
                PlanSha256 = $planSha256
            }
        } catch {
            if ($createdDirectory) {
                Remove-Item -LiteralPath $preparedDirectory -Recurse -Force -ErrorAction SilentlyContinue
            }
            throw 'Idle Preflight plan could not be written.'
        }

    } finally {
        if ($receiptStream) { $receiptStream.Dispose() }
    }
    } finally {
        foreach ($handle in @($packageStageBinding.OpenFiles)) {
            if ($handle) { $handle.Dispose() }
        }
    }
}

function Invoke-CvrIdlePreflightPackageWriter {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Capture', 'Plan')][string]$Mode,
        [Parameter(Mandatory = $true)][object]$Capture,
        [Parameter(Mandatory = $true)][string]$ExpectedTargetIdentity,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$ExpectedPins,
        [Parameter(Mandatory = $true)][string]$PackageRoot,
        [Parameter(Mandatory = $true)][string]$ExpectedStageRoot,
        [Parameter(Mandatory = $true)][string]$ExpectedPackageManifestSha256,
        [string]$CaptureDirectory,
        [string]$ReceiptPath
    )

    $writerArguments = @{
        Capture = $Capture
        ExpectedTargetIdentity = $ExpectedTargetIdentity
        ExpectedPins = $ExpectedPins
        PackageRoot = $PackageRoot
        ExpectedStageRoot = $ExpectedStageRoot
        ExpectedPackageManifestSha256 = $ExpectedPackageManifestSha256
    }
    if ($Mode -eq 'Capture') {
        return Save-CvrIdlePreflightCapture @writerArguments
    }

    $writerArguments.CaptureDirectory = $CaptureDirectory
    $writerArguments.ReceiptPath = $ReceiptPath
    return Save-CvrIdlePreflightPlan @writerArguments
}


function Save-CvrIdleFilePreimageBackup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][ValidateSet('gui','service-exe')][string]$Role,
        [Parameter(Mandatory = $true)][string]$SourcePath,
        [Parameter(Mandatory = $true)][string]$ExpectedInstallDirectory,
        [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedSha256
    )

    $rootPath = [IO.Path]::GetFullPath($Root)
    $source = [IO.Path]::GetFullPath($SourcePath)
    $install = [IO.Path]::GetFullPath($ExpectedInstallDirectory)
    $directory = $null
    try {
        $null = Assert-CvrIdleCaptureAcl -Path $rootPath -Directory
        $sourceItem = Get-Item -LiteralPath $source -Force -ErrorAction Stop
        if ($sourceItem.PSIsContainer -or
            (([int]$sourceItem.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0) -or
            [IO.Path]::GetDirectoryName($source) -ine $install -or
            [IO.Path]::GetFileName($source) -notmatch '^[A-Za-z0-9_. -]{1,120}\.exe$') {
            throw 'source'
        }
        $sourceAcl = Get-Acl -LiteralPath $source -ErrorAction Stop
        $sourceSddl = [string]$sourceAcl.Sddl
        if ([string]::IsNullOrWhiteSpace($sourceSddl)) { throw 'source acl' }

        $input = [IO.File]::Open($source, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        try {
            $hasher = [Security.Cryptography.SHA256]::Create()
            try {
                $actualSha = ([BitConverter]::ToString($hasher.ComputeHash($input))).Replace('-', '').ToLowerInvariant()
            } finally { $hasher.Dispose() }
            if ($actualSha -ine $ExpectedSha256.ToLowerInvariant()) { throw 'source hash' }
            $input.Position = 0

            $directory = Join-Path $rootPath ('stcvrc-idle-preimage-' + $Role + '-' + [Guid]::NewGuid().ToString('N'))
            if (Test-Path -LiteralPath $directory) { throw 'preexisting backup' }
            $null = New-Item -ItemType Directory -Path $directory -ErrorAction Stop
            $null = Set-CvrIdleCaptureAcl -Path $directory -Directory
            $backup = Join-Path $directory ([IO.Path]::GetFileName($source))
            $create = [IO.File]::Open($backup, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            $create.Dispose()
            $null = Set-CvrIdleCaptureAcl -Path $backup
            $output = [IO.File]::Open($backup, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try {
                $input.CopyTo($output)
                $output.Flush()
            } finally { $output.Dispose() }
        } finally { $input.Dispose() }

        $backupSha = (Get-FileHash -LiteralPath $backup -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        $backupSddl = [string](Get-Acl -LiteralPath $backup -ErrorAction Stop).Sddl
        $directorySddl = [string](Get-Acl -LiteralPath $directory -ErrorAction Stop).Sddl
        if ($backupSha -ine $ExpectedSha256.ToLowerInvariant()) { throw 'backup hash' }
        $null = Assert-CvrIdleCaptureAcl -Path $directory -Directory
        $null = Assert-CvrIdleCaptureAcl -Path $backup
        return [PSCustomObject]@{
            path = $source
            pathPin = $source
            backup = [IO.Path]::GetFullPath($backup)
            backupPathPin = [IO.Path]::GetFullPath($backup)
            backupRoot = $rootPath
            backupSddl = $backupSddl
            backupDirectorySddl = $directorySddl
            sha256 = $ExpectedSha256.ToLowerInvariant()
            sddl = $sourceSddl
        }
    } catch {
        if ($directory -and (Test-Path -LiteralPath $directory -PathType Container)) {
            Remove-Item -LiteralPath $directory -Recurse -Force -ErrorAction SilentlyContinue
        }
        throw 'Idle executable preimage backup could not be created.'
    }
}

function Get-CvrIdleFilePreimageBackupBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$Entry,
        [Parameter(Mandatory = $true)][ValidateSet('gui','service-exe')][string]$Role,
        [Parameter(Mandatory = $true)][string]$ExpectedPath,
        [Parameter(Mandatory = $true)][string]$ExpectedLocalRoot,
        [Parameter(Mandatory = $true)][string]$ExpectedInstallDirectory,
        [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedSha256
    )

    try {
        $source = [IO.Path]::GetFullPath($ExpectedPath)
        $install = [IO.Path]::GetFullPath($ExpectedInstallDirectory)
        $root = [IO.Path]::GetFullPath($ExpectedLocalRoot)
        $entryPath = [IO.Path]::GetFullPath([string]$Entry.path)
        $pathPin = [IO.Path]::GetFullPath([string]$Entry.pathPin)
        $backup = [IO.Path]::GetFullPath([string]$Entry.backup)
        $backupPin = [IO.Path]::GetFullPath([string]$Entry.backupPathPin)
        $directory = [IO.Path]::GetDirectoryName($backup)
        $label = if ($Role -ceq 'gui') { 'gui' } else { 'service-exe' }
        if ($entryPath -ine $source -or $pathPin -ine $source -or
            $backup -ine $backupPin -or
            [IO.Path]::GetDirectoryName($source) -ine $install -or
            [string]$Entry.backupRoot -ine $root -or
            [IO.Path]::GetDirectoryName($directory) -ine $root -or
            [IO.Path]::GetFileName($directory) -notmatch ('^stcvrc-idle-preimage-' + $label + '-[0-9a-f]{32}$') -or
            [IO.Path]::GetFileName($backup) -cne [IO.Path]::GetFileName($source) -or
            [string]$Entry.sha256 -ine $ExpectedSha256 -or
            [string]::IsNullOrWhiteSpace([string]$Entry.backupSddl) -or
            [string]::IsNullOrWhiteSpace([string]$Entry.backupDirectorySddl) -or
            [string]::IsNullOrWhiteSpace([string]$Entry.sddl)) {
            throw 'metadata'
        }
        $rootItem = Get-Item -LiteralPath $root -Force -ErrorAction Stop
        $directoryItem = Get-Item -LiteralPath $directory -Force -ErrorAction Stop
        $backupItem = Get-Item -LiteralPath $backup -Force -ErrorAction Stop
        if (-not $rootItem.PSIsContainer -or -not $directoryItem.PSIsContainer -or $backupItem.PSIsContainer -or
            (([int]$rootItem.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0) -or
            (([int]$directoryItem.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0) -or
            (([int]$backupItem.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw 'type'
        }
        $null = Assert-CvrIdleCaptureAcl -Path $root -Directory
        $null = Assert-CvrIdleCaptureAcl -Path $directory -Directory
        $null = Assert-CvrIdleCaptureAcl -Path $backup
        if ((Get-Acl -LiteralPath $directory -ErrorAction Stop).Sddl -cne [string]$Entry.backupDirectorySddl -or
            (Get-Acl -LiteralPath $backup -ErrorAction Stop).Sddl -cne [string]$Entry.backupSddl) {
            throw 'acl'
        }
        $bytes = [IO.File]::ReadAllBytes($backup)
        if ((Get-CvrByteArraySha256 -Bytes $bytes) -ine $ExpectedSha256) { throw 'hash' }
        return ,$bytes
    } catch {
        throw "Idle $Role executable preimage backup validation failed."
    }
}

function ConvertTo-CvrIdleFileSecurity {
    param([Parameter(Mandatory = $true)][string]$Sddl)
    if ([string]::IsNullOrWhiteSpace($Sddl)) { throw 'Idle file preimage ACL is missing.' }
    $security = [Security.AccessControl.FileSecurity]::new()
    $security.SetSecurityDescriptorSddlForm($Sddl)
    return $security
}

function Restore-CvrIdleFilePreimage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$Entry,
        [Parameter(Mandatory = $true)][ValidateSet('gui','service-exe')][string]$Role,
        [Parameter(Mandatory = $true)][string]$ExpectedPath,
        [Parameter(Mandatory = $true)][string]$ExpectedLocalRoot,
        [Parameter(Mandatory = $true)][string]$ExpectedInstallDirectory,
        [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedSha256
    )

    $bytes = Get-CvrIdleFilePreimageBackupBytes -Entry $Entry -Role $Role -ExpectedPath $ExpectedPath -ExpectedLocalRoot $ExpectedLocalRoot -ExpectedInstallDirectory $ExpectedInstallDirectory -ExpectedSha256 $ExpectedSha256
    $target = [IO.Path]::GetFullPath($ExpectedPath)
    $parent = [IO.Path]::GetDirectoryName($target)
    $parentItem = Get-Item -LiteralPath $parent -Force -ErrorAction Stop
    if (-not $parentItem.PSIsContainer -or
        (([int]$parentItem.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "Idle $Role executable preimage restore failed."
    }
    if (Test-Path -LiteralPath $target) {
        $item = Get-Item -LiteralPath $target -Force -ErrorAction Stop
        if ($item.PSIsContainer -or (([int]$item.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw "Idle $Role executable preimage restore failed."
        }
    }
    try {
        [IO.File]::WriteAllBytes($target, $bytes)
        $acl = if ($Entry.PSObject.Properties['acl'] -and $Entry.acl) {
            $Entry.acl
        } else {
            ConvertTo-CvrIdleFileSecurity -Sddl ([string]$Entry.sddl)
        }
        Set-Acl -LiteralPath $target -AclObject $acl -ErrorAction Stop
        if ((Get-FileHash -LiteralPath $target -Algorithm SHA256 -ErrorAction Stop).Hash -ine $ExpectedSha256 -or
            (Get-Acl -LiteralPath $target -ErrorAction Stop).Sddl -cne [string]$Entry.sddl) {
            throw 'restore verification'
        }
    } catch {
        throw "Idle $Role executable preimage restore failed."
    }
    return $true
}

function Assert-CvrIdleRollbackState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$Capture,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$ExpectedPins,
        [Parameter(Mandatory = $true)][string]$ExpectedLocalRoot
    )

    try {
        $localRoot = [IO.Path]::GetFullPath($ExpectedLocalRoot)
        $null = Assert-CvrIdleCaptureAcl -Path $localRoot -Directory
        $state = $Capture.rollbackState
        if (-not $state -or [int]$state.schemaVersion -ne 1) { throw 'schema' }
        $install = [IO.Path]::GetFullPath([string]$state.installDirectory)
        $guiPath = [IO.Path]::GetFullPath([string]$Capture.pinnedFiles.gui258)
        $servicePath = [IO.Path]::GetFullPath([string]$Capture.pinnedFiles.serviceExe258)
        if ([IO.Path]::GetDirectoryName($guiPath) -ine $install -or
            [IO.Path]::GetDirectoryName($servicePath) -ine $install) { throw 'install path' }
        $installItem = Get-Item -LiteralPath $install -Force -ErrorAction Stop
        if (-not $installItem.PSIsContainer -or
            (([int]$installItem.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0)) { throw 'install directory' }

        foreach ($item in @(
            [PSCustomObject]@{ Role='gui'; Entry=$state.gui; Path=$guiPath; Pin='gui258' },
            [PSCustomObject]@{ Role='service-exe'; Entry=$state.serviceExe; Path=$servicePath; Pin='serviceExe258' }
        )) {
            $entry = $item.Entry
            if (-not $entry -or -not $ExpectedPins.Contains($item.Pin) -or
                [string]$entry.path -ine $item.Path -or
                [string]$entry.pathPin -ine $item.Path -or
                [string]$entry.sha256 -ine [string]$ExpectedPins[$item.Pin] -or
                [string]$entry.sddl -cne [string](Get-Acl -LiteralPath $item.Path -ErrorAction Stop).Sddl) {
                throw 'target metadata'
            }
            $target = Get-Item -LiteralPath $item.Path -Force -ErrorAction Stop
            if ($target.PSIsContainer -or
                (([int]$target.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0) -or
                (Get-FileHash -LiteralPath $item.Path -Algorithm SHA256 -ErrorAction Stop).Hash -ine [string]$ExpectedPins[$item.Pin]) {
                throw 'target drift'
            }
            $null = Get-CvrIdleFilePreimageBackupBytes -Entry $entry -Role $item.Role -ExpectedPath $item.Path -ExpectedLocalRoot $localRoot -ExpectedInstallDirectory $install -ExpectedSha256 ([string]$ExpectedPins[$item.Pin])
        }

        $observer = $state.observer
        if (-not $observer -or
            [string]$observer.ownerSid -notmatch '^S-\d(-\d+)+$' -or
            [int]$observer.sessionId -lt 0 -or
            [string]$observer.serviceAccountSid -notmatch '^S-\d(-\d+)+$' -or
            [int]$observer.serviceProcessId -le 0) { throw 'observer' }

        $legacy = $state.legacyState
        if (-not $legacy -or @($legacy.files).Count -ne 2 -or @($legacy.registry).Count -ne 4) { throw 'legacy shape' }
        $currentLegacy = Get-CvrLegacyState
        if (@($currentLegacy.files).Count -ne 2 -or @($currentLegacy.registry).Count -ne 4) { throw 'legacy current shape' }
        for ($i = 0; $i -lt 2; $i++) {
            $before = $legacy.files[$i]
            $after = $currentLegacy.files[$i]
            if ([string]$before.path -ine [string]$after.path -or
                [bool]$before.present -ne [bool]$after.present) { throw 'legacy path' }
            if ($before.present) {
                if ([string]$before.bytes -notmatch '^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$' -or
                    [Convert]::FromBase64String([string]$before.bytes).Length -gt 262144 -or
                    [string]::IsNullOrWhiteSpace([string]$before.sddl)) { throw 'legacy preimage' }
                $null = ConvertTo-CvrIdleFileSecurity -Sddl ([string]$before.sddl)
            } elseif ($null -ne $before.bytes -or $null -ne $before.sddl) { throw 'legacy absent' }
        }
        $expectedRunNames = @(
            'CurrentUser|Clash Verge', 'LocalMachine|Clash Verge',
            'CurrentUser|clash-verge', 'LocalMachine|clash-verge'
        )
        for ($i = 0; $i -lt 4; $i++) {
            $entry = $legacy.registry[$i]
            if (($entry.hive + '|' + $entry.name) -cne $expectedRunNames[$i] -or
                ($entry.present -and
                    ([string]$entry.kind -notin @('String','ExpandString') -or
                     $entry.data -isnot [string] -or $entry.data.Length -gt 4096)) -or
                (-not $entry.present -and ($null -ne $entry.kind -or $null -ne $entry.data))) {
                throw 'legacy Run preimage'
            }
        }
        Assert-CvrLegacyState -Expected $legacy -Phase 'idle rollback preimage'
        return $true
    } catch {
        $message = [string]$_.Exception.Message
        if ($message -match 'CVR (?:window-state|Run-value|preimage)') { throw }
        throw 'Idle target legacy rollback preimage validation failed.'
    }
}

function ConvertTo-CvrIdleTransactionCapture {
    param([Parameter(Mandatory = $true)][object]$Receipt)

    $receiptText = ConvertTo-Json -InputObject $Receipt -Depth 16 -Compress -ErrorAction Stop
    $Receipt = ConvertFrom-Json -InputObject $receiptText -ErrorAction Stop
    $capturedAt = [DateTime]::Parse(
        [string]$Receipt.capturedAtUtc,
        [Globalization.CultureInfo]::InvariantCulture,
        ([Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal)
    )
    $pins = [ordered]@{}
    foreach ($property in @($Receipt.expectedPins.PSObject.Properties)) {
        $pins[[string]$property.Name] = [string]$property.Value
    }
    $files = [ordered]@{}
    foreach ($property in @($Receipt.pinnedFiles.PSObject.Properties)) {
        $files[[string]$property.Name] = [string]$property.Value
    }
    $observation = [ordered]@{}
    foreach ($property in @($Receipt.idleObservation.PSObject.Properties)) {
        $observation[[string]$property.Name] = $property.Value
    }
    foreach ($role in @('programFiles','service')) {
        $entry = $Receipt.corePair.$role
        $null = $entry | Add-Member -MemberType NoteProperty -Name 'acl' -Value (ConvertTo-CvrIdleFileSecurity -Sddl ([string]$entry.sddl)) -Force
    }
    foreach ($entry in @($Receipt.rollbackState.legacyState.files)) {
        if ($entry.present) {
            $null = $entry | Add-Member -MemberType NoteProperty -Name 'acl' -Value (ConvertTo-CvrIdleFileSecurity -Sddl ([string]$entry.sddl)) -Force
        } else {
            $null = $entry | Add-Member -MemberType NoteProperty -Name 'acl' -Value $null -Force
        }
    }
    return [PSCustomObject]@{
        targetIdentity = [string]$Receipt.targetIdentity
        capturedAtUtc = $capturedAt
        coreShouldBeRunning = [bool]$Receipt.coreShouldBeRunning
        expectedPins = $pins
        pinnedFiles = $files
        rollbackState = $Receipt.rollbackState
        idleObservation = $observation
        corePair = $Receipt.corePair
    }
}

function Open-CvrIdleHandoffRecord {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$LocalRoot,
        [Parameter(Mandatory = $true)][ValidateSet('capture-idle','prepared-idle','preflight-idle')][string]$DirectoryPrefix,
        [Parameter(Mandatory = $true)][string]$FileName,
        [Parameter(Mandatory = $true)][ValidateRange(1,1048576)][int]$MaximumBytes,
        [Parameter(Mandatory = $true)][Collections.Generic.List[IO.FileStream]]$OpenFiles
    )

    $fullPath = [IO.Path]::GetFullPath($Path)
    $directory = [IO.Path]::GetDirectoryName($fullPath)
    if ([IO.Path]::GetDirectoryName($directory) -ine [IO.Path]::GetFullPath($LocalRoot) -or
        [IO.Path]::GetFileName($directory) -notmatch ('^' + $DirectoryPrefix + '-[0-9a-f]{32}$') -or
        [IO.Path]::GetFileName($fullPath) -cne $FileName) { throw 'path' }
    $directoryItem = Get-Item -LiteralPath $directory -Force -ErrorAction Stop
    $fileItem = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
    if (-not $directoryItem.PSIsContainer -or $fileItem.PSIsContainer -or
        (([int]$directoryItem.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0) -or
        (([int]$fileItem.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0)) { throw 'type' }
    $null = Assert-CvrIdleCaptureAcl -Path $directory -Directory
    $null = Assert-CvrIdleCaptureAcl -Path $fullPath
    $stream = [IO.File]::Open($fullPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $null = $OpenFiles.Add($stream)
    if ($stream.Length -gt $MaximumBytes) { throw 'size' }
    $memory = [IO.MemoryStream]::new()
    try { $stream.CopyTo($memory); $bytes = $memory.ToArray() }
    finally { $memory.Dispose() }
    $text = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    if ($text.Length -gt 0 -and $text[0] -eq [char]0xFEFF) { $text = $text.Substring(1) }
    $sha = Get-CvrByteArraySha256 -Bytes $bytes
    $document = ConvertFrom-Json -InputObject $text -ErrorAction Stop
    if ($document -isnot [PSCustomObject]) { throw 'shape' }
    return [PSCustomObject]@{ Path=$fullPath; Bytes=$bytes; Sha256=$sha; Document=$document }
}

function Get-CvrIdleHandoffProjection {
    param([Parameter(Mandatory = $true)][object]$Document)
    $projection = [ordered]@{}
    foreach ($name in @(
        'targetIdentity','packageStageBinding','capturedAtUtc','coreShouldBeRunning',
        'expectedPins','pinnedFiles','rollbackState','idleObservation','corePair'
    )) {
        $property = $Document.PSObject.Properties[$name]
        if (-not $property) { throw 'Idle handoff binding is incomplete.' }
        $projection[$name] = $property.Value
    }
    return ConvertTo-Json -InputObject $projection -Depth 16 -Compress -ErrorAction Stop
}

function Get-CvrIdleObservationText {
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Observation)
    $projection = [ordered]@{
        CoreShouldBeRunning = $Observation.CoreShouldBeRunning
        OwnedGuiProcessIds = @($Observation.OwnedGuiProcessIds)
        OwnedCoreProcessIds = @($Observation.OwnedCoreProcessIds)
        ControllerListening = $Observation.ControllerListening
        OwnedListenerProcessIds = @($Observation.OwnedListenerProcessIds)
        ServiceStatus = [string]$Observation.ServiceStatus
        ExpectedProgramFilesCoreSha256 = [string]$Observation.ExpectedProgramFilesCoreSha256
        ObservedProgramFilesCoreSha256 = [string]$Observation.ObservedProgramFilesCoreSha256
        ExpectedServiceCoreSha256 = [string]$Observation.ExpectedServiceCoreSha256
        ObservedServiceCoreSha256 = [string]$Observation.ObservedServiceCoreSha256
    }
    return ConvertTo-Json -InputObject $projection -Depth 5 -Compress -ErrorAction Stop
}

function Assert-CvrIdleFreshObservation {
    param(
        [Parameter(Mandatory = $true)][object]$Capture,
        [Parameter(Mandatory = $true)][object]$Fresh,
        [switch]$RequireSameServicePid
    )

    if (-not $Fresh -or $Fresh.SampledAtUtc -isnot [DateTime] -or
        $Fresh.SampledAtUtc.Kind -ne [DateTimeKind]::Utc) {
        throw 'Fresh idle observation is unavailable.'
    }
    $age = [DateTime]::UtcNow - $Fresh.SampledAtUtc
    if ($age.TotalSeconds -lt 0 -or $age.TotalSeconds -gt 60) { throw 'Fresh idle observation is stale.' }
    $expected = $Capture.rollbackState.observer
    $actual = $Fresh.Observer
    if (-not $expected -or
        [string]$expected.ownerSid -notmatch '^S-\d(-\d+)+$' -or
        [int]$expected.sessionId -lt 0 -or
        [string]$expected.serviceAccountSid -notmatch '^S-\d(-\d+)+$' -or
        [int]$expected.serviceProcessId -le 0 -or
        -not $actual -or
        [string]$actual.ownerSid -notmatch '^S-\d(-\d+)+$' -or
        [int]$actual.sessionId -lt 0 -or
        [string]$actual.serviceAccountSid -notmatch '^S-\d(-\d+)+$' -or
        [int]$actual.serviceProcessId -le 0 -or
        [string]$actual.ownerSid -cne [string]$expected.ownerSid -or
        [int]$actual.sessionId -ne [int]$expected.sessionId -or
        [string]$actual.serviceAccountSid -cne [string]$expected.serviceAccountSid -or
        ($RequireSameServicePid -and [int]$actual.serviceProcessId -ne [int]$expected.serviceProcessId)) {
        throw 'Fresh idle observation ownership does not match the capture.'
    }
    $observation = $Fresh.Observation
    if ($observation -isnot [System.Collections.IDictionary]) { throw 'Fresh idle observation is incomplete.' }
    $null = Assert-CvrIdleBaseline @observation
    if ((Get-CvrIdleObservationText -Observation $observation) -cne
        (Get-CvrIdleObservationText -Observation $Capture.idleObservation)) {
        throw 'Fresh idle observation differs from the protected capture.'
    }
    return $true
}

function Invoke-CvrIdlePreflightTargetTransaction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$CaptureReceiptPath,
        [Parameter(Mandatory = $true)][string]$PlanPath,
        [Parameter(Mandatory = $true)][string]$PreflightReceiptPath,
        [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedPlanSha256,
        [Parameter(Mandatory = $true)][string]$ExpectedStageRoot,
        [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedPackageManifestSha256,
        [Parameter(Mandatory = $true)][string]$ExpectedTargetIdentity,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$ExpectedPins,
        [Parameter(Mandatory = $true)][scriptblock]$RefreshObservationScript,
        [Parameter(Mandatory = $true)][scriptblock]$ActionScript,
        [Parameter(Mandatory = $true)][scriptblock]$CandidateCheckScript,
        [Parameter(Mandatory = $true)][scriptblock]$RestoreScript,
        [Parameter(Mandatory = $true)][scriptblock]$VerifyScript
    )

    $binding = $null
    $openFiles = [Collections.Generic.List[IO.FileStream]]::new()
    $handoffState = [PSCustomObject]@{
        ActionErrorType = $null
        RestoreErrorType = $null
        VerifyErrorType = $null
        ActionResult = $null
    }
    try {
        $localRoot = [IO.Path]::GetFullPath((Join-Path ([IO.Path]::GetFullPath($ExpectedStageRoot)) 'local'))
        $null = Assert-CvrIdleCaptureAcl -Path ([IO.Path]::GetFullPath($ExpectedStageRoot)) -Directory
        $null = Assert-CvrIdleCaptureAcl -Path $localRoot -Directory
        $binding = Get-CvrIdlePackageStageBinding -StageRoot $ExpectedStageRoot -ExpectedStageRoot $ExpectedStageRoot -ExpectedPackageManifestSha256 $ExpectedPackageManifestSha256
        $captureRecord = Open-CvrIdleHandoffRecord -Path $CaptureReceiptPath -LocalRoot $localRoot -DirectoryPrefix 'capture-idle' -FileName 'capture.json' -MaximumBytes 1048576 -OpenFiles $openFiles
        $planRecord = Open-CvrIdleHandoffRecord -Path $PlanPath -LocalRoot $localRoot -DirectoryPrefix 'prepared-idle' -FileName 'plan.json' -MaximumBytes 1048576 -OpenFiles $openFiles
        $preflightRecord = Open-CvrIdleHandoffRecord -Path $PreflightReceiptPath -LocalRoot $localRoot -DirectoryPrefix 'preflight-idle' -FileName 'result.json' -MaximumBytes 4096 -OpenFiles $openFiles
        if ($planRecord.Sha256 -ine $ExpectedPlanSha256 -or
            [string]$planRecord.Document.targetIdentity -cne $ExpectedTargetIdentity -or
            [string]$planRecord.Document.packageStageBinding.stageRoot -ine $binding.StageRoot -or
            [string]$planRecord.Document.packageStageBinding.sourceManifestSha256 -ine $binding.SourceManifestSha256) {
            throw 'Idle handoff Plan or stage pin mismatch.'
        }
        $plan = $planRecord.Document
        if ([IO.Path]::GetFullPath([string]$plan.captureDirectory) -ine [IO.Path]::GetDirectoryName($captureRecord.Path) -or
            [IO.Path]::GetFullPath([string]$plan.captureReceiptPath) -ine $captureRecord.Path -or
            [string]$plan.captureReceiptSha256 -ine $captureRecord.Sha256 -or
            (Get-CvrIdleHandoffProjection -Document $captureRecord.Document) -cne
            (Get-CvrIdleHandoffProjection -Document $plan)) {
            throw 'Idle handoff Capture and Plan do not match.'
        }
        $preflight = $preflightRecord.Document
        if ([string]$preflight.result -cne 'PASS' -or [int]$preflight.exitCode -ne 0 -or
            $preflight.timedOut -isnot [bool] -or $preflight.timedOut -or
            $preflight.childStopped -isnot [bool] -or -not $preflight.childStopped -or
            [int]$preflight.childExitCode -ne 0 -or
            [string]$preflight.planSha256 -ine $planRecord.Sha256 -or
            [string]$preflight.sourceManifestSha256 -ine $binding.SourceManifestSha256 -or
            [string]$preflight.receiptId -notmatch '^[0-9a-f]{32}$' -or
            [IO.Path]::GetDirectoryName($preflightRecord.Path) -ine
                [IO.Path]::GetFullPath((Join-Path $localRoot ('preflight-idle-' + [string]$preflight.receiptId))) {
            throw 'Idle handoff does not contain a successful bound Preflight.'
        }

        $capture = ConvertTo-CvrIdleTransactionCapture -Receipt $captureRecord.Document
        if ($capture.targetIdentity -cne $ExpectedTargetIdentity -or
            $ExpectedPins.Count -ne 9 -or $capture.expectedPins.Count -ne $ExpectedPins.Count) {
            throw 'Idle handoff target or pin set is incomplete.'
        }
        foreach ($name in $ExpectedPins.Keys) {
            if (-not $capture.expectedPins.Contains($name) -or
                [string]$capture.expectedPins[$name] -ine [string]$ExpectedPins[$name]) {
                throw 'Idle handoff pins differ from the approved inputs.'
            }
        }
        $payloadPins = [ordered]@{
            candidateCore = 'payload/verge-mihomo.exe'
            updateInstaller = 'payload/Clash.Verge_2.5.10_x64-setup.exe'
            recoveryInstaller = 'payload/Clash.Verge_2.5.8_x64-setup.exe'
        }
        $manifestFile = Join-Path $binding.StageRoot 'source-manifest.json'
        if ((Get-Item -LiteralPath $manifestFile -Force -ErrorAction Stop).Length -gt 1048576) { throw 'Idle package stage manifest is oversized.' }
        $manifestText = [Text.UTF8Encoding]::new($false, $true).GetString([IO.File]::ReadAllBytes($manifestFile))
        $manifest = ConvertFrom-Json -InputObject $manifestText -ErrorAction Stop
        foreach ($name in $payloadPins.Keys) {
            $entry = @($manifest.files | Where-Object { [string]$_.path -ceq [string]$payloadPins[$name] })
            $relative = ([string]$payloadPins[$name]).Replace('/', '\')
            $stagePath = [IO.Path]::GetFullPath((Join-Path $binding.StageRoot $relative))
            if ($entry.Count -ne 1 -or
                [string]$entry[0].sha256 -ine [string]$ExpectedPins[$name] -or
                [IO.Path]::GetFullPath([string]$capture.pinnedFiles[$name]) -ine $stagePath) {
                throw 'Idle handoff candidate payload identity does not match the pinned stage.'
            }
        }
        $null = Assert-CvrIdleTargetCapture -Capture $capture -ExpectedTargetIdentity $ExpectedTargetIdentity -ExpectedPins $ExpectedPins
        $null = Assert-CvrIdleRollbackState -Capture $capture -ExpectedPins $ExpectedPins -ExpectedLocalRoot $localRoot

        $actionClosure = {
            param($unused)
            try {
                $contextPins = [ordered]@{}
                foreach ($pinName in $ExpectedPins.Keys) { $contextPins[$pinName] = [string]$ExpectedPins[$pinName] }
                $context = [PSCustomObject]@{
                    Capture = ConvertTo-CvrIdleTransactionCapture -Receipt $captureRecord.Document
                    StageRoot = $binding.StageRoot
                    SourceManifestSha256 = $binding.SourceManifestSha256
                    ExpectedPins = $contextPins
                }
                $handoffState.ActionResult = & $ActionScript $context
                $candidateAccepted = & $CandidateCheckScript $context $handoffState.ActionResult
                if ($candidateAccepted -isnot [bool] -or -not $candidateAccepted) {
                    throw 'Candidate acceptance check did not pass.'
                }
                return $handoffState.ActionResult
            } catch {
                $handoffState.ActionErrorType = $_.Exception.GetBaseException().GetType().Name
                throw 'candidate-action'
            }
        }.GetNewClosure()
        $restoreClosure = {
            param($unused)
            try {
                $contextPins = [ordered]@{}
                foreach ($pinName in $ExpectedPins.Keys) { $contextPins[$pinName] = [string]$ExpectedPins[$pinName] }
                $context = [PSCustomObject]@{
                    Capture = ConvertTo-CvrIdleTransactionCapture -Receipt $captureRecord.Document
                    StageRoot = $binding.StageRoot
                    SourceManifestSha256 = $binding.SourceManifestSha256
                    ExpectedPins = $contextPins
                }
                $restoreResult = & $RestoreScript $context $handoffState.ActionResult
                return $restoreResult
            } catch {
                $handoffState.RestoreErrorType = $_.Exception.GetBaseException().GetType().Name
                throw 'restore-callback'
            }
        }.GetNewClosure()
        $verifyClosure = {
            param($unused, $restoreResult)
            try {
                $null = Assert-CvrIdleTargetCapture -Capture $capture -ExpectedTargetIdentity $ExpectedTargetIdentity -ExpectedPins $ExpectedPins
                $null = Assert-CvrIdleRollbackState -Capture $capture -ExpectedPins $ExpectedPins -ExpectedLocalRoot $localRoot
                $freshAfter = & $RefreshObservationScript $capture
                $null = Assert-CvrIdleFreshObservation -Capture $capture -Fresh $freshAfter
                $contextPins = [ordered]@{}
                foreach ($pinName in $ExpectedPins.Keys) { $contextPins[$pinName] = [string]$ExpectedPins[$pinName] }
                $context = [PSCustomObject]@{
                    Capture = ConvertTo-CvrIdleTransactionCapture -Receipt $captureRecord.Document
                    StageRoot = $binding.StageRoot
                    SourceManifestSha256 = $binding.SourceManifestSha256
                    ExpectedPins = $contextPins
                }
                $verified = & $VerifyScript $context $restoreResult $handoffState.ActionResult
                if ($verified -isnot [bool] -or -not $verified) { throw 'Caller restore verification did not pass.' }
                return [bool]$true
            } catch {
                $handoffState.VerifyErrorType = $_.Exception.GetBaseException().GetType().Name
                throw 'restore-verification'
            }
        }.GetNewClosure()
        $captureScript = {
            $null = Assert-CvrIdleTargetCapture -Capture $capture -ExpectedTargetIdentity $ExpectedTargetIdentity -ExpectedPins $ExpectedPins
            $null = Assert-CvrIdleRollbackState -Capture $capture -ExpectedPins $ExpectedPins -ExpectedLocalRoot $localRoot
            $freshBefore = & $RefreshObservationScript $capture
            $null = Assert-CvrIdleFreshObservation -Capture $capture -Fresh $freshBefore -RequireSameServicePid
            return $capture
        }.GetNewClosure()
        $transaction = Invoke-CvrIdleTargetTransaction -CaptureScript $captureScript -ExpectedTargetIdentity $ExpectedTargetIdentity -ExpectedPins $ExpectedPins -ActionScript $actionClosure -RestoreScript $restoreClosure -VerifyScript $verifyClosure
        return [PSCustomObject]@{
            status = if ($transaction.RestoreFailure) { 'RESTORE_FAILED' } elseif ($transaction.ActionFailure) { 'ACTION_FAILED_RESTORED' } else { 'PASS' }
            actionErrorType = $handoffState.ActionErrorType
            restoreErrorType = if ($transaction.RestoreFailure) { if ($handoffState.RestoreErrorType) { $handoffState.RestoreErrorType } else { $handoffState.VerifyErrorType } } else { $null }
        }
    } finally {
        if ($binding) {
            foreach ($handle in @($binding.OpenFiles)) { if ($handle) { $handle.Dispose() } }
        }
        foreach ($handle in $openFiles) { if ($handle) { $handle.Dispose() } }
    }
}

