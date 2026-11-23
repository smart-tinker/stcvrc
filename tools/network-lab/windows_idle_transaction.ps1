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
        packageStageBinding = [ordered]@{
            stageRoot = [string]$packageStageBinding.StageRoot
            sourceManifestSha256 = [string]$packageStageBinding.SourceManifestSha256
        }
        capturedAtUtc = $Capture.capturedAtUtc.ToString('o')
        coreShouldBeRunning = [bool]$Capture.coreShouldBeRunning
        expectedPins = $storedPins
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
