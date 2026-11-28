# Shared by the fast synthetic rollback check and the native installer smoke.

function Get-CvrLegacyRunValue {
    param([string]$Hive, [string]$Name)
    $registryHive = [System.Enum]::Parse([Microsoft.Win32.RegistryHive], $Hive)
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($registryHive, [Microsoft.Win32.RegistryView]::Registry64)
    try {
        $key = $base.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Run', $false)
        if (-not $key) { return $null }
        try {
            if (@($key.GetValueNames()) -notcontains $Name) { return $null }
            return [PSCustomObject]@{
                kind = $key.GetValueKind($Name).ToString()
                data = $key.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            }
        } finally { $key.Dispose() }
    } finally { $base.Dispose() }
}

function Set-CvrLegacyRunValue {
    param([string]$Hive, [string]$Name, [string]$Kind, [object]$Data)
    $registryHive = [System.Enum]::Parse([Microsoft.Win32.RegistryHive], $Hive)
    $valueKind = [System.Enum]::Parse([Microsoft.Win32.RegistryValueKind], $Kind)
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($registryHive, [Microsoft.Win32.RegistryView]::Registry64)
    try {
        $key = $base.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Run', $true)
        if (-not $key) { $key = $base.CreateSubKey('Software\Microsoft\Windows\CurrentVersion\Run', $true) }
        if (-not $key) { throw 'Could not create the synthetic Run-key fixture.' }
        try { $key.SetValue($Name, $Data, $valueKind) }
        finally { $key.Dispose() }
    } finally { $base.Dispose() }
}

function Remove-CvrLegacyRunValue {
    param([string]$Hive, [string]$Name)
    $registryHive = [System.Enum]::Parse([Microsoft.Win32.RegistryHive], $Hive)
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($registryHive, [Microsoft.Win32.RegistryView]::Registry64)
    try {
        $key = $base.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Run', $true)
        if (-not $key) { return }
        try { $key.DeleteValue($Name, $false) }
        finally { $key.Dispose() }
    } finally { $base.Dispose() }
}

function Assert-CvrLegacyStatePath {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        $fullPath = [IO.Path]::GetFullPath($Path)
        $currentPath = $fullPath
        while (-not [string]::IsNullOrEmpty($currentPath)) {
            $item = $null
            try {
                $item = Get-Item -LiteralPath $currentPath -Force -ErrorAction Stop
            } catch {
                if ($_.CategoryInfo.Category -ne [System.Management.Automation.ErrorCategory]::ObjectNotFound) { throw }
            }
            if ($item) {
                $isLeaf = $currentPath -ieq $fullPath
                if ((([int]$item.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0) -or
                    ($isLeaf -and $item.PSIsContainer) -or (-not $isLeaf -and -not $item.PSIsContainer)) {
                    throw 'unsafe path'
                }
            }
            $parentPath = [IO.Path]::GetDirectoryName($currentPath)
            if ([string]::IsNullOrEmpty($parentPath) -or $parentPath -ceq $currentPath) { break }
            $currentPath = $parentPath
        }
        return $fullPath
    } catch {
        throw 'CVR window-state path validation failed.'
    }
}

function Get-CvrLegacyState {
    $windowStateRoot = [IO.Path]::GetFullPath((Join-Path $env:APPDATA 'io.github.clash-verge-rev.clash-verge-rev'))
    $filePaths = @(
        (Join-Path $windowStateRoot 'window-state.json'),
        (Join-Path $windowStateRoot '.window-state.json')
    )
    $files = foreach ($path in $filePaths) {
        $path = [IO.Path]::GetFullPath($path)
        $null = Assert-CvrLegacyStatePath -Path $path
        if (Test-Path -LiteralPath $path -PathType Leaf -ErrorAction Stop) {
            $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
            if ($item.Length -gt 262144) { throw 'CVR window-state preimage exceeds the bounded receipt size.' }
            $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
            $null = Assert-CvrLegacyStatePath -Path $path
            $bytes = [IO.File]::ReadAllBytes($path)
            [PSCustomObject]@{
                path = $path
                present = $true
                bytes = [Convert]::ToBase64String($bytes)
                sddl = $acl.Sddl
                acl = $acl
            }
        } elseif (Test-Path -LiteralPath $path -ErrorAction Stop) {
            throw 'CVR window-state target is not a regular file.'
        } else {
            [PSCustomObject]@{ path = $path; present = $false; bytes = $null; sddl = $null; acl = $null }
        }
    }
    $registryTargets = @(
        [PSCustomObject]@{ hive='CurrentUser'; name='Clash Verge' },
        [PSCustomObject]@{ hive='LocalMachine'; name='Clash Verge' },
        [PSCustomObject]@{ hive='CurrentUser'; name='clash-verge' },
        [PSCustomObject]@{ hive='LocalMachine'; name='clash-verge' }
    )
    $registry = foreach ($target in $registryTargets) {
        $value = Get-CvrLegacyRunValue -Hive $target.hive -Name $target.name
        if ($value -and ($value.kind -notin @('String','ExpandString') -or $value.data -isnot [string] -or $value.data.Length -gt 4096)) {
            throw 'CVR Run-value preimage is outside the bounded rollback contract.'
        }
        [PSCustomObject]@{
            hive = $target.hive
            name = $target.name
            present = [bool]$value
            kind = if ($value) { $value.kind } else { $null }
            data = if ($value) { $value.data } else { $null }
        }
    }
    return [PSCustomObject]@{ files=@($files); registry=@($registry) }
}

function Test-CvrRegistryDataEqual {
    param([object]$Expected, [object]$Actual)
    $expectedJson = ConvertTo-Json -InputObject $Expected -Compress -Depth 8
    $actualJson = ConvertTo-Json -InputObject $Actual -Compress -Depth 8
    return $expectedJson -ceq $actualJson
}

function Assert-CvrLegacyState {
    param($Expected, [string]$Phase)
    $actual = Get-CvrLegacyState
    $failures = [Collections.Generic.List[string]]::new()
    for ($index = 0; $index -lt $Expected.files.Count; $index++) {
        $before = $Expected.files[$index]
        $after = $actual.files[$index]
        if ([bool]$after.present -ne [bool]$before.present) {
            $failures.Add('window-state presence changed')
            continue
        }
        if ($before.present) {
            if ($after.bytes -cne $before.bytes) { $failures.Add('window-state content changed') }
            if ($after.sddl -cne $before.sddl) { $failures.Add('window-state ACL changed') }
        }
    }
    for ($index = 0; $index -lt $Expected.registry.Count; $index++) {
        $before = $Expected.registry[$index]
        $after = $actual.registry[$index]
        if ([bool]$after.present -ne [bool]$before.present) {
            $failures.Add("Run value presence changed: $($before.hive)/Registry64/$($before.name)")
            continue
        }
        if ($before.present -and (
            $after.kind -cne $before.kind -or
            -not (Test-CvrRegistryDataEqual -Expected $before.data -Actual $after.data)
        )) {
            $failures.Add("Run value type/data changed: $($before.hive)/Registry64/$($before.name)")
        }
    }
    if ($failures.Count) { throw "CVR $Phase state mismatch: $($failures -join '; ')." }
}

function Assert-CvrInstallerChangedLegacyPreimage {
    param($Preimage, [string]$Phase)
    $actual = Get-CvrLegacyState
    for ($index = 0; $index -lt $Preimage.files.Count; $index++) {
        $before = $Preimage.files[$index]
        $after = $actual.files[$index]
        if ($before.present -and $after.present -and $after.bytes -ceq $before.bytes) {
            throw "CVR $Phase NSIS did not replace or delete its synthetic window-state preimage."
        }
    }
    for ($index = 0; $index -lt $Preimage.registry.Count; $index++) {
        $before = $Preimage.registry[$index]
        $after = $actual.registry[$index]
        if ($before.present -and $after.present -and $after.kind -ceq $before.kind -and
            (Test-CvrRegistryDataEqual -Expected $before.data -Actual $after.data)) {
            throw "CVR $Phase NSIS did not replace or delete its synthetic Run-value preimage."
        }
    }
}

function Restore-CvrLegacyState {
    param($State)
    $windowStateRoot = [IO.Path]::GetFullPath((Join-Path $env:APPDATA 'io.github.clash-verge-rev.clash-verge-rev'))
    $expectedPaths = @(
        (Join-Path $windowStateRoot 'window-state.json'),
        (Join-Path $windowStateRoot '.window-state.json')
    )
    if (-not $State -or @($State.files).Count -ne $expectedPaths.Count) {
        throw 'CVR window-state rollback paths are invalid.'
    }
    for ($index = 0; $index -lt $expectedPaths.Count; $index++) {
        $path = [IO.Path]::GetFullPath([string]$State.files[$index].path)
        if ($path -ine $expectedPaths[$index]) { throw 'CVR window-state rollback paths are invalid.' }
        $null = Assert-CvrLegacyStatePath -Path $path
    }

    $failures = [Collections.Generic.List[string]]::new()
    foreach ($entry in $State.files) {
        try {
            $path = [IO.Path]::GetFullPath([string]$entry.path)
            $null = Assert-CvrLegacyStatePath -Path $path
            if (-not $entry.present) {
                if (Test-Path -LiteralPath $path -ErrorAction Stop) {
                    $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
                    if ($item.PSIsContainer) { throw 'target is not a file' }
                    $null = Assert-CvrLegacyStatePath -Path $path
                    Remove-Item -LiteralPath $path -Force -ErrorAction Stop
                }
                continue
            }
            $bytes = [Convert]::FromBase64String([string]$entry.bytes)
            if ($bytes.Length -gt 262144) { throw 'preimage too large' }
            $acl = [Security.AccessControl.FileSecurity]::new()
            $acl.SetSecurityDescriptorSddlForm([string]$entry.sddl)
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $path) | Out-Null
            $null = Assert-CvrLegacyStatePath -Path $path
            [IO.File]::WriteAllBytes($path, $bytes)
            if ((Get-Acl -LiteralPath $path -ErrorAction Stop).Sddl -cne [string]$entry.sddl) {
                Set-Acl -LiteralPath $path -AclObject $acl -ErrorAction Stop
            }
        } catch {
            $failures.Add('window-state preimage restore failed')
        }
    }
    foreach ($entry in $State.registry) {
        try {
            if (-not $entry.present) {
                Remove-CvrLegacyRunValue -Hive $entry.hive -Name $entry.name
                continue
            }
            Set-CvrLegacyRunValue -Hive $entry.hive -Name $entry.name -Kind $entry.kind -Data $entry.data
        } catch {
            $failures.Add("Run-value preimage restore failed: $($entry.hive)/Registry64/$($entry.name)")
        }
    }
    if ($failures.Count) { throw "CVR preimage rollback was incomplete: $($failures -join '; ')." }
    Assert-CvrLegacyState -Expected $State -Phase 'preimage restore'
}

function New-CvrSyntheticLegacyPreimage {
    $baseline = Get-CvrLegacyState
    if (@($baseline.files | Where-Object { $_.present }).Count -or @($baseline.registry | Where-Object { $_.present }).Count) {
        throw 'Refusing preexisting synthetic window-state or Run-value targets.'
    }
    $windowStateRoot = Join-Path $env:APPDATA 'io.github.clash-verge-rev.clash-verge-rev'
    $files = @(
        (Join-Path $windowStateRoot 'window-state.json'),
        (Join-Path $windowStateRoot '.window-state.json')
    )
    $fixtureId = [Guid]::NewGuid().ToString('N')
    $registry = @(
        [PSCustomObject]@{ hive='CurrentUser'; name='Clash Verge'; kind='String'; data="STCVRC-fixture-$fixtureId-cu-main" },
        [PSCustomObject]@{ hive='LocalMachine'; name='Clash Verge'; kind='String'; data="STCVRC-fixture-$fixtureId-lm-main" },
        [PSCustomObject]@{ hive='CurrentUser'; name='clash-verge'; kind='ExpandString'; data="STCVRC-fixture-$fixtureId-cu-legacy" },
        [PSCustomObject]@{ hive='LocalMachine'; name='clash-verge'; kind='ExpandString'; data="STCVRC-fixture-$fixtureId-lm-legacy" }
    )
    New-Item -ItemType Directory -Force -Path $windowStateRoot | Out-Null
    foreach ($path in $files) {
        $text = '{"fixture":"' + $fixtureId + '","state":"synthetic"}' + [Environment]::NewLine
        [IO.File]::WriteAllBytes($path, [Text.UTF8Encoding]::new($false).GetBytes($text))
    }
    foreach ($entry in $registry) {
        Set-CvrLegacyRunValue -Hive $entry.hive -Name $entry.name -Kind $entry.kind -Data $entry.data
    }
    $state = Get-CvrLegacyState
    Assert-CvrLegacyState -Expected $state -Phase 'synthetic fixture setup'
    return [PSCustomObject]@{ baseline=$baseline; state=$state; fixtureId=$fixtureId }
}

function Remove-CvrSyntheticLegacyPreimage {
    param($Fixture)
    Restore-CvrLegacyState -State $Fixture.baseline
    Assert-CvrLegacyState -Expected $Fixture.baseline -Phase 'synthetic baseline restore'
}

function Invoke-CvrStateTransaction {
    param(
        [string]$Phase,
        [ValidateSet('2.5.8','2.5.10')][string]$HelperVersion,
        [string]$InstallDirectory,
        [switch]$PreserveCorePair,
        [Parameter(Mandatory)][scriptblock]$Action
    )
    if ($script:legacyStateFixture) {
        Restore-CvrLegacyState -State $script:legacyStateFixture.state
    }
    $legacyPreimage = Get-CvrLegacyState
    $corePreimage = $null
    if ($PreserveCorePair) { $corePreimage = Get-CvrCorePairPreimage -InstallDirectory $InstallDirectory }

    $result = $null
    $actionFailure = $null
    try {
        $result = & $Action
        if ($script:legacyStateFixture) {
            Assert-CvrInstallerChangedLegacyPreimage -Preimage $legacyPreimage -Phase $Phase
        }
    } catch {
        $actionFailure = $_.Exception.Message
    }

    $restoreFailures = [Collections.Generic.List[string]]::new()
    try {
        Restore-CvrLegacyState -State $legacyPreimage
        Assert-CvrLegacyState -Expected $legacyPreimage -Phase "$Phase legacy restore"
    } catch {
        $restoreFailures.Add("legacy state: $($_.Exception.Message)")
    }
    if ($corePreimage) {
        try {
            Restore-CvrCorePairPreimage -Preimage $corePreimage -HelperVersion $HelperVersion
            Assert-CvrCorePairPreimage -Preimage $corePreimage -Phase $Phase
        } catch {
            $restoreFailures.Add("separate core files: $($_.Exception.Message)")
        }
    }
    if ($restoreFailures.Count) {
        throw "CVR $Phase rollback failed; installer/action error [$actionFailure]; restore errors [$($restoreFailures -join '; ')]."
    }
    if ($actionFailure) { throw "CVR $Phase failed after its preimages were restored: $actionFailure" }
    return $result
}

function Test-CvrInstallerActionFailureRollback {
    if ($env:GITHUB_ACTIONS -ne 'true' -or $env:GITHUB_REPOSITORY -ne 'smart-tinker/stcvrc') {
        throw 'Synthetic rollback check is restricted to the public STCVRC GitHub Actions runner.'
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Synthetic rollback check requires the disposable runner to be elevated.'
    }

    $fixture = $null
    $failure = $null
    $cleanupFailure = $null
    $script:legacyStateFixture = $null
    try {
        $fixture = New-CvrSyntheticLegacyPreimage
        $script:legacyStateFixture = $fixture
        $actionFailure = $null
        try {
            Invoke-CvrStateTransaction -Phase 'intentional action-failure self-check' -HelperVersion '2.5.8' -InstallDirectory '' -Action {
                throw 'synthetic action failure'
            }
        } catch {
            $actionFailure = [string]$_.Exception.Message
        }
        if ($actionFailure -notmatch 'failed after its preimages were restored: synthetic action failure') {
            throw "Synthetic action-failure rollback was not reported after restore. Observed: $actionFailure"
        }
        Assert-CvrLegacyState -Expected $fixture.state -Phase 'action-failure self-check'
        Write-Host 'Synthetic action-failure rollback and exact preimage restore self-check passed.'
    } catch {
        $failure = $_.Exception.Message
    }
    if ($fixture) {
        try { Remove-CvrSyntheticLegacyPreimage -Fixture $fixture }
        catch { $cleanupFailure = $_.Exception.Message }
    }
    $script:legacyStateFixture = $null
    if ($failure -and $cleanupFailure) { throw "Synthetic rollback self-check failed [$failure]; cleanup failed [$cleanupFailure]." }
    if ($failure) { throw $failure }
    if ($cleanupFailure) { throw "Synthetic rollback self-check cleanup failed: $cleanupFailure" }
}
