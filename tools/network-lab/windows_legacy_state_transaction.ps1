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

function Get-CvrLegacyState {
    $windowStateRoot = Join-Path $env:APPDATA 'io.github.clash-verge-rev.clash-verge-rev'
    $filePaths = @(
        (Join-Path $windowStateRoot 'window-state.json'),
        (Join-Path $windowStateRoot '.window-state.json')
    )
    $files = foreach ($path in $filePaths) {
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $acl = Get-Acl -LiteralPath $path
            [PSCustomObject]@{
                path = $path
                present = $true
                bytes = [Convert]::ToBase64String([IO.File]::ReadAllBytes($path))
                sddl = $acl.Sddl
                acl = $acl
            }
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
    $failures = [Collections.Generic.List[string]]::new()
    foreach ($entry in $State.files) {
        try {
            if (-not $entry.present) {
                if (Test-Path -LiteralPath $entry.path) {
                    if (-not (Test-Path -LiteralPath $entry.path -PathType Leaf)) { throw 'target is not a file' }
                    Remove-Item -LiteralPath $entry.path -Force -ErrorAction Stop
                }
                continue
            }
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $entry.path) | Out-Null
            [IO.File]::WriteAllBytes($entry.path, [Convert]::FromBase64String($entry.bytes))
            if ((Get-Acl -LiteralPath $entry.path).Sddl -cne $entry.sddl) {
                Set-Acl -LiteralPath $entry.path -AclObject $entry.acl
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
