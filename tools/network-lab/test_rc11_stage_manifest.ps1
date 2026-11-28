param(
    [Parameter(Mandatory = $true)]
    [string]$SourceRoot
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

function Assert-StageTest([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}
function Get-StageBytesSha256([byte[]]$Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}
function Read-ZipEntryBytes([IO.Compression.ZipArchiveEntry]$Entry) {
    $source = $Entry.Open()
    $memory = [IO.MemoryStream]::new()
    try { $source.CopyTo($memory); return ,$memory.ToArray() }
    finally { $source.Dispose(); $memory.Dispose() }
}
function Invoke-StagePack(
    [string]$Packager, [string]$SyntheticSource, [string]$SourceSha,
    [string]$BuildPath, [string]$InputsPath, [string]$CorePath, [string]$CoreSha,
    [string]$RecoveryPath, [string]$UpdatePath, [string]$OutputPath, [string]$RecordPath
) {
    $python = (Get-Command python.exe -ErrorAction Stop).Source
    $packArgs = @(
        'pack', '--source-root', $SyntheticSource, '--source-sha', $SourceSha,
        '--build-report', $BuildPath, '--inputs', $InputsPath, '--core', $CorePath,
        '--native-core-sha256', $CoreSha, '--recovery-installer', $RecoveryPath,
        '--update-installer', $UpdatePath,
        '--recovery-ipc-archive', $script:recoveryIpcArchivePath,
        '--update-ipc-archive', $script:updateIpcArchivePath,
        '--output', $OutputPath, '--record', $RecordPath
    )
    $arguments = @($Packager) + $packArgs
    foreach ($argument in $arguments) {
        if ($argument.Contains('"')) { throw 'Unsafe Python argument.' }
    }
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $python
    $startInfo.Arguments = (@($arguments | ForEach-Object { '"' + $_ + '"' }) -join ' ')
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.StandardOutputEncoding = [Text.UTF8Encoding]::new($false, $true)
    $startInfo.StandardErrorEncoding = [Text.UTF8Encoding]::new($false, $true)
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    $started = $false
    try {
        if (-not $process.Start()) { throw 'Python stage packager did not start.' }
        $started = $true
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(30000)) {
            try { $process.Kill(); $null = $process.WaitForExit(5000) } catch {}
            if (-not $process.HasExited) { throw 'Python stage packager stop could not be proven.' }
            throw 'Python stage packager exceeded 30 seconds.'
        }
        $output = @()
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ($stdout.Length -gt 0) { $output += $stdout }
        if ($stderr.Length -gt 0) { $output += $stderr }
        return [PSCustomObject]@{ ExitCode = [int]$process.ExitCode; StdOut = $stdout; StdErr = $stderr; Output = $output }
    } finally {
        if ($started -and -not $process.HasExited) {
            try { $process.Kill(); $null = $process.WaitForExit(5000) } catch {}
            if (-not $process.HasExited) { throw 'Python stage packager did not stop.' }
        }
        $process.Dispose()
    }
}
function Write-TestZip([string]$Path, [Collections.IDictionary]$Entries) {
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    $archive = $null
    try {
        $archive = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Create, $true)
        foreach ($name in $Entries.Keys) {
            $entry = $archive.CreateEntry([string]$name, [IO.Compression.CompressionLevel]::NoCompression)
            $target = $entry.Open()
            try {
                [byte[]]$bytes = $Entries[$name]
                $target.Write($bytes, 0, $bytes.Length)
            } finally { $target.Dispose() }
        }
    } finally {
        if ($archive) { $archive.Dispose() }
        $stream.Dispose()
    }
}
function Assert-PackageRejected(
    [string]$Packager, [string]$SyntheticSource, [string]$SourceSha,
    [string]$BuildPath, [string]$InputsPath, [string]$CorePath, [string]$CoreSha,
    [string]$RecoveryPath, [string]$UpdatePath, [string]$OutputPath, [string]$RecordPath,
    [string]$Case
) {
    $result = Invoke-StagePack $Packager $SyntheticSource $SourceSha $BuildPath $InputsPath $CorePath $CoreSha $RecoveryPath $UpdatePath $OutputPath $RecordPath
    Assert-StageTest ($result.ExitCode -ne 0) "$Case was accepted by the RC11 stage packager."
    Assert-StageTest ($result.StdErr -match '(?m)^RC11 stage packaging failed: .+') "$Case did not return a packager rejection diagnostic on stderr."
    Assert-StageTest (-not (Test-Path -LiteralPath $OutputPath) -and -not (Test-Path -LiteralPath $RecordPath)) "$Case left a partial stage package."
}

$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('stcvrc-rc11-stage-' + [Guid]::NewGuid().ToString('N'))
if (Test-Path -LiteralPath $tempRoot) { throw 'RC11 stage fixture path unexpectedly exists.' }
$null = New-Item -ItemType Directory -Path $tempRoot
try {
    $syntheticSource = Join-Path $tempRoot 'source'
    $null = New-Item -ItemType Directory -Path $syntheticSource
    $packager = Join-Path $SourceRoot 'tools\network-lab\rc11_stage_package.py'
    $sourceNames = @(
        'tools/network-lab/windows_idle_capture_operator.ps1',
        'tools/network-lab/windows_core_preimage_paths.ps1',
        'tools/network-lab/windows_idle_baseline_guard.ps1',
        'tools/network-lab/windows_idle_transaction.ps1',
        'tools/network-lab/windows_legacy_state_transaction.ps1',
        'tools/network-lab/windows_idle_preflight_package_writer.ps1',
        'tools/network-lab/windows_idle_preflight.ps1',
        'tools/network-lab/windows_idle_preflight_target_operator.ps1',
        'tools/network-lab/windows_idle_target_runtime.ps1',
        'tools/network-lab/idle-target-candidate-traffic.md',
        'tools/network-lab/windows_native_acceptance.ps1',
        'tools/network-lab/windows_native_port_plan.ps1',
        'tools/network-lab/windows_native_udp_ports.py',
        'tools/network-lab/windows_ssh_fixture_cleanup.ps1'
    )
    foreach ($name in $sourceNames) {
        $path = Join-Path $syntheticSource ($name -replace '/', '\')
        $null = New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force
        [IO.File]::WriteAllText($path, "synthetic source: $name" + [string][char]10, [Text.UTF8Encoding]::new($false))
    }
    & git -C $syntheticSource init --quiet
    if ($LASTEXITCODE -ne 0) { throw 'Could not initialize synthetic source revision.' }
    & git -C $syntheticSource config core.autocrlf false
    if ($LASTEXITCODE -ne 0) { throw 'Could not disable line-ending conversion for synthetic source.' }
    & git -C $syntheticSource config user.name 'STCVRC stage fixture'
    if ($LASTEXITCODE -ne 0) { throw 'Could not configure synthetic source author.' }
    & git -C $syntheticSource config user.email 'stcvrc-stage-fixture@example.invalid'
    if ($LASTEXITCODE -ne 0) { throw 'Could not configure synthetic source author email.' }
    & git -C $syntheticSource add -- tools
    if ($LASTEXITCODE -ne 0) { throw 'Could not stage synthetic source files.' }
    & git -C $syntheticSource commit --quiet -m 'Synthetic RC11 stage source'
    if ($LASTEXITCODE -ne 0) { throw 'Could not commit synthetic source files.' }
    $sourceSha = (& git -C $syntheticSource rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $sourceSha -notmatch '^[0-9a-f]{40}$') { throw 'Synthetic source SHA is invalid.' }

    $corePath = Join-Path $tempRoot 'verge-mihomo.exe'
    $recoveryPath = Join-Path $tempRoot 'Clash.Verge_2.5.8_x64-setup.exe'
    $updatePath = Join-Path $tempRoot 'Clash.Verge_2.5.10_x64-setup.exe'
    $script:recoveryIpcArchivePath = Join-Path $tempRoot 'clash-verge-service-ipc-v2.7.6.zip'
    $script:updateIpcArchivePath = Join-Path $tempRoot 'clash-verge-service-ipc-v2.7.7.zip'
    $licenseBytes = [Text.Encoding]::UTF8.GetBytes("Synthetic Service IPC license`r`n")
    $sourceLicenseBytes = [Text.Encoding]::UTF8.GetBytes("Synthetic Service IPC license`n")
    $recoveryHelperBytes = [Text.Encoding]::UTF8.GetBytes('synthetic-v2.7.6-helper')
    $updateHelperBytes = [Text.Encoding]::UTF8.GetBytes('synthetic-v2.7.7-helper')
    Write-TestZip $script:recoveryIpcArchivePath @{
        'bin/clash-verge-service-install.exe' = $recoveryHelperBytes
        'LICENSE' = $licenseBytes
    }
    Write-TestZip $script:updateIpcArchivePath @{
        'bin/clash-verge-service-install.exe' = $updateHelperBytes
        'LICENSE' = $licenseBytes
    }
    $recoveryInstallerEntries = Join-Path $tempRoot 'recovery-installer-entries.zip'
    $updateInstallerEntries = Join-Path $tempRoot 'update-installer-entries.zip'
    Write-TestZip $recoveryInstallerEntries @{ 'resources/clash-verge-service-install.exe' = $recoveryHelperBytes }
    Write-TestZip $updateInstallerEntries @{ 'resources/clash-verge-service-install.exe' = $updateHelperBytes }
    Copy-Item -LiteralPath $recoveryInstallerEntries -Destination $recoveryPath
    Copy-Item -LiteralPath $updateInstallerEntries -Destination $updatePath
    $coreBytes = [byte[]]@(0x4D, 0x5A, 0x52, 0x43, 0x31, 0x31)
    [IO.File]::WriteAllBytes($corePath, $coreBytes)
    $recoveryBytes = [IO.File]::ReadAllBytes($recoveryPath)
    $updateBytes = [IO.File]::ReadAllBytes($updatePath)
    $recoveryIpcBytes = [IO.File]::ReadAllBytes($script:recoveryIpcArchivePath)
    $updateIpcBytes = [IO.File]::ReadAllBytes($script:updateIpcArchivePath)
    $coreSha = (Get-FileHash -LiteralPath $corePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $recoverySha = (Get-FileHash -LiteralPath $recoveryPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $updateSha = (Get-FileHash -LiteralPath $updatePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $recoveryIpcSha = Get-StageBytesSha256 $recoveryIpcBytes
    $updateIpcSha = Get-StageBytesSha256 $updateIpcBytes
    $recoveryHelperSha = Get-StageBytesSha256 $recoveryHelperBytes
    $updateHelperSha = Get-StageBytesSha256 $updateHelperBytes
    $licenseSha = Get-StageBytesSha256 $licenseBytes
    $sourceLicenseSha = Get-StageBytesSha256 $sourceLicenseBytes
    $buildPath = Join-Path $tempRoot 'build.json'
    $inputsPath = Join-Path $tempRoot 'inputs.json'
    $build = [ordered]@{
        schema_version = 1
        status = 'fresh-source-build'
        build_host = 'windows/amd64'
        recipe_commit = $sourceSha
        version = '1.19.33-STCVRC-rc.11'
        core_source_commit = 'a884ad53a3999dd35acab979e0bb040c47f6dbc9'
        selected_dependency_versions = @{
            'github.com/gobwas/ws' = 'v1.5.0'
            'github.com/insomniacslk/dhcp' = 'v0.0.0-20260719225207-c76316d4aa82'
        }
        artifacts = @(@{
            name = 'verge-mihomo.exe'
            target = 'windows/amd64'
            sha256 = $coreSha
            size = $coreBytes.Length
        })
    }
    [IO.File]::WriteAllText($buildPath, (ConvertTo-Json -InputObject $build -Depth 8), [Text.UTF8Encoding]::new($false))
    $inputs = [ordered]@{
        repository = 'clash-verge-rev/clash-verge-rev'
        serviceIpcLicense = @{
            repository = 'clash-verge-rev/clash-verge-service-ipc'
            path = 'licenses/clash-verge-service-ipc/LICENSE'
            sourcePath = 'LICENSE'
            sourceCommit = ('3' * 40)
            sourceSha256 = $sourceLicenseSha
            archiveSha256 = $licenseSha
        }
        releases = @(
            @{
                version = '2.5.8'; tag = 'v2.5.8'; releaseId = 258; serviceInstallHelperSha256 = $recoveryHelperSha
                serviceInstallHelperProvenance = @{
                    repository='clash-verge-rev/clash-verge-service-ipc'; tag='v2.7.6'; sourceCommit=('1' * 40)
                    asset=@{ id=276; name='clash-verge-service-ipc-v2.7.6-x86_64-pc-windows-msvc.zip'; size=$recoveryIpcBytes.Length; sha256=$recoveryIpcSha; url='https://github.com/clash-verge-rev/clash-verge-service-ipc/releases/download/v2.7.6/clash-verge-service-ipc-v2.7.6-x86_64-pc-windows-msvc.zip' }
                    helper=@{ file='clash-verge-service-install.exe'; size=$recoveryHelperBytes.Length; sha256=$recoveryHelperSha }; licenseSha256=$licenseSha
                }
                assets=@{ installer=@{ file='Clash.Verge_2.5.8_x64-setup.exe'; name='Clash.Verge_2.5.8_x64-setup.exe'; id=2580; size=$recoveryBytes.Length; sha256=$recoverySha; url='https://github.com/clash-verge-rev/clash-verge-rev/releases/download/v2.5.8/Clash.Verge_2.5.8_x64-setup.exe' } }
            },
            @{
                version = '2.5.10'; tag = 'v2.5.10'; releaseId = 2510; serviceInstallHelperSha256 = $updateHelperSha
                serviceInstallHelperProvenance = @{
                    repository='clash-verge-rev/clash-verge-service-ipc'; tag='v2.7.7'; sourceCommit=('3' * 40)
                    asset=@{ id=277; name='clash-verge-service-ipc-v2.7.7-x86_64-pc-windows-msvc.zip'; size=$updateIpcBytes.Length; sha256=$updateIpcSha; url='https://github.com/clash-verge-rev/clash-verge-service-ipc/releases/download/v2.7.7/clash-verge-service-ipc-v2.7.7-x86_64-pc-windows-msvc.zip' }
                    helper=@{ file='clash-verge-service-install.exe'; size=$updateHelperBytes.Length; sha256=$updateHelperSha }; licenseSha256=$licenseSha
                }
                assets=@{ installer=@{ file='Clash.Verge_2.5.10_x64-setup.exe'; name='Clash.Verge_2.5.10_x64-setup.exe'; id=25100; size=$updateBytes.Length; sha256=$updateSha; url='https://github.com/clash-verge-rev/clash-verge-rev/releases/download/v2.5.10/Clash.Verge_2.5.10_x64-setup.exe' } }
            }
        )
    }
    [IO.File]::WriteAllText($inputsPath, (ConvertTo-Json -InputObject $inputs -Depth 10), [Text.UTF8Encoding]::new($false))
    $goodOutput = Join-Path $tempRoot 'RC11-WINDOWS-STAGE.zip'
    $goodRecord = Join-Path $tempRoot 'RC11-WINDOWS-STAGE.json'
    $packed = Invoke-StagePack $packager $syntheticSource $sourceSha $buildPath $inputsPath $corePath $coreSha $recoveryPath $updatePath $goodOutput $goodRecord
    Assert-StageTest ($packed.ExitCode -eq 0) ('Valid synthetic RC11 package was rejected: ' + ($packed.Output -join ' '))
    $record = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($goodRecord, [Text.UTF8Encoding]::new($false, $true))) -ErrorAction Stop
    Assert-StageTest ($record.schemaVersion -eq 1 -and $record.releaseTag -ceq 'stcvrc-1.19.33-rc.11' -and $record.sourceCommit -ceq $sourceSha) 'External stage record did not bind RC11 and its exact source.'
    Assert-StageTest ($record.sourceManifest.path -ceq 'source-manifest.json' -and $record.sourceManifest.sha256 -match '^[0-9a-f]{64}$') 'External stage manifest pin is malformed.'
    Assert-StageTest ($record.archive.sha256 -ceq (Get-FileHash -LiteralPath $goodOutput -Algorithm SHA256).Hash.ToLowerInvariant()) 'External stage archive pin does not match its bytes.'
    Assert-StageTest ($record.core.sha256 -ceq $coreSha -and $record.core.size -eq $coreBytes.Length) 'Staged core is not bound to the fresh Windows build.'
    Assert-StageTest ($record.cvrInstallers.'2.5.8'.sha256 -ceq $recoverySha -and $record.cvrInstallers.'2.5.10'.sha256 -ceq $updateSha) 'Staged installers are not bound to both CVR release pins.'
    Assert-StageTest ($record.inputManifestSha256 -ceq (Get-FileHash -LiteralPath $inputsPath -Algorithm SHA256).Hash.ToLowerInvariant()) 'External stage record does not bind the input manifest.'
    Assert-StageTest (@($record.sourceFiles).Count -eq $sourceNames.Count) 'External stage record omitted an allowlisted source file.'
    Assert-StageTest (@($record.cvrServiceInstallHelpers).Count -eq 2) 'External stage record omitted provenance for both Service IPC helpers.'
    Assert-StageTest ($record.cvrServiceInstallHelpers[0].serviceIpc.sourceCommit -ceq ('1' * 40) -and $record.cvrServiceInstallHelpers[0].installer.sha256 -ceq $recoverySha) 'Recovery helper source and installer pins do not agree.'
    Assert-StageTest ($record.cvrServiceInstallHelpers[1].sha256 -ceq $updateHelperSha -and $record.cvrServiceInstallHelpers[1].serviceIpc.asset.sha256 -ceq $updateIpcSha) 'Update helper is not tied to its pinned Service IPC asset.'
    Assert-StageTest ($record.serviceIpcLicense.sha256 -ceq $licenseSha -and $record.serviceIpcLicense.sourceSha256 -ceq $sourceLicenseSha -and $record.provenanceFile.path -ceq 'provenance/cvr-service-install-helpers.json') 'Service IPC license or provenance document is not externally bound.'
    Assert-StageTest (@($record.cvrServiceInstallHelpers).Count -eq 2) 'Stage record omitted provenance for both Service IPC helpers.'

    $archive = [IO.Compression.ZipFile]::OpenRead($goodOutput)
    try {
        $manifestEntry = $archive.GetEntry('source-manifest.json')
        Assert-StageTest ($null -ne $manifestEntry) 'Stage archive has no schema-1 manifest.'
        $manifestBytes = Read-ZipEntryBytes $manifestEntry
        $manifestSha = Get-StageBytesSha256 $manifestBytes
        Assert-StageTest ($manifestSha -ceq $record.sourceManifest.sha256) 'External manifest digest does not pin archive bytes.'
        $manifest = ConvertFrom-Json -InputObject ([Text.UTF8Encoding]::new($false, $true).GetString($manifestBytes)) -ErrorAction Stop
        $provenanceEntry = $archive.GetEntry('provenance/cvr-service-install-helpers.json')
        Assert-StageTest ($null -ne $provenanceEntry) 'Stage archive has no helper provenance JSON.'
        $provenanceBytes = Read-ZipEntryBytes $provenanceEntry
        Assert-StageTest ((Get-StageBytesSha256 $provenanceBytes) -ceq $record.provenanceFile.sha256) 'Inner provenance bytes do not match the external stage record.'
        $provenance = ConvertFrom-Json -InputObject ([Text.UTF8Encoding]::new($false, $true).GetString($provenanceBytes)) -ErrorAction Stop
        $innerHelpers = @($provenance.cvrServiceInstallHelpers)
        $externalHelpers = @($record.cvrServiceInstallHelpers)
        Assert-StageTest ($provenance.schemaVersion -eq 1 -and $innerHelpers.Count -eq 2 -and $externalHelpers.Count -eq 2) 'Inner or external helper provenance schema/count is wrong.'
        foreach ($version in @('2.5.8', '2.5.10')) {
            $innerMatches = @($innerHelpers | Where-Object { $_.version -ceq $version })
            $externalMatches = @($externalHelpers | Where-Object { $_.version -ceq $version })
            Assert-StageTest ($innerMatches.Count -eq 1 -and $externalMatches.Count -eq 1) ('Helper provenance omitted or duplicated CVR ' + $version)
            $innerHelper = $innerMatches[0]
            $externalHelper = $externalMatches[0]
            Assert-StageTest (
                $innerHelper.version -ceq $externalHelper.version -and
                $innerHelper.path -ceq $externalHelper.path -and
                $innerHelper.sha256 -ceq $externalHelper.sha256 -and
                $innerHelper.size -eq $externalHelper.size -and
                $innerHelper.installer.path -ceq $externalHelper.installer.path -and
                $innerHelper.installer.sha256 -ceq $externalHelper.installer.sha256 -and
                $innerHelper.installer.size -eq $externalHelper.installer.size -and
                $innerHelper.installer.tag -ceq $externalHelper.installer.tag -and
                $innerHelper.installer.releaseId -eq $externalHelper.installer.releaseId -and
                $innerHelper.installer.assetId -eq $externalHelper.installer.assetId -and
                $innerHelper.serviceIpc.repository -ceq $externalHelper.serviceIpc.repository -and
                $innerHelper.serviceIpc.tag -ceq $externalHelper.serviceIpc.tag -and
                $innerHelper.serviceIpc.sourceCommit -ceq $externalHelper.serviceIpc.sourceCommit -and
                $innerHelper.serviceIpc.asset.id -eq $externalHelper.serviceIpc.asset.id -and
                $innerHelper.serviceIpc.asset.name -ceq $externalHelper.serviceIpc.asset.name -and
                $innerHelper.serviceIpc.asset.size -eq $externalHelper.serviceIpc.asset.size -and
                $innerHelper.serviceIpc.asset.sha256 -ceq $externalHelper.serviceIpc.asset.sha256 -and
                $innerHelper.serviceIpc.asset.url -ceq $externalHelper.serviceIpc.asset.url -and
                $innerHelper.serviceIpc.helper.file -ceq $externalHelper.serviceIpc.helper.file -and
                $innerHelper.serviceIpc.helper.size -eq $externalHelper.serviceIpc.helper.size -and
                $innerHelper.serviceIpc.helper.sha256 -ceq $externalHelper.serviceIpc.helper.sha256
            ) ('Inner and external provenance differ for CVR ' + $version)
        }
        Assert-StageTest (
            $provenance.serviceIpcLicense.path -ceq $record.serviceIpcLicense.path -and
            $provenance.serviceIpcLicense.sha256 -ceq $record.serviceIpcLicense.sha256 -and
            $provenance.serviceIpcLicense.size -eq $record.serviceIpcLicense.size -and
            $provenance.serviceIpcLicense.repository -ceq $record.serviceIpcLicense.repository -and
            $provenance.serviceIpcLicense.sourcePath -ceq $record.serviceIpcLicense.sourcePath -and
            $provenance.serviceIpcLicense.sourceCommit -ceq $record.serviceIpcLicense.sourceCommit -and
            $provenance.serviceIpcLicense.sourceSha256 -ceq $record.serviceIpcLicense.sourceSha256 -and
            $provenance.serviceIpcLicense.archive.id -eq $record.serviceIpcLicense.archive.id -and
            $provenance.serviceIpcLicense.archive.name -ceq $record.serviceIpcLicense.archive.name -and
            $provenance.serviceIpcLicense.archive.size -eq $record.serviceIpcLicense.archive.size -and
            $provenance.serviceIpcLicense.archive.sha256 -ceq $record.serviceIpcLicense.archive.sha256 -and
            $provenance.serviceIpcLicense.archive.url -ceq $record.serviceIpcLicense.archive.url
        ) 'Inner and external Service IPC license records differ.'

        Assert-StageTest ($manifest.schemaVersion -eq 1 -and @($manifest.files).Count -eq 21) 'Source manifest schema or file count is wrong.'
        $expectedFiles = @($sourceNames)
        $expectedFiles += @(
            'payload/verge-mihomo.exe',
            'payload/Clash.Verge_2.5.8_x64-setup.exe',
            'payload/Clash.Verge_2.5.10_x64-setup.exe',
            'payload/cvr-2.5.8/clash-verge-service-install.exe',
            'payload/cvr-2.5.10/clash-verge-service-install.exe',
            'licenses/clash-verge-service-ipc/LICENSE',
            'provenance/cvr-service-install-helpers.json'
        )
        $expectedFiles = @($expectedFiles | Sort-Object)
        $actualFiles = @($manifest.files | ForEach-Object { [string]$_.path } | Sort-Object)
        Assert-StageTest (($actualFiles -join ([string][char]10)) -ceq ($expectedFiles -join ([string][char]10))) 'Stage manifest does not contain the explicit RC11 file allowlist.'
        Assert-StageTest (-not (@($manifest.files | Where-Object { $_.path -ceq 'source-manifest.json' }).Count)) 'Source manifest recursively lists itself.'
        foreach ($entry in @($manifest.files)) {
            Assert-StageTest ($entry.path -notmatch '(^/|\\|:|(^|/)\.\.?(/|$))') 'Source manifest contains an unsafe path.'
            $zipEntry = $archive.GetEntry([string]$entry.path)
            Assert-StageTest ($null -ne $zipEntry) 'A source manifest file is missing from the package.'
            Assert-StageTest ((Get-StageBytesSha256 (Read-ZipEntryBytes $zipEntry)) -ceq [string]$entry.sha256) 'A packaged stage file does not match its manifest.'
        }
        $archiveNames = @($archive.Entries | ForEach-Object { $_.FullName } | Sort-Object)
        $expectedNames = @('source-manifest.json') + @($manifest.files | ForEach-Object { [string]$_.path })
        $expectedNames = @($expectedNames | Sort-Object)
        Assert-StageTest (($archiveNames -join ([string][char]10)) -ceq ($expectedNames -join ([string][char]10))) 'Stage archive has missing or unlisted entries.'

        $stageRoot = Join-Path $tempRoot 'protected-stage'
        $null = New-Item -ItemType Directory -Path $stageRoot
        . (Join-Path $SourceRoot 'tools\network-lab\windows_idle_transaction.ps1')
        $null = Set-CvrIdleCaptureAcl -Path $stageRoot -Directory
        $allPaths = @('source-manifest.json') + @($manifest.files | ForEach-Object { [string]$_.path })
        $directoryPaths = @()
        foreach ($relativePath in $allPaths) {
            $parts = $relativePath.Split('/')
            for ($depth = 1; $depth -lt $parts.Length; $depth++) {
                $directoryPaths += ($parts[0..($depth - 1)] -join '/')
            }
        }
        foreach ($relativeDirectory in @($directoryPaths | Select-Object -Unique | Sort-Object Length)) {
            $directoryPath = Join-Path $stageRoot ($relativeDirectory -replace '/', '\')
            $null = New-Item -ItemType Directory -Path $directoryPath
            $null = Set-CvrIdleCaptureAcl -Path $directoryPath -Directory
        }
        foreach ($relativePath in $allPaths) {
            $targetPath = Join-Path $stageRoot ($relativePath -replace '/', '\')
            $empty = [IO.File]::Open($targetPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            $empty.Dispose()
            $null = Set-CvrIdleCaptureAcl -Path $targetPath
            $entry = $archive.GetEntry([string]$relativePath)
            Assert-StageTest ($null -ne $entry) 'Archive member disappeared before protected-stage copy.'
            $sourceStream = $entry.Open()
            $targetStream = [IO.File]::Open($targetPath, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try { $sourceStream.CopyTo($targetStream) } finally { $targetStream.Dispose(); $sourceStream.Dispose() }
        }

        $expectedRoot = [IO.Path]::GetFullPath($stageRoot)
        $wrongPin = if ($manifestSha[0] -ceq '0') { '1' + $manifestSha.Substring(1) } else { '0' + $manifestSha.Substring(1) }
        $wrongDigestRejected = $false
        try {
            $null = Get-CvrIdlePackageStageBinding -StageRoot $expectedRoot -ExpectedStageRoot $expectedRoot -ExpectedPackageManifestSha256 $wrongPin
        } catch { $wrongDigestRejected = $true }
        Assert-StageTest $wrongDigestRejected 'Wrong external source-manifest SHA256 reached stage handoff.'
        $binding = Get-CvrIdlePackageStageBinding -StageRoot $expectedRoot -ExpectedStageRoot $expectedRoot -ExpectedPackageManifestSha256 $manifestSha
        Assert-StageTest ($binding.SourceManifestSha256 -ceq $manifestSha -and $binding.OpenFiles.Count -eq 22) 'Verified package did not bind all listed files.'
        foreach ($handle in $binding.OpenFiles) { $handle.Dispose() }

        $tamperPath = Join-Path $stageRoot 'payload\verge-mihomo.exe'
        $tampered = [IO.File]::Open($tamperPath, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::Read)
        try { $tampered.Position = $tampered.Length; $tampered.WriteByte(0x42) } finally { $tampered.Dispose() }
        $tamperRejected = $false
        try {
            $null = Get-CvrIdlePackageStageBinding -StageRoot $expectedRoot -ExpectedStageRoot $expectedRoot -ExpectedPackageManifestSha256 $manifestSha
        } catch { $tamperRejected = $true }
        Assert-StageTest $tamperRejected 'Tampered staged core reached a successful handoff.'
        $archive.Dispose()
    } catch {
        if ($archive) { $archive.Dispose() }
        throw
    }

    $badBuildPath = Join-Path $tempRoot 'wrong-release-build.json'
    $badBuild = ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $build -Depth 8) -ErrorAction Stop
    $badBuild.version = '1.19.33-STCVRC-rc.10'
    [IO.File]::WriteAllText($badBuildPath, (ConvertTo-Json -InputObject $badBuild -Depth 8), [Text.UTF8Encoding]::new($false))
    $badReleaseZip = Join-Path $tempRoot 'wrong-release.zip'
    $badReleaseRecord = Join-Path $tempRoot 'wrong-release.json'
    Assert-PackageRejected $packager $syntheticSource $sourceSha $badBuildPath $inputsPath $corePath $coreSha $recoveryPath $updatePath $badReleaseZip $badReleaseRecord 'RC10 build identity'

    $badDependencyBuildPath = Join-Path $tempRoot 'wrong-dependency-build.json'
    $badDependencyBuild = ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $build -Depth 8) -ErrorAction Stop
    $badDependencyBuild.selected_dependency_versions = @{
        'github.com/gobwas/ws' = 'v1.4.0'
        'github.com/insomniacslk/dhcp' = 'v0.0.0-20260719225207-c76316d4aa82'
    }
    [IO.File]::WriteAllText($badDependencyBuildPath, (ConvertTo-Json -InputObject $badDependencyBuild -Depth 8), [Text.UTF8Encoding]::new($false))
    $badDependencyZip = Join-Path $tempRoot 'wrong-dependency.zip'
    $badDependencyRecord = Join-Path $tempRoot 'wrong-dependency.json'
    Assert-PackageRejected $packager $syntheticSource $sourceSha $badDependencyBuildPath $inputsPath $corePath $coreSha $recoveryPath $updatePath $badDependencyZip $badDependencyRecord 'wrong dependency pin'

    $wrongSourceSha = if ($sourceSha[0] -ceq '0') { '1' + $sourceSha.Substring(1) } else { '0' + $sourceSha.Substring(1) }
    $wrongSourceZip = Join-Path $tempRoot 'wrong-source.zip'
    $wrongSourceRecord = Join-Path $tempRoot 'wrong-source.json'
    Assert-PackageRejected $packager $syntheticSource $wrongSourceSha $buildPath $inputsPath $corePath $coreSha $recoveryPath $updatePath $wrongSourceZip $wrongSourceRecord 'source SHA mismatch'

    $swappedIpcZip = Join-Path $tempRoot 'swapped-ipc.zip'
    $swappedIpcRecord = Join-Path $tempRoot 'swapped-ipc.json'
    $originalRecoveryIpcArchivePath = $script:recoveryIpcArchivePath
    $originalUpdateIpcArchivePath = $script:updateIpcArchivePath
    try {
        $script:recoveryIpcArchivePath = $originalUpdateIpcArchivePath
        $script:updateIpcArchivePath = $originalRecoveryIpcArchivePath
        Assert-PackageRejected $packager $syntheticSource $sourceSha $buildPath $inputsPath $corePath $coreSha $recoveryPath $updatePath $swappedIpcZip $swappedIpcRecord 'swapped Service IPC archives'
    } finally {
        $script:recoveryIpcArchivePath = $originalRecoveryIpcArchivePath
        $script:updateIpcArchivePath = $originalUpdateIpcArchivePath
    }

    $badLicenseInputsPath = Join-Path $tempRoot 'wrong-service-ipc-source-license.json'
    $badLicenseInputs = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($inputsPath, [Text.UTF8Encoding]::new($false, $true))) -ErrorAction Stop
    $badLicenseInputs.serviceIpcLicense.sourceSha256 = if ($sourceLicenseSha[0] -ceq '0') { '1' + $sourceLicenseSha.Substring(1) } else { '0' + $sourceLicenseSha.Substring(1) }
    [IO.File]::WriteAllText($badLicenseInputsPath, (ConvertTo-Json -InputObject $badLicenseInputs -Depth 10), [Text.UTF8Encoding]::new($false))
    $wrongLicenseZip = Join-Path $tempRoot 'wrong-service-ipc-source-license.zip'
    $wrongLicenseRecord = Join-Path $tempRoot 'wrong-service-ipc-source-license.record.json'
    Assert-PackageRejected $packager $syntheticSource $sourceSha $buildPath $badLicenseInputsPath $corePath $coreSha $recoveryPath $updatePath $wrongLicenseZip $wrongLicenseRecord 'wrong Service IPC source LICENSE digest'

    $sourceTamperPath = Join-Path $syntheticSource 'tools\network-lab\windows_idle_preflight.ps1'
    [IO.File]::AppendAllText($sourceTamperPath, 'uncommitted source bytes', [Text.UTF8Encoding]::new($false))
    $sourceTamperZip = Join-Path $tempRoot 'tampered-source.zip'
    $sourceTamperRecord = Join-Path $tempRoot 'tampered-source.json'
    Assert-PackageRejected $packager $syntheticSource $sourceSha $buildPath $inputsPath $corePath $coreSha $recoveryPath $updatePath $sourceTamperZip $sourceTamperRecord 'source bytes differing from exact commit'

    $badInstaller = Join-Path $tempRoot 'tampered-recovery.exe'
    [IO.File]::WriteAllBytes($badInstaller, [byte[]]@(1, 2, 3, 4))
    $wrongInstallerZip = Join-Path $tempRoot 'wrong-installer.zip'
    $wrongInstallerRecord = Join-Path $tempRoot 'wrong-installer.json'
    Assert-PackageRejected $packager $syntheticSource $sourceSha $buildPath $inputsPath $corePath $coreSha $badInstaller $updatePath $wrongInstallerZip $wrongInstallerRecord 'recovery installer mismatch'

    Write-Host 'RC11 stage package, external pins, Windows protection, wrong-digest, tamper and identity negatives passed.'
} finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction Stop
}
