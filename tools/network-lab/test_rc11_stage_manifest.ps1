param(
    [Parameter(Mandatory = $true)]
    [string]$SourceRoot
)

$ErrorActionPreference = 'Stop'
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
        '--update-installer', $UpdatePath, '--output', $OutputPath, '--record', $RecordPath
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
        'tools/network-lab/windows_idle_preflight_package_writer.ps1',
        'tools/network-lab/windows_idle_preflight.ps1'
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
    $coreBytes = [byte[]]@(0x4D, 0x5A, 0x52, 0x43, 0x31, 0x31)
    $recoveryBytes = [byte[]]@(0x52, 0x45, 0x43, 0x4F, 0x56, 0x45, 0x52)
    $updateBytes = [byte[]]@(0x55, 0x50, 0x44, 0x41, 0x54, 0x45)
    [IO.File]::WriteAllBytes($corePath, $coreBytes)
    [IO.File]::WriteAllBytes($recoveryPath, $recoveryBytes)
    [IO.File]::WriteAllBytes($updatePath, $updateBytes)
    $coreSha = (Get-FileHash -LiteralPath $corePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $recoverySha = (Get-FileHash -LiteralPath $recoveryPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $updateSha = (Get-FileHash -LiteralPath $updatePath -Algorithm SHA256).Hash.ToLowerInvariant()
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
        releases = @(
            @{
                version = '2.5.8'
                tag = 'v2.5.8'
                releaseId = 258
                serviceInstallHelperSha256 = ('1' * 64)
                assets = @{ installer = @{
                    file = 'Clash.Verge_2.5.8_x64-setup.exe'
                    name = 'Clash.Verge_2.5.8_x64-setup.exe'
                    id = 2580
                    size = $recoveryBytes.Length
                    sha256 = $recoverySha
                    url = 'https://github.com/clash-verge-rev/clash-verge-rev/releases/download/v2.5.8/Clash.Verge_2.5.8_x64-setup.exe'
                } }
            },
            @{
                version = '2.5.10'
                tag = 'v2.5.10'
                releaseId = 2510
                serviceInstallHelperSha256 = ('2' * 64)
                assets = @{ installer = @{
                    file = 'Clash.Verge_2.5.10_x64-setup.exe'
                    name = 'Clash.Verge_2.5.10_x64-setup.exe'
                    id = 25100
                    size = $updateBytes.Length
                    sha256 = $updateSha
                    url = 'https://github.com/clash-verge-rev/clash-verge-rev/releases/download/v2.5.10/Clash.Verge_2.5.10_x64-setup.exe'
                } }
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

    $archive = [IO.Compression.ZipFile]::OpenRead($goodOutput)
    try {
        $manifestEntry = $archive.GetEntry('source-manifest.json')
        Assert-StageTest ($null -ne $manifestEntry) 'Stage archive has no schema-1 manifest.'
        $manifestBytes = Read-ZipEntryBytes $manifestEntry
        $manifestSha = Get-StageBytesSha256 $manifestBytes
        Assert-StageTest ($manifestSha -ceq $record.sourceManifest.sha256) 'External manifest digest does not pin archive bytes.'
        $manifest = ConvertFrom-Json -InputObject ([Text.UTF8Encoding]::new($false, $true).GetString($manifestBytes)) -ErrorAction Stop
        Assert-StageTest ($manifest.schemaVersion -eq 1 -and @($manifest.files).Count -eq 9) 'Source manifest schema or file count is wrong.'
        $expectedFiles = @($sourceNames)
        $expectedFiles += @(
            'payload/verge-mihomo.exe',
            'payload/Clash.Verge_2.5.8_x64-setup.exe',
            'payload/Clash.Verge_2.5.10_x64-setup.exe'
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
        Assert-StageTest ($binding.SourceManifestSha256 -ceq $manifestSha -and $binding.OpenFiles.Count -eq 10) 'Verified package did not bind all listed files.'
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
