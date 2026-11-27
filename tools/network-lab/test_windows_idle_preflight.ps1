$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows_core_preimage_paths.ps1')
. (Join-Path $PSScriptRoot 'windows_idle_baseline_guard.ps1')
. (Join-Path $PSScriptRoot 'windows_idle_transaction.ps1')

function Assert-PreflightTest([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function New-PreflightTestDirectory([string]$Path) {
    $null = New-Item -ItemType Directory -Path $Path -ErrorAction Stop
    $null = Set-CvrIdleCaptureAcl -Path $Path -Directory
}

function Write-PreflightTestFile([string]$Path, [byte[]]$Bytes, [switch]$Protected) {
    $null = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None).Dispose()
    if ($Protected) { $null = Set-CvrIdleCaptureAcl -Path $Path }
    [IO.File]::WriteAllBytes($Path, $Bytes)
}

function Get-PreflightTestSnapshot([string[]]$Paths) {
    $snapshot = [ordered]@{}
    foreach ($path in $Paths) {
        $snapshot[$path] = [PSCustomObject]@{
            Sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
            Sddl = (Get-Acl -LiteralPath $path -ErrorAction Stop).Sddl
        }
    }
    return $snapshot
}

function Assert-PreflightTestSnapshot($Before, $Paths) {
    $after = Get-PreflightTestSnapshot -Paths $Paths
    foreach ($path in $Paths) {
        if ($Before[$path].Sha256 -cne $after[$path].Sha256 -or $Before[$path].Sddl -cne $after[$path].Sddl) {
            throw 'Read-only Preflight changed a pinned synthetic input.'
        }
    }
}

function Quote-PreflightTestArgument([string]$Value) {
    if ($Value.Contains('"')) { throw 'Unsafe synthetic Preflight argument.' }
    return '"' + $Value + '"'
}

function Invoke-PreflightTestCommand(
    [string]$ScriptPath,
    [string[]]$ScriptArguments,
    [string]$PlanPath,
    [string]$PlanSha256,
    [string]$StageRoot,
    [string]$ManifestSha256,
    [int]$TimeoutSeconds,
    [int]$SyntheticDelaySeconds = 0,
    [ValidateSet('Capture', 'Plan')][string]$WriterMode,
    [object]$Request
) {
    if (($WriterMode -and $null -eq $Request) -or (-not $WriterMode -and $null -ne $Request)) {
        throw 'Writer mode and JSON request must be supplied together.'
    }
    $requestBytes = $null
    if ($null -ne $Request) {
        $requestJson = ConvertTo-Json -InputObject $Request -Depth 16 -Compress -ErrorAction Stop
        $requestBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($requestJson)
        if ($requestBytes.Length -gt 1048576) { throw 'Synthetic writer request exceeded the input limit.' }
    }

    $powershell51 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $parts = @(
        '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'RemoteSigned',
        '-File', (Quote-PreflightTestArgument $ScriptPath)
    )
    if ($null -ne $ScriptArguments) {
        foreach ($argument in $ScriptArguments) {
            $parts += Quote-PreflightTestArgument ([string]$argument)
        }
    } elseif ($WriterMode) {
        $parts += @('-Mode', (Quote-PreflightTestArgument $WriterMode))
    } else {
        $parts += @(
            '-PlanPath', (Quote-PreflightTestArgument $PlanPath),
            '-ExpectedPlanSha256', (Quote-PreflightTestArgument $PlanSha256),
            '-ExpectedStageRoot', (Quote-PreflightTestArgument $StageRoot),
            '-ExpectedPackageManifestSha256', (Quote-PreflightTestArgument $ManifestSha256),
            '-TimeoutSeconds', [string]$TimeoutSeconds
        )
        if ($SyntheticDelaySeconds -gt 0) {
            $parts += @('-SyntheticTestDelaySeconds', [string]$SyntheticDelaySeconds)
        }
    }

    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $powershell51
    $startInfo.Arguments = $parts -join ' '
    $startInfo.WorkingDirectory = [IO.Path]::GetTempPath()
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = ($null -ne $requestBytes)
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.StandardOutputEncoding = [Text.UTF8Encoding]::new($false, $true)
    $startInfo.StandardErrorEncoding = [Text.UTF8Encoding]::new($false, $true)
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    $started = $false
    $stdinTask = $null
    $stdoutTask = $null
    $stderrTask = $null
    try {
        if (-not $process.Start()) { throw 'Preflight command did not start.' }
        $started = $true
        $deadline = [DateTime]::UtcNow.AddSeconds(45)
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if ($null -ne $requestBytes) {
            $stdinTask = $process.StandardInput.BaseStream.WriteAsync($requestBytes, 0, $requestBytes.Length)
            $remaining = [int][Math]::Max(1, ($deadline - [DateTime]::UtcNow).TotalMilliseconds)
            if (-not $stdinTask.Wait($remaining)) { throw 'Preflight request write exceeded the bounded test deadline.' }
            $stdinTask.GetAwaiter().GetResult()
            $process.StandardInput.Close()
        }
        $remaining = [int][Math]::Max(1, ($deadline - [DateTime]::UtcNow).TotalMilliseconds)
        if (-not $process.WaitForExit($remaining)) {
            throw 'Preflight command exceeded the bounded test deadline.'
        }
        $remaining = [int][Math]::Max(1, ($deadline - [DateTime]::UtcNow).TotalMilliseconds)
        if (-not $stdoutTask.Wait($remaining) -or -not $stderrTask.Wait($remaining)) {
            throw 'Preflight output exceeded the bounded test deadline.'
        }
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ($stdout.Length -gt 4096 -or $stderr.Length -gt 4096) {
            throw 'Preflight diagnostics exceeded the test output limit.'
        }
        $document = $null
        if ($stdout -match '^\s*\{') {
            try { $document = ConvertFrom-Json -InputObject $stdout -ErrorAction Stop } catch {}
        }
        return [PSCustomObject]@{ ExitCode = [int]$process.ExitCode; StdOut = $stdout; StdErr = $stderr; Document = $document }
    } finally {
        if ($started) {
            if (-not $process.HasExited) {
                try { $process.Kill(); $null = $process.WaitForExit(5000) } catch {}
            }
            if (-not $process.HasExited) { throw 'Preflight command stop could not be proven.' }
            foreach ($task in @($stdinTask, $stdoutTask, $stderrTask)) {
                if ($task -and -not $task.IsCompleted) {
                    try { $null = $task.Wait(5000) } catch {}
                }
            }
        }
        $process.Dispose()
    }
}

function Invoke-CaptureOperatorTestCommand(
    [string]$BootstrapPath,
    [string]$OperatorPath,
    [string]$StageRoot,
    [string]$ManifestSha256,
    [string]$RequestPath,
    [string]$ScenarioPath,
    [int]$TimeoutSeconds = 30
) {
    $arguments = @(
        '-OperatorPath', $OperatorPath,
        '-StageRoot', $StageRoot,
        '-ExpectedPackageManifestSha256', $ManifestSha256,
        '-RequestPath', $RequestPath,
        '-ScenarioPath', $ScenarioPath,
        '-TimeoutSeconds', [string]$TimeoutSeconds
    )
    return Invoke-PreflightTestCommand -ScriptPath $BootstrapPath -ScriptArguments $arguments -TimeoutSeconds 30
}

function Get-CaptureOperatorOutputCounts([string]$LocalRoot) {
    return [PSCustomObject]@{
        Capture = @(Get-ChildItem -LiteralPath $LocalRoot -Directory -Filter 'capture-idle-*' -ErrorAction Stop).Count
        Plan = @(Get-ChildItem -LiteralPath $LocalRoot -Directory -Filter 'prepared-idle-*' -ErrorAction Stop).Count
        Preflight = @(Get-ChildItem -LiteralPath $LocalRoot -Directory -Filter 'preflight-idle-*' -ErrorAction Stop).Count
    }
}

function Assert-CaptureOperatorNoOutput([object]$Before, [object]$After, [string]$Reason) {
    Assert-PreflightTest (
        $Before.Capture -eq $After.Capture -and
        $Before.Plan -eq $After.Plan -and
        $Before.Preflight -eq $After.Preflight
    ) ('Capture operator ' + $Reason + ' refusal created protected output.')
}

function Assert-CaptureOperatorResponse(
    [object]$Invocation,
    [string]$ExpectedStatus,
    [string]$ExpectedReason,
    [string]$StageRoot,
    [string]$RequestPath,
    [string]$TargetIdentity,
    [string]$ServiceImagePath,
    [string]$OwnerSid
) {
    $result = $Invocation.Document
    $observedStatus = if ($result -and [string]$result.status -match '^(COMPLETE|REFUSED|INCOMPLETE)$') { [string]$result.status } else { 'missing' }
    $observedReason = if ($result -and [string]$result.reason -match '^[a-z][a-z0-9-]{0,63}$') { [string]$result.reason } else { 'missing' }
    $reportedExit = if ($result -and [string]$result.exitCode -match '^-?\d{1,3}$') { [string]$result.exitCode } else { 'missing' }
    $processExit = if ($Invocation.ExitCode -is [int] -or $Invocation.ExitCode -is [long]) { [string]$Invocation.ExitCode } else { 'missing' }
    Assert-PreflightTest (
        $null -ne $result -and
        $Invocation.ExitCode -eq [int]$result.exitCode -and
        [int]$result.exitCode -eq 2 -and
        [string]$result.status -ceq $ExpectedStatus -and
        [string]$result.reason -ceq $ExpectedReason
    ) ('Capture operator did not return the expected ' + $ExpectedStatus + '/' + $ExpectedReason +
        ' status. Observed status=' + $observedStatus + ' reason=' + $observedReason +
        ' resultExit=' + $reportedExit + ' processExit=' + $processExit + '.')
    Assert-PreflightTest (
        -not $Invocation.StdOut.Contains($StageRoot) -and
        -not $Invocation.StdErr.Contains($StageRoot) -and
        -not $Invocation.StdOut.Contains($RequestPath) -and
        -not $Invocation.StdErr.Contains($RequestPath) -and
        -not $Invocation.StdOut.Contains($TargetIdentity) -and
        -not $Invocation.StdErr.Contains($TargetIdentity) -and
        -not $Invocation.StdOut.Contains($ServiceImagePath) -and
        -not $Invocation.StdErr.Contains($ServiceImagePath) -and
        -not $Invocation.StdOut.Contains($OwnerSid) -and
        -not $Invocation.StdErr.Contains($OwnerSid) -and
        -not $Invocation.StdOut.Contains('8101') -and
        -not $Invocation.StdOut.Contains('8102') -and
        -not $Invocation.StdOut.Contains('8103') -and
        -not $Invocation.StdOut.Contains('8111') -and
        -not $Invocation.StdOut.Contains('8121') -and
        -not $Invocation.StdErr.Contains('8101') -and
        -not $Invocation.StdErr.Contains('8102') -and
        -not $Invocation.StdErr.Contains('8103') -and
        -not $Invocation.StdErr.Contains('8111') -and
        -not $Invocation.StdErr.Contains('8121')
    ) 'Capture operator disclosed protected target data.'
}

function Assert-PreflightReceipt(
    [object]$Invocation,
    [string]$ExpectedResult,
    [int]$ExpectedExitCode,
    [object]$ExpectedChildExitCode,
    [bool]$ExpectedTimedOut,
    [string]$StageRoot
) {
    $receipt = $Invocation.Document
    Assert-PreflightTest ($null -ne $receipt) 'Preflight did not emit its bounded result record.'
    Assert-PreflightTest ($Invocation.ExitCode -eq $ExpectedExitCode) 'Preflight process exit code did not match its result.'
    Assert-PreflightTest ($receipt.result -ceq $ExpectedResult -and [int]$receipt.exitCode -eq $ExpectedExitCode) 'Preflight result and exit fields were not distinct and correct.'
    Assert-PreflightTest ($receipt.timedOut -is [bool] -and $receipt.timedOut -ceq $ExpectedTimedOut) 'Preflight timeout field was missing or incorrect.'
    Assert-PreflightTest ($receipt.childStopped -is [bool]) 'Preflight child-stop evidence was missing.'
    if ($ExpectedResult -ceq 'PASS') {
        Assert-PreflightTest ($receipt.childStopped -and $receipt.childExitCode -eq $ExpectedChildExitCode) 'Successful Preflight did not prove its child exit.'
    } elseif ($ExpectedResult -ceq 'FAIL') {
        Assert-PreflightTest ($receipt.childStopped -and $receipt.childExitCode -eq $ExpectedChildExitCode) 'Failed Preflight did not preserve the child exit.'
    } else {
        Assert-PreflightTest ($receipt.childStopped -and ($null -eq $receipt.childExitCode -or [string]$receipt.childExitCode -match '^-?\d+$')) 'Timed out Preflight did not prove stop or preserve the available child exit.'
    }
    Assert-PreflightTest ($receipt.planSha256 -match '^[0-9a-f]{64}$' -and $receipt.sourceManifestSha256 -match '^[0-9a-f]{64}$') 'Preflight receipt did not bind the plan and manifest.'
    Assert-PreflightTest ($receipt.receiptId -match '^[0-9a-f]{32}$') 'Preflight receipt identifier is malformed.'
    $resultDirectory = Join-Path (Join-Path $StageRoot 'local') ('preflight-idle-' + $receipt.receiptId)
    $resultPath = Join-Path $resultDirectory 'result.json'
    Assert-PreflightTest (Test-Path -LiteralPath $resultPath -PathType Leaf) 'Preflight result file is missing; outcome is UNKNOWN.'
    $null = Assert-CvrIdleCaptureAcl -Path $resultDirectory -Directory
    $null = Assert-CvrIdleCaptureAcl -Path $resultPath
    $stored = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($resultPath, [Text.UTF8Encoding]::new($false, $true))) -ErrorAction Stop
    Assert-PreflightTest ($stored.result -ceq $receipt.result -and
        [int]$stored.exitCode -eq [int]$receipt.exitCode -and
        $stored.timedOut -ceq $receipt.timedOut -and
        $stored.childExitCode -eq $receipt.childExitCode -and
        $stored.childStopped -ceq $receipt.childStopped) 'Persisted Preflight receipt did not match the process result.'
    Assert-PreflightTest ((Get-Item -LiteralPath $resultPath).Length -le 4096) 'Persisted Preflight diagnostics exceeded the output limit.'
    Assert-PreflightTest (-not $Invocation.StdOut.Contains($StageRoot) -and -not $Invocation.StdErr.Contains($StageRoot)) 'Preflight output disclosed a local path.'
    Assert-PreflightTest (-not $Invocation.StdOut.Contains('stcvrc-ci-synthetic-preflight') -and -not $Invocation.StdErr.Contains('stcvrc-ci-synthetic-preflight')) 'Preflight output disclosed target identity.'
}

$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('stcvrc-preflight-' + [Guid]::NewGuid().ToString('N'))
$packageRoot = Join-Path $fixtureRoot 'stage'
$toolsStageRoot = Join-Path $packageRoot 'tools'
$networkLabStageRoot = Join-Path $toolsStageRoot 'network-lab'
$localRoot = Join-Path $packageRoot 'local'
$stageFilesRoot = Join-Path $packageRoot 'pins'
$payloadRoot = Join-Path $packageRoot 'payload'
$targetIdentity = 'stcvrc-ci-synthetic-preflight'
try {
    New-PreflightTestDirectory $fixtureRoot
    New-PreflightTestDirectory $packageRoot
    New-PreflightTestDirectory $toolsStageRoot
    New-PreflightTestDirectory $networkLabStageRoot
    New-PreflightTestDirectory $localRoot
    New-PreflightTestDirectory $stageFilesRoot
    New-PreflightTestDirectory $payloadRoot

    $pinBytes = [ordered]@{
        gui258 = [byte[]]@(2, 5, 8, 1)
        serviceExe258 = [byte[]]@(2, 5, 8, 2)
        candidateCore = [byte[]]@(1, 19, 33, 11)
        updateInstaller = [byte[]]@(2, 5, 10, 1)
        updateHelper = [byte[]]@(2, 7, 7, 1)
        recoveryInstaller = [byte[]]@(2, 5, 8, 3)
        recoveryHelper = [byte[]]@(2, 7, 6, 1)
    }
    $pinPaths = [ordered]@{}
    $manifestEntries = @()
    $pinFileNames = @{
        gui258 = 'Clash Verge.exe'
        serviceExe258 = 'clash-verge-service.exe'
    }
    $payloadFileNames = @{
        candidateCore = 'verge-mihomo.exe'
        updateInstaller = 'Clash.Verge_2.5.10_x64-setup.exe'
        recoveryInstaller = 'Clash.Verge_2.5.8_x64-setup.exe'
    }
    foreach ($name in $pinBytes.Keys) {
        if ($payloadFileNames.ContainsKey($name)) {
            $fileName = $payloadFileNames[$name]
            $path = Join-Path $payloadRoot $fileName
            $archivePath = 'payload/' + $fileName
        } else {
            $fileName = if ($pinFileNames.ContainsKey($name)) { $pinFileNames[$name] } else { $name + '.bin' }
            $path = Join-Path $stageFilesRoot $fileName
            $archivePath = 'pins/' + $fileName
        }
        Write-PreflightTestFile -Path $path -Bytes $pinBytes[$name] -Protected
        $pinPaths[$name] = $path
        $manifestEntries += [ordered]@{
            path = $archivePath
            sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }

    $operatorStageFiles = @(
        'windows_idle_capture_operator.ps1',
        'windows_core_preimage_paths.ps1',
        'windows_idle_baseline_guard.ps1',
        'windows_idle_transaction.ps1',
        'windows_idle_preflight_package_writer.ps1',
        'windows_idle_preflight.ps1'
    )
    foreach ($name in $operatorStageFiles) {
        $sourcePath = Join-Path $PSScriptRoot $name
        $stagedPath = Join-Path $networkLabStageRoot $name
        Write-PreflightTestFile -Path $stagedPath -Bytes ([IO.File]::ReadAllBytes($sourcePath)) -Protected
        $manifestEntries += [ordered]@{
            path = ('tools/network-lab/' + $name)
            sha256 = (Get-FileHash -LiteralPath $stagedPath -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }

    $manifestPath = Join-Path $packageRoot 'source-manifest.json'
    Write-PreflightTestFile -Path $manifestPath -Bytes ([byte[]]@()) -Protected
    $manifest = [ordered]@{ schemaVersion = 1; scope = 'synthetic read-only Capture/Plan/Preflight'; files = $manifestEntries }
    [IO.File]::WriteAllText($manifestPath, (ConvertTo-Json -InputObject $manifest -Depth 5 -Compress), [Text.UTF8Encoding]::new($false))
    $manifestSha256 = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $stageRoot = [IO.Path]::GetFullPath($packageRoot)

    $programFilesDirectory = Join-Path $fixtureRoot 'program-files'
    $serviceDirectory = Join-Path $fixtureRoot 'service-core'
    $null = New-Item -ItemType Directory -Path $programFilesDirectory -ErrorAction Stop
    $null = New-Item -ItemType Directory -Path $serviceDirectory -ErrorAction Stop
    $programFilesPath = Join-Path $programFilesDirectory 'verge-mihomo.exe'
    $serviceCorePath = Join-Path $serviceDirectory 'verge-mihomo.exe'
    [IO.File]::WriteAllBytes($programFilesPath, [byte[]]@(2, 5, 8, 4))
    [IO.File]::WriteAllBytes($serviceCorePath, [byte[]]@(2, 5, 8, 5))
    $programFilesBackup = Save-CvrCorePreimageBackup -Root $fixtureRoot -Label 'program-files' -SourcePath $programFilesPath -ExpectedSha256 (Get-FileHash -LiteralPath $programFilesPath -Algorithm SHA256).Hash
    $serviceBackup = Save-CvrCorePreimageBackup -Root $fixtureRoot -Label 'service' -SourcePath $serviceCorePath -ExpectedSha256 (Get-FileHash -LiteralPath $serviceCorePath -Algorithm SHA256).Hash
    $programFilesSha = (Get-FileHash -LiteralPath $programFilesPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $serviceSha = (Get-FileHash -LiteralPath $serviceCorePath -Algorithm SHA256).Hash.ToLowerInvariant()

    $expectedPins = [ordered]@{
        gui258 = (Get-FileHash -LiteralPath $pinPaths.gui258 -Algorithm SHA256).Hash.ToLowerInvariant()
        serviceExe258 = (Get-FileHash -LiteralPath $pinPaths.serviceExe258 -Algorithm SHA256).Hash.ToLowerInvariant()
        programFilesCore = $programFilesSha
        serviceCore = $serviceSha
        candidateCore = (Get-FileHash -LiteralPath $pinPaths.candidateCore -Algorithm SHA256).Hash.ToLowerInvariant()
        updateInstaller = (Get-FileHash -LiteralPath $pinPaths.updateInstaller -Algorithm SHA256).Hash.ToLowerInvariant()
        updateHelper = (Get-FileHash -LiteralPath $pinPaths.updateHelper -Algorithm SHA256).Hash.ToLowerInvariant()
        recoveryInstaller = (Get-FileHash -LiteralPath $pinPaths.recoveryInstaller -Algorithm SHA256).Hash.ToLowerInvariant()
        recoveryHelper = (Get-FileHash -LiteralPath $pinPaths.recoveryHelper -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $pinnedFiles = [ordered]@{
        gui258 = $pinPaths.gui258
        serviceExe258 = $pinPaths.serviceExe258
        programFilesCore = $programFilesPath
        serviceCore = $serviceCorePath
        candidateCore = $pinPaths.candidateCore
        updateInstaller = $pinPaths.updateInstaller
        updateHelper = $pinPaths.updateHelper
        recoveryInstaller = $pinPaths.recoveryInstaller
        recoveryHelper = $pinPaths.recoveryHelper
    }
    $programFilesAcl = Get-Acl -LiteralPath $programFilesPath
    $serviceAcl = Get-Acl -LiteralPath $serviceCorePath
    $capture = [PSCustomObject]@{
        targetIdentity = $targetIdentity
        capturedAtUtc = [DateTime]::UtcNow
        coreShouldBeRunning = [bool]$false
        idleObservation = @{
            CoreShouldBeRunning = [bool]$false
            OwnedGuiProcessIds = [int[]]@()
            OwnedCoreProcessIds = [int[]]@()
            ControllerListening = [bool]$false
            OwnedListenerProcessIds = [int[]]@()
            ServiceStatus = 'Running'
            ExpectedProgramFilesCoreSha256 = $programFilesSha
            ObservedProgramFilesCoreSha256 = $programFilesSha
            ExpectedServiceCoreSha256 = $serviceSha
            ObservedServiceCoreSha256 = $serviceSha
        }
        pinnedFiles = $pinnedFiles
        corePair = @{
            programFiles = [PSCustomObject]@{
                path = $programFilesPath; pathPin = $programFilesPath
                backup = $programFilesBackup.backup; backupPathPin = $programFilesBackup.backupPathPin
                backupRoot = $programFilesBackup.backupRoot
                backupSddl = $programFilesBackup.backupSddl
                backupDirectorySddl = $programFilesBackup.backupDirectorySddl
                sha256 = $programFilesSha; sddl = $programFilesAcl.Sddl; acl = $programFilesAcl
            }
            service = [PSCustomObject]@{
                path = $serviceCorePath; pathPin = $serviceCorePath
                backup = $serviceBackup.backup; backupPathPin = $serviceBackup.backupPathPin
                backupRoot = $serviceBackup.backupRoot
                backupSddl = $serviceBackup.backupSddl
                backupDirectorySddl = $serviceBackup.backupDirectorySddl
                sha256 = $serviceSha; sddl = $serviceAcl.Sddl; acl = $serviceAcl
            }
        }
    }
    foreach ($role in @('programFiles', 'service')) {
        $entry = $capture.corePair[$role]
        $entry.acl = [ordered]@{ Sddl = [string]$entry.sddl }
    }
    $capture.capturedAtUtc = $capture.capturedAtUtc.ToString('o')
    $writerRequest = [ordered]@{
        Capture = $capture
        ExpectedTargetIdentity = $targetIdentity
        ExpectedPins = $expectedPins
        PackageRoot = $packageRoot
        ExpectedStageRoot = $stageRoot
        ExpectedPackageManifestSha256 = $manifestSha256
    }
    $writerPath = Join-Path $PSScriptRoot 'windows_idle_preflight_package_writer.ps1'
    $operatorPath = Join-Path $networkLabStageRoot 'windows_idle_capture_operator.ps1'
    $seedPath = Join-Path $localRoot 'capture-seed.json'
    $seedCapture = ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $capture -Depth 20 -Compress) -ErrorAction Stop
    $null = $seedCapture.PSObject.Properties.Remove('capturedAtUtc')
    $null = $seedCapture.PSObject.Properties.Remove('idleObservation')
    $seedRequest = [ordered]@{
        Capture = $seedCapture
        ExpectedTargetIdentity = $targetIdentity
        ExpectedPins = $expectedPins
        Observer = [ordered]@{
            ExpectedOwnerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            ExpectedSessionId = [int][Diagnostics.Process]::GetCurrentProcess().SessionId
            ExpectedServiceAccountSid = 'S-1-5-18'
        }
    }
    $seedBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes(
        (ConvertTo-Json -InputObject $seedRequest -Depth 20 -Compress -ErrorAction Stop)
    )
    Write-PreflightTestFile -Path $seedPath -Bytes $seedBytes -Protected
    $operatorFixtureRoot = Join-Path $fixtureRoot 'operator-fixtures'
    New-PreflightTestDirectory $operatorFixtureRoot
    $bootstrapPath = Join-Path $operatorFixtureRoot 'operator-bootstrap.ps1'
    $bootstrapSource = @'
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$OperatorPath,
    [Parameter(Mandatory = $true)][string]$StageRoot,
    [Parameter(Mandatory = $true)][string]$ExpectedPackageManifestSha256,
    [Parameter(Mandatory = $true)][string]$RequestPath,
    [Parameter(Mandatory = $true)][string]$ScenarioPath,
    [ValidateRange(1, 300)][int]$TimeoutSeconds = 30
)
$ErrorActionPreference = 'Stop'
$global:scenario = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($ScenarioPath, [Text.UTF8Encoding]::new($false, $true))) -ErrorAction Stop

function global:Get-CimInstance {
    [CmdletBinding()]
    param([string]$ClassName, [string]$Filter, [string[]]$Property)
    if ($ClassName -ceq 'Win32_Service') { return $global:scenario.Service }
    if ($ClassName -ceq 'Win32_Process') { return @($global:scenario.Processes) }
    throw 'synthetic observation unavailable'
}

function global:Invoke-CimMethod {
    [CmdletBinding()]
    param([object]$InputObject, [string]$MethodName)
    if ($MethodName -cne 'GetOwnerSid') { throw 'synthetic owner unavailable' }
    if (@($global:scenario.UnknownOwnerPids) -contains [int]$InputObject.ProcessId) {
        return [PSCustomObject]@{ ReturnValue = 2; Sid = $null }
    }
    return [PSCustomObject]@{ ReturnValue = 0; Sid = [string]$InputObject.OwnerSid }
}

function global:Get-Service {
    [CmdletBinding()]
    param([string]$Name)
    if ($Name -cne 'clash_verge_service') { throw 'synthetic service unavailable' }
    return [PSCustomObject]@{ Status = [string]$global:scenario.Service.State }
}

function global:Get-NetTCPConnection {
    [CmdletBinding()]
    param([string]$State)
    if ([bool]$global:scenario.FailTcp) { throw 'synthetic listener unavailable' }
    return @($global:scenario.TcpOwnerProcessIds | ForEach-Object {
        [PSCustomObject]@{ State = 'Listen'; OwningProcess = [int]$_ }
    })
}

function global:Get-NetUDPEndpoint {
    [CmdletBinding()]
    param()
    if ([bool]$global:scenario.FailUdp) { throw 'synthetic listener unavailable' }
    return @($global:scenario.UdpOwnerProcessIds | ForEach-Object {
        [PSCustomObject]@{ OwningProcess = [int]$_ }
    })
}

& $OperatorPath -StageRoot $StageRoot -ExpectedPackageManifestSha256 $ExpectedPackageManifestSha256 -RequestPath $RequestPath -TimeoutSeconds $TimeoutSeconds
$operatorExitCode = $LASTEXITCODE
if ($null -eq $operatorExitCode) { throw 'Operator exit code was unavailable.' }
exit ([int]$operatorExitCode)
'@
    Write-PreflightTestFile -Path $bootstrapPath -Bytes ([Text.UTF8Encoding]::new($false, $true).GetBytes($bootstrapSource)) -Protected
    $operatorTrackedPaths = @(
        $manifestPath, $programFilesPath, $serviceCorePath,
        $programFilesBackup.backup, $serviceBackup.backup, $seedPath
    ) + @($pinPaths.Values) + @($operatorStageFiles | ForEach-Object { Join-Path $networkLabStageRoot $_ })
    $operatorInputSnapshot = Get-PreflightTestSnapshot -Paths $operatorTrackedPaths

    function New-CaptureOperatorScenario(
        [switch]$UnknownServiceOwner,
        [switch]$UnknownListener,
        [switch]$RunningCore,
        [switch]$RunningAlpha,
        [switch]$OrphanService,
        [switch]$DuplicateService
    ) {
        $servicePid = 8101
        $service = [ordered]@{
            Name = 'clash_verge_service'
            State = 'Running'
            ProcessId = $servicePid
            PathName = '"' + $pinPaths.serviceExe258 + '"'
            StartName = 'LocalSystem'
        }
        $processes = [Collections.Generic.List[object]]::new()
        $processes.Add([PSCustomObject]@{
            Name = [IO.Path]::GetFileName($pinPaths.serviceExe258)
            ExecutablePath = $pinPaths.serviceExe258
            ProcessId = $servicePid
            ParentProcessId = 4
            SessionId = 0
            OwnerSid = 'S-1-5-18'
        })
        if ($OrphanService) { $processes.Clear() }
        if ($OrphanService -or $DuplicateService) {
            $serviceImagePid = if ($OrphanService) { 8111 } else { 8121 }
            $processes.Add([PSCustomObject]@{
                Name = [IO.Path]::GetFileName($pinPaths.serviceExe258)
                ExecutablePath = $pinPaths.serviceExe258
                ProcessId = $serviceImagePid
                ParentProcessId = 4
                SessionId = 0
                OwnerSid = 'S-1-5-18'
            })
        }
        $udpOwners = [int[]]@()
        if ($RunningCore) {
            $corePid = 8102
            $processes.Add([PSCustomObject]@{
                Name = 'verge-mihomo.exe'
                ExecutablePath = $serviceCorePath
                ProcessId = $corePid
                ParentProcessId = $servicePid
                SessionId = 0
                OwnerSid = 'S-1-5-18'
            })
            $udpOwners = [int[]]@($corePid)
        }
        if ($RunningAlpha) {
            $alphaPid = 8103
            $processes.Add([PSCustomObject]@{
                Name = 'verge-mihomo-alpha.exe'
                ExecutablePath = (Join-Path $programFilesDirectory 'verge-mihomo-alpha.exe')
                ProcessId = $alphaPid
                ParentProcessId = 8100
                SessionId = [int][Diagnostics.Process]::GetCurrentProcess().SessionId
                OwnerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            })
            $udpOwners = [int[]]@($udpOwners + $alphaPid)
        }
        $unknownOwners = if ($UnknownServiceOwner) { [int[]]@($servicePid) } else { [int[]]@() }
        return [PSCustomObject]@{
            Service = [PSCustomObject]$service
            Processes = @($processes.ToArray())
            UnknownOwnerPids = $unknownOwners
            TcpOwnerProcessIds = [int[]]@()
            UdpOwnerProcessIds = $udpOwners
            FailTcp = $false
            FailUdp = [bool]$UnknownListener
        }
    }

    function Save-CaptureOperatorScenario([string]$Name, [object]$Scenario) {
        $path = Join-Path $operatorFixtureRoot ($Name + '.json')
        $bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes(
            (ConvertTo-Json -InputObject $Scenario -Depth 5 -Compress -ErrorAction Stop)
        )
        Write-PreflightTestFile -Path $path -Bytes $bytes -Protected
        return $path
    }

    function Invoke-CaptureOperatorScenario([string]$Name, [object]$Scenario) {
        $scenarioPath = Save-CaptureOperatorScenario -Name $Name -Scenario $Scenario
        return Invoke-CaptureOperatorTestCommand -BootstrapPath $bootstrapPath -OperatorPath $operatorPath -StageRoot $stageRoot -ManifestSha256 $manifestSha256 -RequestPath $seedPath -ScenarioPath $scenarioPath -TimeoutSeconds 30
    }

    function Assert-CaptureOperatorNegative([string]$Name, [object]$Scenario, [string]$Status, [string]$Reason) {
        $before = Get-CaptureOperatorOutputCounts -LocalRoot $localRoot
        $invocation = Invoke-CaptureOperatorScenario -Name $Name -Scenario $Scenario
        $after = Get-CaptureOperatorOutputCounts -LocalRoot $localRoot
        Assert-CaptureOperatorNoOutput -Before $before -After $after -Reason $Reason
        Assert-CaptureOperatorResponse -Invocation $invocation -ExpectedStatus $Status -ExpectedReason $Reason -StageRoot $stageRoot -RequestPath $seedPath -TargetIdentity $targetIdentity -ServiceImagePath $pinPaths.serviceExe258 -OwnerSid $seedRequest.Observer.ExpectedOwnerSid
    }

    $operatorOutputsBefore = Get-CaptureOperatorOutputCounts -LocalRoot $localRoot
    $operatorCaptureDirectoriesBefore = @(Get-ChildItem -LiteralPath $localRoot -Directory -Filter 'capture-idle-*' -ErrorAction Stop | ForEach-Object { $_.FullName })
    $operatorPlanDirectoriesBefore = @(Get-ChildItem -LiteralPath $localRoot -Directory -Filter 'prepared-idle-*' -ErrorAction Stop | ForEach-Object { $_.FullName })
    $validOperator = Invoke-CaptureOperatorScenario -Name 'valid' -Scenario (New-CaptureOperatorScenario)
    $validOperatorResult = $validOperator.Document
    Assert-PreflightTest (
        $null -ne $validOperatorResult -and
        $validOperator.ExitCode -eq 0 -and
        [string]$validOperatorResult.status -ceq 'COMPLETE' -and
        [string]$validOperatorResult.reason -ceq 'preflight-complete' -and
        [string]$validOperatorResult.result -ceq 'PASS' -and
        [int]$validOperatorResult.exitCode -eq 0 -and
        $validOperatorResult.timedOut -is [bool] -and -not $validOperatorResult.timedOut -and
        $validOperatorResult.childStopped -is [bool] -and $validOperatorResult.childStopped -and
        [int]$validOperatorResult.childExitCode -eq 0 -and
        [string]$validOperatorResult.planSha256 -match '^[0-9a-f]{64}$' -and
        [string]$validOperatorResult.sourceManifestSha256 -ceq $manifestSha256 -and
        [string]$validOperatorResult.receiptId -match '^[0-9a-f]{32}$' -and
        [string]::IsNullOrEmpty($validOperator.StdErr)
    ) 'The public Capture operator did not complete Capture/Plan/Preflight with distinct PASS evidence.'
    Assert-PreflightTest (
        -not $validOperator.StdOut.Contains($stageRoot) -and
        -not $validOperator.StdOut.Contains($seedPath) -and
        -not $validOperator.StdOut.Contains($targetIdentity) -and
        -not $validOperator.StdOut.Contains($pinPaths.serviceExe258) -and
        -not $validOperator.StdOut.Contains($programFilesPath) -and
        -not $validOperator.StdOut.Contains([string]$seedRequest.Observer.ExpectedOwnerSid) -and
        -not $validOperator.StdOut.Contains('8101') -and
        -not $validOperator.StdOut.Contains('8102')
    ) 'The public Capture operator disclosed protected target data.'

    $operatorOutputsAfter = Get-CaptureOperatorOutputCounts -LocalRoot $localRoot
    Assert-PreflightTest (
        $operatorOutputsAfter.Capture -eq ($operatorOutputsBefore.Capture + 1) -and
        $operatorOutputsAfter.Plan -eq ($operatorOutputsBefore.Plan + 1) -and
        $operatorOutputsAfter.Preflight -eq ($operatorOutputsBefore.Preflight + 1)
    ) 'The public Capture operator did not create exactly one Capture, Plan, and Preflight record.'
    $operatorCaptureDirectories = @(
        Get-ChildItem -LiteralPath $localRoot -Directory -Filter 'capture-idle-*' -ErrorAction Stop |
            Where-Object { $operatorCaptureDirectoriesBefore -notcontains $_.FullName }
    )
    $operatorPlanDirectories = @(
        Get-ChildItem -LiteralPath $localRoot -Directory -Filter 'prepared-idle-*' -ErrorAction Stop |
            Where-Object { $operatorPlanDirectoriesBefore -notcontains $_.FullName }
    )
    Assert-PreflightTest ($operatorCaptureDirectories.Count -eq 1 -and $operatorPlanDirectories.Count -eq 1) 'The operator created ambiguous Capture/Plan output.'
    $operatorCaptureDirectory = $operatorCaptureDirectories[0].FullName
    $operatorCaptureReceiptPath = Join-Path $operatorCaptureDirectory 'capture.json'
    $null = Assert-CvrIdleCaptureAcl -Path $operatorCaptureDirectory -Directory
    $null = Assert-CvrIdleCaptureAcl -Path $operatorCaptureReceiptPath
    $operatorCaptureReceipt = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($operatorCaptureReceiptPath, [Text.UTF8Encoding]::new($false, $true))) -ErrorAction Stop
    Assert-PreflightTest (
        [string]$operatorCaptureReceipt.packageStageBinding.sourceManifestSha256 -ceq $manifestSha256 -and
        [string]$operatorCaptureReceipt.idleObservation.ServiceStatus -ceq 'Running' -and
        $operatorCaptureReceipt.idleObservation.CoreShouldBeRunning -is [bool] -and -not $operatorCaptureReceipt.idleObservation.CoreShouldBeRunning -and
        $operatorCaptureReceipt.idleObservation.ControllerListening -is [bool] -and -not $operatorCaptureReceipt.idleObservation.ControllerListening -and
        @($operatorCaptureReceipt.idleObservation.OwnedGuiProcessIds).Count -eq 0 -and
        @($operatorCaptureReceipt.idleObservation.OwnedCoreProcessIds).Count -eq 0 -and
        @($operatorCaptureReceipt.idleObservation.OwnedListenerProcessIds).Count -eq 0
    ) 'The public Capture receipt did not preserve the fresh owner-scoped idle observation and stage pin.'
    $operatorPlanDirectory = $operatorPlanDirectories[0].FullName
    $operatorPlanPath = Join-Path $operatorPlanDirectory 'plan.json'
    $null = Assert-CvrIdleCaptureAcl -Path $operatorPlanDirectory -Directory
    $null = Assert-CvrIdleCaptureAcl -Path $operatorPlanPath
    $operatorPlanRecord = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($operatorPlanPath, [Text.UTF8Encoding]::new($false, $true))) -ErrorAction Stop
    Assert-PreflightTest (
        (Get-FileHash -LiteralPath $operatorPlanPath -Algorithm SHA256).Hash.ToLowerInvariant() -ceq [string]$validOperatorResult.planSha256 -and
        [string]$operatorPlanRecord.packageStageBinding.sourceManifestSha256 -ceq $manifestSha256
    ) 'The public Plan record did not match its reported digest and trusted stage pin.'
    $operatorPreflightInvocation = [PSCustomObject]@{
        ExitCode = [int]$validOperatorResult.exitCode
        StdOut = [string]$validOperator.StdOut
        StdErr = [string]$validOperator.StdErr
        Document = $validOperatorResult
    }
    Assert-PreflightReceipt -Invocation $operatorPreflightInvocation -ExpectedResult 'PASS' -ExpectedExitCode 0 -ExpectedChildExitCode 0 -ExpectedTimedOut $false -StageRoot $stageRoot

    $operatorPreflightReceiptPath = Join-Path (Join-Path $localRoot ('preflight-idle-' + [string]$validOperatorResult.receiptId)) 'result.json'
    $preflightHandoffActionCalls = 0
    $preflightHandoffError = $null
    try {
        $handoff = Invoke-CvrIdlePreflightTargetTransaction -CaptureReceiptPath $operatorCaptureReceiptPath -PlanPath $operatorPlanPath -PreflightReceiptPath $operatorPreflightReceiptPath -ExpectedPlanSha256 ([string]$validOperatorResult.planSha256) -ExpectedStageRoot $stageRoot -ExpectedPackageManifestSha256 $manifestSha256 -ExpectedTargetIdentity $targetIdentity -ExpectedPins $expectedPins -ActionScript {
            $script:preflightHandoffActionCalls++
            'synthetic-candidate-accepted'
        } -RestoreScript {
            'synthetic-idle-restored'
        } -VerifyScript {
            param($capture, $restored)
            $restored -ceq 'synthetic-idle-restored'
        }
    } catch {
        $preflightHandoffError = $_.Exception.Message
    }
    if ($preflightHandoffActionCalls -ne 1) {
        Write-Output ('Observed Capture/Plan/Preflight PASS; candidate action calls={0}; handoff error={1}' -f $preflightHandoffActionCalls, $(if ($preflightHandoffError) { $preflightHandoffError } else { 'none' }))
        throw 'Expected behavior RED: the valid idle Capture/Plan/Preflight chain has no guarded candidate-action handoff.'
    }
    Assert-PreflightTest (
        $null -eq $preflightHandoffError -and
        $handoff.ActionFailure -eq $null -and
        $handoff.RestoreFailure -eq $null -and
        $handoff.ActionResult -ceq 'synthetic-candidate-accepted'
    ) 'The guarded candidate-action handoff did not complete after the verified PASS.'

    $wrongRootBefore = Get-CaptureOperatorOutputCounts -LocalRoot $localRoot
    $wrongRoot = Invoke-CaptureOperatorTestCommand -BootstrapPath $bootstrapPath -OperatorPath $operatorPath -StageRoot $fixtureRoot -ManifestSha256 $manifestSha256 -RequestPath $seedPath -ScenarioPath (Save-CaptureOperatorScenario -Name 'wrong-stage-root' -Scenario (New-CaptureOperatorScenario)) -TimeoutSeconds 30
    $wrongRootAfter = Get-CaptureOperatorOutputCounts -LocalRoot $localRoot
    Assert-CaptureOperatorNoOutput -Before $wrongRootBefore -After $wrongRootAfter -Reason 'wrong-stage-root'
    Assert-CaptureOperatorResponse -Invocation $wrongRoot -ExpectedStatus 'INCOMPLETE' -ExpectedReason 'stage-path' -StageRoot $fixtureRoot -RequestPath $seedPath -TargetIdentity $targetIdentity -ServiceImagePath $pinPaths.serviceExe258 -OwnerSid $seedRequest.Observer.ExpectedOwnerSid

    $wrongDigestBefore = Get-CaptureOperatorOutputCounts -LocalRoot $localRoot
    $wrongDigest = Invoke-CaptureOperatorTestCommand -BootstrapPath $bootstrapPath -OperatorPath $operatorPath -StageRoot $stageRoot -ManifestSha256 '0000000000000000000000000000000000000000000000000000000000000000' -RequestPath $seedPath -ScenarioPath (Save-CaptureOperatorScenario -Name 'wrong-stage-digest' -Scenario (New-CaptureOperatorScenario)) -TimeoutSeconds 30
    $wrongDigestAfter = Get-CaptureOperatorOutputCounts -LocalRoot $localRoot
    Assert-CaptureOperatorNoOutput -Before $wrongDigestBefore -After $wrongDigestAfter -Reason 'wrong-stage-digest'
    Assert-CaptureOperatorResponse -Invocation $wrongDigest -ExpectedStatus 'INCOMPLETE' -ExpectedReason 'stage-pin' -StageRoot $stageRoot -RequestPath $seedPath -TargetIdentity $targetIdentity -ServiceImagePath $pinPaths.serviceExe258 -OwnerSid $seedRequest.Observer.ExpectedOwnerSid

    Assert-CaptureOperatorNegative -Name 'unknown-owner' -Scenario (New-CaptureOperatorScenario -UnknownServiceOwner) -Status 'INCOMPLETE' -Reason 'unknown-ownership'
    Assert-CaptureOperatorNegative -Name 'unknown-listener' -Scenario (New-CaptureOperatorScenario -UnknownListener) -Status 'INCOMPLETE' -Reason 'unknown-unavailable'
    Assert-CaptureOperatorNegative -Name 'running-core' -Scenario (New-CaptureOperatorScenario -RunningCore) -Status 'REFUSED' -Reason 'not-idle'
    Assert-CaptureOperatorNegative -Name 'running-alpha-core' -Scenario (New-CaptureOperatorScenario -RunningAlpha) -Status 'REFUSED' -Reason 'not-idle'
    Assert-CaptureOperatorNegative -Name 'orphan-service-process' -Scenario (New-CaptureOperatorScenario -OrphanService) -Status 'INCOMPLETE' -Reason 'unknown-service-pid'
    Assert-CaptureOperatorNegative -Name 'duplicate-service-process' -Scenario (New-CaptureOperatorScenario -DuplicateService) -Status 'INCOMPLETE' -Reason 'unknown-service-pid'

    foreach ($pinName in @('candidateCore','updateInstaller','recoveryInstaller')) {
        $alternatePath = Join-Path $localRoot ($pinName + '-alternate.exe')
        $alternateBytes = [byte[]]@(99, 88, 77)
        Write-PreflightTestFile -Path $alternatePath -Bytes $alternateBytes -Protected
        $alternateSeed = ConvertFrom-Json -InputObject ([Text.UTF8Encoding]::new($false, $true).GetString($seedBytes)) -ErrorAction Stop
        $alternateSha = (Get-FileHash -LiteralPath $alternatePath -Algorithm SHA256).Hash.ToLowerInvariant()
        $alternateSeed.Capture.pinnedFiles.$pinName = $alternatePath
        $alternateSeed.ExpectedPins.$pinName = $alternateSha
        [IO.File]::WriteAllBytes($seedPath, [Text.UTF8Encoding]::new($false, $true).GetBytes((ConvertTo-Json -InputObject $alternateSeed -Depth 20 -Compress -ErrorAction Stop)))
        try {
            $alternateBefore = Get-CaptureOperatorOutputCounts -LocalRoot $localRoot
            $alternate = Invoke-CaptureOperatorTestCommand -BootstrapPath $bootstrapPath -OperatorPath $operatorPath -StageRoot $stageRoot -ManifestSha256 $manifestSha256 -RequestPath $seedPath -ScenarioPath (Save-CaptureOperatorScenario -Name ($pinName + '-alternate-pin') -Scenario (New-CaptureOperatorScenario)) -TimeoutSeconds 30
            $alternateAfter = Get-CaptureOperatorOutputCounts -LocalRoot $localRoot
            Assert-CaptureOperatorNoOutput -Before $alternateBefore -After $alternateAfter -Reason 'alternate-stage-pin'
            Assert-CaptureOperatorResponse -Invocation $alternate -ExpectedStatus 'INCOMPLETE' -ExpectedReason 'stage-pin' -StageRoot $stageRoot -RequestPath $seedPath -TargetIdentity $targetIdentity -ServiceImagePath $pinPaths.serviceExe258 -OwnerSid $seedRequest.Observer.ExpectedOwnerSid
            Assert-PreflightTest (-not $alternate.StdOut.Contains($alternatePath) -and -not $alternate.StdErr.Contains($alternatePath)) 'Capture operator disclosed an alternate seed path.'
        } finally {
            [IO.File]::WriteAllBytes($seedPath, $seedBytes)
            if (Test-Path -LiteralPath $alternatePath -PathType Leaf) { Remove-Item -LiteralPath $alternatePath -Force -ErrorAction Stop }
        }
        Assert-PreflightTest (-not (Test-Path -LiteralPath $alternatePath)) 'Alternate seed fixture cleanup failed.'
    }

    $staleSeed = ConvertFrom-Json -InputObject ([Text.UTF8Encoding]::new($false, $true).GetString($seedBytes)) -ErrorAction Stop
    $staleSeed.Capture | Add-Member -MemberType NoteProperty -Name capturedAtUtc -Value ([DateTime]::UtcNow.AddMinutes(-6).ToString('o'))
    [IO.File]::WriteAllBytes($seedPath, [Text.UTF8Encoding]::new($false, $true).GetBytes((ConvertTo-Json -InputObject $staleSeed -Depth 20 -Compress -ErrorAction Stop)))
    try {
        Assert-CaptureOperatorNegative -Name 'stale-seed' -Scenario (New-CaptureOperatorScenario) -Status 'INCOMPLETE' -Reason 'stale-seed'
    } finally {
        [IO.File]::WriteAllBytes($seedPath, $seedBytes)
    }

    $programFilesOriginalBytes = [IO.File]::ReadAllBytes($programFilesPath)
    try {
        [IO.File]::WriteAllBytes($programFilesPath, [byte[]]@(9, 9, 9, 9))
        Assert-CaptureOperatorNegative -Name 'pin-drift' -Scenario (New-CaptureOperatorScenario) -Status 'INCOMPLETE' -Reason 'unknown-pin-drift'
    } finally {
        [IO.File]::WriteAllBytes($programFilesPath, $programFilesOriginalBytes)
    }
    Assert-PreflightTestSnapshot $operatorInputSnapshot $operatorTrackedPaths

    $wrongWriterManifest = ('0' * 64)
    if ($manifestSha256 -ceq $wrongWriterManifest) { $wrongWriterManifest = ('f' * 64) }
    $badCaptureRequest = [ordered]@{}
    foreach ($name in $writerRequest.Keys) { $badCaptureRequest[$name] = $writerRequest[$name] }
    $badCaptureRequest.ExpectedPackageManifestSha256 = $wrongWriterManifest
    $captureDirectoriesBefore = @(Get-ChildItem -LiteralPath $localRoot -Directory -Filter 'capture-idle-*' -ErrorAction Stop | ForEach-Object { $_.FullName })
    $badCapture = Invoke-PreflightTestCommand -ScriptPath $writerPath -WriterMode Capture -Request $badCaptureRequest -TimeoutSeconds 30
    $captureDirectoriesAfter = @(Get-ChildItem -LiteralPath $localRoot -Directory -Filter 'capture-idle-*' -ErrorAction Stop | ForEach-Object { $_.FullName })
    Assert-PreflightTest (
        $badCapture.ExitCode -ne 0 -and $null -eq $badCapture.Document -and
        [string]::IsNullOrEmpty($badCapture.StdOut) -and
        -not [string]::IsNullOrEmpty($badCapture.StdErr) -and
        $captureDirectoriesAfter.Count -eq $captureDirectoriesBefore.Count
    ) 'Invalid Capture stage pin was not rejected before output.'

    $captureInvocation = Invoke-PreflightTestCommand -ScriptPath $writerPath -WriterMode Capture -Request $writerRequest -TimeoutSeconds 30
    Assert-PreflightTest ($captureInvocation.ExitCode -eq 0 -and $null -ne $captureInvocation.Document -and [string]::IsNullOrEmpty($captureInvocation.StdErr)) 'The actual PS5.1 Capture CLI did not return a clean result.'
    $captureResult = $captureInvocation.Document
    Assert-PreflightTest (
        (Test-Path -LiteralPath $captureResult.ReceiptPath -PathType Leaf) -and
        (Test-Path -LiteralPath $captureResult.CaptureDirectory -PathType Container) -and
        [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($captureResult.CaptureDirectory)) -ieq [IO.Path]::GetFullPath($localRoot) -and
        [IO.Path]::GetFileName($captureResult.CaptureDirectory) -match '^capture-idle-[0-9a-f]{32}$'
    ) 'The actual Capture CLI did not write its protected receipt under the staged local root.'
    $null = Assert-CvrIdleCaptureAcl -Path $captureResult.CaptureDirectory -Directory
    $null = Assert-CvrIdleCaptureAcl -Path $captureResult.ReceiptPath
    $captureReceipt = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($captureResult.ReceiptPath, [Text.UTF8Encoding]::new($false, $true))) -ErrorAction Stop
    Assert-PreflightTest (
        [IO.Path]::GetFullPath([string]$captureReceipt.packageStageBinding.stageRoot) -ceq $stageRoot -and
        [string]$captureReceipt.packageStageBinding.sourceManifestSha256 -ceq $manifestSha256
    ) 'The actual Capture CLI receipt did not bind the synthetic stage.'

    $planRequest = [ordered]@{}
    foreach ($name in $writerRequest.Keys) { $planRequest[$name] = $writerRequest[$name] }
    $planRequest.CaptureDirectory = [string]$captureResult.CaptureDirectory
    $planRequest.ReceiptPath = [string]$captureResult.ReceiptPath
    $planRequest.ExpectedPackageManifestSha256 = $wrongWriterManifest
    $planDirectoriesBefore = @(Get-ChildItem -LiteralPath $localRoot -Directory -Filter 'prepared-idle-*' -ErrorAction Stop | ForEach-Object { $_.FullName })
    $badPlan = Invoke-PreflightTestCommand -ScriptPath $writerPath -WriterMode Plan -Request $planRequest -TimeoutSeconds 30
    $planDirectoriesAfter = @(Get-ChildItem -LiteralPath $localRoot -Directory -Filter 'prepared-idle-*' -ErrorAction Stop | ForEach-Object { $_.FullName })
    Assert-PreflightTest (
        $badPlan.ExitCode -ne 0 -and $null -eq $badPlan.Document -and
        [string]::IsNullOrEmpty($badPlan.StdOut) -and
        -not [string]::IsNullOrEmpty($badPlan.StdErr) -and
        $planDirectoriesAfter.Count -eq $planDirectoriesBefore.Count
    ) 'Invalid Plan stage pin was not rejected before output.'

    $planRequest.ExpectedPackageManifestSha256 = $manifestSha256
    $planInvocation = Invoke-PreflightTestCommand -ScriptPath $writerPath -WriterMode Plan -Request $planRequest -TimeoutSeconds 30
    Assert-PreflightTest ($planInvocation.ExitCode -eq 0 -and $null -ne $planInvocation.Document -and [string]::IsNullOrEmpty($planInvocation.StdErr)) 'The actual PS5.1 Plan CLI did not return a clean result.'
    $plan = $planInvocation.Document
    Assert-PreflightTest (
        (Test-Path -LiteralPath $plan.PlanPath -PathType Leaf) -and
        [IO.Path]::GetFileName($plan.PlanPath) -ceq 'plan.json' -and
        [IO.Path]::GetFileName([IO.Path]::GetDirectoryName($plan.PlanPath)) -match '^prepared-idle-[0-9a-f]{32}$'
    ) 'The actual Plan CLI did not write the protected plan.'
    $null = Assert-CvrIdleCaptureAcl -Path ([IO.Path]::GetDirectoryName($plan.PlanPath)) -Directory
    $null = Assert-CvrIdleCaptureAcl -Path $plan.PlanPath
    $planRecord = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($plan.PlanPath, [Text.UTF8Encoding]::new($false, $true))) -ErrorAction Stop
    $planSha256 = (Get-FileHash -LiteralPath $plan.PlanPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    Assert-PreflightTest (
        [IO.Path]::GetFullPath([string]$planRecord.packageStageBinding.stageRoot) -ceq $stageRoot -and
        [string]$planRecord.packageStageBinding.sourceManifestSha256 -ceq $manifestSha256 -and
        [string]$plan.PlanSha256 -ceq $planSha256
    ) 'The actual Plan CLI did not produce the pinned stage-bound plan.'

    $scriptPath = Join-Path $PSScriptRoot 'windows_idle_preflight.ps1'
    $trackedPaths = @(
        $manifestPath, $programFilesPath, $serviceCorePath,
        $programFilesBackup.backup, $serviceBackup.backup
    ) + @($pinPaths.Values) + @($captureResult.ReceiptPath, $plan.PlanPath)
    $snapshot = Get-PreflightTestSnapshot -Paths $trackedPaths
    $firstPreflight = Invoke-PreflightTestCommand -ScriptPath $scriptPath -PlanPath $plan.PlanPath -PlanSha256 $plan.PlanSha256 -StageRoot $stageRoot -ManifestSha256 $manifestSha256 -TimeoutSeconds 30
    Assert-PreflightReceipt -Invocation $firstPreflight -ExpectedResult 'PASS' -ExpectedExitCode 0 -ExpectedChildExitCode 0 -ExpectedTimedOut $false -StageRoot $stageRoot
    Assert-PreflightTestSnapshot $snapshot $trackedPaths

    $wrongPlan = ('0' * 64)
    if ($plan.PlanSha256 -ceq $wrongPlan) { $wrongPlan = ('f' * 64) }
    $failedPreflight = Invoke-PreflightTestCommand -ScriptPath $scriptPath -PlanPath $plan.PlanPath -PlanSha256 $wrongPlan -StageRoot $stageRoot -ManifestSha256 $manifestSha256 -TimeoutSeconds 30
    Assert-PreflightReceipt -Invocation $failedPreflight -ExpectedResult 'FAIL' -ExpectedExitCode 1 -ExpectedChildExitCode 1 -ExpectedTimedOut $false -StageRoot $stageRoot
    Assert-PreflightTestSnapshot $snapshot $trackedPaths

    $preflightDirectoriesBefore = @(Get-ChildItem -LiteralPath $localRoot -Directory -Filter 'preflight-idle-*' -ErrorAction Stop | ForEach-Object { $_.FullName })
    $wrongManifest = ('0' * 64)
    if ($manifestSha256 -ceq $wrongManifest) { $wrongManifest = ('f' * 64) }
    $wrongBinding = Invoke-PreflightTestCommand -ScriptPath $scriptPath -PlanPath $plan.PlanPath -PlanSha256 $plan.PlanSha256 -StageRoot $stageRoot -ManifestSha256 $wrongManifest -TimeoutSeconds 30
    $preflightDirectoriesAfter = @(Get-ChildItem -LiteralPath $localRoot -Directory -Filter 'preflight-idle-*' -ErrorAction Stop | ForEach-Object { $_.FullName })
    Assert-PreflightTest ($wrongBinding.ExitCode -ne 0 -and $null -eq $wrongBinding.Document -and $preflightDirectoriesAfter.Count -eq $preflightDirectoriesBefore.Count) 'Invalid external stage pin was not rejected before output.'
    Assert-PreflightTestSnapshot $snapshot $trackedPaths

    $timeoutPreflight = Invoke-PreflightTestCommand -ScriptPath $scriptPath -PlanPath $plan.PlanPath -PlanSha256 $plan.PlanSha256 -StageRoot $stageRoot -ManifestSha256 $manifestSha256 -TimeoutSeconds 1 -SyntheticDelaySeconds 10
    Assert-PreflightReceipt -Invocation $timeoutPreflight -ExpectedResult 'TIMEOUT' -ExpectedExitCode 124 -ExpectedChildExitCode $null -ExpectedTimedOut $true -StageRoot $stageRoot
    Assert-PreflightTestSnapshot $snapshot $trackedPaths
} finally {
    if (Test-Path -LiteralPath $fixtureRoot -PathType Container) {
        Remove-Item -LiteralPath $fixtureRoot -Recurse -Force -ErrorAction Stop
    }
}
Write-Output 'Windows public Capture/Plan/Preflight operator passed synthetic owner, service, alpha-core, stage-pin, idle, stale, drift, refusal, receipt, and cleanup checks.'
