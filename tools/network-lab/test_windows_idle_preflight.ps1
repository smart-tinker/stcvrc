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
    if ($WriterMode) {
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
$localRoot = Join-Path $packageRoot 'local'
$stageFilesRoot = Join-Path $packageRoot 'pins'
$targetIdentity = 'stcvrc-ci-synthetic-preflight'
try {
    New-PreflightTestDirectory $fixtureRoot
    New-PreflightTestDirectory $packageRoot
    New-PreflightTestDirectory $localRoot
    New-PreflightTestDirectory $stageFilesRoot

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
    foreach ($name in $pinBytes.Keys) {
        $path = Join-Path $stageFilesRoot ($name + '.bin')
        Write-PreflightTestFile -Path $path -Bytes $pinBytes[$name] -Protected
        $pinPaths[$name] = $path
        $manifestEntries += [ordered]@{
            path = ('pins/' + $name + '.bin')
            sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }

    $manifestPath = Join-Path $packageRoot 'source-manifest.json'
    Write-PreflightTestFile -Path $manifestPath -Bytes ([byte[]]@()) -Protected
    $manifest = [ordered]@{ schemaVersion = 1; scope = 'synthetic read-only Preflight'; files = $manifestEntries }
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
Write-Output 'Windows read-only idle Preflight contract passed: result/exit/timeout, binding, no-output refusal, and unchanged synthetic inputs.'
