[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateSet('Capture', 'Plan')][string]$Mode,
    [Parameter(Mandatory = $true)][string]$CaseName,
    [Parameter(Mandatory = $true)][string]$WriterScriptPath,
    [string]$CaptureSourceReceiptPath,
    [string]$ExpectedTargetIdentity,
    [string]$PackageRoot,
    [switch]$HasExpectedStageRoot,
    [string]$ExpectedStageRoot,
    [switch]$HasExpectedPackageManifestSha256,
    [string]$ExpectedPackageManifestSha256,
    [string]$CaptureDirectory,
    [string]$PlanReceiptPath,
    [string]$PinnedFilePathsBase64,
    [switch]$SyntheticRequest,
    [ValidateRange(0, 30)][int]$SyntheticSerializationDelaySeconds = 0,
    [switch]$SyntheticExitBeforeWriterPidWrite,
    [Parameter(Mandatory = $true)][string]$CallDirectory
)

$ErrorActionPreference = 'Stop'
$caseLabel = $CaseName -replace '[^A-Za-z0-9-]', '-'
$statusPath = Join-Path $CallDirectory 'result.txt'
$stdoutPath = Join-Path $CallDirectory 'writer.stdout'
$stderrPath = Join-Path $CallDirectory 'writer.stderr'
$writerPidPath = Join-Path $CallDirectory 'writer.pid'
$stage = 'request-serialize'
$process = $null
$started = $false
$stdoutTask = $null
$stderrTask = $null
$workerState = 'failure'
$workerExitCode = 1
$childStopped = $true
$writerStdOut = ''
$writerStdErr = ''

function Write-CvrPackageWriterMarker([string]$MarkerStage) {
    [Console]::Out.WriteLine(('package-writer case=' + $caseLabel + ' stage=' + $MarkerStage))
    [Console]::Out.Flush()
}

function Save-CvrPackageWriterResult(
    [string]$State,
    [string]$ResultStage,
    [int]$ExitCode,
    [bool]$Stopped,
    [string]$StandardOutput,
    [string]$StandardError
) {
    $encoding = [Text.UTF8Encoding]::new($false)
    [IO.File]::WriteAllText($stdoutPath, [string]$StandardOutput, $encoding)
    [IO.File]::WriteAllText($stderrPath, [string]$StandardError, $encoding)
    $resultLines = @(
        ('State=' + $State)
        ('Stage=' + $ResultStage)
        ('ExitCode=' + $ExitCode)
        ('ChildStopped=' + $Stopped.ToString())
    )
    [IO.File]::WriteAllLines($statusPath, [string[]]$resultLines, $encoding)
}

function Quote-CvrPackageWriterWorkerArgument([string]$Value) {
    if ($Value.Contains('"')) { throw 'Unsafe synthetic package-writer argument.' }
    return '"' + $Value + '"'
}

try {
    Write-CvrPackageWriterMarker 'before-request-serialize'
    if ($SyntheticRequest) {
        $request = [PSCustomObject]@{ synthetic = $true }
        if ($SyntheticSerializationDelaySeconds -gt 0) {
            $delaySource = 'Start-Sleep -Seconds ' + $SyntheticSerializationDelaySeconds + [Environment]::NewLine + "'complete'"
            $delayScript = [scriptblock]::Create($delaySource)
            $null = Add-Member -InputObject $request -MemberType ScriptProperty -Name delayed -Value $delayScript -Force
        }
    } else {
        $receiptText = [IO.File]::ReadAllText($CaptureSourceReceiptPath, [Text.UTF8Encoding]::new($false, $true))
        $receipt = ConvertFrom-Json -InputObject $receiptText -ErrorAction Stop
        if ($receipt -isnot [PSCustomObject] -or $receipt.expectedPins -isnot [PSCustomObject]) {
            throw 'invalid receipt'
        }

        $pinNames = @(
            'gui258', 'serviceExe258', 'programFilesCore', 'serviceCore',
            'candidateCore', 'updateInstaller', 'updateHelper',
            'recoveryInstaller', 'recoveryHelper'
        )
        $encodedPaths = ([string]$PinnedFilePathsBase64).Split(',')
        if ($encodedPaths.Count -ne $pinNames.Count) { throw 'invalid pinned path map' }
        $pinnedFiles = [ordered]@{}
        for ($pinIndex = 0; $pinIndex -lt $pinNames.Count; $pinIndex++) {
            $pathBytes = [Convert]::FromBase64String($encodedPaths[$pinIndex])
            $pinnedFiles[$pinNames[$pinIndex]] = [Text.UTF8Encoding]::new($false, $true).GetString($pathBytes)
        }

        $corePair = [ordered]@{}
        foreach ($role in @('programFiles', 'service')) {
            $entry = $receipt.corePair.$role
            $corePair[$role] = [ordered]@{
                path = [string]$entry.path
                pathPin = [string]$entry.pathPin
                backup = [string]$entry.backup
                backupPathPin = [string]$entry.backupPathPin
                backupRoot = [string]$entry.backupRoot
                backupSddl = [string]$entry.backupSddl
                backupDirectorySddl = [string]$entry.backupDirectorySddl
                sha256 = [string]$entry.sha256
                sddl = [string]$entry.sddl
                acl = [ordered]@{ Sddl = [string]$entry.sddl }
            }
        }
        $capture = [ordered]@{
            targetIdentity = [string]$receipt.targetIdentity
            capturedAtUtc = [string]$receipt.capturedAtUtc
            coreShouldBeRunning = [bool]$receipt.coreShouldBeRunning
            idleObservation = $receipt.idleObservation
            pinnedFiles = $pinnedFiles
            corePair = $corePair
        }
        $request = [ordered]@{
            Capture = $capture
            ExpectedTargetIdentity = [string]$ExpectedTargetIdentity
            ExpectedPins = $receipt.expectedPins
            PackageRoot = [string]$PackageRoot
        }
        if ($HasExpectedStageRoot) { $request.ExpectedStageRoot = [string]$ExpectedStageRoot }
        if ($HasExpectedPackageManifestSha256) { $request.ExpectedPackageManifestSha256 = [string]$ExpectedPackageManifestSha256 }
        if ($Mode -eq 'Plan') {
            $request.CaptureDirectory = [string]$CaptureDirectory
            $request.ReceiptPath = [string]$PlanReceiptPath
        }
    }
    if ($SyntheticSerializationDelaySeconds -gt 0 -and -not $SyntheticRequest) {
        throw 'serialization delay requires a synthetic request'
    }
    if ($SyntheticExitBeforeWriterPidWrite -and -not $SyntheticRequest) {
        throw 'writer PID interruption requires a synthetic request'
    }

    $stage = 'request-serialize'
    $requestJson = ConvertTo-Json -InputObject $request -Depth 16 -Compress -ErrorAction Stop
    Write-CvrPackageWriterMarker 'after-request-serialize'
    $stage = 'parent-json-parse'
    Write-CvrPackageWriterMarker 'before-parent-json-parse'
    $parsedRequest = ConvertFrom-Json -InputObject $requestJson -ErrorAction Stop
    if ($parsedRequest -isnot [PSCustomObject]) { throw 'invalid request round-trip' }
    Write-CvrPackageWriterMarker 'after-parent-json-parse'

    $requestBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($requestJson)
    $powershell51 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $commandLineParts = @(
        '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'RemoteSigned',
        '-File', (Quote-CvrPackageWriterWorkerArgument $WriterScriptPath),
        '-Mode', (Quote-CvrPackageWriterWorkerArgument $Mode)
    )
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $powershell51
    $startInfo.Arguments = $commandLineParts -join ' '
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.StandardOutputEncoding = [Text.UTF8Encoding]::new($false, $true)
    $startInfo.StandardErrorEncoding = [Text.UTF8Encoding]::new($false, $true)

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    $stage = 'process-start'
    Write-CvrPackageWriterMarker ('before-' + $stage)
    if (-not $process.Start()) { throw 'writer start failed' }
    $started = $true
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    if ($SyntheticExitBeforeWriterPidWrite) {
        $stage = 'writer-pid'
        Write-CvrPackageWriterMarker 'before-writer-pid'
        $readyPath = Join-Path ([IO.Path]::GetDirectoryName($WriterScriptPath)) 'synthetic-writer-ready.txt'
        $readyDeadline = [DateTime]::UtcNow.AddSeconds(5)
        while (-not (Test-Path -LiteralPath $readyPath -PathType Leaf) -and [DateTime]::UtcNow -lt $readyDeadline) { Start-Sleep -Milliseconds 10 }
        if (-not (Test-Path -LiteralPath $readyPath -PathType Leaf)) { throw 'Synthetic writer start handshake timed out.' }
        [Environment]::Exit(86)
    }
    $writerPidRecord = [string]$process.Id + '|' + [string]$process.StartTime.ToUniversalTime().Ticks
    [IO.File]::WriteAllText($writerPidPath, $writerPidRecord, [Text.UTF8Encoding]::new($false))
    Write-CvrPackageWriterMarker ('after-' + $stage)

    $stage = 'stdin-write'
    Write-CvrPackageWriterMarker ('before-' + $stage)
    $process.StandardInput.BaseStream.Write($requestBytes, 0, $requestBytes.Length)
    Write-CvrPackageWriterMarker ('after-' + $stage)

    $stage = 'stdin-flush'
    Write-CvrPackageWriterMarker ('before-' + $stage)
    $process.StandardInput.BaseStream.Flush()
    Write-CvrPackageWriterMarker ('after-' + $stage)

    $stage = 'stdin-close'
    Write-CvrPackageWriterMarker ('before-' + $stage)
    $process.StandardInput.Close()
    Write-CvrPackageWriterMarker ('after-' + $stage)

    $stage = 'process-wait'
    Write-CvrPackageWriterMarker ('before-' + $stage)
    $process.WaitForExit()
    $childStopped = [bool]$process.HasExited
    Write-CvrPackageWriterMarker ('after-' + $stage)

    $stage = 'stdout-read'
    Write-CvrPackageWriterMarker ('before-' + $stage)
    $writerStdOut = $stdoutTask.GetAwaiter().GetResult()
    Write-CvrPackageWriterMarker ('after-' + $stage)

    $stage = 'stderr-read'
    Write-CvrPackageWriterMarker ('before-' + $stage)
    $writerStdErr = $stderrTask.GetAwaiter().GetResult()
    if ($writerStdOut.Length -gt 65536 -or $writerStdErr.Length -gt 65536) {
        throw 'writer output limit'
    }
    $workerState = 'completed'
    $workerExitCode = [int]$process.ExitCode
    $stage = 'complete'
    Write-CvrPackageWriterMarker ('complete exit=' + $workerExitCode)
    Save-CvrPackageWriterResult -State $workerState -ResultStage $stage -ExitCode $workerExitCode -Stopped $childStopped -StandardOutput $writerStdOut -StandardError $writerStdErr
} catch {
    $failedStage = $stage
    Write-CvrPackageWriterMarker 'before-cleanup'
    if ($started -and $process) {
        try {
            if (-not $process.HasExited) {
                $process.Kill()
                $null = $process.WaitForExit(1000)
            }
            $childStopped = [bool]$process.HasExited
        } catch {
            $childStopped = $false
        }
    }
    Write-CvrPackageWriterMarker 'before-cleanup-output'
    foreach ($task in @($stdoutTask, $stderrTask)) {
        if ($task -and -not $task.IsCompleted) {
            try { $null = $task.Wait(1000) } catch {}
        }
    }
    if ($stdoutTask -and $stdoutTask.IsCompleted) {
        try { $writerStdOut = $stdoutTask.GetAwaiter().GetResult() } catch {}
    }
    if ($stderrTask -and $stderrTask.IsCompleted) {
        try { $writerStdErr = $stderrTask.GetAwaiter().GetResult() } catch {}
    }
    if ($writerStdOut.Length -gt 65536) { $writerStdOut = '' }
    if ($writerStdErr.Length -gt 65536) { $writerStdErr = '' }
    Write-CvrPackageWriterMarker 'after-cleanup-output'
    Write-CvrPackageWriterMarker ('after-cleanup child-stopped=' + $childStopped)
    $workerExitCode = if ($started -and $process -and $process.HasExited) { [int]$process.ExitCode } else { -1 }
    try {
        Save-CvrPackageWriterResult -State 'failure' -ResultStage $failedStage -ExitCode $workerExitCode -Stopped $childStopped -StandardOutput $writerStdOut -StandardError $writerStdErr
    } catch {}
} finally {
    if ($process) { $process.Dispose() }
}
if ($workerState -eq 'completed') { exit 0 }
exit 1
