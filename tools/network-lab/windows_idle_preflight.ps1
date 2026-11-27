[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PlanPath,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedPlanSha256,
    [Parameter(Mandatory = $true)][string]$ExpectedStageRoot,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedPackageManifestSha256,
    [ValidateRange(1, 300)][int]$TimeoutSeconds = 30,
    [ValidateRange(0, 10)][int]$SyntheticTestDelaySeconds = 0,
    [switch]$Worker
)

$ErrorActionPreference = 'Stop'

function Get-CvrPreflightSha256([byte[]]$Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Get-CvrPreflightExceptionType($Record) {
    $name = $Record.Exception.GetBaseException().GetType().Name
    if ($name -match '^[A-Za-z][A-Za-z0-9]{0,63}(Exception|Error)$') { return $name }
    return 'Exception'
}

function Assert-CvrPreflightPlanPath([string]$Path, [string]$Root) {
    if (-not [IO.Path]::IsPathRooted($Path) -or -not [IO.Path]::IsPathRooted($Root)) { throw 'path' }
    $fullPath = [IO.Path]::GetFullPath($Path)
    $local = [IO.Path]::GetFullPath((Join-Path ([IO.Path]::GetFullPath($Root)) 'local'))
    $directory = [IO.Path]::GetDirectoryName($fullPath)
    if ([IO.Path]::GetDirectoryName($directory) -ine $local -or
        [IO.Path]::GetFileName($directory) -notmatch '^prepared-idle-[0-9a-f]{32}$' -or
        [IO.Path]::GetFileName($fullPath) -cne 'plan.json') { throw 'path' }
    return $fullPath
}

function Convert-CvrPreflightCoreEntry([object]$Entry) {
    if ($Entry -isnot [PSCustomObject]) { throw 'core entry' }
    foreach ($name in @('path','pathPin','backup','backupPathPin','backupRoot','backupSddl','backupDirectorySddl','sha256','sddl')) {
        if (-not $Entry.PSObject.Properties[$name] -or $Entry.$name -isnot [string]) { throw 'core entry' }
    }
    return [PSCustomObject]@{
        path = [string]$Entry.path; pathPin = [string]$Entry.pathPin
        backup = [string]$Entry.backup; backupPathPin = [string]$Entry.backupPathPin
        backupRoot = [string]$Entry.backupRoot; backupSddl = [string]$Entry.backupSddl
        backupDirectorySddl = [string]$Entry.backupDirectorySddl; sha256 = [string]$Entry.sha256
        sddl = [string]$Entry.sddl; acl = [PSCustomObject]@{ Sddl = [string]$Entry.sddl }
    }
}

function Invoke-CvrIdlePreflightWorker {
    $stage = 'load-helpers'
    $binding = $null
    try {
        . (Join-Path $PSScriptRoot 'windows_core_preimage_paths.ps1')
        . (Join-Path $PSScriptRoot 'windows_idle_baseline_guard.ps1')
        . (Join-Path $PSScriptRoot 'windows_idle_transaction.ps1')

        $root = [IO.Path]::GetFullPath($ExpectedStageRoot)
        $stage = 'package-stage'
        $binding = Get-CvrIdlePackageStageBinding -StageRoot $root -ExpectedStageRoot $root -ExpectedPackageManifestSha256 $ExpectedPackageManifestSha256
        $null = Assert-CvrIdleCaptureAcl -Path $root -Directory
        $local = [IO.Path]::GetFullPath((Join-Path $root 'local'))
        $null = Assert-CvrIdleCaptureAcl -Path $local -Directory

        $stage = 'plan'
        $planPath = Assert-CvrPreflightPlanPath -Path $PlanPath -Root $root
        $planDirectory = [IO.Path]::GetDirectoryName($planPath)
        $null = Assert-CvrIdleCaptureAcl -Path $planDirectory -Directory
        $null = Assert-CvrIdleCaptureAcl -Path $planPath
        if ((Get-Item -LiteralPath $planPath -Force).Length -gt 1048576) { throw 'plan size' }
        $planBytes = [IO.File]::ReadAllBytes($planPath)
        if ((Get-CvrPreflightSha256 -Bytes $planBytes) -ine $ExpectedPlanSha256) { throw 'plan pin' }
        $plan = ConvertFrom-Json -InputObject ([Text.UTF8Encoding]::new($false, $true).GetString($planBytes)) -ErrorAction Stop
        if ($plan -isnot [PSCustomObject] -or
            $plan.packageStageBinding -isnot [PSCustomObject] -or
            [IO.Path]::GetFullPath([string]$plan.packageStageBinding.stageRoot) -ine $root -or
            [string]$plan.packageStageBinding.sourceManifestSha256 -ine $ExpectedPackageManifestSha256 -or
            [string]::IsNullOrWhiteSpace([string]$plan.targetIdentity) -or
            $plan.coreShouldBeRunning -isnot [bool] -or $plan.coreShouldBeRunning) {
            throw 'plan binding'
        }
        if ($plan.expectedPins -isnot [PSCustomObject] -or @($plan.expectedPins.PSObject.Properties).Count -ne 9 -or
            $plan.pinnedFiles -isnot [PSCustomObject] -or @($plan.pinnedFiles.PSObject.Properties).Count -ne 9 -or
            $plan.idleObservation -isnot [PSCustomObject] -or
            $plan.corePair -isnot [PSCustomObject] -or
            -not $plan.corePair.programFiles -or -not $plan.corePair.service) { throw 'plan shape' }

        $stage = 'capture-receipt'
        $captureDirectory = [IO.Path]::GetFullPath([string]$plan.captureDirectory)
        $receiptPath = [IO.Path]::GetFullPath([string]$plan.captureReceiptPath)
        if ([IO.Path]::GetDirectoryName($captureDirectory) -ine $local -or
            [IO.Path]::GetFileName($captureDirectory) -notmatch '^capture-idle-[0-9a-f]{32}$' -or
            $receiptPath -ine [IO.Path]::GetFullPath((Join-Path $captureDirectory 'capture.json')) -or
            [string]$plan.captureReceiptSha256 -notmatch '^[0-9a-fA-F]{64}$') { throw 'capture path' }
        $null = Assert-CvrIdleCaptureAcl -Path $captureDirectory -Directory
        $null = Assert-CvrIdleCaptureAcl -Path $receiptPath
        if ((Get-Item -LiteralPath $receiptPath -Force).Length -gt 1048576) { throw 'receipt size' }
        $receiptBytes = [IO.File]::ReadAllBytes($receiptPath)
        if ((Get-CvrPreflightSha256 -Bytes $receiptBytes) -ine [string]$plan.captureReceiptSha256) { throw 'receipt pin' }
        $receipt = ConvertFrom-Json -InputObject ([Text.UTF8Encoding]::new($false, $true).GetString($receiptBytes)) -ErrorAction Stop
        if ($receipt -isnot [PSCustomObject] -or
            [string]$receipt.targetIdentity -cne [string]$plan.targetIdentity -or
            [string]$receipt.capturedAtUtc -cne [string]$plan.capturedAtUtc -or
            $receipt.coreShouldBeRunning -isnot [bool] -or $receipt.coreShouldBeRunning -cne $plan.coreShouldBeRunning -or
            $receipt.packageStageBinding -isnot [PSCustomObject] -or
            [IO.Path]::GetFullPath([string]$receipt.packageStageBinding.stageRoot) -ine $root -or
            [string]$receipt.packageStageBinding.sourceManifestSha256 -ine $ExpectedPackageManifestSha256) { throw 'receipt binding' }

        $stage = 'normalize-capture'
        $pins = [ordered]@{}
        foreach ($property in @($plan.expectedPins.PSObject.Properties)) {
            if ($property.Value -isnot [string]) { throw 'pins' }
            $pins[[string]$property.Name] = [string]$property.Value
        }
        $files = [ordered]@{}
        foreach ($property in @($plan.pinnedFiles.PSObject.Properties)) {
            if ($property.Value -isnot [string]) { throw 'pin paths' }
            $files[[string]$property.Name] = [string]$property.Value
        }
        $observation = [ordered]@{}
        foreach ($property in @($plan.idleObservation.PSObject.Properties)) {
            $observation[[string]$property.Name] = $property.Value
        }
        $capture = [PSCustomObject]@{
            targetIdentity = [string]$plan.targetIdentity
            capturedAtUtc = [DateTime]::Parse([string]$plan.capturedAtUtc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind)
            coreShouldBeRunning = [bool]$plan.coreShouldBeRunning
            idleObservation = $observation
            pinnedFiles = $files
            corePair = [ordered]@{
                programFiles = Convert-CvrPreflightCoreEntry $plan.corePair.programFiles
                service = Convert-CvrPreflightCoreEntry $plan.corePair.service
            }
        }

        $stage = 'idle-baseline'
        $valid = Assert-CvrIdleTargetCapture -Capture $capture -ExpectedTargetIdentity ([string]$plan.targetIdentity) -ExpectedPins $pins
        if ($valid -isnot [bool] -or -not $valid) { throw 'idle baseline' }
        if ($SyntheticTestDelaySeconds -gt 0) {
            if ([string]$plan.targetIdentity -cne 'stcvrc-ci-synthetic-preflight') { throw 'synthetic delay' }
            $stage = 'synthetic-delay'
            Start-Sleep -Seconds $SyntheticTestDelaySeconds
        }
    } catch {
        $failureType = Get-CvrPreflightExceptionType $_
    } finally {
        if ($binding) {
            foreach ($handle in @($binding.OpenFiles)) {
                if ($handle) { try { $handle.Dispose() } catch {} }
            }
        }
    }
    if ($failureType) {
        [Console]::Error.WriteLine(('stage=' + $stage + ' type=' + $failureType))
        return 1
    }
    [Console]::Out.WriteLine('stage=complete')
    return 0
}

function Write-CvrIdlePreflightReceipt([string]$Directory, [object]$Receipt) {
    $path = Join-Path $Directory 'result.json'
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-Json -InputObject $Receipt -Depth 4 -Compress -ErrorAction Stop))
    if ($bytes.Length -gt 4096) { throw 'result size' }
    $stream = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $stream.Dispose()
    $null = Set-CvrIdleCaptureAcl -Path $path
    $stream = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush() }
    finally { $stream.Dispose() }
}

function Quote-CvrPreflightArgument([string]$Value) {
    if ($Value.Contains('"')) { throw 'Unsafe Preflight argument.' }
    return '"' + $Value + '"'
}

function Invoke-CvrIdlePreflightParent {
    . (Join-Path $PSScriptRoot 'windows_core_preimage_paths.ps1')
    . (Join-Path $PSScriptRoot 'windows_idle_baseline_guard.ps1')
    . (Join-Path $PSScriptRoot 'windows_idle_transaction.ps1')
    try {
        if (-not [IO.Path]::IsPathRooted($ExpectedStageRoot)) { throw 'stage path' }
        $root = [IO.Path]::GetFullPath($ExpectedStageRoot)
        $null = Assert-CvrIdleCaptureAcl -Path $root -Directory
        $local = [IO.Path]::GetFullPath((Join-Path $root 'local'))
        $null = Assert-CvrIdleCaptureAcl -Path $local -Directory
        $manifestPath = Join-Path $root 'source-manifest.json'
        $null = Assert-CvrIdleCaptureAcl -Path $manifestPath
        if ((Get-Item -LiteralPath $manifestPath -Force).Length -gt 4194304 -or
            (Get-CvrPreflightSha256 -Bytes ([IO.File]::ReadAllBytes($manifestPath))) -ine $ExpectedPackageManifestSha256) {
            throw 'manifest pin'
        }
        $safePlanPath = Assert-CvrPreflightPlanPath -Path $PlanPath -Root $root
    } catch {
        $type = Get-CvrPreflightExceptionType $_
        [Console]::Error.WriteLine(('Idle Preflight rejected before result (stage=trusted-input type=' + $type + ').'))
        return 1
    }

    $receiptId = [Guid]::NewGuid().ToString('N')
    $directory = Join-Path $local ('preflight-idle-' + $receiptId)
    try {
        if (Test-Path -LiteralPath $directory) { throw 'exists' }
        $null = New-Item -ItemType Directory -Path $directory -ErrorAction Stop
        $null = Set-CvrIdleCaptureAcl -Path $directory -Directory
    } catch {
        [Console]::Error.WriteLine('Idle Preflight could not create a protected result directory.')
        return 1
    }

    $process = $null
    $timedOut = $false
    $childStopped = $null
    $childExitCode = $null
    $stage = 'start-worker'
    $errorType = $null
    $parentExitCode = 1
    try {
        $powershell51 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $parts = @(
            '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'RemoteSigned',
            '-File', (Quote-CvrPreflightArgument $PSCommandPath), '-Worker',
            '-PlanPath', (Quote-CvrPreflightArgument $safePlanPath),
            '-ExpectedPlanSha256', (Quote-CvrPreflightArgument $ExpectedPlanSha256),
            '-ExpectedStageRoot', (Quote-CvrPreflightArgument $root),
            '-ExpectedPackageManifestSha256', (Quote-CvrPreflightArgument $ExpectedPackageManifestSha256),
            '-TimeoutSeconds', [string]$TimeoutSeconds,
            '-SyntheticTestDelaySeconds', [string]$SyntheticTestDelaySeconds
        )
        $info = New-Object System.Diagnostics.ProcessStartInfo
        $info.FileName = $powershell51
        $info.Arguments = $parts -join ' '
        $info.WorkingDirectory = [IO.Path]::GetTempPath()
        $info.UseShellExecute = $false
        $info.CreateNoWindow = $true
        $info.RedirectStandardOutput = $true
        $info.RedirectStandardError = $true
        $info.StandardOutputEncoding = [Text.UTF8Encoding]::new($false, $true)
        $info.StandardErrorEncoding = [Text.UTF8Encoding]::new($false, $true)
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $info
        if (-not $process.Start()) { throw 'worker start' }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $timedOut = $true
            try { if (-not $process.HasExited) { $process.Kill(); $null = $process.WaitForExit(5000) } } catch {}
        }
        $childStopped = [bool]$process.HasExited
        if ($childStopped) { try { $childExitCode = [int]$process.ExitCode } catch {} }

        $stdout = ''
        $stderr = ''
        if ($childStopped) {
            try {
                if ($stdoutTask.Wait(5000) -and $stderrTask.Wait(5000)) {
                    $stdout = $stdoutTask.GetAwaiter().GetResult()
                    $stderr = $stderrTask.GetAwaiter().GetResult()
                }
            } catch {}
        }
        if ($timedOut) {
            $stage = 'worker-timeout'
        } elseif ($childStopped -and $childExitCode -eq 0 -and $stdout.Length -le 4096 -and
            $stderr.Length -eq 0 -and $stdout.Trim() -ceq 'stage=complete') {
            $stage = 'complete'
            $parentExitCode = 0
        } elseif ($stderr.Trim() -match '^stage=([a-z-]+) type=([A-Za-z0-9]+Exception)$') {
            $stage = $Matches[1]
            $errorType = $Matches[2]
        } else {
            $stage = 'worker-failed'
            $errorType = if ($childStopped) { 'InvalidOperationException' } else { 'TimeoutException' }
        }
    } catch {
        $errorType = Get-CvrPreflightExceptionType $_
    } finally {
        if ($process) { $process.Dispose() }
    }

    $result = if ($timedOut) { 'TIMEOUT' } elseif ($parentExitCode -eq 0) { 'PASS' } else { 'FAIL' }
    $parentExitCode = if ($timedOut) { 124 } elseif ($result -ceq 'PASS') { 0 } else { 1 }
    $record = [ordered]@{
        schemaVersion = 1
        receiptId = $receiptId
        result = $result
        exitCode = [int]$parentExitCode
        childExitCode = $childExitCode
        timedOut = [bool]$timedOut
        childStopped = $childStopped
        stage = $stage
        errorType = $errorType
        planSha256 = $ExpectedPlanSha256.ToLowerInvariant()
        sourceManifestSha256 = $ExpectedPackageManifestSha256.ToLowerInvariant()
        completedAtUtc = [DateTime]::UtcNow.ToString('o')
    }
    try {
        Write-CvrIdlePreflightReceipt -Directory $directory -Receipt $record
    } catch {
        [Console]::Error.WriteLine('Idle Preflight could not persist its result; outcome is UNKNOWN.')
        return 1
    }
    [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
    [Console]::Out.WriteLine((ConvertTo-Json -InputObject $record -Depth 4 -Compress -ErrorAction Stop))
    return [int]$parentExitCode
}

if ($Worker) { exit (Invoke-CvrIdlePreflightWorker) }
exit (Invoke-CvrIdlePreflightParent)
