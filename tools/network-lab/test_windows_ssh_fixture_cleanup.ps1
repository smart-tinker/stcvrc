$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:GITHUB_REPOSITORY -ne 'smart-tinker/stcvrc' -or -not $env:RUNNER_TEMP) {
    throw 'SSH fixture cleanup checks require the disposable public GitHub runner.'
}
. (Join-Path $PSScriptRoot 'windows_ssh_fixture_cleanup.ps1')
$powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
function New-SshFixtureTestRoot {
    $path = Join-Path $env:RUNNER_TEMP ('stcvrc-ssh-fixture-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $path | Out-Null
    [IO.File]::WriteAllText((Join-Path $path 'ssh-fixture.exe'), 'synthetic fixture')
    return $path
}
function Assert-SshFixtureRemoved {
    param($Result, [string]$Root, $Process)
    $Process.Refresh()
    if (-not $Process.HasExited -or -not $Result.ProcessExited -or -not $Result.ExecutableRemoved -or -not $Result.DirectoryRemoved -or
        (Test-Path -LiteralPath (Join-Path $Root 'ssh-fixture.exe')) -or (Test-Path -LiteralPath $Root)) {
        throw 'SSH fixture cleanup did not prove process exit and executable/directory removal.'
    }
}
$positiveRoot = $null
$positiveProcess = $null
$lockedRoot = $null
$lockedProcess = $null
$lock = $null
try {
    $positiveRoot = New-SshFixtureTestRoot
    $positiveProcess = Start-Process -FilePath $powershell -ArgumentList @('-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 30') -PassThru
    $positive = Remove-StcvrcSshFixture -Fixture ([pscustomobject]@{ Root=$positiveRoot; Process=$positiveProcess }) -TimeoutSeconds 5
    Assert-SshFixtureRemoved -Result $positive -Root $positiveRoot -Process $positiveProcess
    Write-Host "SSH fixture cleanup positive: process_exited=true executable_removed=true directory_removed=true pid=$($positive.ProcessId) exit_code=$($positive.ExitCode)"

    $lockedRoot = New-SshFixtureTestRoot
    $lockedProcess = Start-Process -FilePath $powershell -ArgumentList @('-NoProfile','-NonInteractive','-Command','exit 0') -PassThru
    if (-not $lockedProcess.WaitForExit(10000)) { throw 'Synthetic exited-process setup exceeded its deadline.' }
    $lockPath = Join-Path $lockedRoot 'ssh-fixture.exe'
    $lock = [IO.File]::Open($lockPath, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $cleanupError = $null
    $errorType = 'none'
    try {
        [void](Remove-StcvrcSshFixture -Fixture ([pscustomobject]@{ Root=$lockedRoot; Process=$lockedProcess }) -TimeoutSeconds 2)
    } catch {
        $cleanupError = [string]$_.Exception.Message
        $errorType = $_.Exception.GetType().Name
    }
    $diagnosticPattern = 'stage=remove-directory process_exited=true pid=\d+ exit_code=0 attempts=[2-9]\d* error_type=[A-Za-z]+Exception error_hresult=0x[0-9a-f]{8} executable_exists=true directory_exists=true timeout_seconds=2'
    $safeFields = @()
    foreach ($name in @('stage','process_exited','pid','exit_code','attempts','error_type','error_hresult','executable_exists','directory_exists','timeout_seconds')) {
        $field = [regex]::Match([string]$cleanupError, "(?:^|[ (])$name=([A-Za-z0-9_.-]+)")
        $value = if ($field.Success) { $field.Groups[1].Value } else { 'missing' }
        $safeFields += "$name=$value"
    }
    $runnerPathPresent = $false
    if ($cleanupError) { $runnerPathPresent = $cleanupError.IndexOf($lockedRoot, [StringComparison]::OrdinalIgnoreCase) -ge 0 }
    if (-not $cleanupError -or $cleanupError -notmatch $diagnosticPattern -or $runnerPathPresent) {
        $safeDiagnostic = $safeFields -join ' '
        throw "SSH fixture lock regression failed: expected bounded redacted process/handle evidence; fields=$safeDiagnostic runner_path_present=$($runnerPathPresent.ToString().ToLowerInvariant()) observed_error_type=$errorType elapsed_ms=$($watch.ElapsedMilliseconds)."
    }
    if (-not (Test-Path -LiteralPath $lockPath -PathType Leaf) -or -not (Test-Path -LiteralPath $lockedRoot -PathType Container)) {
        throw 'SSH fixture lock failure did not preserve the locked executable and directory.'
    }
    if ($watch.ElapsedMilliseconds -gt 6000) { throw 'SSH fixture lock failure exceeded its bounded cleanup deadline.' }
    Write-Host "SSH fixture cleanup lock negative: bounded=true process_exited=true evidence=stage/remove-directory error_type=$errorType"
    $lock.Dispose()
    $lock = $null
    $retry = Remove-StcvrcSshFixture -Fixture ([pscustomobject]@{ Root=$lockedRoot; Process=$lockedProcess }) -TimeoutSeconds 5
    Assert-SshFixtureRemoved -Result $retry -Root $lockedRoot -Process $lockedProcess
    Write-Host 'SSH fixture cleanup lock release: executable_removed=true directory_removed=true'
} finally {
    if ($lock) { $lock.Dispose() }
    foreach ($process in @($positiveProcess,$lockedProcess)) {
        if ($process) {
            try {
                $process.Refresh()
                if (-not $process.HasExited) { $process.Kill(); [void]$process.WaitForExit(5000) }
            } catch {}
        }
    }
    foreach ($root in @($positiveRoot,$lockedRoot)) {
        if ($root -and (Test-Path -LiteralPath $root -PathType Container)) {
            Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop
        }
    }
}
