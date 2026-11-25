function Stop-StcvrcSshFixtureProcess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Fixture,
        [ValidateRange(1,30)][int]$TimeoutSeconds = 5
    )
    if ($null -eq $Fixture.Process) { throw 'SSH fixture cleanup failed (stage=inspect-process process_exited=unknown pid=none).' }
    $process = $Fixture.Process
    $pidValue = [int]$process.Id
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $stopError = $null
    $processExited = $false
    try {
        $process.Refresh()
        if (-not $process.HasExited) {
            try { $process.Kill() } catch { $stopError = $_.Exception }
        }
        $process.Refresh()
        if (-not $process.HasExited) {
            $remaining = [int][Math]::Max(0, ($TimeoutSeconds * 1000) - [int]$watch.ElapsedMilliseconds)
            if ($remaining -gt 0) {
                try { [void]$process.WaitForExit($remaining) }
                catch { if ($null -eq $stopError) { $stopError = $_.Exception } }
            }
        }
        $process.Refresh()
        $processExited = [bool]$process.HasExited
    } catch {
        if ($null -eq $stopError) { $stopError = $_.Exception }
    }
    if (-not $processExited) {
        $errorType = if ($stopError) { $stopError.GetType().Name } else { 'TimeoutException' }
        throw "SSH fixture cleanup failed (stage=wait-process process_exited=false pid=$pidValue attempts=1 error_type=$errorType timeout_seconds=$TimeoutSeconds)."
    }
    return [pscustomobject]@{ ProcessId=$pidValue; ProcessExited=$true; ExitCode=[int]$process.ExitCode }
}

function Remove-StcvrcSshFixture {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Fixture,
        [ValidateRange(1,30)][int]$TimeoutSeconds = 5
    )
    if ([string]::IsNullOrWhiteSpace([string]$Fixture.Root) -or [string]::IsNullOrWhiteSpace([string]$env:RUNNER_TEMP)) {
        throw 'SSH fixture cleanup rejected an incomplete runner-temp binding (stage=validate-root).'
    }
    $root = [IO.Path]::GetFullPath([string]$Fixture.Root).TrimEnd([char[]]@([IO.Path]::DirectorySeparatorChar,[IO.Path]::AltDirectorySeparatorChar))
    $temp = [IO.Path]::GetFullPath([string]$env:RUNNER_TEMP).TrimEnd([char[]]@([IO.Path]::DirectorySeparatorChar,[IO.Path]::AltDirectorySeparatorChar))
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetDirectoryName($root), $temp) -or
        [IO.Path]::GetFileName($root) -notmatch '^stcvrc-ssh-fixture-[0-9a-f]{32}$') {
        throw 'SSH fixture cleanup rejected an out-of-scope root (stage=validate-root).'
    }
    if (Test-Path -LiteralPath $root) {
        $rootItem = Get-Item -LiteralPath $root -Force -ErrorAction Stop
        if (-not $rootItem.PSIsContainer -or (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw 'SSH fixture cleanup rejected a reparse-point or non-directory root (stage=validate-root).'
        }
    }
    $process = Stop-StcvrcSshFixtureProcess -Fixture $Fixture -TimeoutSeconds $TimeoutSeconds
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $attempts = 0
    $lastErrorType = 'none'
    $lastHresult = 'none'
    while ($true) {
        $attempts++
        if (Test-Path -LiteralPath $root) {
            $rootItem = Get-Item -LiteralPath $root -Force -ErrorAction Stop
            if (-not $rootItem.PSIsContainer -or (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
                throw 'SSH fixture cleanup rejected a changed root (stage=validate-root).'
            }
            try { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop }
            catch {
                $lastErrorType = $_.Exception.GetType().Name
                $lastHresult = '0x' + $_.Exception.HResult.ToString('x8')
            }
        }
        $executableExists = Test-Path -LiteralPath (Join-Path $root 'ssh-fixture.exe') -PathType Leaf
        $directoryExists = Test-Path -LiteralPath $root -PathType Container
        if (-not $executableExists -and -not $directoryExists) { break }
        $remaining = [int][Math]::Max(0, ($TimeoutSeconds * 1000) - [int]$watch.ElapsedMilliseconds)
        if ($remaining -le 0) {
            throw "SSH fixture cleanup failed (stage=remove-directory process_exited=$($process.ProcessExited.ToString().ToLowerInvariant()) pid=$($process.ProcessId) exit_code=$($process.ExitCode) attempts=$attempts error_type=$lastErrorType error_hresult=$lastHresult executable_exists=$($executableExists.ToString().ToLowerInvariant()) directory_exists=$($directoryExists.ToString().ToLowerInvariant()) timeout_seconds=$TimeoutSeconds)."
        }
        Start-Sleep -Milliseconds ([int][Math]::Min(100, $remaining))
    }
    return [pscustomobject]@{
        ProcessId = $process.ProcessId
        ProcessExited = $process.ProcessExited
        ExitCode = $process.ExitCode
        ExecutableRemoved = -not $executableExists
        DirectoryRemoved = -not $directoryExists
        DeleteAttempts = $attempts
    }
}