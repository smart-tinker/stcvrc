function Stop-StcvrcSshFixtureProcess {
    param([Parameter(Mandatory)]$Fixture, [int]$TimeoutSeconds = 5)
    if ($Fixture.Process -and -not $Fixture.Process.HasExited) {
        Stop-Process -Id $Fixture.Process.Id -Force -ErrorAction SilentlyContinue
        try { Wait-Process -Id $Fixture.Process.Id -Timeout $TimeoutSeconds -ErrorAction SilentlyContinue } catch {}
    }
    $Fixture.Process.Refresh()
    return [pscustomobject]@{
        ProcessId = [int]$Fixture.Process.Id
        ProcessExited = [bool]$Fixture.Process.HasExited
        ExitCode = if ($Fixture.Process.HasExited) { [int]$Fixture.Process.ExitCode } else { $null }
    }
}

function Remove-StcvrcSshFixture {
    param([Parameter(Mandatory)]$Fixture, [int]$TimeoutSeconds = 5)
    $root = [IO.Path]::GetFullPath([string]$Fixture.Root)
    $temp = [IO.Path]::GetFullPath([string]$env:RUNNER_TEMP)
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetDirectoryName($root), $temp) -or
        [IO.Path]::GetFileName($root) -notmatch '^stcvrc-ssh-fixture-[0-9a-f]{32}$') {
        throw 'SSH fixture cleanup rejected an out-of-scope root (stage=validate-root).'
    }
    if (Test-Path -LiteralPath $root -PathType Container) {
        $rootItem = Get-Item -LiteralPath $root -Force -ErrorAction Stop
        if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'SSH fixture cleanup rejected a reparse-point root (stage=validate-root).'
        }
    }
    $process = Stop-StcvrcSshFixtureProcess -Fixture $Fixture -TimeoutSeconds $TimeoutSeconds
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop
    return [pscustomobject]@{
        ProcessId = $process.ProcessId
        ProcessExited = $process.ProcessExited
        ExitCode = $process.ExitCode
        ExecutableRemoved = -not (Test-Path -LiteralPath (Join-Path $root 'ssh-fixture.exe') -PathType Leaf)
        DirectoryRemoved = -not (Test-Path -LiteralPath $root -PathType Container)
        DeleteAttempts = 1
    }
}