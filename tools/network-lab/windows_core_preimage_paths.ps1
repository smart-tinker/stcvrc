function New-CvrCorePreimageBackupPath {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][ValidatePattern('^[a-z0-9-]+$')][string]$Label
    )
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) { throw 'Core preimage backup root is missing.' }
    $directory = Join-Path $Root ("stcvrc-core-preimage-$Label-" + [Guid]::NewGuid().ToString('N'))
    if (Test-Path -LiteralPath $directory) { throw 'Refusing a preexisting core preimage directory.' }
    New-Item -ItemType Directory -Path $directory -ErrorAction Stop | Out-Null
    return (Join-Path $directory 'verge-mihomo.exe')
}

function Get-CvrStringSha256 {
    param([Parameter(Mandatory)][string]$Value)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value))).Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
}

function Get-CvrByteArraySha256 {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return [BitConverter]::ToString($sha.ComputeHash($Bytes)).Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
}

function Save-CvrCorePreimageBackup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][ValidatePattern('^[a-z0-9-]+$')][string]$Label,
        [Parameter(Mandatory = $true)][string]$SourcePath,
        [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedSha256
    )

    $sourceBytes = [IO.File]::ReadAllBytes($SourcePath)
    $sourceSha = Get-CvrByteArraySha256 -Bytes $sourceBytes
    if ($sourceSha -ine $ExpectedSha256) {
        throw "Core preimage source SHA256 changed before backup; expected=$ExpectedSha256 actual=$sourceSha."
    }

    $backupPath = [IO.Path]::GetFullPath((New-CvrCorePreimageBackupPath -Root $Root -Label $Label))
    $backupDirectory = [IO.Path]::GetDirectoryName($backupPath)
    $rootPath = [IO.Path]::GetFullPath($Root)
    $stage = 'backup directory ACL'
    $diagnostic = ''
    try {
        if ([IO.Path]::GetDirectoryName($backupDirectory) -ine $rootPath) { throw 'backup root binding mismatch' }
        $null = Set-CvrIdleCaptureAcl -Path $backupDirectory -Directory

        $stage = 'backup file creation'
        $stream = [IO.File]::Open($backupPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $stream.Dispose()
        $stage = 'backup file ACL'
        $null = Set-CvrIdleCaptureAcl -Path $backupPath

        $stage = 'backup bytes write'
        [IO.File]::WriteAllBytes($backupPath, $sourceBytes)
        $stage = 'backup SHA256'
        $backupSha = Get-CvrByteArraySha256 -Bytes ([IO.File]::ReadAllBytes($backupPath))
        if ($backupSha -ine $ExpectedSha256) {
            $diagnostic = "expected=$ExpectedSha256 actual=$backupSha"
            throw 'backup SHA256 mismatch'
        }
        $stage = 'backup ACL recording'
        $backupSddl = (Get-Acl -LiteralPath $backupPath -ErrorAction Stop).Sddl
        $backupDirectorySddl = (Get-Acl -LiteralPath $backupDirectory -ErrorAction Stop).Sddl
        return [PSCustomObject]@{
            backup = $backupPath
            backupPathPin = $backupPath
            backupRoot = $rootPath
            backupSddl = $backupSddl
            backupDirectorySddl = $backupDirectorySddl
            sha256 = $sourceSha
        }
    } catch {
        if (Test-Path -LiteralPath $backupDirectory -PathType Container) {
            Remove-Item -LiteralPath $backupDirectory -Recurse -Force -ErrorAction SilentlyContinue
        }
        $detail = if ($diagnostic) { " ($diagnostic)" } else { '' }
        throw "Core preimage backup save failed at $stage$detail."
    }
}

function Get-CvrCorePreimageBackupBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$Entry,
        [Parameter(Mandatory = $true)][ValidateSet('Program Files', 'service', '2.5.8 stock')][string]$Role
    )

    $stage = 'metadata'
    $diagnostic = ''
    try {
        foreach ($name in @('path', 'pathPin', 'backup', 'backupPathPin', 'backupRoot', 'sha256', 'sddl', 'acl', 'backupSddl', 'backupDirectorySddl')) {
            if (-not $Entry.PSObject.Properties[$name]) { throw 'required backup metadata is missing' }
        }
        $expectedSha = [string]$Entry.sha256
        if ($expectedSha -notmatch '^[0-9a-fA-F]{64}$' -or
            [string]$Entry.acl.Sddl -cne [string]$Entry.sddl) {
            throw 'preimage metadata is invalid'
        }

        $stage = 'live path pin'
        $livePath = [IO.Path]::GetFullPath([string]$Entry.path)
        $livePathPin = [IO.Path]::GetFullPath([string]$Entry.pathPin)
        if ($livePath -ine $livePathPin -or [IO.Path]::GetFileName($livePath) -cne 'verge-mihomo.exe') {
            throw 'live path pin mismatch'
        }

        $stage = 'backup path pin'
        $backupPath = [IO.Path]::GetFullPath([string]$Entry.backup)
        $backupPathPin = [IO.Path]::GetFullPath([string]$Entry.backupPathPin)
        $rootPath = [IO.Path]::GetFullPath([string]$Entry.backupRoot)
        $backupDirectory = [IO.Path]::GetDirectoryName($backupPath)
        if ($backupPath -ine $backupPathPin -or
            [IO.Path]::GetFileName($backupPath) -cne 'verge-mihomo.exe' -or
            [IO.Path]::GetDirectoryName($backupDirectory) -ine $rootPath -or
            [IO.Path]::GetFileName($backupDirectory) -notmatch '^stcvrc-core-preimage-[a-z0-9-]+-[0-9a-f]{32}$') {
            throw 'backup path is not the pinned unique preimage'
        }

        $stage = 'backup path type and reparse checks'
        $rootItem = Get-Item -LiteralPath $rootPath -Force -ErrorAction Stop
        $directoryItem = Get-Item -LiteralPath $backupDirectory -Force -ErrorAction Stop
        $backupItem = Get-Item -LiteralPath $backupPath -Force -ErrorAction Stop
        if (-not $rootItem.PSIsContainer -or -not $directoryItem.PSIsContainer -or
            $backupItem.PSIsContainer -or
            (([int]$rootItem.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0) -or
            (([int]$directoryItem.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0) -or
            (([int]$backupItem.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw 'backup path type or reparse check failed'
        }

        $stage = 'backup directory ACL'
        $actualDirectorySddl = (Get-Acl -LiteralPath $backupDirectory -ErrorAction Stop).Sddl
        $diagnostic = "directory SDDL SHA256 expected=$(Get-CvrStringSha256 -Value ([string]$Entry.backupDirectorySddl)) actual=$(Get-CvrStringSha256 -Value $actualDirectorySddl)"
        if ($actualDirectorySddl -cne [string]$Entry.backupDirectorySddl) { throw 'backup directory ACL pin mismatch' }
        $null = Assert-CvrIdleCaptureAcl -Path $backupDirectory -Directory

        $stage = 'backup file ACL'
        $actualBackupSddl = (Get-Acl -LiteralPath $backupPath -ErrorAction Stop).Sddl
        $diagnostic = "file SDDL SHA256 expected=$(Get-CvrStringSha256 -Value ([string]$Entry.backupSddl)) actual=$(Get-CvrStringSha256 -Value $actualBackupSddl)"
        if ($actualBackupSddl -cne [string]$Entry.backupSddl) { throw 'backup file ACL pin mismatch' }
        $null = Assert-CvrIdleCaptureAcl -Path $backupPath

        $stage = 'backup SHA256'
        $bytes = [IO.File]::ReadAllBytes($backupPath)
        $backupSha = Get-CvrByteArraySha256 -Bytes $bytes
        $diagnostic = "SHA256 expected=$expectedSha actual=$backupSha"
        if ($backupSha -ine $expectedSha) { throw 'backup bytes do not match the pinned preimage' }
        return ,$bytes
    } catch {
        $detail = if ($diagnostic) { " ($diagnostic)" } else { '' }
        throw "$Role core preimage backup validation failed at $stage$detail."
    }
}

function Restore-CvrCoreFilePreimage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$Entry,
        [Parameter(Mandatory = $true)][ValidateSet('Program Files', 'service')][string]$Role
    )

    $bytes = Get-CvrCorePreimageBackupBytes -Entry $Entry -Role $Role
    $stage = 'live target verification'
    $diagnostic = ''
    try {
        $livePath = [IO.Path]::GetFullPath([string]$Entry.path)
        $liveItem = Get-Item -LiteralPath $livePath -Force -ErrorAction Stop
        if (-not $liveItem -or $liveItem.PSIsContainer -or
            (([int]$liveItem.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw 'live target is not a regular pinned file'
        }

        $stage = 'live bytes write'
        [IO.File]::WriteAllBytes($livePath, [byte[]]$bytes)
        $stage = 'live ACL restore'
        Set-Acl -LiteralPath $livePath -AclObject $Entry.acl -ErrorAction Stop

        $stage = 'live SHA256 verification'
        $restoredSha = (Get-FileHash -LiteralPath $livePath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        $expectedSha = [string]$Entry.sha256
        $diagnostic = "SHA256 expected=$expectedSha actual=$restoredSha"
        if ($restoredSha -ine $expectedSha) { throw 'restored bytes do not match the pinned preimage' }

        $stage = 'live ACL verification'
        $restoredSddl = (Get-Acl -LiteralPath $livePath -ErrorAction Stop).Sddl
        $diagnostic = "SDDL SHA256 expected=$(Get-CvrStringSha256 -Value ([string]$Entry.sddl)) actual=$(Get-CvrStringSha256 -Value $restoredSddl)"
        if ($restoredSddl -cne [string]$Entry.sddl) { throw 'restored ACL does not match the pinned preimage' }
    } catch {
        $detail = if ($diagnostic) { " ($diagnostic)" } else { '' }
        throw "$Role core preimage restore failed at $stage$detail."
    }
}


function Test-CvrCorePreimageBackupPathContract {
    param([Parameter(Mandatory)][string]$Root)
    $paths = [Collections.Generic.List[string]]::new()
    $sourcePath = Join-Path $Root ("core-preimage-contract-" + [Guid]::NewGuid().ToString('N') + '.bin')
    $ownsSource = $false
    try {
        $paths.Add((New-CvrCorePreimageBackupPath -Root $Root -Label 'program-files'))
        $paths.Add((New-CvrCorePreimageBackupPath -Root $Root -Label 'service'))
        $paths.Add((New-CvrCorePreimageBackupPath -Root $Root -Label '258-stock'))
        $directories = @($paths | ForEach-Object { [IO.Path]::GetDirectoryName($_) } | Select-Object -Unique)
        $wrongNames = @($paths | Where-Object { [IO.Path]::GetFileName($_) -cne 'verge-mihomo.exe' })
        if ($directories.Count -ne $paths.Count -or $wrongNames.Count -gt 0) {
            throw 'Core preimage backup paths do not preserve helper filename and isolation.'
        }
        if (Test-Path -LiteralPath $sourcePath) { throw 'Refusing a preexisting core preimage self-check source.' }
        $ownsSource = $true
        [IO.File]::WriteAllBytes($sourcePath, [byte[]](0x53, 0x54, 0x43, 0x56, 0x52, 0x43))
        $expectedHash = (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash.ToLowerInvariant()
        foreach ($path in $paths) {
            Copy-Item -LiteralPath $sourcePath -Destination $path -ErrorAction Stop
            if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expectedHash) {
                throw 'Core preimage backup path/hash self-check failed.'
            }
        }
        Write-Host 'Core preimage backup filename, unique-directory and SHA256 self-check passed.'
    } finally {
        if ($ownsSource -and (Test-Path -LiteralPath $sourcePath)) { Remove-Item -LiteralPath $sourcePath -Force -ErrorAction Stop }
        foreach ($path in $paths) {
            $directory = [IO.Path]::GetDirectoryName($path)
            if (Test-Path -LiteralPath $directory -PathType Container) {
                Remove-Item -LiteralPath $directory -Recurse -Force -ErrorAction Stop
            }
        }
    }
}
