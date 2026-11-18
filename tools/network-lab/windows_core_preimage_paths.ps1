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
