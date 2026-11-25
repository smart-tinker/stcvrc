function Get-StcvrcWindowsCoreVersionIdentity {
    param($Build)

    $buildTimeText = ([DateTime]$Build.build_time).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss'Z'", [Globalization.CultureInfo]::InvariantCulture)
    return "Mihomo Meta $($Build.version) windows amd64 with go$($Build.go_version) $buildTimeText"
}

function Test-StcvrcWindowsCoreVersionOutput {
    param([string[]]$VersionLines, [string]$ExpectedIdentity)

    if ($null -eq $VersionLines -or $VersionLines.Count -lt 1) { return $false }
    return ([string]$VersionLines[0]) -ceq $ExpectedIdentity
}

function Assert-StcvrcWindowsCoreVersionOutputVectors {
    $build = [PSCustomObject]@{
        version = '1.19.33-STCVRC-rc.10'
        go_version = '1.26.11'
        build_time = '2026-11-25T00:00:00Z'
    }
    $expected = Get-StcvrcWindowsCoreVersionIdentity -Build $build
    $valid = @($expected, 'Use tags: with_gvisor')
    if (-not (Test-StcvrcWindowsCoreVersionOutput -VersionLines $valid -ExpectedIdentity $expected)) {
        throw 'Windows core identity rejected valid multi-line -v output.'
    }
    $wrong = @($expected.Replace('rc.10', 'rc.9'), 'Use tags: with_gvisor')
    if (Test-StcvrcWindowsCoreVersionOutput -VersionLines $wrong -ExpectedIdentity $expected) {
        throw 'Windows core identity accepted the wrong candidate version.'
    }
}
