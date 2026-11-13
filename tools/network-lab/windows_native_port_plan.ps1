function Get-StcvrcNativePortPlan {
    param([Parameter(Mandatory)][string]$Path)

    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        $plan = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop
    } else {
        $ports = [Collections.Generic.List[int]]::new()
        while ($ports.Count -lt 3) {
            $probe = [Net.Sockets.UdpClient]::new(
                [Net.IPEndPoint]::new([Net.IPAddress]::Loopback, 0)
            )
            try {
                $port = [int]([Net.IPEndPoint]$probe.Client.LocalEndPoint).Port
            } finally {
                $probe.Dispose()
            }
            if (-not $ports.Contains($port)) { $ports.Add($port) }
        }

        $plan = [ordered]@{
            schemaVersion = 1
            coreDnsPort = $ports[0]
            profileDnsPort = $ports[1]
            appDnsPort = $ports[2]
        }
        $parent = Split-Path -Parent $Path
        if ($parent -and -not (Test-Path -LiteralPath $parent -PathType Container)) {
            New-Item -ItemType Directory -Path $parent -Force | Out-Null
        }
        [IO.File]::WriteAllText(
            $Path,
            (ConvertTo-Json -InputObject $plan -Compress),
            [Text.UTF8Encoding]::new($false)
        )
    }

    $ports = @([int]$plan.coreDnsPort, [int]$plan.profileDnsPort, [int]$plan.appDnsPort)
    if ([int]$plan.schemaVersion -ne 1 -or
        @($ports | Where-Object { $_ -lt 1 -or $_ -gt 65535 }).Count -gt 0 -or
        @($ports | Sort-Object -Unique).Count -ne 3) {
        throw 'The persisted native DNS port plan is invalid.'
    }
    return [PSCustomObject]@{
        schemaVersion = 1
        coreDnsPort = $ports[0]
        profileDnsPort = $ports[1]
        appDnsPort = $ports[2]
    }
}
