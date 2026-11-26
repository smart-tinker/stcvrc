function Get-StcvrcNativePortPlan {
    param([Parameter(Mandatory)][string]$Path)

    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        $plan = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop
    } else {
        $ports = [Collections.Generic.List[int]]::new()
        while ($ports.Count -lt 4) {
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
            subscriptionDnsPort = $ports[3]
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

    $ports = @([int]$plan.coreDnsPort, [int]$plan.profileDnsPort, [int]$plan.appDnsPort, [int]$plan.subscriptionDnsPort)
    if ([int]$plan.schemaVersion -ne 1 -or
        @($ports | Where-Object { $_ -lt 1 -or $_ -gt 65535 }).Count -gt 0 -or
        @($ports | Sort-Object -Unique).Count -ne 4) {
        throw 'The persisted native DNS port plan is invalid.'
    }
    return [PSCustomObject]@{
        schemaVersion = 1
        coreDnsPort = $ports[0]
        profileDnsPort = $ports[1]
        appDnsPort = $ports[2]
        subscriptionDnsPort = $ports[3]
    }
}

function Wait-StcvrcNativePortPlanReady {
    param(
        [Parameter(Mandatory)][string]$PlanPath,
        [Parameter(Mandatory)][string]$ReceiptPath,
        [Parameter(Mandatory)][System.Diagnostics.Process]$Process,
        [ValidateRange(1,60)][int]$TimeoutSeconds = 10
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $Process.Refresh()
        if ($Process.HasExited) { throw 'Native UDP fixture process exited before publishing readiness.' }
        if (Test-Path -LiteralPath $ReceiptPath -PathType Leaf) {
            $receipt = Get-Content -LiteralPath $ReceiptPath -Raw | ConvertFrom-Json -ErrorAction Stop
            if ($null -eq $receipt -or [int]$receipt.schemaVersion -ne 1) {
                throw 'Native UDP fixture readiness receipt schema is invalid.'
            }
            $plan = Get-StcvrcNativePortPlan -Path $PlanPath
            $names = @('coreDnsPort','profileDnsPort','appDnsPort','subscriptionDnsPort')
            $receiptPorts = @()
            foreach ($name in $names) {
                $rawPort = $receipt.$name
                if ($null -eq $rawPort -or [string]$rawPort -notmatch '^\d+$') {
                    throw 'Native UDP fixture readiness receipt contains an invalid endpoint.'
                }
                $port = [int]$rawPort
                if ($port -lt 1 -or $port -gt 65535 -or $port -ne [int]$plan.$name) {
                    throw 'Native UDP fixture readiness receipt does not match the persisted port plan.'
                }
                $receiptPorts += $port
            }
            if (@($receiptPorts | Sort-Object -Unique).Count -ne $names.Count) {
                throw 'Native UDP fixture readiness receipt contains duplicate endpoints.'
            }
            $Process.Refresh()
            if ($Process.HasExited) { throw 'Native UDP fixture process exited after publishing readiness.' }
            return $plan
        }
        Start-Sleep -Milliseconds 50
    }
    throw 'Native UDP fixture readiness receipt timed out.'
}
