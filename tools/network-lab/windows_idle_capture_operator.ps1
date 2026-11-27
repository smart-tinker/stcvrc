[CmdletBinding()]
param(
    [string]$StageRoot,
    [string]$ExpectedPackageManifestSha256,
    [string]$RequestPath,
    [ValidateRange(1, 300)][int]$TimeoutSeconds = 30
)

$ErrorActionPreference = 'Stop'

function Get-CvrIdleOperatorAccountSid([string]$Account) {
    $name = $Account.Trim()
    if ($name -match '^(?i:LocalSystem|SYSTEM|NT AUTHORITY\\SYSTEM)$') { return 'S-1-5-18' }
    if ($name -match '^(?i:NT AUTHORITY\\LOCAL SERVICE|LOCAL SERVICE)$') { return 'S-1-5-19' }
    if ($name -match '^(?i:NT AUTHORITY\\NETWORK SERVICE|NETWORK SERVICE)$') { return 'S-1-5-20' }
    try {
        return ([Security.Principal.NTAccount]::new($name)).Translate([Security.Principal.SecurityIdentifier]).Value
    } catch {
        throw 'CVR_CAPTURE_UNKNOWN:service-owner'
    }
}

function Get-CvrIdleOperatorProcessOwnerSid([object]$ProcessRecord) {
    try {
        $owner = Invoke-CimMethod -InputObject $ProcessRecord -MethodName GetOwnerSid -ErrorAction Stop
        if ($null -eq $owner -or [int]$owner.ReturnValue -ne 0 -or
            [string]$owner.Sid -notmatch '^S-\d(-\d+)+$') {
            throw 'owner'
        }
        return [string]$owner.Sid
    } catch {
        throw 'CVR_CAPTURE_UNKNOWN:ownership'
    }
}

function Get-CvrIdleOperatorWindowsSnapshot {
    param([Parameter(Mandatory = $true)][object]$Request)

    $startedAtUtc = [DateTime]::UtcNow
    try {
        $ownerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $sessionId = [Diagnostics.Process]::GetCurrentProcess().SessionId
        $serviceRecords = @(Get-CimInstance -ClassName Win32_Service -Filter "Name='clash_verge_service'" -ErrorAction Stop)
        if ($serviceRecords.Count -ne 1) { throw 'service' }
        $service = $serviceRecords[0]
        $servicePid = [int]$service.ProcessId
        $servicePathMatch = [regex]::Match([string]$service.PathName, '^\s*(?:"([^"]+)"|(\S+))')
        if ($servicePid -le 0 -or -not $servicePathMatch.Success) { throw 'service' }
        $serviceImagePath = if ($servicePathMatch.Groups[1].Success) { $servicePathMatch.Groups[1].Value } else { $servicePathMatch.Groups[2].Value }
        $serviceAccountSid = Get-CvrIdleOperatorAccountSid -Account ([string]$service.StartName)
        $serviceController = Get-Service -Name 'clash_verge_service' -ErrorAction Stop
        $processRows = @(Get-CimInstance -ClassName Win32_Process -Property @('Name','ExecutablePath','ProcessId','ParentProcessId','SessionId') -ErrorAction Stop)
        $guiPath = [string]$Request.Capture.pinnedFiles.gui258
        $guiName = [IO.Path]::GetFileName($guiPath)
        $serviceName = [IO.Path]::GetFileName([string]$Request.Capture.pinnedFiles.serviceExe258)
        if ($guiName -notmatch '^[A-Za-z0-9_. -]{1,120}\.exe$' -or
            $serviceName -notmatch '^[A-Za-z0-9_. -]{1,120}\.exe$') { throw 'CVR_CAPTURE_UNKNOWN:input' }
        $processes = @()
        foreach ($process in @($processRows | Where-Object {
            [int]$_.ProcessId -eq $servicePid -or
            [string]$_.Name -ieq $serviceName -or
            [string]$_.Name -ieq 'clash-verge-service.exe' -or
            [string]$_.Name -ieq $guiName -or
            [string]$_.Name -ieq 'verge-mihomo.exe' -or
            [string]$_.Name -ieq 'verge-mihomo-alpha.exe'
        })) {
            $processes += [PSCustomObject]@{
                ProcessId = [int]$process.ProcessId
                ParentProcessId = [int]$process.ParentProcessId
                SessionId = [int]$process.SessionId
                Name = [string]$process.Name
                ImagePath = [string]$process.ExecutablePath
                OwnerSid = (Get-CvrIdleOperatorProcessOwnerSid -ProcessRecord $process)
            }
        }
        $tcpOwnerProcessIds = @(
            Get-NetTCPConnection -State Listen -ErrorAction Stop |
                ForEach-Object { [int]$_.OwningProcess }
        )
        $udpOwnerProcessIds = @(
            Get-NetUDPEndpoint -ErrorAction Stop |
                ForEach-Object { [int]$_.OwningProcess }
        )
        return [PSCustomObject]@{
            StartedAtUtc = $startedAtUtc
            SampledAtUtc = [DateTime]::UtcNow
            CurrentOwnerSid = [string]$ownerSid
            CurrentSessionId = [int]$sessionId
            Service = [PSCustomObject]@{
                Name = [string]$service.Name
                State = [string]$service.State
                ProcessId = $servicePid
                ImagePath = [string]$serviceImagePath
                AccountSid = [string]$serviceAccountSid
                ControllerState = [string]$serviceController.Status
            }
            Processes = @($processes)
            TcpOwnerProcessIds = [int[]]$tcpOwnerProcessIds
            UdpOwnerProcessIds = [int[]]$udpOwnerProcessIds
        }
    } catch {
        if ($_.Exception.Message -match '^CVR_CAPTURE_UNKNOWN:[a-z-]+$') { throw }
        throw 'CVR_CAPTURE_UNKNOWN:unavailable'
    }
}

function ConvertTo-CvrIdleOperatorObservation {
    param(
        [Parameter(Mandatory = $true)][object]$Snapshot,
        [Parameter(Mandatory = $true)][object]$Request
    )

    $observer = $Request.Observer
    $expectedOwnerSid = [string]$observer.ExpectedOwnerSid
    $expectedServiceSid = [string]$observer.ExpectedServiceAccountSid
    $expectedSession = [int]$observer.ExpectedSessionId
    if ($Snapshot.CurrentOwnerSid -cne $expectedOwnerSid -or
        [int]$Snapshot.CurrentSessionId -ne $expectedSession) {
        throw 'CVR_CAPTURE_UNKNOWN:ownership'
    }
    if ($Snapshot.SampledAtUtc -isnot [DateTime] -or
        $Snapshot.SampledAtUtc.Kind -ne [DateTimeKind]::Utc) {
        throw 'CVR_CAPTURE_UNKNOWN:stale'
    }
    $age = [DateTime]::UtcNow - $Snapshot.SampledAtUtc
    if ($age.TotalSeconds -lt 0 -or $age.TotalMinutes -gt 5) {
        throw 'CVR_CAPTURE_UNKNOWN:stale'
    }

    $capture = $Request.Capture
    $pins = $Request.ExpectedPins
    $service = $Snapshot.Service
    if ([string]$service.Name -cne 'clash_verge_service' -or
        [string]$service.State -cne 'Running' -or
        [string]$service.ControllerState -cne 'Running' -or
        [int]$service.ProcessId -le 0 -or
        [string]$service.AccountSid -cne $expectedServiceSid) {
        throw 'CVR_CAPTURE_UNKNOWN:service'
    }
    $expectedServiceExe = [IO.Path]::GetFullPath([string]$capture.pinnedFiles.serviceExe258)
    if ([IO.Path]::GetFullPath([string]$service.ImagePath) -ine $expectedServiceExe) {
        throw 'CVR_CAPTURE_UNKNOWN:service-image'
    }

    $expectedServiceName = [IO.Path]::GetFileName($expectedServiceExe)
    if ($expectedServiceName -ine 'clash-verge-service.exe') { throw 'CVR_CAPTURE_UNKNOWN:service-image' }
    $serviceProcesses = @($Snapshot.Processes | Where-Object {
        [string]$_.Name -ieq $expectedServiceName -or [string]$_.Name -ieq 'clash-verge-service.exe'
    })
    if ($serviceProcesses.Count -eq 0) { throw 'CVR_CAPTURE_UNKNOWN:service-pid' }
    foreach ($serviceProcess in $serviceProcesses) {
        if ([string]::IsNullOrWhiteSpace([string]$serviceProcess.ImagePath) -or
            [IO.Path]::GetFullPath([string]$serviceProcess.ImagePath) -ine $expectedServiceExe -or
            [string]$serviceProcess.OwnerSid -cne $expectedServiceSid -or
            [int]$serviceProcess.SessionId -ne 0) {
            throw 'CVR_CAPTURE_UNKNOWN:service-pid'
        }
    }
    if ($serviceProcesses.Count -ne 1 -or [int]$serviceProcesses[0].ProcessId -ne [int]$service.ProcessId) {
        throw 'CVR_CAPTURE_UNKNOWN:service-pid'
    }
    $serviceProcess = $serviceProcesses[0]

    $expectedGui = [IO.Path]::GetFullPath([string]$capture.pinnedFiles.gui258)
    $expectedGuiName = [IO.Path]::GetFileName($expectedGui)
    $expectedCorePaths = @(
        [IO.Path]::GetFullPath([string]$capture.corePair.programFiles.path),
        [IO.Path]::GetFullPath([string]$capture.corePair.service.path)
    )
    $guiIds = [Collections.Generic.List[int]]::new()
    $coreIds = [Collections.Generic.List[int]]::new()
    foreach ($process in @($Snapshot.Processes)) {
        if ([string]$process.Name -ieq $expectedGuiName) {
            if ([IO.Path]::GetFullPath([string]$process.ImagePath) -ine $expectedGui -or
                [string]$process.OwnerSid -cne $expectedOwnerSid -or
                [int]$process.SessionId -ne $expectedSession) {
                throw 'CVR_CAPTURE_UNKNOWN:ownership'
            }
            $guiIds.Add([int]$process.ProcessId)
        } elseif ([string]$process.Name -ieq 'verge-mihomo.exe') {
            $imagePath = [IO.Path]::GetFullPath([string]$process.ImagePath)
            $imageMatches = @($expectedCorePaths | Where-Object { $_ -ieq $imagePath }).Count -gt 0
            $interactiveOwner = [string]$process.OwnerSid -ceq $expectedOwnerSid -and [int]$process.SessionId -eq $expectedSession
            $serviceChild = [string]$process.OwnerSid -ceq $expectedServiceSid -and
                [int]$process.SessionId -eq 0 -and [int]$process.ParentProcessId -eq [int]$service.ProcessId
            if (-not $imageMatches -or (-not $interactiveOwner -and -not $serviceChild)) {
                throw 'CVR_CAPTURE_UNKNOWN:ownership'
            }
            $coreIds.Add([int]$process.ProcessId)
        } elseif ([string]$process.Name -ieq 'verge-mihomo-alpha.exe') {
            if ([string]::IsNullOrWhiteSpace([string]$process.ImagePath)) {
                throw 'CVR_CAPTURE_UNKNOWN:ownership'
            }
            $alphaImagePath = [IO.Path]::GetFullPath([string]$process.ImagePath)
            $interactiveOwner = [string]$process.OwnerSid -ceq $expectedOwnerSid -and [int]$process.SessionId -eq $expectedSession
            $serviceChild = [string]$process.OwnerSid -ceq $expectedServiceSid -and
                [int]$process.SessionId -eq 0 -and [int]$process.ParentProcessId -eq [int]$service.ProcessId
            if ([IO.Path]::GetFileName($alphaImagePath) -ine 'verge-mihomo-alpha.exe' -or
                (-not $interactiveOwner -and -not $serviceChild)) {
                throw 'CVR_CAPTURE_UNKNOWN:ownership'
            }
            $coreIds.Add([int]$process.ProcessId)
        }
    }

    $targetPids = [Collections.Generic.HashSet[int]]::new()
    $null = $targetPids.Add([int]$service.ProcessId)
    foreach ($id in $guiIds) { $null = $targetPids.Add([int]$id) }
    foreach ($id in $coreIds) { $null = $targetPids.Add([int]$id) }
    $listenerIds = [Collections.Generic.HashSet[int]]::new()
    foreach ($id in @($Snapshot.TcpOwnerProcessIds) + @($Snapshot.UdpOwnerProcessIds)) {
        $ownerPid = [int]$id
        if ($ownerPid -le 0) { throw 'CVR_CAPTURE_UNKNOWN:listener' }
        if ($targetPids.Contains($ownerPid)) { $null = $listenerIds.Add($ownerPid) }
    }
    $controllerPids = [Collections.Generic.HashSet[int]]::new()
    foreach ($id in $guiIds) { $null = $controllerPids.Add([int]$id) }
    foreach ($id in $coreIds) { $null = $controllerPids.Add([int]$id) }
    $controllerListening = $false
    foreach ($id in $listenerIds) {
        if ($controllerPids.Contains([int]$id)) { $controllerListening = $true }
    }

    $programFilesPath = [string]$capture.corePair.programFiles.path
    $serviceCorePath = [string]$capture.corePair.service.path
    try {
        $programFilesSha = (Get-FileHash -LiteralPath $programFilesPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        $serviceCoreSha = (Get-FileHash -LiteralPath $serviceCorePath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    } catch {
        throw 'CVR_CAPTURE_UNKNOWN:pin-drift'
    }
    if ($programFilesSha -ine [string]$pins.programFilesCore -or
        $serviceCoreSha -ine [string]$pins.serviceCore) {
        throw 'CVR_CAPTURE_UNKNOWN:pin-drift'
    }

    return [ordered]@{
        CoreShouldBeRunning = [bool]$false
        OwnedGuiProcessIds = [int[]]@($guiIds.ToArray())
        OwnedCoreProcessIds = [int[]]@($coreIds.ToArray())
        ControllerListening = [bool]$controllerListening
        OwnedListenerProcessIds = [int[]]@($listenerIds | Sort-Object)
        ServiceStatus = 'Running'
        ExpectedProgramFilesCoreSha256 = [string]$pins.programFilesCore
        ObservedProgramFilesCoreSha256 = [string]$programFilesSha
        ExpectedServiceCoreSha256 = [string]$pins.serviceCore
        ObservedServiceCoreSha256 = [string]$serviceCoreSha
    }
}

function Get-CvrIdleOperatorFreshObservation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$Capture,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$ExpectedPins
    )

    $observer = $Capture.rollbackState.observer
    $request = [PSCustomObject]@{
        Capture = $Capture
        ExpectedPins = $ExpectedPins
        Observer = [PSCustomObject]@{
            ExpectedOwnerSid = [string]$observer.ownerSid
            ExpectedSessionId = [int]$observer.sessionId
            ExpectedServiceAccountSid = [string]$observer.serviceAccountSid
        }
    }
    $snapshot = Get-CvrIdleOperatorWindowsSnapshot -Request $request
    $observation = ConvertTo-CvrIdleOperatorObservation -Snapshot $snapshot -Request $request
    return [PSCustomObject]@{
        SampledAtUtc = $snapshot.SampledAtUtc
        Observation = $observation
        Observer = [PSCustomObject]@{
            ownerSid = [string]$snapshot.CurrentOwnerSid
            sessionId = [int]$snapshot.CurrentSessionId
            serviceAccountSid = [string]$snapshot.Service.AccountSid
            serviceProcessId = [int]$snapshot.Service.ProcessId
        }
    }
}

function Quote-CvrIdleOperatorArgument([string]$Value) {
    if ($Value.Contains('"')) { throw 'CVR_CAPTURE_UNKNOWN:argument' }
    return '"' + $Value + '"'
}

function Stop-CvrIdleOperatorProcessTree([Diagnostics.Process]$Process) {
    if ($Process.HasExited) { return $true }
    try { $Process.Kill() } catch {}
    try { if ($Process.WaitForExit(5000)) { return $true } } catch {}
    $killer = $null
    try {
        $info = New-Object Diagnostics.ProcessStartInfo
        $info.FileName = Join-Path $env:SystemRoot 'System32\taskkill.exe'
        $info.Arguments = '/PID ' + [string]$Process.Id + ' /T /F'
        $info.UseShellExecute = $false
        $info.CreateNoWindow = $true
        $info.RedirectStandardOutput = $true
        $info.RedirectStandardError = $true
        $killer = New-Object Diagnostics.Process
        $killer.StartInfo = $info
        if ($killer.Start() -and $killer.WaitForExit(5000)) {
            $null = $Process.WaitForExit(5000)
        }
    } catch {
    } finally {
        if ($killer) { $killer.Dispose() }
    }
    return $Process.HasExited
}

function Invoke-CvrIdleOperatorChild {
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [object]$Request,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory
    )
    $powershell51 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $parts = @('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','RemoteSigned','-File',
        (Quote-CvrIdleOperatorArgument $ScriptPath))
    foreach ($argument in $Arguments) {
        $parts += Quote-CvrIdleOperatorArgument ([string]$argument)
    }
    $requestBytes = $null
    if ($null -ne $Request) {
        $json = ConvertTo-Json -InputObject $Request -Depth 16 -Compress -ErrorAction Stop
        $requestBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($json)
        if ($requestBytes.Length -gt 1048576) { throw 'CVR_CAPTURE_UNKNOWN:input' }
    }
    $startInfo = New-Object Diagnostics.ProcessStartInfo
    $startInfo.FileName = $powershell51
    $startInfo.Arguments = $parts -join ' '
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = ($null -ne $requestBytes)
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.StandardOutputEncoding = [Text.UTF8Encoding]::new($false, $true)
    $startInfo.StandardErrorEncoding = [Text.UTF8Encoding]::new($false, $true)
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $startInfo
    $started = $false
    $stdoutTask = $null
    $stderrTask = $null
    $stdinTask = $null
    try {
        if (-not $process.Start()) { throw 'CVR_CAPTURE_UNKNOWN:child-start' }
        $started = $true
        $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if ($null -ne $requestBytes) {
            $stdinTask = $process.StandardInput.BaseStream.WriteAsync($requestBytes, 0, $requestBytes.Length)
            $remaining = [int][Math]::Max(1, ($deadline - [DateTime]::UtcNow).TotalMilliseconds)
            if (-not $stdinTask.Wait($remaining)) { throw 'CVR_CAPTURE_UNKNOWN:child-timeout' }
            $stdinTask.GetAwaiter().GetResult()
            $process.StandardInput.Close()
        }
        $remaining = [int][Math]::Max(1, ($deadline - [DateTime]::UtcNow).TotalMilliseconds)
        if (-not $process.WaitForExit($remaining)) { throw 'CVR_CAPTURE_UNKNOWN:child-timeout' }
        $remaining = [int][Math]::Max(1, ($deadline - [DateTime]::UtcNow).TotalMilliseconds)
        if (-not $stdoutTask.Wait($remaining) -or -not $stderrTask.Wait($remaining)) {
            throw 'CVR_CAPTURE_UNKNOWN:child-output-timeout'
        }
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ($stdout.Length -gt 4096 -or $stderr.Length -gt 4096) { throw 'CVR_CAPTURE_UNKNOWN:child-output-limit' }
        return [PSCustomObject]@{
            ExitCode = [int]$process.ExitCode
            StdOut = [string]$stdout
            StdErr = [string]$stderr
            ChildStopped = [bool]$process.HasExited
        }
    } finally {
        if ($started -and -not $process.HasExited) {
            if (-not (Stop-CvrIdleOperatorProcessTree -Process $process)) {
                throw 'CVR_CAPTURE_UNKNOWN:child-stop'
            }
        }
        foreach ($task in @($stdinTask,$stdoutTask,$stderrTask)) {
            if ($task -and -not $task.IsCompleted) {
                try { $null = $task.Wait(5000) } catch {}
            }
        }
        $process.Dispose()
    }
}

function New-CvrIdleOperatorOutcome {
    param(
        [string]$Status,
        [string]$Reason,
        [string]$Result = 'UNKNOWN',
        [int]$ExitCode = 2,
        [object]$TimedOut,
        [object]$ChildStopped,
        [object]$ChildExitCode,
        [string]$ReceiptId,
        [string]$PlanSha256,
        [string]$SourceManifestSha256
    )
    $value = [ordered]@{
        status = $Status
        reason = $Reason
        result = $Result
        exitCode = $ExitCode
    }
    if ($null -ne $TimedOut) { $value.timedOut = [bool]$TimedOut }
    if ($null -ne $ChildStopped) { $value.childStopped = [bool]$ChildStopped }
    if ($null -ne $ChildExitCode) { $value.childExitCode = [int]$ChildExitCode }
    if ($ReceiptId) { $value.receiptId = $ReceiptId }
    if ($PlanSha256) { $value.planSha256 = $PlanSha256 }
    if ($SourceManifestSha256) { $value.sourceManifestSha256 = $SourceManifestSha256 }
    return [PSCustomObject]$value
}

function Invoke-CvrIdleCaptureOperator {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$StageRoot,
        [Parameter(Mandatory = $true)][string]$ExpectedPackageManifestSha256,
        [Parameter(Mandatory = $true)][string]$RequestPath,
        [ValidateRange(1,300)][int]$TimeoutSeconds = 30
    )

    $stage = 'stage'
    $binding = $null
    $manifestHandle = $null
    $seedHandle = $null
    $scriptLocks = [Collections.Generic.List[IO.FileStream]]::new()
    try {
        if ($ExpectedPackageManifestSha256 -notmatch '^[0-9a-fA-F]{64}$') {
            return [PSCustomObject]@{ Public = (New-CvrIdleOperatorOutcome -Status 'INCOMPLETE' -Reason 'stage-pin') }
        }
        $root = [IO.Path]::GetFullPath($StageRoot)
        $operatorDirectory = [IO.Path]::GetFullPath((Join-Path $root 'tools\network-lab'))
        if ([IO.Path]::GetFullPath($PSScriptRoot) -ine $operatorDirectory) {
            return [PSCustomObject]@{ Public = (New-CvrIdleOperatorOutcome -Status 'INCOMPLETE' -Reason 'stage-path') }
        }
        $rootItem = Get-Item -LiteralPath $root -Force -ErrorAction Stop
        $operatorDirectoryItem = Get-Item -LiteralPath $operatorDirectory -Force -ErrorAction Stop
        if (-not $rootItem.PSIsContainer -or -not $operatorDirectoryItem.PSIsContainer -or
            (([int]$rootItem.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0) -or
            (([int]$operatorDirectoryItem.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0)) {
            return [PSCustomObject]@{ Public = (New-CvrIdleOperatorOutcome -Status 'INCOMPLETE' -Reason 'stage-path') }
        }
        $manifestPath = Join-Path $root 'source-manifest.json'
        $manifestItem = Get-Item -LiteralPath $manifestPath -Force -ErrorAction Stop
        if ($manifestItem.PSIsContainer -or
            (([int]$manifestItem.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0)) {
            return [PSCustomObject]@{ Public = (New-CvrIdleOperatorOutcome -Status 'INCOMPLETE' -Reason 'stage-manifest') }
        }
        $manifestHandle = [IO.File]::Open($manifestPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        if ($manifestHandle.Length -gt 1048576) { return [PSCustomObject]@{ Public = (New-CvrIdleOperatorOutcome -Status 'INCOMPLETE' -Reason 'stage-manifest') } }
        $manifestMemory = [IO.MemoryStream]::new()
        try { $manifestHandle.CopyTo($manifestMemory); $manifestBytes = $manifestMemory.ToArray() }
        finally { $manifestMemory.Dispose() }
        $manifestHasher = [Security.Cryptography.SHA256]::Create()
        try { $manifestSha = ([BitConverter]::ToString($manifestHasher.ComputeHash($manifestBytes))).Replace('-', '').ToLowerInvariant() }
        finally { $manifestHasher.Dispose() }
        if ($manifestSha -ine $ExpectedPackageManifestSha256.ToLowerInvariant()) {
            return [PSCustomObject]@{ Public = (New-CvrIdleOperatorOutcome -Status 'INCOMPLETE' -Reason 'stage-pin') }
        }
        $manifest = ConvertFrom-Json -InputObject ([Text.UTF8Encoding]::new($false, $true).GetString($manifestBytes)) -ErrorAction Stop
        $manifestIndex = @{}
        foreach ($entry in @($manifest.files)) { $manifestIndex[[string]$entry.path] = [string]$entry.sha256 }
        $required = @(
            'tools/network-lab/windows_idle_capture_operator.ps1',
            'tools/network-lab/windows_core_preimage_paths.ps1',
            'tools/network-lab/windows_idle_baseline_guard.ps1',
            'tools/network-lab/windows_idle_transaction.ps1',
            'tools/network-lab/windows_legacy_state_transaction.ps1',
            'tools/network-lab/windows_idle_preflight_package_writer.ps1',
            'tools/network-lab/windows_idle_preflight.ps1'
        )
        foreach ($name in $required) {
            if (-not $manifestIndex.ContainsKey($name) -or
                $manifestIndex[$name] -notmatch '^[0-9a-fA-F]{64}$') {
                return [PSCustomObject]@{ Public = (New-CvrIdleOperatorOutcome -Status 'INCOMPLETE' -Reason 'stage-file') }
            }
            $path = Join-Path $root ($name.Replace('/', '\'))
            $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
            if ($item.PSIsContainer -or (([int]$item.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0)) {
                return [PSCustomObject]@{ Public = (New-CvrIdleOperatorOutcome -Status 'INCOMPLETE' -Reason 'stage-file') }
            }
            $locked = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
            $null = $scriptLocks.Add($locked)
            $hasher = [Security.Cryptography.SHA256]::Create()
            try { $actualSha = ([BitConverter]::ToString($hasher.ComputeHash($locked))).Replace('-', '').ToLowerInvariant() }
            finally { $hasher.Dispose() }
            if ($actualSha -ine $manifestIndex[$name]) {
                return [PSCustomObject]@{ Public = (New-CvrIdleOperatorOutcome -Status 'INCOMPLETE' -Reason 'stage-file') }
            }
        }
        . (Join-Path $root 'tools\network-lab\windows_core_preimage_paths.ps1')
        . (Join-Path $root 'tools\network-lab\windows_idle_baseline_guard.ps1')
        . (Join-Path $root 'tools\network-lab\windows_legacy_state_transaction.ps1')
        . (Join-Path $root 'tools\network-lab\windows_idle_transaction.ps1')
        $null = Assert-CvrIdleCaptureAcl -Path $root -Directory
        $stage = 'binding'
        $binding = Get-CvrIdlePackageStageBinding -StageRoot $root -ExpectedStageRoot $root -ExpectedPackageManifestSha256 $ExpectedPackageManifestSha256
        $local = [IO.Path]::GetFullPath((Join-Path $root 'local'))
        $null = Assert-CvrIdleCaptureAcl -Path $local -Directory
        $requestFullPath = [IO.Path]::GetFullPath($RequestPath)
        if ([IO.Path]::GetDirectoryName($requestFullPath) -ine $local -or
            [IO.Path]::GetFileName($requestFullPath) -cne 'capture-seed.json') {
            return [PSCustomObject]@{ Public = (New-CvrIdleOperatorOutcome -Status 'INCOMPLETE' -Reason 'seed-path') }
        }
        $requestItem = Get-Item -LiteralPath $requestFullPath -Force -ErrorAction Stop
        if ($requestItem.PSIsContainer -or
            (([int]$requestItem.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0) -or
            $requestItem.Length -gt 1048576) {
            return [PSCustomObject]@{ Public = (New-CvrIdleOperatorOutcome -Status 'INCOMPLETE' -Reason 'seed-file') }
        }
        $null = Assert-CvrIdleCaptureAcl -Path $requestFullPath
        $seedHandle = [IO.File]::Open($requestFullPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        if ($seedHandle.Length -gt 1048576) { return [PSCustomObject]@{ Public = (New-CvrIdleOperatorOutcome -Status 'INCOMPLETE' -Reason 'seed-file') } }
        $seedMemory = [IO.MemoryStream]::new()
        try { $seedHandle.CopyTo($seedMemory); $seedBytes = $seedMemory.ToArray() }
        finally { $seedMemory.Dispose() }
        $requestText = [Text.UTF8Encoding]::new($false, $true).GetString($seedBytes)
        $request = ConvertFrom-Json -InputObject $requestText -ErrorAction Stop
        if ($request -isnot [PSCustomObject] -or
            $request.Capture -isnot [PSCustomObject] -or
            $request.Capture.pinnedFiles -isnot [PSCustomObject] -or
            $request.ExpectedPins -isnot [PSCustomObject] -or
            $request.Observer -isnot [PSCustomObject] -or
            [string]::IsNullOrWhiteSpace([string]$request.ExpectedTargetIdentity)) {
            return [PSCustomObject]@{ Public = (New-CvrIdleOperatorOutcome -Status 'INCOMPLETE' -Reason 'seed-shape') }
        }
        if ($request.Capture.PSObject.Properties['capturedAtUtc'] -or
            $request.Capture.PSObject.Properties['idleObservation'] -or
            $request.Capture.PSObject.Properties['rollbackState']) {
            return [PSCustomObject]@{ Public = (New-CvrIdleOperatorOutcome -Status 'INCOMPLETE' -Reason 'stale-seed') }
        }
        $payloadPins = [ordered]@{
            candidateCore = 'payload/verge-mihomo.exe'
            updateInstaller = 'payload/Clash.Verge_2.5.10_x64-setup.exe'
            updateHelper = 'payload/cvr-2.5.10/clash-verge-service-install.exe'
            recoveryInstaller = 'payload/Clash.Verge_2.5.8_x64-setup.exe'
            recoveryHelper = 'payload/cvr-2.5.8/clash-verge-service-install.exe'
        }
        foreach ($name in $payloadPins.Keys) {
            $archivePath = [string]$payloadPins[$name]
            $expectedSha = [string]$manifestIndex[$archivePath]
            $shaProperty = $request.ExpectedPins.PSObject.Properties[$name]
            $pathProperty = $request.Capture.pinnedFiles.PSObject.Properties[$name]
            if (-not $manifestIndex.ContainsKey($archivePath) -or
                $expectedSha -notmatch '^[0-9a-fA-F]{64}$' -or
                $null -eq $shaProperty -or $null -eq $pathProperty -or
                [string]$shaProperty.Value -notmatch '^[0-9a-fA-F]{64}$' -or
                [string]$shaProperty.Value -ine $expectedSha) {
                return [PSCustomObject]@{ Public = (New-CvrIdleOperatorOutcome -Status 'INCOMPLETE' -Reason 'stage-pin') }
            }
            try {
                $stagePayloadPath = [IO.Path]::GetFullPath((Join-Path $root ($archivePath.Replace('/', '\'))))
                $seedPayloadPath = [IO.Path]::GetFullPath([string]$pathProperty.Value)
            } catch {
                return [PSCustomObject]@{ Public = (New-CvrIdleOperatorOutcome -Status 'INCOMPLETE' -Reason 'stage-pin') }
            }
            if ($seedPayloadPath -ine $stagePayloadPath) {
                return [PSCustomObject]@{ Public = (New-CvrIdleOperatorOutcome -Status 'INCOMPLETE' -Reason 'stage-pin') }
            }
        }
        if (@($request.Observer.PSObject.Properties).Count -ne 3 -or
            [string]$request.Observer.ExpectedOwnerSid -notmatch '^S-\d(-\d+)+$' -or
            [int]$request.Observer.ExpectedSessionId -lt 0 -or
            [string]$request.Observer.ExpectedServiceAccountSid -notmatch '^S-\d(-\d+)+$') {
            return [PSCustomObject]@{ Public = (New-CvrIdleOperatorOutcome -Status 'INCOMPLETE' -Reason 'observer-pin') }
        }
        $stage = 'observe'
        try {
            $snapshot = Get-CvrIdleOperatorWindowsSnapshot -Request $request
            $observation = ConvertTo-CvrIdleOperatorObservation -Snapshot $snapshot -Request $request
        } catch {
            $reason = 'unknown-observation'
            if ($_.Exception.Message -match '^CVR_CAPTURE_UNKNOWN:([a-z-]+)$') {
                $reason = 'unknown-' + $Matches[1]
            }
            return [PSCustomObject]@{ Public = (New-CvrIdleOperatorOutcome -Status 'INCOMPLETE' -Reason $reason) }
        }

        $pins = [ordered]@{}
        foreach ($property in @($request.ExpectedPins.PSObject.Properties)) { $pins[[string]$property.Name] = [string]$property.Value }
        $capture = $request.Capture
        $pinnedFiles = [ordered]@{}
        foreach ($property in @($capture.pinnedFiles.PSObject.Properties)) { $pinnedFiles[[string]$property.Name] = [string]$property.Value }
        $capture.pinnedFiles = $pinnedFiles
        $null = $capture | Add-Member -MemberType NoteProperty -Name idleObservation -Value $observation
        $null = $capture | Add-Member -MemberType NoteProperty -Name capturedAtUtc -Value ([DateTime]$snapshot.SampledAtUtc)
        $stage = 'capture-guard'
        try {
            $null = Assert-CvrIdleBaseline @observation
        } catch {
            return [PSCustomObject]@{ Public = (New-CvrIdleOperatorOutcome -Status 'REFUSED' -Reason 'not-idle') }
        }
        try {
            $installDirectory = [IO.Path]::GetFullPath([IO.Path]::GetDirectoryName([string]$capture.pinnedFiles.gui258))
            $programData = [IO.Path]::GetFullPath([string]$env:ProgramData)
            $serviceDataDirectory = [IO.Path]::GetFullPath((Join-Path $programData 'clash-verge-service'))
            $ExpectedServiceExecutableDirectory = [IO.Path]::GetFullPath((Join-Path $serviceDataDirectory 'bin'))
            if ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath([string]$capture.pinnedFiles.serviceExe258)) -ine $ExpectedServiceExecutableDirectory) {
                throw 'rollback service executable directory'
            }
            foreach ($directory in @($programData,$serviceDataDirectory,$ExpectedServiceExecutableDirectory)) {
                $directoryItem = Get-Item -LiteralPath $directory -Force -ErrorAction Stop
                if (-not $directoryItem.PSIsContainer -or
                    (([int]$directoryItem.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0)) {
                    throw 'rollback service executable reparse path'
                }
            }
            $legacySnapshot = Get-CvrLegacyState
            $legacyState = [ordered]@{
                files = @($legacySnapshot.files | ForEach-Object {
                    [ordered]@{ path=[string]$_.path; present=[bool]$_.present; bytes=$_.bytes; sddl=$_.sddl }
                })
                registry = @($legacySnapshot.registry | ForEach-Object {
                    [ordered]@{ hive=[string]$_.hive; name=[string]$_.name; present=[bool]$_.present; kind=$_.kind; data=$_.data }
                })
            }
            $rollbackState = [ordered]@{
                schemaVersion = 1
                installDirectory = $installDirectory
                gui = Save-CvrIdleFilePreimageBackup -Root $local -Role 'gui' -SourcePath ([string]$capture.pinnedFiles.gui258) -ExpectedDirectory $installDirectory -ExpectedSha256 ([string]$pins.gui258)
                serviceExe = Save-CvrIdleFilePreimageBackup -Root $local -Role 'service-exe' -SourcePath ([string]$capture.pinnedFiles.serviceExe258) -ExpectedDirectory $ExpectedServiceExecutableDirectory -ExpectedSha256 ([string]$pins.serviceExe258)
                legacyState = $legacyState
                observer = [ordered]@{
                    ownerSid = [string]$request.Observer.ExpectedOwnerSid
                    sessionId = [int]$request.Observer.ExpectedSessionId
                    serviceAccountSid = [string]$request.Observer.ExpectedServiceAccountSid
                    serviceProcessId = [int]$snapshot.Service.ProcessId
                }
            }
            $null = $capture | Add-Member -MemberType NoteProperty -Name 'rollbackState' -Value $rollbackState
            $null = Assert-CvrIdleTargetCapture -Capture $capture -ExpectedTargetIdentity ([string]$request.ExpectedTargetIdentity) -ExpectedPins $pins
            $null = Assert-CvrIdleRollbackState -Capture $capture -ExpectedPins $pins -ExpectedLocalRoot $local
        } catch {
            $reason = if ($_.Exception.Message -match 'pin|pinned input') { 'pin-drift' } else { 'rollback-state' }
            return [PSCustomObject]@{ Public = (New-CvrIdleOperatorOutcome -Status 'INCOMPLETE' -Reason $reason) }
        }
        $capture.capturedAtUtc = $capture.capturedAtUtc.ToString('o')
        $writerRequest = [ordered]@{
            Capture = $capture
            ExpectedTargetIdentity = [string]$request.ExpectedTargetIdentity
            ExpectedPins = $pins
            PackageRoot = $root
            ExpectedStageRoot = $root
            ExpectedPackageManifestSha256 = $ExpectedPackageManifestSha256.ToLowerInvariant()
        }
        $writer = Join-Path $root 'tools\network-lab\windows_idle_preflight_package_writer.ps1'
        $stage = 'capture'
        $captureChild = Invoke-CvrIdleOperatorChild -ScriptPath $writer -Arguments @('-Mode','Capture') -Request $writerRequest -TimeoutSeconds 60 -WorkingDirectory $root
        if ($captureChild.ExitCode -ne 0 -or -not [string]::IsNullOrEmpty($captureChild.StdErr)) {
            return [PSCustomObject]@{ Public = (New-CvrIdleOperatorOutcome -Status 'REFUSED' -Reason 'capture-rejected') }
        }
        $captureResult = ConvertFrom-Json -InputObject $captureChild.StdOut -ErrorAction Stop
        $captureDirectory = [IO.Path]::GetFullPath([string]$captureResult.CaptureDirectory)
        $receiptPath = [IO.Path]::GetFullPath([string]$captureResult.ReceiptPath)
        if ([IO.Path]::GetDirectoryName($captureDirectory) -ine $local -or
            [IO.Path]::GetFileName($captureDirectory) -notmatch '^capture-idle-[0-9a-f]{32}$' -or
            $receiptPath -ine [IO.Path]::GetFullPath((Join-Path $captureDirectory 'capture.json'))) {
            return [PSCustomObject]@{ Public = (New-CvrIdleOperatorOutcome -Status 'INCOMPLETE' -Reason 'capture-record') }
        }
        $planRequest = [ordered]@{}
        foreach ($key in $writerRequest.Keys) { $planRequest[$key] = $writerRequest[$key] }
        $planRequest.CaptureDirectory = $captureDirectory
        $planRequest.ReceiptPath = $receiptPath
        $stage = 'plan'
        $planChild = Invoke-CvrIdleOperatorChild -ScriptPath $writer -Arguments @('-Mode','Plan') -Request $planRequest -TimeoutSeconds 60 -WorkingDirectory $root
        if ($planChild.ExitCode -ne 0 -or -not [string]::IsNullOrEmpty($planChild.StdErr)) {
            return [PSCustomObject]@{ Public = (New-CvrIdleOperatorOutcome -Status 'REFUSED' -Reason 'plan-rejected') }
        }
        $planResult = ConvertFrom-Json -InputObject $planChild.StdOut -ErrorAction Stop
        $planPath = [IO.Path]::GetFullPath([string]$planResult.PlanPath)
        $planDirectory = [IO.Path]::GetDirectoryName($planPath)
        $planSha = [string]$planResult.PlanSha256
        if ([IO.Path]::GetDirectoryName($planDirectory) -ine $local -or
            [IO.Path]::GetFileName($planDirectory) -notmatch '^prepared-idle-[0-9a-f]{32}$' -or
            [IO.Path]::GetFileName($planPath) -cne 'plan.json' -or
            $planSha -notmatch '^[0-9a-f]{64}$') {
            return [PSCustomObject]@{ Public = (New-CvrIdleOperatorOutcome -Status 'INCOMPLETE' -Reason 'plan-record') }
        }

        $stage = 'preflight'
        $preflightScript = Join-Path $root 'tools\network-lab\windows_idle_preflight.ps1'
        $preflightChild = Invoke-CvrIdleOperatorChild -ScriptPath $preflightScript -Arguments @(
            '-PlanPath',$planPath,
            '-ExpectedPlanSha256',$planSha,
            '-ExpectedStageRoot',$root,
            '-ExpectedPackageManifestSha256',$ExpectedPackageManifestSha256.ToLowerInvariant(),
            '-TimeoutSeconds',[string]$TimeoutSeconds
        ) -TimeoutSeconds ($TimeoutSeconds + 60) -WorkingDirectory $root
        $preflight = $null
        try { $preflight = ConvertFrom-Json -InputObject $preflightChild.StdOut -ErrorAction Stop } catch {}
        if ($null -eq $preflight -or
            [string]$preflight.result -notin @('PASS','FAIL','TIMEOUT') -or
            [int]$preflight.exitCode -notin @(0,1,124) -or
            $preflight.timedOut -isnot [bool] -or
            $preflight.childStopped -isnot [bool] -or $preflight.childStopped -cne $true -or
            ([string]$preflight.result -ceq 'PASS' -and ([int]$preflight.exitCode -ne 0 -or $preflight.timedOut)) -or
            ([string]$preflight.result -ceq 'FAIL' -and ([int]$preflight.exitCode -ne 1 -or $preflight.timedOut)) -or
            ([string]$preflight.result -ceq 'TIMEOUT' -and ([int]$preflight.exitCode -ne 124 -or -not $preflight.timedOut)) -or
            [string]$preflight.planSha256 -ine $planSha -or
            [string]$preflight.sourceManifestSha256 -ine $ExpectedPackageManifestSha256 -or
            [string]$preflight.receiptId -notmatch '^[0-9a-f]{32}$' -or
            [string]$preflightChild.StdOut -match [regex]::Escape($root) -or
            [string]$preflightChild.StdErr -match [regex]::Escape($root)) {
            return [PSCustomObject]@{ Public = (New-CvrIdleOperatorOutcome -Status 'INCOMPLETE' -Reason 'preflight-record') }
        }
        if ([int]$preflightChild.ExitCode -ne [int]$preflight.exitCode) {
            return [PSCustomObject]@{ Public = (New-CvrIdleOperatorOutcome -Status 'INCOMPLETE' -Reason 'preflight-exit') }
        }
        $resultDirectory = Join-Path $local ('preflight-idle-' + [string]$preflight.receiptId)
        $resultPath = Join-Path $resultDirectory 'result.json'
        $null = Assert-CvrIdleCaptureAcl -Path $resultDirectory -Directory
        $null = Assert-CvrIdleCaptureAcl -Path $resultPath
        if ((Get-Item -LiteralPath $resultPath -Force -ErrorAction Stop).Length -gt 4096) {
            return [PSCustomObject]@{ Public = (New-CvrIdleOperatorOutcome -Status 'INCOMPLETE' -Reason 'preflight-size') }
        }
        $stored = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($resultPath, [Text.UTF8Encoding]::new($false, $true))) -ErrorAction Stop
        if ([string]$stored.result -cne [string]$preflight.result -or
            [int]$stored.exitCode -ne [int]$preflight.exitCode -or
            $stored.timedOut -cne $preflight.timedOut -or
            $stored.childStopped -cne $preflight.childStopped -or
            [string]$stored.childExitCode -cne [string]$preflight.childExitCode -or
            [string]$stored.planSha256 -ine $planSha -or
            [string]$stored.sourceManifestSha256 -ine $ExpectedPackageManifestSha256) {
            return [PSCustomObject]@{ Public = (New-CvrIdleOperatorOutcome -Status 'INCOMPLETE' -Reason 'preflight-receipt') }
        }
        $stage = 'post-preflight-observation'
        $freshObservation = Get-CvrIdleOperatorFreshObservation -Capture $capture -ExpectedPins $pins
        $null = Assert-CvrIdleFreshObservation -Capture $capture -Fresh $freshObservation -RequireSameServicePid
        $public = New-CvrIdleOperatorOutcome -Status 'COMPLETE' -Reason 'preflight-complete' -Result ([string]$preflight.result) -ExitCode ([int]$preflight.exitCode) -TimedOut ([bool]$preflight.timedOut) -ChildStopped ([bool]$preflight.childStopped) -ChildExitCode $preflight.childExitCode -ReceiptId ([string]$preflight.receiptId) -PlanSha256 $planSha -SourceManifestSha256 ([string]$preflight.sourceManifestSha256)
        return [PSCustomObject]@{
            Public = $public
            CaptureDirectory = $captureDirectory
            CaptureReceiptPath = $receiptPath
            PlanPath = $planPath
            PreflightReceiptPath = $resultPath
            PreflightDocument = $preflight
        }
    } catch {
        $reason = 'operator-error'
        if ($stage -eq 'observe') { $reason = 'unknown-unavailable' }
        elseif ($stage -eq 'binding') { $reason = 'stage-binding' }
        elseif ($stage -eq 'capture-guard') { $reason = 'capture-guard' }
        elseif ($stage -eq 'capture') { $reason = 'capture-failed' }
        elseif ($stage -eq 'plan') { $reason = 'plan-failed' }
        elseif ($stage -eq 'preflight') { $reason = 'preflight-unknown' }
        elseif ($stage -eq 'post-preflight-observation') { $reason = 'fresh-observation' }
        return [PSCustomObject]@{ Public = (New-CvrIdleOperatorOutcome -Status 'INCOMPLETE' -Reason $reason) }
    } finally {
        if ($binding -and $binding.OpenFiles) {
            foreach ($handle in @($binding.OpenFiles)) { if ($handle) { try { $handle.Dispose() } catch {} } }
        }
        foreach ($handle in $scriptLocks) { if ($handle) { try { $handle.Dispose() } catch {} } }
        if ($seedHandle) { try { $seedHandle.Dispose() } catch {} }
        if ($manifestHandle) { try { $manifestHandle.Dispose() } catch {} }
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    $result = Invoke-CvrIdleCaptureOperator -StageRoot $StageRoot -ExpectedPackageManifestSha256 $ExpectedPackageManifestSha256 -RequestPath $RequestPath -TimeoutSeconds $TimeoutSeconds
    [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
    [Console]::Out.WriteLine((ConvertTo-Json -InputObject $result.Public -Depth 4 -Compress -ErrorAction Stop))
    exit ([int]$result.Public.exitCode)
}
