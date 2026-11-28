$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows_core_preimage_paths.ps1')
. (Join-Path $PSScriptRoot 'windows_idle_baseline_guard.ps1')
. (Join-Path $PSScriptRoot 'windows_legacy_state_transaction.ps1')
. (Join-Path $PSScriptRoot 'windows_idle_transaction.ps1')

function Assert-PreflightTest([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function New-PreflightTestDirectory([string]$Path) {
    $null = New-Item -ItemType Directory -Path $Path -ErrorAction Stop
    $null = Set-CvrIdleCaptureAcl -Path $Path -Directory
}

function Write-PreflightTestFile([string]$Path, [byte[]]$Bytes, [switch]$Protected) {
    $null = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None).Dispose()
    if ($Protected) { $null = Set-CvrIdleCaptureAcl -Path $Path }
    [IO.File]::WriteAllBytes($Path, $Bytes)
}

function Add-PreflightTestAclDrift([string]$Path) {
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $rule = [Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),
        [Security.AccessControl.FileSystemRights]::Read,
        [Security.AccessControl.AccessControlType]::Allow
    )
    $null = $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
}

function Get-PreflightTestSnapshot([string[]]$Paths) {
    $snapshot = [ordered]@{}
    foreach ($path in $Paths) {
        $snapshot[$path] = [PSCustomObject]@{
            Sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
            Sddl = (Get-Acl -LiteralPath $path -ErrorAction Stop).Sddl
        }
    }
    return $snapshot
}

function Assert-PreflightTestSnapshot($Before, $Paths) {
    $after = Get-PreflightTestSnapshot -Paths $Paths
    foreach ($path in $Paths) {
        if ($Before[$path].Sha256 -cne $after[$path].Sha256 -or $Before[$path].Sddl -cne $after[$path].Sddl) {
            throw 'Read-only Preflight changed a pinned synthetic input.'
        }
    }
}

function Quote-PreflightTestArgument([string]$Value) {
    if ($Value.Contains('"')) { throw 'Unsafe synthetic Preflight argument.' }
    return '"' + $Value + '"'
}

function Invoke-PreflightTestCommand(
    [string]$ScriptPath,
    [string[]]$ScriptArguments,
    [string]$PlanPath,
    [string]$PlanSha256,
    [string]$StageRoot,
    [string]$ManifestSha256,
    [int]$TimeoutSeconds,
    [int]$SyntheticDelaySeconds = 0,
    [ValidateSet('Capture', 'Plan')][string]$WriterMode,
    [object]$Request
) {
    if (($WriterMode -and $null -eq $Request) -or (-not $WriterMode -and $null -ne $Request)) {
        throw 'Writer mode and JSON request must be supplied together.'
    }
    $requestBytes = $null
    if ($null -ne $Request) {
        $requestJson = ConvertTo-Json -InputObject $Request -Depth 16 -Compress -ErrorAction Stop
        $requestBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($requestJson)
        if ($requestBytes.Length -gt 1048576) { throw 'Synthetic writer request exceeded the input limit.' }
    }

    $powershell51 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $parts = @(
        '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'RemoteSigned',
        '-File', (Quote-PreflightTestArgument $ScriptPath)
    )
    if ($null -ne $ScriptArguments) {
        foreach ($argument in $ScriptArguments) {
            $parts += Quote-PreflightTestArgument ([string]$argument)
        }
    } elseif ($WriterMode) {
        $parts += @('-Mode', (Quote-PreflightTestArgument $WriterMode))
    } else {
        $parts += @(
            '-PlanPath', (Quote-PreflightTestArgument $PlanPath),
            '-ExpectedPlanSha256', (Quote-PreflightTestArgument $PlanSha256),
            '-ExpectedStageRoot', (Quote-PreflightTestArgument $StageRoot),
            '-ExpectedPackageManifestSha256', (Quote-PreflightTestArgument $ManifestSha256),
            '-TimeoutSeconds', [string]$TimeoutSeconds
        )
        if ($SyntheticDelaySeconds -gt 0) {
            $parts += @('-SyntheticTestDelaySeconds', [string]$SyntheticDelaySeconds)
        }
    }

    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $powershell51
    $startInfo.Arguments = $parts -join ' '
    $startInfo.WorkingDirectory = [IO.Path]::GetTempPath()
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = ($null -ne $requestBytes)
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.StandardOutputEncoding = [Text.UTF8Encoding]::new($false, $true)
    $startInfo.StandardErrorEncoding = [Text.UTF8Encoding]::new($false, $true)
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    $started = $false
    $stdinTask = $null
    $stdoutTask = $null
    $stderrTask = $null
    try {
        if (-not $process.Start()) { throw 'Preflight command did not start.' }
        $started = $true
        $deadline = [DateTime]::UtcNow.AddSeconds(45)
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if ($null -ne $requestBytes) {
            $stdinTask = $process.StandardInput.BaseStream.WriteAsync($requestBytes, 0, $requestBytes.Length)
            $remaining = [int][Math]::Max(1, ($deadline - [DateTime]::UtcNow).TotalMilliseconds)
            if (-not $stdinTask.Wait($remaining)) { throw 'Preflight request write exceeded the bounded test deadline.' }
            $stdinTask.GetAwaiter().GetResult()
            $process.StandardInput.Close()
        }
        $remaining = [int][Math]::Max(1, ($deadline - [DateTime]::UtcNow).TotalMilliseconds)
        if (-not $process.WaitForExit($remaining)) {
            throw 'Preflight command exceeded the bounded test deadline.'
        }
        $remaining = [int][Math]::Max(1, ($deadline - [DateTime]::UtcNow).TotalMilliseconds)
        if (-not $stdoutTask.Wait($remaining) -or -not $stderrTask.Wait($remaining)) {
            throw 'Preflight output exceeded the bounded test deadline.'
        }
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ($stdout.Length -gt 4096 -or $stderr.Length -gt 4096) {
            throw 'Preflight diagnostics exceeded the test output limit.'
        }
        $document = $null
        if ($stdout -match '^\s*\{') {
            try { $document = ConvertFrom-Json -InputObject $stdout -ErrorAction Stop } catch {}
        }
        return [PSCustomObject]@{ ExitCode = [int]$process.ExitCode; StdOut = $stdout; StdErr = $stderr; Document = $document }
    } finally {
        if ($started) {
            if (-not $process.HasExited) {
                try { $process.Kill(); $null = $process.WaitForExit(5000) } catch {}
            }
            if (-not $process.HasExited) { throw 'Preflight command stop could not be proven.' }
            foreach ($task in @($stdinTask, $stdoutTask, $stderrTask)) {
                if ($task -and -not $task.IsCompleted) {
                    try { $null = $task.Wait(5000) } catch {}
                }
            }
        }
        $process.Dispose()
    }
}

function Invoke-CaptureOperatorTestCommand(
    [string]$BootstrapPath,
    [string]$OperatorPath,
    [string]$StageRoot,
    [string]$ManifestSha256,
    [string]$RequestPath,
    [string]$ScenarioPath,
    [int]$TimeoutSeconds = 30
) {
    $arguments = @(
        '-OperatorPath', $OperatorPath,
        '-StageRoot', $StageRoot,
        '-ExpectedPackageManifestSha256', $ManifestSha256,
        '-RequestPath', $RequestPath,
        '-ScenarioPath', $ScenarioPath,
        '-TimeoutSeconds', [string]$TimeoutSeconds
    )
    return Invoke-PreflightTestCommand -ScriptPath $BootstrapPath -ScriptArguments $arguments -TimeoutSeconds 30
}

function Get-CaptureOperatorOutputCounts([string]$LocalRoot) {
    return [PSCustomObject]@{
        Capture = @(Get-ChildItem -LiteralPath $LocalRoot -Directory -Filter 'capture-idle-*' -ErrorAction Stop).Count
        Plan = @(Get-ChildItem -LiteralPath $LocalRoot -Directory -Filter 'prepared-idle-*' -ErrorAction Stop).Count
        Preflight = @(Get-ChildItem -LiteralPath $LocalRoot -Directory -Filter 'preflight-idle-*' -ErrorAction Stop).Count
    }
}

function Assert-CaptureOperatorNoOutput([object]$Before, [object]$After, [string]$Reason) {
    Assert-PreflightTest (
        $Before.Capture -eq $After.Capture -and
        $Before.Plan -eq $After.Plan -and
        $Before.Preflight -eq $After.Preflight
    ) ('Capture operator ' + $Reason + ' refusal created protected output.')
}

function Assert-CaptureOperatorResponse(
    [object]$Invocation,
    [string]$ExpectedStatus,
    [string]$ExpectedReason,
    [string]$StageRoot,
    [string]$RequestPath,
    [string]$TargetIdentity,
    [string]$ServiceImagePath,
    [string]$OwnerSid
) {
    $result = $Invocation.Document
    $observedStatus = if ($result -and [string]$result.status -match '^(COMPLETE|REFUSED|INCOMPLETE)$') { [string]$result.status } else { 'missing' }
    $observedReason = if ($result -and [string]$result.reason -match '^[a-z][a-z0-9-]{0,63}$') { [string]$result.reason } else { 'missing' }
    $reportedExit = if ($result -and [string]$result.exitCode -match '^-?\d{1,3}$') { [string]$result.exitCode } else { 'missing' }
    $processExit = if ($Invocation.ExitCode -is [int] -or $Invocation.ExitCode -is [long]) { [string]$Invocation.ExitCode } else { 'missing' }
    Assert-PreflightTest (
        $null -ne $result -and
        $Invocation.ExitCode -eq [int]$result.exitCode -and
        [int]$result.exitCode -eq 2 -and
        [string]$result.status -ceq $ExpectedStatus -and
        [string]$result.reason -ceq $ExpectedReason
    ) ('Capture operator did not return the expected ' + $ExpectedStatus + '/' + $ExpectedReason +
        ' status. Observed status=' + $observedStatus + ' reason=' + $observedReason +
        ' resultExit=' + $reportedExit + ' processExit=' + $processExit + '.')
    Assert-PreflightTest (
        -not $Invocation.StdOut.Contains($StageRoot) -and
        -not $Invocation.StdErr.Contains($StageRoot) -and
        -not $Invocation.StdOut.Contains($RequestPath) -and
        -not $Invocation.StdErr.Contains($RequestPath) -and
        -not $Invocation.StdOut.Contains($TargetIdentity) -and
        -not $Invocation.StdErr.Contains($TargetIdentity) -and
        -not $Invocation.StdOut.Contains($ServiceImagePath) -and
        -not $Invocation.StdErr.Contains($ServiceImagePath) -and
        -not $Invocation.StdOut.Contains($OwnerSid) -and
        -not $Invocation.StdErr.Contains($OwnerSid) -and
        -not $Invocation.StdOut.Contains('8101') -and
        -not $Invocation.StdOut.Contains('8102') -and
        -not $Invocation.StdOut.Contains('8103') -and
        -not $Invocation.StdOut.Contains('8111') -and
        -not $Invocation.StdOut.Contains('8121') -and
        -not $Invocation.StdErr.Contains('8101') -and
        -not $Invocation.StdErr.Contains('8102') -and
        -not $Invocation.StdErr.Contains('8103') -and
        -not $Invocation.StdErr.Contains('8111') -and
        -not $Invocation.StdErr.Contains('8121')
    ) 'Capture operator disclosed protected target data.'
}

function Assert-PreflightReceipt(
    [object]$Invocation,
    [string]$ExpectedResult,
    [int]$ExpectedExitCode,
    [object]$ExpectedChildExitCode,
    [bool]$ExpectedTimedOut,
    [string]$StageRoot
) {
    $receipt = $Invocation.Document
    Assert-PreflightTest ($null -ne $receipt) 'Preflight did not emit its bounded result record.'
    Assert-PreflightTest ($Invocation.ExitCode -eq $ExpectedExitCode) 'Preflight process exit code did not match its result.'
    Assert-PreflightTest ($receipt.result -ceq $ExpectedResult -and [int]$receipt.exitCode -eq $ExpectedExitCode) 'Preflight result and exit fields were not distinct and correct.'
    Assert-PreflightTest ($receipt.timedOut -is [bool] -and $receipt.timedOut -ceq $ExpectedTimedOut) 'Preflight timeout field was missing or incorrect.'
    Assert-PreflightTest ($receipt.childStopped -is [bool]) 'Preflight child-stop evidence was missing.'
    if ($ExpectedResult -ceq 'PASS') {
        Assert-PreflightTest ($receipt.childStopped -and $receipt.childExitCode -eq $ExpectedChildExitCode) 'Successful Preflight did not prove its child exit.'
    } elseif ($ExpectedResult -ceq 'FAIL') {
        Assert-PreflightTest ($receipt.childStopped -and $receipt.childExitCode -eq $ExpectedChildExitCode) 'Failed Preflight did not preserve the child exit.'
    } else {
        Assert-PreflightTest ($receipt.childStopped -and ($null -eq $receipt.childExitCode -or [string]$receipt.childExitCode -match '^-?\d+$')) 'Timed out Preflight did not prove stop or preserve the available child exit.'
    }
    Assert-PreflightTest ($receipt.planSha256 -match '^[0-9a-f]{64}$' -and $receipt.sourceManifestSha256 -match '^[0-9a-f]{64}$') 'Preflight receipt did not bind the plan and manifest.'
    Assert-PreflightTest ($receipt.receiptId -match '^[0-9a-f]{32}$') 'Preflight receipt identifier is malformed.'
    $resultDirectory = Join-Path (Join-Path $StageRoot 'local') ('preflight-idle-' + $receipt.receiptId)
    $resultPath = Join-Path $resultDirectory 'result.json'
    Assert-PreflightTest (Test-Path -LiteralPath $resultPath -PathType Leaf) 'Preflight result file is missing; outcome is UNKNOWN.'
    $null = Assert-CvrIdleCaptureAcl -Path $resultDirectory -Directory
    $null = Assert-CvrIdleCaptureAcl -Path $resultPath
    $stored = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($resultPath, [Text.UTF8Encoding]::new($false, $true))) -ErrorAction Stop
    Assert-PreflightTest ($stored.result -ceq $receipt.result -and
        [int]$stored.exitCode -eq [int]$receipt.exitCode -and
        $stored.timedOut -ceq $receipt.timedOut -and
        $stored.childExitCode -eq $receipt.childExitCode -and
        $stored.childStopped -ceq $receipt.childStopped) 'Persisted Preflight receipt did not match the process result.'
    Assert-PreflightTest ((Get-Item -LiteralPath $resultPath).Length -le 4096) 'Persisted Preflight diagnostics exceeded the output limit.'
    Assert-PreflightTest (-not $Invocation.StdOut.Contains($StageRoot) -and -not $Invocation.StdErr.Contains($StageRoot)) 'Preflight output disclosed a local path.'
    Assert-PreflightTest (-not $Invocation.StdOut.Contains('stcvrc-ci-synthetic-preflight') -and -not $Invocation.StdErr.Contains('stcvrc-ci-synthetic-preflight')) 'Preflight output disclosed target identity.'
}

$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('stcvrc-preflight-' + [Guid]::NewGuid().ToString('N'))
$packageRoot = Join-Path $fixtureRoot 'stage'
$toolsStageRoot = Join-Path $packageRoot 'tools'
$networkLabStageRoot = Join-Path $toolsStageRoot 'network-lab'
$localRoot = Join-Path $packageRoot 'local'
$stageFilesRoot = Join-Path $packageRoot 'pins'
$payloadRoot = Join-Path $packageRoot 'payload'
$targetIdentity = 'stcvrc-ci-synthetic-preflight'
$originalAppData = $env:APPDATA
$legacyFixture = $null
try {
    New-PreflightTestDirectory $fixtureRoot
    $env:APPDATA = Join-Path $fixtureRoot 'appdata'
    New-PreflightTestDirectory $env:APPDATA
    $legacyFixture = New-CvrSyntheticLegacyPreimage
    New-PreflightTestDirectory $packageRoot
    New-PreflightTestDirectory $toolsStageRoot
    New-PreflightTestDirectory $networkLabStageRoot
    New-PreflightTestDirectory $localRoot
    New-PreflightTestDirectory $stageFilesRoot
    New-PreflightTestDirectory $payloadRoot
    New-PreflightTestDirectory (Join-Path $payloadRoot 'cvr-2.5.10')
    New-PreflightTestDirectory (Join-Path $payloadRoot 'cvr-2.5.8')

    $pinBytes = [ordered]@{
        gui258 = [byte[]]@(2, 5, 8, 1)
        serviceExe258 = [byte[]]@(2, 5, 8, 2)
        candidateCore = [byte[]]@(1, 19, 33, 11)
        updateInstaller = [byte[]]@(2, 5, 10, 1)
        updateHelper = [byte[]]@(2, 7, 7, 1)
        recoveryInstaller = [byte[]]@(2, 5, 8, 3)
        recoveryHelper = [byte[]]@(2, 7, 6, 1)
    }
    $pinPaths = [ordered]@{}
    $manifestEntries = @()
    $pinFileNames = @{
        gui258 = 'Clash Verge.exe'
        serviceExe258 = 'clash-verge-service.exe'
    }
    $payloadFileNames = @{
        candidateCore = 'verge-mihomo.exe'
        updateInstaller = 'Clash.Verge_2.5.10_x64-setup.exe'
        updateHelper = 'cvr-2.5.10\clash-verge-service-install.exe'
        recoveryInstaller = 'Clash.Verge_2.5.8_x64-setup.exe'
        recoveryHelper = 'cvr-2.5.8\clash-verge-service-install.exe'
    }
    foreach ($name in $pinBytes.Keys) {
        if ($name -in @('gui258','serviceExe258')) { continue }
        if ($payloadFileNames.ContainsKey($name)) {
            $fileName = $payloadFileNames[$name]
            $path = Join-Path $payloadRoot $fileName
            $archivePath = 'payload/' + $fileName.Replace('\','/')
        } else {
            $fileName = if ($pinFileNames.ContainsKey($name)) { $pinFileNames[$name] } else { $name + '.bin' }
            $path = Join-Path $stageFilesRoot $fileName
            $archivePath = 'pins/' + $fileName
        }
        Write-PreflightTestFile -Path $path -Bytes $pinBytes[$name] -Protected
        $pinPaths[$name] = $path
        $manifestEntries += [ordered]@{
            path = $archivePath
            sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }

    $operatorStageFiles = @(
        'windows_idle_capture_operator.ps1',
        'windows_core_preimage_paths.ps1',
        'windows_idle_baseline_guard.ps1',
        'windows_idle_transaction.ps1',
        'windows_legacy_state_transaction.ps1',
        'windows_idle_preflight_package_writer.ps1',
        'windows_idle_preflight.ps1',
        'windows_idle_preflight_target_operator.ps1',
        'windows_idle_target_runtime.ps1'
    )
    foreach ($name in $operatorStageFiles) {
        $sourcePath = Join-Path $PSScriptRoot $name
        $stagedPath = Join-Path $networkLabStageRoot $name
        Write-PreflightTestFile -Path $stagedPath -Bytes ([IO.File]::ReadAllBytes($sourcePath)) -Protected
        $manifestEntries += [ordered]@{
            path = ('tools/network-lab/' + $name)
            sha256 = (Get-FileHash -LiteralPath $stagedPath -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }

    $manifestPath = Join-Path $packageRoot 'source-manifest.json'
    Write-PreflightTestFile -Path $manifestPath -Bytes ([byte[]]@()) -Protected
    $manifest = [ordered]@{ schemaVersion = 1; scope = 'synthetic read-only Capture/Plan/Preflight'; files = $manifestEntries }
    [IO.File]::WriteAllText($manifestPath, (ConvertTo-Json -InputObject $manifest -Depth 5 -Compress), [Text.UTF8Encoding]::new($false))
    $manifestSha256 = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $stageRoot = [IO.Path]::GetFullPath($packageRoot)
    . (Join-Path $networkLabStageRoot 'windows_idle_preflight_target_operator.ps1')


    $trafficStartedUtc = [DateTime]::UtcNow.AddSeconds(-1)
    $trafficCompletedUtc = [DateTime]::UtcNow
    $trafficRequest = [PSCustomObject]@{
        challenge = 'b' * 32
        candidateCoreSha256 = 'a' * 64
        candidateGuiSha256 = 'c' * 64
        candidateServiceExeSha256 = 'd' * 64
        requiredProbes = [string[]]@('dns','http')
    }
    $trafficReceipt = [PSCustomObject]@{
        schemaVersion = 1
        status = 'PASS'
        challenge = $trafficRequest.challenge
        candidateCoreSha256 = $trafficRequest.candidateCoreSha256
        candidateGuiSha256 = $trafficRequest.candidateGuiSha256
        candidateServiceExeSha256 = $trafficRequest.candidateServiceExeSha256
        probes = @(
            [PSCustomObject]@{ protocol='dns'; passed=[bool]$true; observedAtUtcMs=[DateTimeOffset]::new($trafficStartedUtc.AddMilliseconds(250)).ToUnixTimeMilliseconds(); processId=8701; coreSha256=$trafficRequest.candidateCoreSha256 },
            [PSCustomObject]@{ protocol='http'; passed=[bool]$true; observedAtUtcMs=[DateTimeOffset]::new($trafficStartedUtc.AddMilliseconds(500)).ToUnixTimeMilliseconds(); processId=8701; coreSha256=$trafficRequest.candidateCoreSha256 }
        )
    }
    $validTrafficSummary = Assert-CvrIdleCandidateTrafficVerification -Verification $trafficReceipt -Request $trafficRequest -StartedUtc $trafficStartedUtc -CompletedUtc $trafficCompletedUtc
    Assert-PreflightTest ($validTrafficSummary.status -ceq 'PASS' -and @($validTrafficSummary.protocols).Count -eq 2 -and @($validTrafficSummary.processIds | Select-Object -Unique).Count -eq 1 -and $validTrafficSummary.candidateGuiSha256 -ceq $trafficRequest.candidateGuiSha256 -and $validTrafficSummary.candidateServiceExeSha256 -ceq $trafficRequest.candidateServiceExeSha256) 'A bound DNS/HTTP traffic receipt and all candidate pins were not accepted.'

    function Assert-CandidateTrafficRejected([object]$Verification,[object]$Request,[DateTime]$StartedUtc,[DateTime]$CompletedUtc,[string]$Reason) {
        $rejected = $false
        try { $null = Assert-CvrIdleCandidateTrafficVerification -Verification $Verification -Request $Request -StartedUtc $StartedUtc -CompletedUtc $CompletedUtc } catch { $rejected = $true }
        Assert-PreflightTest $rejected ('Invalid candidate traffic evidence was accepted: ' + $Reason)
    }
    $wrongTrafficChallenge = ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $trafficReceipt -Depth 5 -Compress) -ErrorAction Stop
    $wrongTrafficChallenge.challenge = 'c' * 32
    Assert-CandidateTrafficRejected $wrongTrafficChallenge $trafficRequest $trafficStartedUtc $trafficCompletedUtc 'challenge'
    $wrongTrafficHash = ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $trafficReceipt -Depth 5 -Compress) -ErrorAction Stop
    $wrongTrafficHash.probes[1].coreSha256 = 'c' * 64
    Assert-CandidateTrafficRejected $wrongTrafficHash $trafficRequest $trafficStartedUtc $trafficCompletedUtc 'core hash'
    $wrongTrafficGui = ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $trafficReceipt -Depth 5 -Compress) -ErrorAction Stop
    $wrongTrafficGui.candidateGuiSha256 = 'd' * 64
    Assert-CandidateTrafficRejected $wrongTrafficGui $trafficRequest $trafficStartedUtc $trafficCompletedUtc 'GUI SHA'
    $wrongTrafficService = ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $trafficReceipt -Depth 5 -Compress) -ErrorAction Stop
    $wrongTrafficService.candidateServiceExeSha256 = 'e' * 64
    Assert-CandidateTrafficRejected $wrongTrafficService $trafficRequest $trafficStartedUtc $trafficCompletedUtc 'service executable SHA'
    $missingTrafficProbe = ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $trafficReceipt -Depth 5 -Compress) -ErrorAction Stop
    $missingTrafficProbe.probes = @($missingTrafficProbe.probes[0])
    Assert-CandidateTrafficRejected $missingTrafficProbe $trafficRequest $trafficStartedUtc $trafficCompletedUtc 'missing protocol'
    $differentTrafficPid = ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $trafficReceipt -Depth 5 -Compress) -ErrorAction Stop
    $differentTrafficPid.probes[1].processId = 8702
    Assert-CandidateTrafficRejected $differentTrafficPid $trafficRequest $trafficStartedUtc $trafficCompletedUtc 'multiple process owners'
    $failedTrafficProbe = ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $trafficReceipt -Depth 5 -Compress) -ErrorAction Stop
    $failedTrafficProbe.probes[0].passed = $false
    Assert-CandidateTrafficRejected $failedTrafficProbe $trafficRequest $trafficStartedUtc $trafficCompletedUtc 'failed probe'
    $lateTrafficProbe = ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $trafficReceipt -Depth 5 -Compress) -ErrorAction Stop
    $lateTrafficProbe.probes[1].observedAtUtcMs = [DateTimeOffset]::new($trafficCompletedUtc.AddSeconds(1)).ToUnixTimeMilliseconds()
    Assert-CandidateTrafficRejected $lateTrafficProbe $trafficRequest $trafficStartedUtc $trafficCompletedUtc 'out-of-window probe'

    $missingTrafficArguments = @{
        CaptureReceiptPath = (Join-Path $stageRoot 'local\capture-idle-00000000000000000000000000000000\capture.json')
        PlanPath = (Join-Path $stageRoot 'local\prepared-idle-00000000000000000000000000000000\plan.json')
        PreflightReceiptPath = (Join-Path $stageRoot 'local\preflight-idle-00000000000000000000000000000000\result.json')
        ExpectedPlanSha256 = 'a' * 64
        ExpectedStageRoot = $stageRoot
        ExpectedPackageManifestSha256 = $manifestSha256
        ExpectedTargetIdentity = 'synthetic-target'
        ExpectedPins = [ordered]@{}
        ExpectedCandidateGuiSha256 = 'b' * 64
        ExpectedCandidateServiceExeSha256 = 'c' * 64
        RequiredCandidateProbes = [string[]]@('dns','http')
        RecoveryVerificationScript = { param($request) return [bool]$true }
    }
    $missingTrafficOutputCounts = Get-CaptureOperatorOutputCounts -LocalRoot $localRoot
    $missingTrafficRefused = $false
    try { Invoke-CvrIdlePreflightTargetAcceptance @missingTrafficArguments } catch { $missingTrafficRefused = $_.Exception -is [System.Management.Automation.ParameterBindingException] }
    $missingTrafficAfterCounts = Get-CaptureOperatorOutputCounts -LocalRoot $localRoot
    Assert-CaptureOperatorNoOutput -Before $missingTrafficOutputCounts -After $missingTrafficAfterCounts -Reason 'missing candidate traffic callback'
    Assert-PreflightTest $missingTrafficRefused 'Target acceptance ran without the mandatory traffic callback.'

    $missingRecoveryArguments = $missingTrafficArguments.Clone()
    $missingRecoveryArguments.CandidateTrafficScript = { param($request) throw 'This callback must not run.' }
    $null = $missingRecoveryArguments.Remove('RecoveryVerificationScript')
    $missingRecoveryOutputCounts = Get-CaptureOperatorOutputCounts -LocalRoot $localRoot
    $missingRecoveryRefused = $false
    try { Invoke-CvrIdlePreflightTargetAcceptance @missingRecoveryArguments } catch { $missingRecoveryRefused = $_.Exception -is [System.Management.Automation.ParameterBindingException] }
    $missingRecoveryAfterCounts = Get-CaptureOperatorOutputCounts -LocalRoot $localRoot
    Assert-CaptureOperatorNoOutput -Before $missingRecoveryOutputCounts -After $missingRecoveryAfterCounts -Reason 'missing recovery verification callback'
    Assert-PreflightTest $missingRecoveryRefused 'Target acceptance ran without the mandatory recovery verification callback.'

    $programFilesDirectory = Join-Path $fixtureRoot 'program-files'
    $serviceDirectory = Join-Path $fixtureRoot 'service-core'
    $null = New-Item -ItemType Directory -Path $programFilesDirectory -ErrorAction Stop
    $null = Set-CvrIdleCaptureAcl -Path $programFilesDirectory -Directory
    $null = New-Item -ItemType Directory -Path $serviceDirectory -ErrorAction Stop
    $null = Set-CvrIdleCaptureAcl -Path $serviceDirectory -Directory
    $programFilesPath = Join-Path $programFilesDirectory 'verge-mihomo.exe'
    $serviceCorePath = Join-Path $serviceDirectory 'verge-mihomo.exe'
    $guiPath = Join-Path $programFilesDirectory 'Clash Verge.exe'
    $serviceExePath = Join-Path $programFilesDirectory 'clash-verge-service.exe'
    Write-PreflightTestFile -Path $guiPath -Bytes $pinBytes.gui258 -Protected
    Write-PreflightTestFile -Path $serviceExePath -Bytes $pinBytes.serviceExe258 -Protected
    $pinPaths.gui258 = $guiPath
    $pinPaths.serviceExe258 = $serviceExePath
    [IO.File]::WriteAllBytes($programFilesPath, [byte[]]@(2, 5, 8, 4))
    [IO.File]::WriteAllBytes($serviceCorePath, [byte[]]@(2, 5, 8, 5))
    $programFilesBackup = Save-CvrCorePreimageBackup -Root $fixtureRoot -Label 'program-files' -SourcePath $programFilesPath -ExpectedSha256 (Get-FileHash -LiteralPath $programFilesPath -Algorithm SHA256).Hash
    $serviceBackup = Save-CvrCorePreimageBackup -Root $fixtureRoot -Label 'service' -SourcePath $serviceCorePath -ExpectedSha256 (Get-FileHash -LiteralPath $serviceCorePath -Algorithm SHA256).Hash
    $programFilesSha = (Get-FileHash -LiteralPath $programFilesPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $serviceSha = (Get-FileHash -LiteralPath $serviceCorePath -Algorithm SHA256).Hash.ToLowerInvariant()

    $expectedPins = [ordered]@{
        gui258 = (Get-FileHash -LiteralPath $pinPaths.gui258 -Algorithm SHA256).Hash.ToLowerInvariant()
        serviceExe258 = (Get-FileHash -LiteralPath $pinPaths.serviceExe258 -Algorithm SHA256).Hash.ToLowerInvariant()
        programFilesCore = $programFilesSha
        serviceCore = $serviceSha
        candidateCore = (Get-FileHash -LiteralPath $pinPaths.candidateCore -Algorithm SHA256).Hash.ToLowerInvariant()
        updateInstaller = (Get-FileHash -LiteralPath $pinPaths.updateInstaller -Algorithm SHA256).Hash.ToLowerInvariant()
        updateHelper = (Get-FileHash -LiteralPath $pinPaths.updateHelper -Algorithm SHA256).Hash.ToLowerInvariant()
        recoveryInstaller = (Get-FileHash -LiteralPath $pinPaths.recoveryInstaller -Algorithm SHA256).Hash.ToLowerInvariant()
        recoveryHelper = (Get-FileHash -LiteralPath $pinPaths.recoveryHelper -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $pinnedFiles = [ordered]@{
        gui258 = $pinPaths.gui258
        serviceExe258 = $pinPaths.serviceExe258
        programFilesCore = $programFilesPath
        serviceCore = $serviceCorePath
        candidateCore = $pinPaths.candidateCore
        updateInstaller = $pinPaths.updateInstaller
        updateHelper = $pinPaths.updateHelper
        recoveryInstaller = $pinPaths.recoveryInstaller
        recoveryHelper = $pinPaths.recoveryHelper
    }
    $programFilesAcl = Get-Acl -LiteralPath $programFilesPath
    $serviceAcl = Get-Acl -LiteralPath $serviceCorePath
    $capture = [PSCustomObject]@{
        targetIdentity = $targetIdentity
        capturedAtUtc = [DateTime]::UtcNow
        coreShouldBeRunning = [bool]$false
        idleObservation = @{
            CoreShouldBeRunning = [bool]$false
            OwnedGuiProcessIds = [int[]]@()
            OwnedCoreProcessIds = [int[]]@()
            ControllerListening = [bool]$false
            OwnedListenerProcessIds = [int[]]@()
            ServiceStatus = 'Running'
            ExpectedProgramFilesCoreSha256 = $programFilesSha
            ObservedProgramFilesCoreSha256 = $programFilesSha
            ExpectedServiceCoreSha256 = $serviceSha
            ObservedServiceCoreSha256 = $serviceSha
        }
        pinnedFiles = $pinnedFiles
        corePair = @{
            programFiles = [PSCustomObject]@{
                path = $programFilesPath; pathPin = $programFilesPath
                backup = $programFilesBackup.backup; backupPathPin = $programFilesBackup.backupPathPin
                backupRoot = $programFilesBackup.backupRoot
                backupSddl = $programFilesBackup.backupSddl
                backupDirectorySddl = $programFilesBackup.backupDirectorySddl
                sha256 = $programFilesSha; sddl = $programFilesAcl.Sddl; acl = $programFilesAcl
            }
            service = [PSCustomObject]@{
                path = $serviceCorePath; pathPin = $serviceCorePath
                backup = $serviceBackup.backup; backupPathPin = $serviceBackup.backupPathPin
                backupRoot = $serviceBackup.backupRoot
                backupSddl = $serviceBackup.backupSddl
                backupDirectorySddl = $serviceBackup.backupDirectorySddl
                sha256 = $serviceSha; sddl = $serviceAcl.Sddl; acl = $serviceAcl
            }
        }
    }
    foreach ($role in @('programFiles', 'service')) {
        $entry = $capture.corePair[$role]
        $entry.acl = [ordered]@{ Sddl = [string]$entry.sddl }
    }
    $capture.capturedAtUtc = $capture.capturedAtUtc.ToString('o')
    $legacyForCapture = [ordered]@{
        files = @($legacyFixture.state.files | ForEach-Object {
            [ordered]@{ path=[string]$_.path; present=[bool]$_.present; bytes=$_.bytes; sddl=$_.sddl }
        })
        registry = @($legacyFixture.state.registry | ForEach-Object {
            [ordered]@{ hive=[string]$_.hive; name=[string]$_.name; present=[bool]$_.present; kind=$_.kind; data=$_.data }
        })
    }
    $capture | Add-Member -MemberType NoteProperty -Name 'rollbackState' -Value ([ordered]@{
        schemaVersion = 1
        installDirectory = $programFilesDirectory
        gui = Save-CvrIdleFilePreimageBackup -Root $localRoot -Role 'gui' -SourcePath $guiPath -ExpectedDirectory $programFilesDirectory -ExpectedSha256 $expectedPins.gui258
        serviceExe = Save-CvrIdleFilePreimageBackup -Root $localRoot -Role 'service-exe' -SourcePath $serviceExePath -ExpectedDirectory $programFilesDirectory -ExpectedSha256 $expectedPins.serviceExe258
        legacyState = $legacyForCapture
        observer = [ordered]@{
            ownerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            sessionId = [int][Diagnostics.Process]::GetCurrentProcess().SessionId
            serviceAccountSid = 'S-1-5-18'
            serviceProcessId = 8101
        }
    })
    $writerRequest = [ordered]@{
        Capture = $capture
        ExpectedTargetIdentity = $targetIdentity
        ExpectedPins = $expectedPins
        PackageRoot = $packageRoot
        ExpectedStageRoot = $stageRoot
        ExpectedPackageManifestSha256 = $manifestSha256
    }
    $writerPath = Join-Path $PSScriptRoot 'windows_idle_preflight_package_writer.ps1'
    $operatorPath = Join-Path $networkLabStageRoot 'windows_idle_capture_operator.ps1'
    $seedPath = Join-Path $localRoot 'capture-seed.json'
    $seedCapture = ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $capture -Depth 20 -Compress) -ErrorAction Stop
    $null = $seedCapture.PSObject.Properties.Remove('capturedAtUtc')
    $null = $seedCapture.PSObject.Properties.Remove('idleObservation')
    $null = $seedCapture.PSObject.Properties.Remove('rollbackState')
    $seedRequest = [ordered]@{
        Capture = $seedCapture
        ExpectedTargetIdentity = $targetIdentity
        ExpectedPins = $expectedPins
        Observer = [ordered]@{
            ExpectedOwnerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            ExpectedSessionId = [int][Diagnostics.Process]::GetCurrentProcess().SessionId
            ExpectedServiceAccountSid = 'S-1-5-18'
        }
    }
    $seedBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes(
        (ConvertTo-Json -InputObject $seedRequest -Depth 20 -Compress -ErrorAction Stop)
    )
    Write-PreflightTestFile -Path $seedPath -Bytes $seedBytes -Protected
    $operatorFixtureRoot = Join-Path $fixtureRoot 'operator-fixtures'
    New-PreflightTestDirectory $operatorFixtureRoot
    $bootstrapPath = Join-Path $operatorFixtureRoot 'operator-bootstrap.ps1'
    $bootstrapSource = @'
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$OperatorPath,
    [Parameter(Mandatory = $true)][string]$StageRoot,
    [Parameter(Mandatory = $true)][string]$ExpectedPackageManifestSha256,
    [Parameter(Mandatory = $true)][string]$RequestPath,
    [Parameter(Mandatory = $true)][string]$ScenarioPath,
    [ValidateRange(1, 300)][int]$TimeoutSeconds = 30
)
$ErrorActionPreference = 'Stop'
$global:scenario = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($ScenarioPath, [Text.UTF8Encoding]::new($false, $true))) -ErrorAction Stop

function global:Get-CimInstance {
    [CmdletBinding()]
    param([string]$ClassName, [string]$Filter, [string[]]$Property)
    if ($ClassName -ceq 'Win32_Service') { return $global:scenario.Service }
    if ($ClassName -ceq 'Win32_Process') { return @($global:scenario.Processes) }
    throw 'synthetic observation unavailable'
}

function global:Invoke-CimMethod {
    [CmdletBinding()]
    param([object]$InputObject, [string]$MethodName)
    if ($MethodName -cne 'GetOwnerSid') { throw 'synthetic owner unavailable' }
    if (@($global:scenario.UnknownOwnerPids) -contains [int]$InputObject.ProcessId) {
        return [PSCustomObject]@{ ReturnValue = 2; Sid = $null }
    }
    return [PSCustomObject]@{ ReturnValue = 0; Sid = [string]$InputObject.OwnerSid }
}

function global:Get-Service {
    [CmdletBinding()]
    param([string]$Name)
    if ($Name -cne 'clash_verge_service') { throw 'synthetic service unavailable' }
    return [PSCustomObject]@{ Status = [string]$global:scenario.Service.State }
}

function global:Get-NetTCPConnection {
    [CmdletBinding()]
    param([string]$State)
    if ([bool]$global:scenario.FailTcp) { throw 'synthetic listener unavailable' }
    return @($global:scenario.TcpOwnerProcessIds | ForEach-Object {
        [PSCustomObject]@{ State = 'Listen'; OwningProcess = [int]$_ }
    })
}

function global:Get-NetUDPEndpoint {
    [CmdletBinding()]
    param()
    if ([bool]$global:scenario.FailUdp) { throw 'synthetic listener unavailable' }
    return @($global:scenario.UdpOwnerProcessIds | ForEach-Object {
        [PSCustomObject]@{ OwningProcess = [int]$_ }
    })
}

& $OperatorPath -StageRoot $StageRoot -ExpectedPackageManifestSha256 $ExpectedPackageManifestSha256 -RequestPath $RequestPath -TimeoutSeconds $TimeoutSeconds
$operatorExitCode = $LASTEXITCODE
if ($null -eq $operatorExitCode) { throw 'Operator exit code was unavailable.' }
exit ([int]$operatorExitCode)
'@
    Write-PreflightTestFile -Path $bootstrapPath -Bytes ([Text.UTF8Encoding]::new($false, $true).GetBytes($bootstrapSource)) -Protected
    $operatorTrackedPaths = @(
        $manifestPath, $programFilesPath, $serviceCorePath, $guiPath, $serviceExePath,
        $programFilesBackup.backup, $serviceBackup.backup, $seedPath
    ) + @($legacyFixture.state.files | Where-Object { $_.present } | ForEach-Object { $_.path }) +
        @($pinPaths.Values) + @($operatorStageFiles | ForEach-Object { Join-Path $networkLabStageRoot $_ })
    $operatorInputSnapshot = Get-PreflightTestSnapshot -Paths $operatorTrackedPaths

    function New-CaptureOperatorScenario(
        [switch]$UnknownServiceOwner,
        [switch]$UnknownListener,
        [switch]$RunningCore,
        [switch]$RunningAlpha,
        [switch]$OrphanService,
        [switch]$DuplicateService
    ) {
        $servicePid = 8101
        $service = [ordered]@{
            Name = 'clash_verge_service'
            State = 'Running'
            ProcessId = $servicePid
            PathName = '"' + $pinPaths.serviceExe258 + '"'
            StartName = 'LocalSystem'
        }
        $processes = [Collections.Generic.List[object]]::new()
        $processes.Add([PSCustomObject]@{
            Name = [IO.Path]::GetFileName($pinPaths.serviceExe258)
            ExecutablePath = $pinPaths.serviceExe258
            ProcessId = $servicePid
            ParentProcessId = 4
            SessionId = 0
            OwnerSid = 'S-1-5-18'
        })
        if ($OrphanService) { $processes.Clear() }
        if ($OrphanService -or $DuplicateService) {
            $serviceImagePid = if ($OrphanService) { 8111 } else { 8121 }
            $processes.Add([PSCustomObject]@{
                Name = [IO.Path]::GetFileName($pinPaths.serviceExe258)
                ExecutablePath = $pinPaths.serviceExe258
                ProcessId = $serviceImagePid
                ParentProcessId = 4
                SessionId = 0
                OwnerSid = 'S-1-5-18'
            })
        }
        $udpOwners = [int[]]@()
        if ($RunningCore) {
            $corePid = 8102
            $processes.Add([PSCustomObject]@{
                Name = 'verge-mihomo.exe'
                ExecutablePath = $serviceCorePath
                ProcessId = $corePid
                ParentProcessId = $servicePid
                SessionId = 0
                OwnerSid = 'S-1-5-18'
            })
            $udpOwners = [int[]]@($corePid)
        }
        if ($RunningAlpha) {
            $alphaPid = 8103
            $processes.Add([PSCustomObject]@{
                Name = 'verge-mihomo-alpha.exe'
                ExecutablePath = (Join-Path $programFilesDirectory 'verge-mihomo-alpha.exe')
                ProcessId = $alphaPid
                ParentProcessId = 8100
                SessionId = [int][Diagnostics.Process]::GetCurrentProcess().SessionId
                OwnerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            })
            $udpOwners = [int[]]@($udpOwners + $alphaPid)
        }
        $unknownOwners = if ($UnknownServiceOwner) { [int[]]@($servicePid) } else { [int[]]@() }
        return [PSCustomObject]@{
            Service = [PSCustomObject]$service
            Processes = @($processes.ToArray())
            UnknownOwnerPids = $unknownOwners
            TcpOwnerProcessIds = [int[]]@()
            UdpOwnerProcessIds = $udpOwners
            FailTcp = $false
            FailUdp = [bool]$UnknownListener
        }
    }

    function Save-CaptureOperatorScenario([string]$Name, [object]$Scenario) {
        $path = Join-Path $operatorFixtureRoot ($Name + '.json')
        $bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes(
            (ConvertTo-Json -InputObject $Scenario -Depth 5 -Compress -ErrorAction Stop)
        )
        Write-PreflightTestFile -Path $path -Bytes $bytes -Protected
        return $path
    }

    function Invoke-CaptureOperatorScenario([string]$Name, [object]$Scenario) {
        $scenarioPath = Save-CaptureOperatorScenario -Name $Name -Scenario $Scenario
        return Invoke-CaptureOperatorTestCommand -BootstrapPath $bootstrapPath -OperatorPath $operatorPath -StageRoot $stageRoot -ManifestSha256 $manifestSha256 -RequestPath $seedPath -ScenarioPath $scenarioPath -TimeoutSeconds 30
    }

    function Assert-CaptureOperatorNegative([string]$Name, [object]$Scenario, [string]$Status, [string]$Reason) {
        $before = Get-CaptureOperatorOutputCounts -LocalRoot $localRoot
        $invocation = Invoke-CaptureOperatorScenario -Name $Name -Scenario $Scenario
        $after = Get-CaptureOperatorOutputCounts -LocalRoot $localRoot
        Assert-CaptureOperatorNoOutput -Before $before -After $after -Reason $Reason
        Assert-CaptureOperatorResponse -Invocation $invocation -ExpectedStatus $Status -ExpectedReason $Reason -StageRoot $stageRoot -RequestPath $seedPath -TargetIdentity $targetIdentity -ServiceImagePath $pinPaths.serviceExe258 -OwnerSid $seedRequest.Observer.ExpectedOwnerSid
    }

    $operatorOutputsBefore = Get-CaptureOperatorOutputCounts -LocalRoot $localRoot
    $operatorCaptureDirectoriesBefore = @(Get-ChildItem -LiteralPath $localRoot -Directory -Filter 'capture-idle-*' -ErrorAction Stop | ForEach-Object { $_.FullName })
    $operatorPlanDirectoriesBefore = @(Get-ChildItem -LiteralPath $localRoot -Directory -Filter 'prepared-idle-*' -ErrorAction Stop | ForEach-Object { $_.FullName })
    $validOperator = Invoke-CaptureOperatorScenario -Name 'valid' -Scenario (New-CaptureOperatorScenario)
    $validOperatorResult = $validOperator.Document
    $observedStatus = if ($validOperatorResult -and [string]$validOperatorResult.status -in @('COMPLETE','REFUSED','INCOMPLETE')) { [string]$validOperatorResult.status } else { 'other' }
    $observedReason = if ($validOperatorResult -and [string]$validOperatorResult.reason -match '^[a-z][a-z0-9-]{0,63}$') { [string]$validOperatorResult.reason } else { 'other' }
    $observedResult = if ($validOperatorResult -and [string]$validOperatorResult.result -in @('PASS','FAIL','TIMEOUT','UNKNOWN')) { [string]$validOperatorResult.result } else { 'other' }
    $observedResultExitCode = if ($validOperatorResult -and ($validOperatorResult.exitCode -is [int] -or $validOperatorResult.exitCode -is [long])) { [string]$validOperatorResult.exitCode } else { 'missing' }
    $observedProcessExitCode = if ($validOperator.ExitCode -is [int] -or $validOperator.ExitCode -is [long]) { [string]$validOperator.ExitCode } else { 'missing' }
    $observedTimedOut = if ($validOperatorResult -and $validOperatorResult.timedOut -is [bool]) { [string]$validOperatorResult.timedOut } else { 'missing' }
    $observedChildStopped = if ($validOperatorResult -and $validOperatorResult.childStopped -is [bool]) { [string]$validOperatorResult.childStopped } else { 'missing' }
    $observedChildExitCode = if ($validOperatorResult -and ($validOperatorResult.childExitCode -is [int] -or $validOperatorResult.childExitCode -is [long])) { [string]$validOperatorResult.childExitCode } else { 'missing' }
    $stderrPresent = -not [string]::IsNullOrEmpty($validOperator.StdErr)
    Assert-PreflightTest (
        $null -ne $validOperatorResult -and
        $validOperator.ExitCode -eq 0 -and
        [string]$validOperatorResult.status -ceq 'COMPLETE' -and
        [string]$validOperatorResult.reason -ceq 'preflight-complete' -and
        [string]$validOperatorResult.result -ceq 'PASS' -and
        [int]$validOperatorResult.exitCode -eq 0 -and
        $validOperatorResult.timedOut -is [bool] -and -not $validOperatorResult.timedOut -and
        $validOperatorResult.childStopped -is [bool] -and $validOperatorResult.childStopped -and
        [int]$validOperatorResult.childExitCode -eq 0 -and
        [string]$validOperatorResult.planSha256 -match '^[0-9a-f]{64}$' -and
        [string]$validOperatorResult.sourceManifestSha256 -ceq $manifestSha256 -and
        [string]$validOperatorResult.receiptId -match '^[0-9a-f]{32}$' -and
        [string]::IsNullOrEmpty($validOperator.StdErr)
    ) ("The public Capture operator did not complete Capture/Plan/Preflight with distinct PASS evidence. status=$observedStatus reason=$observedReason result=$observedResult resultExit=$observedResultExitCode processExit=$observedProcessExitCode timedOut=$observedTimedOut childStopped=$observedChildStopped childExitCode=$observedChildExitCode stderrPresent=$stderrPresent.")
    Assert-PreflightTest (
        -not $validOperator.StdOut.Contains($stageRoot) -and
        -not $validOperator.StdOut.Contains($seedPath) -and
        -not $validOperator.StdOut.Contains($targetIdentity) -and
        -not $validOperator.StdOut.Contains($pinPaths.serviceExe258) -and
        -not $validOperator.StdOut.Contains($programFilesPath) -and
        -not $validOperator.StdOut.Contains([string]$seedRequest.Observer.ExpectedOwnerSid) -and
        -not $validOperator.StdOut.Contains('8101') -and
        -not $validOperator.StdOut.Contains('8102')
    ) 'The public Capture operator disclosed protected target data.'

    $operatorOutputsAfter = Get-CaptureOperatorOutputCounts -LocalRoot $localRoot
    Assert-PreflightTest (
        $operatorOutputsAfter.Capture -eq ($operatorOutputsBefore.Capture + 1) -and
        $operatorOutputsAfter.Plan -eq ($operatorOutputsBefore.Plan + 1) -and
        $operatorOutputsAfter.Preflight -eq ($operatorOutputsBefore.Preflight + 1)
    ) 'The public Capture operator did not create exactly one Capture, Plan, and Preflight record.'
    $operatorCaptureDirectories = @(
        Get-ChildItem -LiteralPath $localRoot -Directory -Filter 'capture-idle-*' -ErrorAction Stop |
            Where-Object { $operatorCaptureDirectoriesBefore -notcontains $_.FullName }
    )
    $operatorPlanDirectories = @(
        Get-ChildItem -LiteralPath $localRoot -Directory -Filter 'prepared-idle-*' -ErrorAction Stop |
            Where-Object { $operatorPlanDirectoriesBefore -notcontains $_.FullName }
    )
    Assert-PreflightTest ($operatorCaptureDirectories.Count -eq 1 -and $operatorPlanDirectories.Count -eq 1) 'The operator created ambiguous Capture/Plan output.'
    $operatorCaptureDirectory = $operatorCaptureDirectories[0].FullName
    $operatorCaptureReceiptPath = Join-Path $operatorCaptureDirectory 'capture.json'
    $null = Assert-CvrIdleCaptureAcl -Path $operatorCaptureDirectory -Directory
    $null = Assert-CvrIdleCaptureAcl -Path $operatorCaptureReceiptPath
    $operatorCaptureReceipt = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($operatorCaptureReceiptPath, [Text.UTF8Encoding]::new($false, $true))) -ErrorAction Stop
    $packagedRestoreContext = [PSCustomObject]@{
        Capture = ConvertTo-CvrIdleTransactionCapture -Receipt $operatorCaptureReceipt
        StageRoot = $stageRoot
        SourceManifestSha256 = $manifestSha256
        ExpectedPins = $expectedPins
    }
    $packagedRestoreValid = Assert-CvrIdlePackagedRestoreState -Context $packagedRestoreContext -Restored $packagedRestoreContext.Capture.idleObservation
    Assert-PreflightTest ($packagedRestoreValid -is [bool] -and $packagedRestoreValid) 'Packaged restore verification required a successful Action result.'

    Assert-PreflightTest (
        [string]$operatorCaptureReceipt.packageStageBinding.sourceManifestSha256 -ceq $manifestSha256 -and
        [string]$operatorCaptureReceipt.idleObservation.ServiceStatus -ceq 'Running' -and
        $operatorCaptureReceipt.idleObservation.CoreShouldBeRunning -is [bool] -and -not $operatorCaptureReceipt.idleObservation.CoreShouldBeRunning -and
        $operatorCaptureReceipt.idleObservation.ControllerListening -is [bool] -and -not $operatorCaptureReceipt.idleObservation.ControllerListening -and
        @($operatorCaptureReceipt.idleObservation.OwnedGuiProcessIds).Count -eq 0 -and
        @($operatorCaptureReceipt.idleObservation.OwnedCoreProcessIds).Count -eq 0 -and
        @($operatorCaptureReceipt.idleObservation.OwnedListenerProcessIds).Count -eq 0
    ) 'The public Capture receipt did not preserve the fresh owner-scoped idle observation and stage pin.'
    $operatorPlanDirectory = $operatorPlanDirectories[0].FullName
    $operatorPlanPath = Join-Path $operatorPlanDirectory 'plan.json'
    $null = Assert-CvrIdleCaptureAcl -Path $operatorPlanDirectory -Directory
    $null = Assert-CvrIdleCaptureAcl -Path $operatorPlanPath
    $operatorPlanRecord = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($operatorPlanPath, [Text.UTF8Encoding]::new($false, $true))) -ErrorAction Stop
    Assert-PreflightTest (
        (Get-FileHash -LiteralPath $operatorPlanPath -Algorithm SHA256).Hash.ToLowerInvariant() -ceq [string]$validOperatorResult.planSha256 -and
        [string]$operatorPlanRecord.packageStageBinding.sourceManifestSha256 -ceq $manifestSha256
    ) 'The public Plan record did not match its reported digest and trusted stage pin.'
    $operatorPreflightInvocation = [PSCustomObject]@{
        ExitCode = [int]$validOperatorResult.exitCode
        StdOut = [string]$validOperator.StdOut
        StdErr = [string]$validOperator.StdErr
        Document = $validOperatorResult
    }
    Assert-PreflightReceipt -Invocation $operatorPreflightInvocation -ExpectedResult 'PASS' -ExpectedExitCode 0 -ExpectedChildExitCode 0 -ExpectedTimedOut $false -StageRoot $stageRoot

    $operatorPreflightReceiptPath = Join-Path (Join-Path $localRoot ('preflight-idle-' + [string]$validOperatorResult.receiptId)) 'result.json'
    $operatorCaptureReceipt = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($operatorCaptureReceiptPath, [Text.UTF8Encoding]::new($false, $true))) -ErrorAction Stop
    $handoffTargets = @(
        $guiPath, $serviceExePath, $programFilesPath, $serviceCorePath,
        $operatorCaptureReceipt.rollbackState.gui.backup,
        $operatorCaptureReceipt.rollbackState.serviceExe.backup
    ) + @($legacyFixture.state.files | Where-Object { $_.present } | ForEach-Object { $_.path })
    $handoffSnapshot = Get-PreflightTestSnapshot -Paths $handoffTargets
    $script:syntheticCandidateRunning = $false
    $script:preflightHandoffActionCalls = 0
    $script:preflightHandoffCandidateChecks = 0
    $script:preflightHandoffRestoreCalls = 0
    $script:preflightHandoffVerifyCalls = 0
    $script:transactionNegativeActionCalls = 0
    $candidateGuiBytes = [byte[]]@(9, 9, 9, 1)
    $candidateServiceBytes = [byte[]]@(9, 9, 9, 2)
    $candidateCheckBytes = [Text.UTF8Encoding]::new($false).GetBytes('{"fixture":"synthetic-candidate","state":"changed"}')
    $expectedCandidateGuiSha256 = Get-CvrByteArraySha256 -Bytes $candidateGuiBytes
    $expectedCandidateServiceSha256 = Get-CvrByteArraySha256 -Bytes $candidateServiceBytes
    $refreshObservation = {
        param($freshCapture)
        $observed = $freshCapture.idleObservation
        if ($script:syntheticCandidateRunning) {
            $observed = [ordered]@{}
            foreach ($key in $freshCapture.idleObservation.Keys) { $observed[$key] = $freshCapture.idleObservation[$key] }
            $observed.OwnedCoreProcessIds = [int[]]@(8199)
        }
        return [PSCustomObject]@{
            SampledAtUtc = [DateTime]::UtcNow
            Observation = $observed
            Observer = $freshCapture.rollbackState.observer
        }
    }
    $candidateAction = {
        param($context)
        $script:preflightHandoffActionCalls++
        $script:syntheticCandidateRunning = $true
        $candidateCoreBytes = [IO.File]::ReadAllBytes([string]$context.Capture.pinnedFiles.candidateCore)
        [IO.File]::WriteAllBytes($guiPath, $candidateGuiBytes)
        [IO.File]::WriteAllBytes($serviceExePath, $candidateServiceBytes)
        [IO.File]::WriteAllBytes([string]$context.Capture.corePair.programFiles.path, $candidateCoreBytes)
        [IO.File]::WriteAllBytes([string]$context.Capture.corePair.service.path, $candidateCoreBytes)
        foreach ($path in @($guiPath,$serviceExePath,$programFilesPath,$serviceCorePath)) {
            Add-PreflightTestAclDrift -Path $path
        }
        foreach ($entry in @($context.Capture.rollbackState.legacyState.files)) {
            if ($entry.present) {
                [IO.File]::WriteAllBytes([string]$entry.path, $candidateCheckBytes)
                Add-PreflightTestAclDrift -Path ([string]$entry.path)
            }
        }
        foreach ($entry in @($context.Capture.rollbackState.legacyState.registry)) {
            if ($entry.present) {
                Set-CvrLegacyRunValue -Hive ([string]$entry.hive) -Name ([string]$entry.name) -Kind ([string]$entry.kind) -Data 'STCVRC-synthetic-candidate'
            }
        }
        $trafficRequest = [PSCustomObject]@{
            challenge = 'd' * 32
            candidateCoreSha256 = [string]$context.ExpectedPins.candidateCore
            candidateGuiSha256 = $expectedCandidateGuiSha256
            candidateServiceExeSha256 = $expectedCandidateServiceSha256
            requiredProbes = [string[]]@('dns','http')
        }
        $trafficCompletedUtc = [DateTime]::UtcNow
        $trafficStartedUtc = $trafficCompletedUtc.AddSeconds(-1)
        $trafficVerification = [PSCustomObject]@{
            schemaVersion = 1
            status = 'PASS'
            challenge = $trafficRequest.challenge
            candidateCoreSha256 = $trafficRequest.candidateCoreSha256
            candidateGuiSha256 = $trafficRequest.candidateGuiSha256
            candidateServiceExeSha256 = $trafficRequest.candidateServiceExeSha256
            probes = @(
                [PSCustomObject]@{ protocol='dns'; passed=[bool]$true; observedAtUtcMs=[DateTimeOffset]::new($trafficStartedUtc.AddMilliseconds(250)).ToUnixTimeMilliseconds(); processId=8102; coreSha256=$trafficRequest.candidateCoreSha256 },
                [PSCustomObject]@{ protocol='http'; passed=[bool]$true; observedAtUtcMs=[DateTimeOffset]::new($trafficStartedUtc.AddMilliseconds(500)).ToUnixTimeMilliseconds(); processId=8102; coreSha256=$trafficRequest.candidateCoreSha256 }
            )
        }
        return [PSCustomObject]@{
            candidateCoreSha256 = (Get-FileHash -LiteralPath ([string]$context.Capture.pinnedFiles.candidateCore) -Algorithm SHA256).Hash.ToLowerInvariant()
            programFilesCoreSha256 = (Get-FileHash -LiteralPath $programFilesPath -Algorithm SHA256).Hash.ToLowerInvariant()
            serviceCoreSha256 = (Get-FileHash -LiteralPath $serviceCorePath -Algorithm SHA256).Hash.ToLowerInvariant()
            guiSha256 = (Get-FileHash -LiteralPath $guiPath -Algorithm SHA256).Hash.ToLowerInvariant()
            serviceExeSha256 = (Get-FileHash -LiteralPath $serviceExePath -Algorithm SHA256).Hash.ToLowerInvariant()
            trafficRequest = $trafficRequest
            trafficVerification = $trafficVerification
            trafficStartedUtc = $trafficStartedUtc
            trafficCompletedUtc = $trafficCompletedUtc
        }
    }
    $candidateCheck = {
        param($context, $actionResult)
        $script:preflightHandoffCandidateChecks++
        $legacyFileCount = @($context.Capture.rollbackState.legacyState.files | Where-Object { $_.present }).Count
        $legacyAclDriftCount = 0
        foreach ($entry in @($context.Capture.rollbackState.legacyState.files | Where-Object { $_.present })) {
            if ((Get-Acl -LiteralPath ([string]$entry.path)).Sddl -cne [string]$entry.sddl) { $legacyAclDriftCount++ }
        }
        $trafficVerification = Assert-CvrIdleCandidateTrafficVerification -Verification $actionResult.trafficVerification -Request $actionResult.trafficRequest -StartedUtc $actionResult.trafficStartedUtc -CompletedUtc $actionResult.trafficCompletedUtc
        return (
            $script:syntheticCandidateRunning -and
            [string]$actionResult.candidateCoreSha256 -ceq [string]$context.ExpectedPins.candidateCore -and
            [string]$actionResult.programFilesCoreSha256 -ceq [string]$context.ExpectedPins.candidateCore -and
            [string]$actionResult.serviceCoreSha256 -ceq [string]$context.ExpectedPins.candidateCore -and
            (Get-Acl -LiteralPath $guiPath).Sddl -cne [string]$context.Capture.rollbackState.gui.sddl -and
            (Get-Acl -LiteralPath $serviceExePath).Sddl -cne [string]$context.Capture.rollbackState.serviceExe.sddl -and
            (Get-Acl -LiteralPath $programFilesPath).Sddl -cne [string]$context.Capture.corePair.programFiles.sddl -and
            (Get-Acl -LiteralPath $serviceCorePath).Sddl -cne [string]$context.Capture.corePair.service.sddl -and
            $legacyAclDriftCount -eq $legacyFileCount -and
            [string]$actionResult.guiSha256 -ceq $expectedCandidateGuiSha256 -and
            [string]$actionResult.serviceExeSha256 -ceq $expectedCandidateServiceSha256 -and
            $trafficVerification.status -ceq 'PASS' -and
            @($trafficVerification.protocols).Count -eq 2
        )
    }
    $restoreAction = {
        param($context, $actionResult)
        $script:preflightHandoffRestoreCalls++
        try {
            Restore-CvrCoreFilePreimage -Entry $context.Capture.corePair.programFiles -Role 'Program Files'
            Restore-CvrCoreFilePreimage -Entry $context.Capture.corePair.service -Role 'service'
            $null = Restore-CvrIdleFilePreimage -Entry $context.Capture.rollbackState.gui -Role 'gui' -ExpectedPath $guiPath -ExpectedLocalRoot $localRoot -ExpectedInstallDirectory $programFilesDirectory -ExpectedSha256 ([string]$context.ExpectedPins.gui258)
            $null = Restore-CvrIdleFilePreimage -Entry $context.Capture.rollbackState.serviceExe -Role 'service-exe' -ExpectedPath $serviceExePath -ExpectedLocalRoot $localRoot -ExpectedInstallDirectory $programFilesDirectory -ExpectedSha256 ([string]$context.ExpectedPins.serviceExe258)
            Restore-CvrLegacyState -State $context.Capture.rollbackState.legacyState
            return 'synthetic-idle-restored'
        } finally {
            $script:syntheticCandidateRunning = $false
        }
    }
    $verifyRestore = {
        param($context, $restoreResult, $actionResult)
        $script:preflightHandoffVerifyCalls++
        Assert-CvrLegacyState -Expected $context.Capture.rollbackState.legacyState -Phase 'synthetic handoff verification'
        return ($restoreResult -ceq 'synthetic-idle-restored')
    }
    $transactionArguments = @{
        CaptureReceiptPath = $operatorCaptureReceiptPath
        PlanPath = $operatorPlanPath
        PreflightReceiptPath = $operatorPreflightReceiptPath
        ExpectedPlanSha256 = [string]$validOperatorResult.planSha256
        ExpectedStageRoot = $stageRoot
        ExpectedPackageManifestSha256 = $manifestSha256
        ExpectedTargetIdentity = $targetIdentity
        ExpectedPins = $expectedPins
        RefreshObservationScript = $refreshObservation
        ActionScript = $candidateAction
        CandidateCheckScript = $candidateCheck
        RestoreScript = $restoreAction
        VerifyScript = $verifyRestore
    }
    $handoff = Invoke-CvrIdlePreflightTargetTransaction @transactionArguments
    $handoffAccepted = (
        $handoff.status -ceq 'PASS' -and
        $null -eq $handoff.actionErrorType -and
        $null -eq $handoff.restoreErrorType -and
        $script:preflightHandoffActionCalls -eq 1 -and
        $script:preflightHandoffCandidateChecks -eq 1 -and
        $script:preflightHandoffRestoreCalls -eq 1 -and
        -not $script:syntheticCandidateRunning
    )
    if (-not $handoffAccepted) {
        $handoffType = '<null>'
        $handoffCount = 0
        $handoffStatus = '<missing>'
        $handoffActionErrorType = '<missing>'
        $handoffRestoreErrorType = '<missing>'
        if ($null -ne $handoff) {
            if ($handoff -is [PSCustomObject]) {
                $handoffType = 'PSCustomObject'
                $handoffCount = @($handoff.PSObject.Properties).Count
            } elseif ($handoff -is [System.Collections.IDictionary]) {
                $handoffType = 'IDictionary'
                $handoffCount = $handoff.Count
            } elseif ($handoff -is [System.Collections.ICollection]) {
                $handoffType = 'ICollection'
                $handoffCount = $handoff.Count
            } else {
                $handoffType = '<other>'
                $handoffCount = @($handoff.PSObject.Properties).Count
            }
            $statusProperty = $handoff.PSObject.Properties['status']
            if ($statusProperty) {
                if ([string]$statusProperty.Value -cin @('PASS','ACTION_FAILED_RESTORED','RESTORE_FAILED')) {
                    $handoffStatus = [string]$statusProperty.Value
                } else {
                    $handoffStatus = '<other>'
                }
            }
            $actionErrorProperty = $handoff.PSObject.Properties['actionErrorType']
            if ($actionErrorProperty) {
                if ($null -eq $actionErrorProperty.Value) {
                    $handoffActionErrorType = $null
                } elseif ($actionErrorProperty.Value -is [string] -and
                    [string]$actionErrorProperty.Value -match '^[A-Za-z][A-Za-z0-9_.]{0,63}$') {
                    $handoffActionErrorType = [string]$actionErrorProperty.Value
                } else {
                    $handoffActionErrorType = '<other>'
                }
            }
            $restoreErrorProperty = $handoff.PSObject.Properties['restoreErrorType']
            if ($restoreErrorProperty) {
                if ($null -eq $restoreErrorProperty.Value) {
                    $handoffRestoreErrorType = $null
                } elseif ($restoreErrorProperty.Value -is [string] -and
                    [string]$restoreErrorProperty.Value -match '^[A-Za-z][A-Za-z0-9_.]{0,63}$') {
                    $handoffRestoreErrorType = [string]$restoreErrorProperty.Value
                } else {
                    $handoffRestoreErrorType = '<other>'
                }
            }
        }
        $failurePhase = if ($script:preflightHandoffRestoreCalls -eq 0) { 'before-restore' } elseif ($script:preflightHandoffVerifyCalls -gt 0) { 'verify' } else { 'restore-callback' }
        $failureEvidence = [ordered]@{
            phase = $failurePhase
            status = $handoffStatus
            actionErrorType = $handoffActionErrorType
            restoreErrorType = $handoffRestoreErrorType
            resultType = $handoffType
            resultCount = [int]$handoffCount
            actionCalls = [int]$script:preflightHandoffActionCalls
            candidateCheckCalls = [int]$script:preflightHandoffCandidateChecks
            restoreCalls = [int]$script:preflightHandoffRestoreCalls
            verifyCalls = [int]$script:preflightHandoffVerifyCalls
            syntheticCandidateRunning = [bool]$script:syntheticCandidateRunning
        }
        $evidenceJson = ConvertTo-Json -InputObject $failureEvidence -Compress -Depth 3 -ErrorAction Stop
        throw ("The verified public Preflight handoff did not run candidate acceptance and exact restore. evidence=" + $evidenceJson)
    }
    Assert-PreflightTestSnapshot $handoffSnapshot $handoffTargets
    Assert-CvrLegacyState -Expected $legacyFixture.state -Phase 'successful candidate handoff'

    $rejectedCandidateArguments = @{}
    foreach ($key in $transactionArguments.Keys) { $rejectedCandidateArguments[$key] = $transactionArguments[$key] }
    $rejectedCandidateArguments.CandidateCheckScript = {
        param($context, $actionResult)
        $invalidReceipt = $actionResult.trafficVerification
        $invalidReceipt.challenge = 'e' * 32
        $null = Assert-CvrIdleCandidateTrafficVerification -Verification $invalidReceipt -Request $actionResult.trafficRequest -StartedUtc $actionResult.trafficStartedUtc -CompletedUtc $actionResult.trafficCompletedUtc
        return [bool]$true
    }
    $candidateRejected = Invoke-CvrIdlePreflightTargetTransaction @rejectedCandidateArguments
    Assert-PreflightTest (
        $candidateRejected.status -ceq 'ACTION_FAILED_RESTORED' -and
        $candidateRejected.actionErrorType -ceq 'RuntimeException' -and
        $candidateRejected.restoreErrorType -ceq $null -and
        $script:preflightHandoffRestoreCalls -eq 2 -and
        -not $script:syntheticCandidateRunning
    ) 'A rejected candidate identity/traffic result did not trigger restoration.'
    Assert-PreflightTestSnapshot $handoffSnapshot $handoffTargets
    Assert-CvrLegacyState -Expected $legacyFixture.state -Phase 'candidate rejection restore'

    $failedActionArguments = @{}
    foreach ($key in $transactionArguments.Keys) { $failedActionArguments[$key] = $transactionArguments[$key] }
    $failedActionArguments.ActionScript = {
        param($context)
        $script:preflightHandoffActionCalls++
        $script:syntheticCandidateRunning = $true
        $candidateCoreBytes = [IO.File]::ReadAllBytes([string]$context.Capture.pinnedFiles.candidateCore)
        [IO.File]::WriteAllBytes($guiPath, $candidateGuiBytes)
        [IO.File]::WriteAllBytes($serviceExePath, $candidateServiceBytes)
        [IO.File]::WriteAllBytes($programFilesPath, $candidateCoreBytes)
        [IO.File]::WriteAllBytes($serviceCorePath, $candidateCoreBytes)
        foreach ($path in @($guiPath, $serviceExePath, $programFilesPath, $serviceCorePath)) { Add-PreflightTestAclDrift -Path $path }
        foreach ($entry in @($context.Capture.rollbackState.legacyState.files)) {
            if ($entry.present) {
                [IO.File]::WriteAllBytes([string]$entry.path, $candidateCheckBytes)
                Add-PreflightTestAclDrift -Path ([string]$entry.path)
            }
        }
        foreach ($entry in @($context.Capture.rollbackState.legacyState.registry)) {
            if ($entry.present) { Set-CvrLegacyRunValue -Hive ([string]$entry.hive) -Name ([string]$entry.name) -Kind ([string]$entry.kind) -Data 'STCVRC-synthetic-failure' }
        }
        throw 'synthetic acceptance failure after changes'
    }
    $actionFailure = Invoke-CvrIdlePreflightTargetTransaction @failedActionArguments
    Assert-PreflightTest (
        $actionFailure.status -ceq 'ACTION_FAILED_RESTORED' -and
        $actionFailure.actionErrorType -ceq 'RuntimeException' -and
        $actionFailure.restoreErrorType -ceq $null -and
        $script:preflightHandoffRestoreCalls -eq 3 -and
        -not $script:syntheticCandidateRunning
    ) 'An injected candidate failure did not remain visible after exact restoration.'
    Assert-PreflightTestSnapshot $handoffSnapshot $handoffTargets
    Assert-CvrLegacyState -Expected $legacyFixture.state -Phase 'injected action failure restore'

    $stopMutationCalls = 0
    $stopRefusal = $null
    try {
        Invoke-CvrIdleStoppedMutation -StopScript { throw 'synthetic stop failure' } -MutationScript { $script:stopMutationCalls++ }
    } catch { $stopRefusal = $_.Exception.GetBaseException().GetType().Name }
    Assert-PreflightTest ($stopRefusal -ceq 'InvalidOperationException' -and $stopMutationCalls -eq 0) 'A failed stopped-state proof reached the dependent mutation.'

    $script:stopFailureActionSnapshot = $null
    $script:stopFailureDependentMutationCalls = 0
    $stopFailureArguments = @{}
    foreach ($key in $transactionArguments.Keys) { $stopFailureArguments[$key] = $transactionArguments[$key] }
    $stopFailureArguments.ActionScript = {
        param($context)
        $script:preflightHandoffActionCalls++
        $script:syntheticCandidateRunning = $true
        [IO.File]::WriteAllBytes($guiPath, $candidateGuiBytes)
        Add-PreflightTestAclDrift -Path $guiPath
        $script:stopFailureActionSnapshot = Get-PreflightTestSnapshot -Paths $handoffTargets
        throw 'synthetic candidate failure before rollback stop proof'
    }
    $stopFailureArguments.RestoreScript = {
        param($context, $actionResult)
        $null = Invoke-CvrIdleStoppedMutation -StopScript { throw 'synthetic stop proof failure' } -MutationScript {
            $script:stopFailureDependentMutationCalls++
            & $restoreAction $context $actionResult
        }
    }
    $stopFailure = Invoke-CvrIdlePreflightTargetTransaction @stopFailureArguments
    $stopFailureAfter = Get-PreflightTestSnapshot -Paths $handoffTargets
    $stopFailureStatePreserved = $true
    foreach ($path in $handoffTargets) {
        if ($script:stopFailureActionSnapshot[$path].Sha256 -cne $stopFailureAfter[$path].Sha256 -or
            $script:stopFailureActionSnapshot[$path].Sddl -cne $stopFailureAfter[$path].Sddl) {
            $stopFailureStatePreserved = $false
        }
    }
    Assert-PreflightTest (
        $stopFailure.status -ceq 'RESTORE_FAILED' -and
        $stopFailure.actionErrorType -ceq 'RuntimeException' -and
        $stopFailure.restoreErrorType -ceq 'InvalidOperationException' -and
        $script:stopFailureDependentMutationCalls -eq 0 -and
        $script:syntheticCandidateRunning -and
        $script:stopFailureActionSnapshot[$guiPath].Sha256 -cne $handoffSnapshot[$guiPath].Sha256 -and
        $stopFailureStatePreserved
    ) 'An Action failure with an unproven stop did not fail rollback before its dependent writes.'
    $stopCleanupContext = [PSCustomObject]@{
        Capture = ConvertTo-CvrIdleTransactionCapture -Receipt $operatorCaptureReceipt
        ExpectedPins = $expectedPins
    }
    $null = & $restoreAction $stopCleanupContext $null
    Assert-PreflightTestSnapshot $handoffSnapshot $handoffTargets
    Assert-CvrLegacyState -Expected $legacyFixture.state -Phase 'stop-failure fixture cleanup'

    $restoreFailureArguments = @{}
    foreach ($key in $transactionArguments.Keys) { $restoreFailureArguments[$key] = $transactionArguments[$key] }
    $restoreFailureArguments.RestoreScript = {
        param($context, $actionResult)
        $script:preflightHandoffRestoreCalls++
        $script:syntheticCandidateRunning = $false
        throw 'synthetic restore failure'
    }
    $restoreFailure = Invoke-CvrIdlePreflightTargetTransaction @restoreFailureArguments
    $afterRestoreFailure = Get-PreflightTestSnapshot -Paths $handoffTargets
    Assert-PreflightTest (
        $restoreFailure.status -ceq 'RESTORE_FAILED' -and
        $null -eq $restoreFailure.actionErrorType -and
        $restoreFailure.restoreErrorType -ceq 'RuntimeException' -and
        $script:preflightHandoffActionCalls -eq 5 -and
        $script:preflightHandoffCandidateChecks -eq 2 -and
        $script:preflightHandoffRestoreCalls -eq 5 -and
        -not $script:syntheticCandidateRunning -and
        $afterRestoreFailure[$programFilesPath].Sha256 -cne $handoffSnapshot[$programFilesPath].Sha256
    ) 'An injected restore exception was not reported as RESTORE_FAILED with the changed preimage visible.'
    $cleanupContext = [PSCustomObject]@{
        Capture = ConvertTo-CvrIdleTransactionCapture -Receipt $operatorCaptureReceipt
        ExpectedPins = $expectedPins
    }
    $null = & $restoreAction $cleanupContext $null
    Assert-PreflightTestSnapshot $handoffSnapshot $handoffTargets
    Assert-CvrLegacyState -Expected $legacyFixture.state -Phase 'restore-failure fixture cleanup'

    function Assert-HandoffRefusalUnchanged([string]$Reason) {

        $current = Get-PreflightTestSnapshot -Paths $handoffTargets
        foreach ($path in $handoffTargets) {
            if ($current[$path].Sha256 -cne $handoffSnapshot[$path].Sha256 -or $current[$path].Sddl -cne $handoffSnapshot[$path].Sddl) {
                throw ('Idle handoff refusal changed a synthetic preimage: ' + $Reason)
            }
        }
        Assert-CvrLegacyState -Expected $legacyFixture.state -Phase ('handoff refusal ' + $Reason)
        if ($script:transactionNegativeActionCalls -ne 0) { throw ('Idle handoff refusal invoked Action: ' + $Reason) }
    }
    $wrongPlanSha = '0' * 64
    if ($wrongPlanSha -ceq [string]$validOperatorResult.planSha256) { $wrongPlanSha = 'f' * 64 }
    $refusal = $null
    $wrongPlanArguments = @{}
    foreach ($key in $transactionArguments.Keys) { $wrongPlanArguments[$key] = $transactionArguments[$key] }
    $wrongPlanArguments.ExpectedPlanSha256 = $wrongPlanSha
    $wrongPlanArguments.ActionScript = { $script:transactionNegativeActionCalls++; 'unexpected' }
    try {
        Invoke-CvrIdlePreflightTargetTransaction @wrongPlanArguments
    } catch { $refusal = $_.Exception.GetType().Name }
    Assert-PreflightTest (-not [string]::IsNullOrEmpty($refusal)) 'Mismatched Plan SHA was not rejected before Action.'
    Assert-HandoffRefusalUnchanged 'plan-sha'

    function Assert-InvalidPreflightHandoff {
        param([string]$Reason, [scriptblock]$Mutate)
        $badPreflightId = [Guid]::NewGuid().ToString('N')
        $badPreflightDirectory = Join-Path $localRoot ('preflight-idle-' + $badPreflightId)
        New-PreflightTestDirectory $badPreflightDirectory
        try {
            $badPreflightPath = Join-Path $badPreflightDirectory 'result.json'
            $badPreflightRecord = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($operatorPreflightReceiptPath, [Text.UTF8Encoding]::new($false, $true))) -ErrorAction Stop
            $badPreflightRecord.receiptId = $badPreflightId
            & $Mutate $badPreflightRecord
            Write-PreflightTestFile -Path $badPreflightPath -Bytes ([Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-Json -InputObject $badPreflightRecord -Depth 5 -Compress))) -Protected
            $refusal = $null
            $badPreflightArguments = @{}
            foreach ($key in $transactionArguments.Keys) { $badPreflightArguments[$key] = $transactionArguments[$key] }
            $badPreflightArguments.PreflightReceiptPath = $badPreflightPath
            $badPreflightArguments.ActionScript = { $script:transactionNegativeActionCalls++; 'unexpected' }
            try {
                Invoke-CvrIdlePreflightTargetTransaction @badPreflightArguments
            } catch { $refusal = $_.Exception.GetType().Name }
            Assert-PreflightTest ($refusal -and $script:transactionNegativeActionCalls -eq 0) ('Malformed Preflight receipt reached Action: ' + $Reason)
            Assert-HandoffRefusalUnchanged $Reason
        } finally {
            if (Test-Path -LiteralPath $badPreflightDirectory) { Remove-Item -LiteralPath $badPreflightDirectory -Recurse -Force -ErrorAction Stop }
            Assert-PreflightTest (-not (Test-Path -LiteralPath $badPreflightDirectory)) 'Handoff refusal fixture cleanup failed.'
        }
    }
    Assert-InvalidPreflightHandoff 'preflight-fail' {
        param($record)
        $record.result = 'FAIL'
        $record.exitCode = 1
        $record.childExitCode = 1
    }
    Assert-InvalidPreflightHandoff 'preflight-schema-missing' {
        param($record)
        $null = $record.PSObject.Properties.Remove('schemaVersion')
    }
    Assert-InvalidPreflightHandoff 'preflight-schema-version' {
        param($record)
        $record.schemaVersion = 2
    }
    Assert-InvalidPreflightHandoff 'preflight-schema-type' {
        param($record)
        $record.schemaVersion = '1'
    }
    Assert-InvalidPreflightHandoff 'preflight-exit-missing' {
        param($record)
        $null = $record.PSObject.Properties.Remove('exitCode')
    }
    Assert-InvalidPreflightHandoff 'preflight-exit-type' {
        param($record)
        $record.exitCode = '0'
    }
    Assert-InvalidPreflightHandoff 'preflight-child-exit-missing' {
        param($record)
        $null = $record.PSObject.Properties.Remove('childExitCode')
    }
    Assert-InvalidPreflightHandoff 'preflight-child-exit-type' {
        param($record)
        $record.childExitCode = '0'
    }

    $driftObservation = {
        param($freshCapture)
        $changed = [ordered]@{}
        foreach ($key in $freshCapture.idleObservation.Keys) { $changed[$key] = $freshCapture.idleObservation[$key] }
        $changed.OwnedCoreProcessIds = [int[]]@(8199)
        return [PSCustomObject]@{
            SampledAtUtc = [DateTime]::UtcNow
            Observation = $changed
            Observer = $freshCapture.rollbackState.observer
        }
    }
    $refusal = $null
    $driftArguments = @{}
    foreach ($key in $transactionArguments.Keys) { $driftArguments[$key] = $transactionArguments[$key] }
    $driftArguments.RefreshObservationScript = $driftObservation
    $driftArguments.ActionScript = { $script:transactionNegativeActionCalls++; 'unexpected' }
    try {
        Invoke-CvrIdlePreflightTargetTransaction @driftArguments
    } catch { $refusal = $_.Exception.GetType().Name }
    Assert-PreflightTest (-not [string]::IsNullOrEmpty($refusal)) 'Drifted fresh owner-scoped observation was not rejected before Action.'
    Assert-HandoffRefusalUnchanged 'fresh-observation-drift'

    $wrongRootBefore = Get-CaptureOperatorOutputCounts -LocalRoot $localRoot
    $wrongRoot = Invoke-CaptureOperatorTestCommand -BootstrapPath $bootstrapPath -OperatorPath $operatorPath -StageRoot $fixtureRoot -ManifestSha256 $manifestSha256 -RequestPath $seedPath -ScenarioPath (Save-CaptureOperatorScenario -Name 'wrong-stage-root' -Scenario (New-CaptureOperatorScenario)) -TimeoutSeconds 30
    $wrongRootAfter = Get-CaptureOperatorOutputCounts -LocalRoot $localRoot
    Assert-CaptureOperatorNoOutput -Before $wrongRootBefore -After $wrongRootAfter -Reason 'wrong-stage-root'
    Assert-CaptureOperatorResponse -Invocation $wrongRoot -ExpectedStatus 'INCOMPLETE' -ExpectedReason 'stage-path' -StageRoot $fixtureRoot -RequestPath $seedPath -TargetIdentity $targetIdentity -ServiceImagePath $pinPaths.serviceExe258 -OwnerSid $seedRequest.Observer.ExpectedOwnerSid

    $wrongDigestBefore = Get-CaptureOperatorOutputCounts -LocalRoot $localRoot
    $wrongDigest = Invoke-CaptureOperatorTestCommand -BootstrapPath $bootstrapPath -OperatorPath $operatorPath -StageRoot $stageRoot -ManifestSha256 '0000000000000000000000000000000000000000000000000000000000000000' -RequestPath $seedPath -ScenarioPath (Save-CaptureOperatorScenario -Name 'wrong-stage-digest' -Scenario (New-CaptureOperatorScenario)) -TimeoutSeconds 30
    $wrongDigestAfter = Get-CaptureOperatorOutputCounts -LocalRoot $localRoot
    Assert-CaptureOperatorNoOutput -Before $wrongDigestBefore -After $wrongDigestAfter -Reason 'wrong-stage-digest'
    Assert-CaptureOperatorResponse -Invocation $wrongDigest -ExpectedStatus 'INCOMPLETE' -ExpectedReason 'stage-pin' -StageRoot $stageRoot -RequestPath $seedPath -TargetIdentity $targetIdentity -ServiceImagePath $pinPaths.serviceExe258 -OwnerSid $seedRequest.Observer.ExpectedOwnerSid

    Assert-CaptureOperatorNegative -Name 'unknown-owner' -Scenario (New-CaptureOperatorScenario -UnknownServiceOwner) -Status 'INCOMPLETE' -Reason 'unknown-ownership'
    Assert-CaptureOperatorNegative -Name 'unknown-listener' -Scenario (New-CaptureOperatorScenario -UnknownListener) -Status 'INCOMPLETE' -Reason 'unknown-unavailable'
    Assert-CaptureOperatorNegative -Name 'running-core' -Scenario (New-CaptureOperatorScenario -RunningCore) -Status 'REFUSED' -Reason 'not-idle'
    Assert-CaptureOperatorNegative -Name 'running-alpha-core' -Scenario (New-CaptureOperatorScenario -RunningAlpha) -Status 'REFUSED' -Reason 'not-idle'
    Assert-CaptureOperatorNegative -Name 'orphan-service-process' -Scenario (New-CaptureOperatorScenario -OrphanService) -Status 'INCOMPLETE' -Reason 'unknown-service-pid'
    Assert-CaptureOperatorNegative -Name 'duplicate-service-process' -Scenario (New-CaptureOperatorScenario -DuplicateService) -Status 'INCOMPLETE' -Reason 'unknown-service-pid'

    foreach ($pinName in @('candidateCore','updateInstaller','recoveryInstaller')) {
        $alternatePath = Join-Path $localRoot ($pinName + '-alternate.exe')
        $alternateBytes = [byte[]]@(99, 88, 77)
        Write-PreflightTestFile -Path $alternatePath -Bytes $alternateBytes -Protected
        $alternateSeed = ConvertFrom-Json -InputObject ([Text.UTF8Encoding]::new($false, $true).GetString($seedBytes)) -ErrorAction Stop
        $alternateSha = (Get-FileHash -LiteralPath $alternatePath -Algorithm SHA256).Hash.ToLowerInvariant()
        $alternateSeed.Capture.pinnedFiles.$pinName = $alternatePath
        $alternateSeed.ExpectedPins.$pinName = $alternateSha
        [IO.File]::WriteAllBytes($seedPath, [Text.UTF8Encoding]::new($false, $true).GetBytes((ConvertTo-Json -InputObject $alternateSeed -Depth 20 -Compress -ErrorAction Stop)))
        try {
            $alternateBefore = Get-CaptureOperatorOutputCounts -LocalRoot $localRoot
            $alternate = Invoke-CaptureOperatorTestCommand -BootstrapPath $bootstrapPath -OperatorPath $operatorPath -StageRoot $stageRoot -ManifestSha256 $manifestSha256 -RequestPath $seedPath -ScenarioPath (Save-CaptureOperatorScenario -Name ($pinName + '-alternate-pin') -Scenario (New-CaptureOperatorScenario)) -TimeoutSeconds 30
            $alternateAfter = Get-CaptureOperatorOutputCounts -LocalRoot $localRoot
            Assert-CaptureOperatorNoOutput -Before $alternateBefore -After $alternateAfter -Reason 'alternate-stage-pin'
            Assert-CaptureOperatorResponse -Invocation $alternate -ExpectedStatus 'INCOMPLETE' -ExpectedReason 'stage-pin' -StageRoot $stageRoot -RequestPath $seedPath -TargetIdentity $targetIdentity -ServiceImagePath $pinPaths.serviceExe258 -OwnerSid $seedRequest.Observer.ExpectedOwnerSid
            Assert-PreflightTest (-not $alternate.StdOut.Contains($alternatePath) -and -not $alternate.StdErr.Contains($alternatePath)) 'Capture operator disclosed an alternate seed path.'
        } finally {
            [IO.File]::WriteAllBytes($seedPath, $seedBytes)
            if (Test-Path -LiteralPath $alternatePath -PathType Leaf) { Remove-Item -LiteralPath $alternatePath -Force -ErrorAction Stop }
        }
        Assert-PreflightTest (-not (Test-Path -LiteralPath $alternatePath)) 'Alternate seed fixture cleanup failed.'
    }

    $staleSeed = ConvertFrom-Json -InputObject ([Text.UTF8Encoding]::new($false, $true).GetString($seedBytes)) -ErrorAction Stop
    $staleSeed.Capture | Add-Member -MemberType NoteProperty -Name capturedAtUtc -Value ([DateTime]::UtcNow.AddMinutes(-6).ToString('o'))
    [IO.File]::WriteAllBytes($seedPath, [Text.UTF8Encoding]::new($false, $true).GetBytes((ConvertTo-Json -InputObject $staleSeed -Depth 20 -Compress -ErrorAction Stop)))
    try {
        Assert-CaptureOperatorNegative -Name 'stale-seed' -Scenario (New-CaptureOperatorScenario) -Status 'INCOMPLETE' -Reason 'stale-seed'
    } finally {
        [IO.File]::WriteAllBytes($seedPath, $seedBytes)
    }

    $programFilesOriginalBytes = [IO.File]::ReadAllBytes($programFilesPath)
    try {
        [IO.File]::WriteAllBytes($programFilesPath, [byte[]]@(9, 9, 9, 9))
        Assert-CaptureOperatorNegative -Name 'pin-drift' -Scenario (New-CaptureOperatorScenario) -Status 'INCOMPLETE' -Reason 'unknown-pin-drift'
    } finally {
        [IO.File]::WriteAllBytes($programFilesPath, $programFilesOriginalBytes)
    }
    Assert-PreflightTestSnapshot $operatorInputSnapshot $operatorTrackedPaths

    $wrongWriterManifest = ('0' * 64)
    if ($manifestSha256 -ceq $wrongWriterManifest) { $wrongWriterManifest = ('f' * 64) }
    $badCaptureRequest = [ordered]@{}
    foreach ($name in $writerRequest.Keys) { $badCaptureRequest[$name] = $writerRequest[$name] }
    $badCaptureRequest.ExpectedPackageManifestSha256 = $wrongWriterManifest
    $captureDirectoriesBefore = @(Get-ChildItem -LiteralPath $localRoot -Directory -Filter 'capture-idle-*' -ErrorAction Stop | ForEach-Object { $_.FullName })
    $badCapture = Invoke-PreflightTestCommand -ScriptPath $writerPath -WriterMode Capture -Request $badCaptureRequest -TimeoutSeconds 30
    $captureDirectoriesAfter = @(Get-ChildItem -LiteralPath $localRoot -Directory -Filter 'capture-idle-*' -ErrorAction Stop | ForEach-Object { $_.FullName })
    Assert-PreflightTest (
        $badCapture.ExitCode -ne 0 -and $null -eq $badCapture.Document -and
        [string]::IsNullOrEmpty($badCapture.StdOut) -and
        -not [string]::IsNullOrEmpty($badCapture.StdErr) -and
        $captureDirectoriesAfter.Count -eq $captureDirectoriesBefore.Count
    ) 'Invalid Capture stage pin was not rejected before output.'

    $writerRequest.Capture.capturedAtUtc = [DateTime]::UtcNow.ToString('o')
    $captureInvocation = Invoke-PreflightTestCommand -ScriptPath $writerPath -WriterMode Capture -Request $writerRequest -TimeoutSeconds 30
    Assert-PreflightTest ($captureInvocation.ExitCode -eq 0 -and $null -ne $captureInvocation.Document -and [string]::IsNullOrEmpty($captureInvocation.StdErr)) 'The actual PS5.1 Capture CLI did not return a clean result.'
    $captureResult = $captureInvocation.Document
    Assert-PreflightTest (
        (Test-Path -LiteralPath $captureResult.ReceiptPath -PathType Leaf) -and
        (Test-Path -LiteralPath $captureResult.CaptureDirectory -PathType Container) -and
        [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($captureResult.CaptureDirectory)) -ieq [IO.Path]::GetFullPath($localRoot) -and
        [IO.Path]::GetFileName($captureResult.CaptureDirectory) -match '^capture-idle-[0-9a-f]{32}$'
    ) 'The actual Capture CLI did not write its protected receipt under the staged local root.'
    $null = Assert-CvrIdleCaptureAcl -Path $captureResult.CaptureDirectory -Directory
    $null = Assert-CvrIdleCaptureAcl -Path $captureResult.ReceiptPath
    $captureReceipt = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($captureResult.ReceiptPath, [Text.UTF8Encoding]::new($false, $true))) -ErrorAction Stop
    Assert-PreflightTest (
        [IO.Path]::GetFullPath([string]$captureReceipt.packageStageBinding.stageRoot) -ceq $stageRoot -and
        [string]$captureReceipt.packageStageBinding.sourceManifestSha256 -ceq $manifestSha256
    ) 'The actual Capture CLI receipt did not bind the synthetic stage.'

    $planRequest = [ordered]@{}
    foreach ($name in $writerRequest.Keys) { $planRequest[$name] = $writerRequest[$name] }
    $planRequest.CaptureDirectory = [string]$captureResult.CaptureDirectory
    $planRequest.ReceiptPath = [string]$captureResult.ReceiptPath
    $planRequest.ExpectedPackageManifestSha256 = $wrongWriterManifest
    $planDirectoriesBefore = @(Get-ChildItem -LiteralPath $localRoot -Directory -Filter 'prepared-idle-*' -ErrorAction Stop | ForEach-Object { $_.FullName })
    $badPlan = Invoke-PreflightTestCommand -ScriptPath $writerPath -WriterMode Plan -Request $planRequest -TimeoutSeconds 30
    $planDirectoriesAfter = @(Get-ChildItem -LiteralPath $localRoot -Directory -Filter 'prepared-idle-*' -ErrorAction Stop | ForEach-Object { $_.FullName })
    Assert-PreflightTest (
        $badPlan.ExitCode -ne 0 -and $null -eq $badPlan.Document -and
        [string]::IsNullOrEmpty($badPlan.StdOut) -and
        -not [string]::IsNullOrEmpty($badPlan.StdErr) -and
        $planDirectoriesAfter.Count -eq $planDirectoriesBefore.Count
    ) 'Invalid Plan stage pin was not rejected before output.'

    $planRequest.ExpectedPackageManifestSha256 = $manifestSha256
    $planInvocation = Invoke-PreflightTestCommand -ScriptPath $writerPath -WriterMode Plan -Request $planRequest -TimeoutSeconds 30
    Assert-PreflightTest ($planInvocation.ExitCode -eq 0 -and $null -ne $planInvocation.Document -and [string]::IsNullOrEmpty($planInvocation.StdErr)) 'The actual PS5.1 Plan CLI did not return a clean result.'
    $plan = $planInvocation.Document
    Assert-PreflightTest (
        (Test-Path -LiteralPath $plan.PlanPath -PathType Leaf) -and
        [IO.Path]::GetFileName($plan.PlanPath) -ceq 'plan.json' -and
        [IO.Path]::GetFileName([IO.Path]::GetDirectoryName($plan.PlanPath)) -match '^prepared-idle-[0-9a-f]{32}$'
    ) 'The actual Plan CLI did not write the protected plan.'
    $null = Assert-CvrIdleCaptureAcl -Path ([IO.Path]::GetDirectoryName($plan.PlanPath)) -Directory
    $null = Assert-CvrIdleCaptureAcl -Path $plan.PlanPath
    $planRecord = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($plan.PlanPath, [Text.UTF8Encoding]::new($false, $true))) -ErrorAction Stop
    $planSha256 = (Get-FileHash -LiteralPath $plan.PlanPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    Assert-PreflightTest (
        [IO.Path]::GetFullPath([string]$planRecord.packageStageBinding.stageRoot) -ceq $stageRoot -and
        [string]$planRecord.packageStageBinding.sourceManifestSha256 -ceq $manifestSha256 -and
        [string]$plan.PlanSha256 -ceq $planSha256
    ) 'The actual Plan CLI did not produce the pinned stage-bound plan.'

    $scriptPath = Join-Path $PSScriptRoot 'windows_idle_preflight.ps1'
    $trackedPaths = @(
        $manifestPath, $programFilesPath, $serviceCorePath, $guiPath, $serviceExePath,
        $programFilesBackup.backup, $serviceBackup.backup
    ) + @($legacyFixture.state.files | Where-Object { $_.present } | ForEach-Object { $_.path }) +
        @($pinPaths.Values) + @($captureResult.ReceiptPath, $plan.PlanPath)
    $snapshot = Get-PreflightTestSnapshot -Paths $trackedPaths
    $firstPreflight = Invoke-PreflightTestCommand -ScriptPath $scriptPath -PlanPath $plan.PlanPath -PlanSha256 $plan.PlanSha256 -StageRoot $stageRoot -ManifestSha256 $manifestSha256 -TimeoutSeconds 30
    Assert-PreflightReceipt -Invocation $firstPreflight -ExpectedResult 'PASS' -ExpectedExitCode 0 -ExpectedChildExitCode 0 -ExpectedTimedOut $false -StageRoot $stageRoot
    Assert-PreflightTestSnapshot $snapshot $trackedPaths

    $wrongPlan = ('0' * 64)
    if ($plan.PlanSha256 -ceq $wrongPlan) { $wrongPlan = ('f' * 64) }
    $failedPreflight = Invoke-PreflightTestCommand -ScriptPath $scriptPath -PlanPath $plan.PlanPath -PlanSha256 $wrongPlan -StageRoot $stageRoot -ManifestSha256 $manifestSha256 -TimeoutSeconds 30
    Assert-PreflightReceipt -Invocation $failedPreflight -ExpectedResult 'FAIL' -ExpectedExitCode 1 -ExpectedChildExitCode 1 -ExpectedTimedOut $false -StageRoot $stageRoot
    Assert-PreflightTestSnapshot $snapshot $trackedPaths

    $preflightDirectoriesBefore = @(Get-ChildItem -LiteralPath $localRoot -Directory -Filter 'preflight-idle-*' -ErrorAction Stop | ForEach-Object { $_.FullName })
    $wrongManifest = ('0' * 64)
    if ($manifestSha256 -ceq $wrongManifest) { $wrongManifest = ('f' * 64) }
    $wrongBinding = Invoke-PreflightTestCommand -ScriptPath $scriptPath -PlanPath $plan.PlanPath -PlanSha256 $plan.PlanSha256 -StageRoot $stageRoot -ManifestSha256 $wrongManifest -TimeoutSeconds 30
    $preflightDirectoriesAfter = @(Get-ChildItem -LiteralPath $localRoot -Directory -Filter 'preflight-idle-*' -ErrorAction Stop | ForEach-Object { $_.FullName })
    Assert-PreflightTest ($wrongBinding.ExitCode -ne 0 -and $null -eq $wrongBinding.Document -and $preflightDirectoriesAfter.Count -eq $preflightDirectoriesBefore.Count) 'Invalid external stage pin was not rejected before output.'
    Assert-PreflightTestSnapshot $snapshot $trackedPaths

    $timeoutPreflight = Invoke-PreflightTestCommand -ScriptPath $scriptPath -PlanPath $plan.PlanPath -PlanSha256 $plan.PlanSha256 -StageRoot $stageRoot -ManifestSha256 $manifestSha256 -TimeoutSeconds 1 -SyntheticDelaySeconds 10
    Assert-PreflightReceipt -Invocation $timeoutPreflight -ExpectedResult 'TIMEOUT' -ExpectedExitCode 124 -ExpectedChildExitCode $null -ExpectedTimedOut $true -StageRoot $stageRoot
    Assert-PreflightTestSnapshot $snapshot $trackedPaths

    $reparseAppData = Join-Path $fixtureRoot 'reparse-appdata'
    $outsideAppData = Join-Path $fixtureRoot 'outside-appdata'
    New-PreflightTestDirectory $reparseAppData
    New-PreflightTestDirectory $outsideAppData
    $reparseWindowStateRoot = Join-Path $reparseAppData 'io.github.clash-verge-rev.clash-verge-rev'
    $sentinelPath = Join-Path $outsideAppData 'window-state.json'
    Write-PreflightTestFile -Path $sentinelPath -Bytes ([byte[]]@(77, 78, 79, 80))
    $sentinelBefore = Get-PreflightTestSnapshot -Paths @($sentinelPath)
    $junctionCreated = $false
    try {
        $null = & $env:ComSpec /d /c ('mklink /J "{0}" "{1}"' -f $reparseWindowStateRoot, $outsideAppData) 2>&1
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $reparseWindowStateRoot)) {
            throw 'Could not create the synthetic AppData junction.'
        }
        $junctionCreated = $true
        $env:APPDATA = $reparseAppData

        $readRefusal = $null
        try { $null = Get-CvrLegacyState } catch { $readRefusal = $_.Exception.GetType().Name }
        Assert-PreflightTest (-not [string]::IsNullOrEmpty($readRefusal)) 'Legacy Capture read accepted an AppData reparse path.'
        Assert-PreflightTestSnapshot $sentinelBefore @($sentinelPath)

        $script:reparseActionCalls = 0
        $reparseArguments = @{}
        foreach ($key in $transactionArguments.Keys) { $reparseArguments[$key] = $transactionArguments[$key] }
        $reparseArguments.ActionScript = { $script:reparseActionCalls++; 'unexpected' }
        $handoffRefusal = $null
        try {
            Invoke-CvrIdlePreflightTargetTransaction @reparseArguments
        } catch { $handoffRefusal = $_.Exception.GetType().Name }
        Assert-PreflightTest ($handoffRefusal -and $script:reparseActionCalls -eq 0) 'Reparse drift reached candidate Action.'
        Assert-PreflightTestSnapshot $sentinelBefore @($sentinelPath)

        $unsafeRestoreState = [PSCustomObject]@{
            files = @(
                [PSCustomObject]@{ path=(Join-Path $reparseWindowStateRoot 'window-state.json'); present=$false; bytes=$null; sddl=$null },
                [PSCustomObject]@{ path=(Join-Path $reparseWindowStateRoot '.window-state.json'); present=$false; bytes=$null; sddl=$null }
            )
            registry = @()
        }
        $restoreRefusal = $null
        try {
            Restore-CvrLegacyState -State $unsafeRestoreState
        } catch { $restoreRefusal = $_.Exception.GetType().Name }
        Assert-PreflightTest (-not [string]::IsNullOrEmpty($restoreRefusal)) 'Legacy restore accepted an AppData reparse path or deleted its sentinel.'
        Assert-PreflightTestSnapshot $sentinelBefore @($sentinelPath)

        $missingLeafRefusal = $null
        try { $null = Assert-CvrLegacyStatePath -Path (Join-Path $reparseWindowStateRoot '.window-state.json') }
        catch { $missingLeafRefusal = $_.Exception.GetType().Name }
        Assert-PreflightTest (-not [string]::IsNullOrEmpty($missingLeafRefusal)) 'Legacy path guard missed reparse ancestors for an absent leaf.'
        Assert-PreflightTestSnapshot $sentinelBefore @($sentinelPath)
    } finally {
        $env:APPDATA = Join-Path $fixtureRoot 'appdata'
        if ($junctionCreated) { [IO.Directory]::Delete($reparseWindowStateRoot, $false) }
    }

} finally {
    try {
        if ($legacyFixture) { Remove-CvrSyntheticLegacyPreimage -Fixture $legacyFixture }
    } finally {
        try {
            if (Test-Path -LiteralPath $fixtureRoot -PathType Container) {
                Remove-Item -LiteralPath $fixtureRoot -Recurse -Force -ErrorAction Stop
            }
        } finally {
            $env:APPDATA = $originalAppData
        }
    }
}
Write-Output 'Windows public Capture/Plan/Preflight operator passed synthetic owner, service, alpha-core, stage-pin, idle, receipt-schema, restore, reparse, drift, refusal, and cleanup checks.'
