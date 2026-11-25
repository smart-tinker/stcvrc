[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Capture', 'Plan')]
    [string]$Mode
)

$ErrorActionPreference = 'Stop'

try {
    . (Join-Path $PSScriptRoot 'windows_idle_baseline_guard.ps1')
    . (Join-Path $PSScriptRoot 'windows_idle_transaction.ps1')

    $requestText = [Console]::In.ReadToEnd()
    $request = ConvertFrom-Json -InputObject $requestText -ErrorAction Stop
    if ($request -isnot [PSCustomObject]) { throw 'invalid request' }

    $expectedPins = [ordered]@{}
    foreach ($property in @($request.ExpectedPins.PSObject.Properties)) {
        $expectedPins[[string]$property.Name] = [string]$property.Value
    }

    $capture = $request.Capture
    if ($capture -isnot [PSCustomObject]) { throw 'invalid capture' }

    $idleObservation = [ordered]@{}
    foreach ($property in @($capture.idleObservation.PSObject.Properties)) {
        $idleObservation[[string]$property.Name] = $property.Value
    }
    $capture.idleObservation = $idleObservation

    $pinnedFiles = [ordered]@{}
    foreach ($property in @($capture.pinnedFiles.PSObject.Properties)) {
        $pinnedFiles[[string]$property.Name] = [string]$property.Value
    }
    $capture.pinnedFiles = $pinnedFiles

    if ($capture.capturedAtUtc -is [DateTime]) {
        $capture.capturedAtUtc = $capture.capturedAtUtc.ToUniversalTime()
    } else {
        $capture.capturedAtUtc = [DateTime]::Parse(
            [string]$capture.capturedAtUtc,
            [Globalization.CultureInfo]::InvariantCulture,
            ([Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal)
        )
    }

    $writerArguments = [ordered]@{
        Mode = $Mode
        Capture = $capture
        ExpectedTargetIdentity = [string]$request.ExpectedTargetIdentity
        ExpectedPins = $expectedPins
        PackageRoot = [string]$request.PackageRoot
        ExpectedStageRoot = [string]$request.ExpectedStageRoot
        ExpectedPackageManifestSha256 = [string]$request.ExpectedPackageManifestSha256
    }
    if ($Mode -eq 'Plan') {
        $writerArguments.CaptureDirectory = [string]$request.CaptureDirectory
        $writerArguments.ReceiptPath = [string]$request.ReceiptPath
    }
    $result = Invoke-CvrIdlePreflightPackageWriter @writerArguments

    if ($Mode -eq 'Capture') {
        $output = [ordered]@{
            CaptureDirectory = $result.CaptureDirectory
            ReceiptPath = $result.ReceiptPath
        }
    } else {
        $output = [ordered]@{
            PreparedDirectory = $result.PreparedDirectory
            PlanPath = $result.PlanPath
            PlanSha256 = $result.PlanSha256
        }
    }
    [Console]::Out.WriteLine((ConvertTo-Json -InputObject $output -Depth 4 -Compress -ErrorAction Stop))
} catch {
    [Console]::Error.WriteLine('Idle Preflight package writer failed.')
    exit 1
}
