[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Capture', 'Plan')]
    [string]$Mode
)

$ErrorActionPreference = 'Stop'
$stage = 'load-helpers'

try {
    . (Join-Path $PSScriptRoot 'windows_idle_baseline_guard.ps1')
    . (Join-Path $PSScriptRoot 'windows_idle_transaction.ps1')

    $stage = 'read-request'
    $requestText = [Console]::In.ReadLine()
    $stage = 'parse-request'
    $request = ConvertFrom-Json -InputObject $requestText -ErrorAction Stop
    if ($request -isnot [PSCustomObject]) { throw 'invalid request' }

    $stage = 'normalize-pins'
    $expectedPins = [ordered]@{}
    foreach ($property in @($request.ExpectedPins.PSObject.Properties)) {
        $expectedPins[[string]$property.Name] = [string]$property.Value
    }

    $stage = 'normalize-capture'
    $capture = $request.Capture
    if ($capture -isnot [PSCustomObject]) { throw 'invalid capture' }

    $stage = 'normalize-observation'
    $idleObservation = [ordered]@{}
    foreach ($property in @($capture.idleObservation.PSObject.Properties)) {
        $idleObservation[[string]$property.Name] = $property.Value
    }
    $capture.idleObservation = $idleObservation

    $stage = 'normalize-pinned-files'
    $pinnedFiles = [ordered]@{}
    foreach ($property in @($capture.pinnedFiles.PSObject.Properties)) {
        $pinnedFiles[[string]$property.Name] = [string]$property.Value
    }
    $capture.pinnedFiles = $pinnedFiles

    $stage = 'normalize-timestamp'
    if ($capture.capturedAtUtc -is [DateTime]) {
        $capture.capturedAtUtc = $capture.capturedAtUtc.ToUniversalTime()
    } else {
        $capture.capturedAtUtc = [DateTime]::Parse(
            [string]$capture.capturedAtUtc,
            [Globalization.CultureInfo]::InvariantCulture,
            ([Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal)
        )
    }

    $stage = 'prepare-writer'
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
    $stage = 'invoke-writer'
    $result = Invoke-CvrIdlePreflightPackageWriter @writerArguments

    $stage = 'format-result'
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
    $stage = 'write-result'
    [Console]::Out.WriteLine((ConvertTo-Json -InputObject $output -Depth 4 -Compress -ErrorAction Stop))
} catch {
    $errorType = $_.Exception.GetBaseException().GetType().Name
    $lineNumber = 0
    if ($_.InvocationInfo) { $lineNumber = [int]$_.InvocationInfo.ScriptLineNumber }
    [Console]::Error.WriteLine("Idle Preflight package writer failed (stage=$stage type=$errorType line=$lineNumber).")
    exit 1
}
