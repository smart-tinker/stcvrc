[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Capture', 'Plan')]
    [string]$Mode
)

$ErrorActionPreference = 'Stop'
$stage = 'load-helpers'
$requestShape = 'unread'
$requestPrefix = 'unread'
$requestSuffix = 'unread'
$requestText = $null
$requestCharacterCount = 0

try {
    . (Join-Path $PSScriptRoot 'windows_idle_baseline_guard.ps1')
    . (Join-Path $PSScriptRoot 'windows_idle_transaction.ps1')

    $stage = 'read-request'
    $requestReader = [IO.StreamReader]::new(
        [Console]::OpenStandardInput(),
        [Text.UTF8Encoding]::new($false, $true),
        $false
    )
    try {
        $requestText = $requestReader.ReadToEnd()
    } finally {
        $requestReader.Dispose()
    }
    $requestPrefix = if ([string]::IsNullOrEmpty($requestText)) { 'empty' } elseif ($requestText[0] -ceq '{') { 'object' } elseif ([int]$requestText[0] -eq 0xFEFF) { 'bom' } elseif ([char]::IsWhiteSpace($requestText[0])) { 'whitespace' } else { 'other' }
    $requestSuffix = if ([string]::IsNullOrEmpty($requestText)) { 'empty' } elseif ($requestText[$requestText.Length - 1] -ceq '}') { 'object' } elseif ([char]::IsWhiteSpace($requestText[$requestText.Length - 1])) { 'whitespace' } else { 'other' }
    $requestShape = if ($requestPrefix -ceq 'empty') { 'empty' } elseif ($requestPrefix -ceq 'object' -and $requestSuffix -ceq 'object') { 'object' } else { 'partial' }
    $requestCharacterCount = $requestText.Length
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
    [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
    [Console]::Out.WriteLine((ConvertTo-Json -InputObject $output -Depth 4 -Compress -ErrorAction Stop))
} catch {
    $errorType = $_.Exception.GetBaseException().GetType().Name
    $lineNumber = 0
    if ($_.InvocationInfo) { $lineNumber = [int]$_.InvocationInfo.ScriptLineNumber }
    [Console]::Error.WriteLine("Idle Preflight package writer failed (stage=$stage shape=$requestShape prefix=$requestPrefix suffix=$requestSuffix chars=$requestCharacterCount type=$errorType line=$lineNumber).")
    exit 1
}
