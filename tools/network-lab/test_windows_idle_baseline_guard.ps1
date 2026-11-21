$ErrorActionPreference = 'Stop'
$guardPath = Join-Path $PSScriptRoot 'windows_idle_baseline_guard.ps1'
if (-not (Test-Path -LiteralPath $guardPath -PathType Leaf)) {
    throw 'Expected behavior RED: the shared idle-baseline guard is missing.'
}
. $guardPath

function Copy-Arguments([hashtable]$Source) {
    $copy = @{}
    foreach ($key in $Source.Keys) { $copy[$key] = $Source[$key] }
    return $copy
}

function Assert-Rejected([string]$Case, [hashtable]$Arguments, [string]$ExpectedMessage) {
    $rejected = $false
    try {
        $null = Assert-CvrIdleBaseline @Arguments
    } catch {
        if ($_.Exception.Message -cne $ExpectedMessage) {
            throw "$Case returned an unexpected guard message."
        }
        $rejected = $true
    }
    if (-not $rejected) { throw "$Case drift was accepted." }
}

$baseline = @{
    CoreShouldBeRunning = $false
    OwnedGuiProcessIds = [int[]]@()
    OwnedCoreProcessIds = [int[]]@()
    ControllerListening = $false
    OwnedListenerProcessIds = [int[]]@()
    ServiceStatus = 'Running'
    ExpectedProgramFilesCoreSha256 = ('a' * 64)
    ObservedProgramFilesCoreSha256 = ('a' * 64)
    ExpectedServiceCoreSha256 = ('b' * 64)
    ObservedServiceCoreSha256 = ('b' * 64)
}
if ((Assert-CvrIdleBaseline @baseline) -ne $true) {
    throw 'The exact idle baseline was not accepted.'
}

$case = Copy-Arguments $baseline
$case.CoreShouldBeRunning = 0
Assert-Rejected 'integer intent' $case 'Idle baseline Boolean observations must be strict Booleans.'

$case = Copy-Arguments $baseline
$case.ControllerListening = 0
Assert-Rejected 'integer controller observation' $case 'Idle baseline Boolean observations must be strict Booleans.'

$case = Copy-Arguments $baseline
$case.CoreShouldBeRunning = $true
Assert-Rejected 'intent' $case 'Idle baseline intent must be false.'

$case = Copy-Arguments $baseline
$case.OwnedGuiProcessIds = [int[]]@(101)
Assert-Rejected 'GUI process' $case 'Idle baseline has owned GUI processes.'

$case = Copy-Arguments $baseline
$case.OwnedCoreProcessIds = [int[]]@(202)
Assert-Rejected 'core process' $case 'Idle baseline has owned core processes.'

$case = Copy-Arguments $baseline
$case.ControllerListening = $true
Assert-Rejected 'controller listener' $case 'Idle baseline controller listener is present.'

$case = Copy-Arguments $baseline
$case.OwnedListenerProcessIds = [int[]]@(202)
Assert-Rejected 'owned listener' $case 'Idle baseline has owned listeners.'

$case = Copy-Arguments $baseline
$case.ServiceStatus = 'Stopped'
Assert-Rejected 'service state' $case 'Idle baseline service is not Running.'

$case = Copy-Arguments $baseline
$case.ObservedProgramFilesCoreSha256 = ('c' * 64)
Assert-Rejected 'Program Files core pin' $case 'Idle baseline Program Files core SHA256 mismatch.'

$case = Copy-Arguments $baseline
$case.ObservedServiceCoreSha256 = ('d' * 64)
Assert-Rejected 'service core pin' $case 'Idle baseline service core SHA256 mismatch.'

$case = Copy-Arguments $baseline
$case.ExpectedProgramFilesCoreSha256 = 'invalid'
Assert-Rejected 'malformed Program Files core pin' $case 'Idle baseline Program Files core SHA256 is malformed.'

Write-Host 'PowerShell idle-baseline behavior checks passed.'