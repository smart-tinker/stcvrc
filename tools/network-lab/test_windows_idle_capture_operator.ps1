$ErrorActionPreference = 'Stop'
$operatorPath = Join-Path $PSScriptRoot 'windows_idle_capture_operator.ps1'
if (-not (Test-Path -LiteralPath $operatorPath -PathType Leaf)) {
    throw 'Expected behavior RED: public idle Capture operator is missing.'
}
