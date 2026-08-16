# MobileFingerprintUnlock - Test Execution Script
[CmdletBinding()]
param (
    [string]$BuildDir = "build",
    [string]$Config = "Debug"
)

$ErrorActionPreference = "Stop"

$testExe = Join-Path $BuildDir "$Config\MobileUnlockTests.exe"
if (-not (Test-Path $testExe)) {
    $testExe = Join-Path $BuildDir "MobileUnlockTests.exe"
}

if (-not (Test-Path $testExe)) {
    Write-Error "Test executable not found at $testExe. Please run Build_Windows.ps1 first."
    exit 1
}

Write-Host "Running GoogleTest Suite ($testExe)..." -ForegroundColor Cyan
& $testExe
if ($LASTEXITCODE -ne 0) {
    Write-Error "GoogleTest execution failed."
    exit $LASTEXITCODE
}

Write-Host "All GoogleTests Passed Successfully!" -ForegroundColor Green
