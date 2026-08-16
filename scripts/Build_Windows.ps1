# MobileFingerprintUnlock - Windows Build Script
[CmdletBinding()]
param (
    [string]$BuildType = "Debug",
    [string]$BuildDir = "build"
)

$ErrorActionPreference = "Stop"

# Find CMake executable
$cmakeCmd = "cmake"
if (Test-Path "C:\Program Files\CMake\bin\cmake.exe") {
    $cmakeCmd = "C:\Program Files\CMake\bin\cmake.exe"
}

Write-Host "Configuring CMake Build ($BuildType)..." -ForegroundColor Cyan
if (-not (Test-Path $BuildDir)) {
    New-Item -ItemType Directory -Path $BuildDir | Out-Null
}

Set-Location $BuildDir

# Detect generator (Prefer MinGW Makefiles if MinGW installed, or default)
$generator = ""
if (Test-Path "C:\MinGW\bin\gcc.exe") {
    $env:PATH = "C:\MinGW\bin;" + $env:PATH
    $generator = "-G`"MinGW Makefiles`""
}

Write-Host "Running CMake with executable: $cmakeCmd" -ForegroundColor Cyan
if ($generator -ne "") {
    & $cmakeCmd -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=$BuildType ..
} else {
    & $cmakeCmd -DCMAKE_BUILD_TYPE=$BuildType ..
}

if ($LASTEXITCODE -ne 0) {
    Write-Error "CMake configuration failed."
    exit $LASTEXITCODE
}

Write-Host "Compiling Windows C++ Targets..." -ForegroundColor Cyan
& $cmakeCmd --build . --config $BuildType
if ($LASTEXITCODE -ne 0) {
    Write-Error "Build failed."
    exit $LASTEXITCODE
}

Write-Host "Build Completed Successfully!" -ForegroundColor Green
Set-Location ..
