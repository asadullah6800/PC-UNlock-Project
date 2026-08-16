# MobileFingerprintUnlock - Service Installation Script
[CmdletBinding()]
param (
    [string]$BinaryPath = "C:\Program Files\MobileFingerprintUnlock\MobileUnlockService.exe"
)

$ErrorActionPreference = "Stop"

Write-Host "Installing MobileUnlockService under NT AUTHORITY\NetworkService identity..." -ForegroundColor Cyan

# 1. Stop service if running
sc.exe stop MobileUnlockService 2>$null | Out-Null
sc.exe delete MobileUnlockService 2>$null | Out-Null

# 2. Create service configured to run under NetworkService
sc.exe create MobileUnlockService binPath= "$BinaryPath" obj= "NT AUTHORITY\NetworkService" start= auto DisplayName= "Mobile Fingerprint Unlock Service"
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to create MobileUnlockService."
    exit $LASTEXITCODE
}

sc.exe description MobileUnlockService "Provides secure Windows unlock and remote lock communication with paired Android mobile devices."

Write-Host "MobileUnlockService installed successfully." -ForegroundColor Green
