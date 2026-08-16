# MobileFingerprintUnlock - Service Removal Script
$ErrorActionPreference = "Stop"

Write-Host "Stopping and Removing MobileUnlockService..." -ForegroundColor Cyan

sc.exe stop MobileUnlockService 2>$null | Out-Null
sc.exe delete MobileUnlockService

Write-Host "MobileUnlockService removed successfully." -ForegroundColor Green
