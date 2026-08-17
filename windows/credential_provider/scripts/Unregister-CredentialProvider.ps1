#Requires -RunAsAdministrator
# ============================================================
# MobileFingerprintUnlock — Credential Provider Unregistration
# Phase 7
#
# VM-ONLY — DO NOT RUN ON THE PHYSICAL HOST MACHINE.
# Removes the CredentialProvider.dll registration from the
# Windows registry. Safe to run even if provider is not present.
# ============================================================

[CmdletBinding()]
param (
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$CLSID    = '{A82D1234-5678-90AB-CDEF-1234567890AB}'
$ClsidKey = "HKLM:\SOFTWARE\Classes\CLSID\$CLSID"
$CpKey    = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$CLSID"

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "[$ts] [$Level] $Message"
}

Write-Log '============================================================'
Write-Log 'MobileFingerprintUnlock Credential Provider Unregistration'
Write-Log 'PHASE 7 — TEST VM ONLY'
Write-Log '============================================================'

if ($DryRun) {
    Write-Log 'DRY-RUN MODE: No registry changes will be made.' 'WARNING'
}

# 1. Remove Credential Provider registration key
if (Test-Path $CpKey) {
    Write-Log "Removing Credential Provider key: $CpKey"
    if (-not $DryRun) {
        Remove-Item -Path $CpKey -Recurse -Force
        Write-Log 'Credential Provider key removed.' 'SUCCESS'
    }
} else {
    Write-Log 'Credential Provider key not found (already removed or never registered).'
}

# 2. Remove CLSID key
if (Test-Path $ClsidKey) {
    Write-Log "Removing CLSID key: $ClsidKey"
    if (-not $DryRun) {
        Remove-Item -Path $ClsidKey -Recurse -Force
        Write-Log 'CLSID key removed.' 'SUCCESS'
    }
} else {
    Write-Log 'CLSID key not found (already removed or never registered).'
}

Write-Log '============================================================'
Write-Log 'Unregistration complete.' 'SUCCESS'
Write-Log 'Reboot the VM and verify:'
Write-Log '  1. MobileFingerprintUnlock tile is gone from the logon screen.'
Write-Log '  2. Native Windows PIN/Password/Hello tiles still appear.'
Write-Log 'Use Verify-CredentialProvider.ps1 to confirm state.'
Write-Log '============================================================'
