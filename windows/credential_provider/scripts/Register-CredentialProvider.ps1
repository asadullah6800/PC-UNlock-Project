#Requires -RunAsAdministrator
# ============================================================
# MobileFingerprintUnlock — Credential Provider Registration
# Phase 7
#
# VM-ONLY — DO NOT RUN ON THE PHYSICAL HOST MACHINE.
# This script registers CredentialProvider.dll in the Windows
# registry. It must only be executed inside the dedicated
# Windows TEST VM.
# ============================================================

[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string]$DllPath,

    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$CLSID     = '{A82D1234-5678-90AB-CDEF-1234567890AB}'
$ClsidKey  = "HKLM:\SOFTWARE\Classes\CLSID\$CLSID"
$InprocKey = "$ClsidKey\InprocServer32"
$CpKey     = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$CLSID"

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$ts] [$Level] $Message"
    Write-Host $line
}

Write-Log '============================================================'
Write-Log 'MobileFingerprintUnlock Credential Provider Registration'
Write-Log 'PHASE 7 — TEST VM ONLY'
Write-Log '============================================================'

if ($DryRun) {
    Write-Log 'DRY-RUN MODE: No registry changes will be made.' 'WARNING'
}

# 1. Validate DLL exists
if (-not (Test-Path $DllPath)) {
    Write-Log "DLL not found at: $DllPath" 'ERROR'
    Write-Log 'Registration aborted. Build CredentialProvider.dll first.' 'ERROR'
    exit 1
}
Write-Log "DLL validated: $DllPath"

# 2. CLSID \ InprocServer32
Write-Log "Writing CLSID key: $ClsidKey"
if (-not $DryRun) {
    if (-not (Test-Path $ClsidKey)) {
        New-Item -Path $ClsidKey -Force | Out-Null
    }
    Set-ItemProperty -Path $ClsidKey -Name '(Default)' `
        -Value 'MobileFingerprintUnlock Credential Provider'

    if (-not (Test-Path $InprocKey)) {
        New-Item -Path $InprocKey -Force | Out-Null
    }
    Set-ItemProperty -Path $InprocKey -Name '(Default)'      -Value $DllPath
    Set-ItemProperty -Path $InprocKey -Name 'ThreadingModel' -Value 'Apartment'
    Write-Log "InprocServer32 set to: $DllPath" 'SUCCESS'
}

# 3. Credential Providers key
Write-Log "Writing Credential Provider key: $CpKey"
if (-not $DryRun) {
    if (-not (Test-Path $CpKey)) {
        New-Item -Path $CpKey -Force | Out-Null
    }
    Set-ItemProperty -Path $CpKey -Name '(Default)' `
        -Value 'MobileFingerprintUnlock Credential Provider'
    Write-Log 'Credential Provider key created.' 'SUCCESS'
}

Write-Log '============================================================'
Write-Log 'Registration complete.' 'SUCCESS'
Write-Log 'Reboot the VM and verify the tile appears at the logon screen.'
Write-Log 'Verify native PIN/Password/Hello tiles remain available.'
Write-Log 'Use Verify-CredentialProvider.ps1 to inspect registration state.'
Write-Log '============================================================'
