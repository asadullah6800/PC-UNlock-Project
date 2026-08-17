#Requires -RunAsAdministrator
# ============================================================
# MobileFingerprintUnlock — LSA Package Unregistration / Rollback
# Phase 8
#
# VM-ONLY — DO NOT RUN ON THE PHYSICAL HOST MACHINE.
# Safely removes LsaAuthenticationPackage from the Windows LSA
# registry array, preserving all native Microsoft packages.
# ============================================================

[CmdletBinding()]
param (
    [switch]$DryRun,
    [string]$BackupDir = "C:\ProgramData\MobileFingerprintUnlock\Backup"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$PackageName = 'LsaAuthenticationPackage'
$LsaRegKey   = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$ValueName   = 'Security Packages'

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "[$ts] [$Level] $Message"
}

Write-Log '============================================================'
Write-Log 'MobileFingerprintUnlock LSA Package Unregistration'
Write-Log 'PHASE 8 — TEST VM ONLY'
Write-Log '============================================================'

if ($DryRun) {
    Write-Log 'DRY-RUN MODE: No changes will be made.' 'WARNING'
}

if (-not (Test-Path $LsaRegKey)) {
    Write-Log "LSA registry key missing ($LsaRegKey)." 'ERROR'
    exit 1
}

$currentPackages = (Get-ItemProperty -Path $LsaRegKey -Name $ValueName -ErrorAction SilentlyContinue).$ValueName
if ($null -eq $currentPackages) {
    Write-Log "Value '$ValueName' is empty or not found." 'INFO'
    exit 0
}

Write-Log "Current LSA packages: $($currentPackages -join ', ')"

# Filter out ONLY our custom package, preserving all native packages
$updatedPackages = @($currentPackages) | Where-Object { $_ -ne $PackageName }

if ($updatedPackages.Count -ne $currentPackages.Count) {
    Write-Log "Removing '$PackageName' from LSA array..." 'INFO'
    if (-not $DryRun) {
        Set-ItemProperty -Path $LsaRegKey -Name $ValueName -Value $updatedPackages
        Write-Log "Successfully updated LSA registry value." 'SUCCESS'
    }
} else {
    Write-Log "Package '$PackageName' was not present in LSA registry array." 'INFO'
}

# Remove DLL from System32 if present
$system32Path = Join-Path $env:SystemRoot "System32\$PackageName.dll"
if (Test-Path $system32Path) {
    Write-Log "Removing $system32Path..." 'INFO'
    if (-not $DryRun) {
        Remove-Item -Path $system32Path -Force -ErrorAction SilentlyContinue
    }
}

Write-Log '============================================================'
Write-Log 'LSA Package Unregistration Complete.' 'SUCCESS'
Write-Log 'Reboot the VM to unload the package from LSASS.'
Write-Log '============================================================'
