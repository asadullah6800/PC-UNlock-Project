#Requires -RunAsAdministrator
# ============================================================
# MobileFingerprintUnlock — LSA Authentication Package Registration
# Phase 8
#
# VM-ONLY — DO NOT RUN ON THE PHYSICAL HOST MACHINE.
# This script registers LsaAuthenticationPackage.dll in the Windows
# LSA security-package registry array. It must only be executed
# inside the dedicated Windows TEST VM.
# ============================================================

[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string]$DllPath,

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
Write-Log 'MobileFingerprintUnlock LSA Package Registration'
Write-Log 'PHASE 8 — TEST VM ONLY'
Write-Log '============================================================'

if ($DryRun) {
    Write-Log 'DRY-RUN MODE: No system or registry changes will be made.' 'WARNING'
}

# 1. Validate DLL exists
if (-not (Test-Path $DllPath)) {
    Write-Log "DLL not found at: $DllPath" 'ERROR'
    Write-Log 'Registration aborted. Build LsaAuthenticationPackage.dll first.' 'ERROR'
    exit 1
}
Write-Log "DLL validated: $DllPath"

# 2. Check registry key existence
if (-not (Test-Path $LsaRegKey)) {
    Write-Log "LSA registry key path not found: $LsaRegKey" 'ERROR'
    exit 1
}

# 3. Create Backup
if (-not $DryRun) {
    New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $backupPath = Join-Path $BackupDir "LsaRegistryBackup_$timestamp.xml"
    Get-ItemProperty -Path $LsaRegKey | Export-Clixml -Path $backupPath
    Write-Log "Backed up LSA registry state to: $backupPath" 'SUCCESS'
}

# 4. Copy DLL into System32 (inside VM only)
$system32Path = Join-Path $env:SystemRoot "System32\$PackageName.dll"
Write-Log "Target System32 path: $system32Path"
if (-not $DryRun) {
    Copy-Item -Path $DllPath -Destination $system32Path -Force
    Write-Log "Copied package DLL to System32." 'SUCCESS'
}

# 5. Read existing Security Packages multi-string array
$currentPackages = (Get-ItemProperty -Path $LsaRegKey -Name $ValueName -ErrorAction SilentlyContinue).$ValueName
if ($null -eq $currentPackages) {
    $currentPackages = @()
} elseif ($currentPackages -is [string]) {
    $currentPackages = @($currentPackages)
}

Write-Log "Current LSA packages: $($currentPackages -join ', ')"

# 6. Additively append our package if not already present
if ($currentPackages -contains $PackageName) {
    Write-Log "Package '$PackageName' is already present in LSA registry array." 'INFO'
} else {
    $updatedPackages = @($currentPackages) + @($PackageName)
    Write-Log "Adding '$PackageName' to LSA $ValueName..." 'INFO'
    if (-not $DryRun) {
        Set-ItemProperty -Path $LsaRegKey -Name $ValueName -Value $updatedPackages
        Write-Log "Successfully updated LSA registry value." 'SUCCESS'
    }
}

Write-Log '============================================================'
Write-Log 'LSA Authentication Package Registration Complete.' 'SUCCESS'
Write-Log 'Reboot the VM to load the package into LSASS.'
Write-Log 'Verify native PIN/Password/Hello logon remains operational.'
Write-Log '============================================================'
