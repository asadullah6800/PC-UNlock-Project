# ============================================================
# MobileFingerprintUnlock — LSA Package State Verifier
# Phase 8 (Read-only — safe to run anywhere)
# ============================================================

$PackageName  = 'LsaAuthenticationPackage'
$LsaRegKey    = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$ValueName    = 'Security Packages'
$System32Path = Join-Path $env:SystemRoot "System32\$PackageName.dll"

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "[$ts] [$Level] $Message"
}

Write-Log '============================================================'
Write-Log 'MobileFingerprintUnlock LSA Package State Verification'
Write-Log '============================================================'

$allOk = $true

# 1. Check DLL in System32
if (Test-Path $System32Path) {
    Write-Log "Package DLL exists in System32: $System32Path" 'SUCCESS'
} else {
    Write-Log "Package DLL NOT present in System32: $System32Path" 'INFO'
    $allOk = $false
}

# 2. Check LSA Security Packages array
if (Test-Path $LsaRegKey) {
    $packages = (Get-ItemProperty -Path $LsaRegKey -Name $ValueName -ErrorAction SilentlyContinue).$ValueName
    if ($packages -contains $PackageName) {
        Write-Log "Package '$PackageName' is listed in LSA '$ValueName'." 'SUCCESS'
        Write-Log "Full LSA package list: $($packages -join ', ')"
    } else {
        Write-Log "Package '$PackageName' is NOT in LSA '$ValueName'." 'INFO'
        $allOk = $false
    }
} else {
    Write-Log "LSA Registry key missing ($LsaRegKey)." 'ERROR'
    $allOk = $false
}

Write-Log '============================================================'
if ($allOk) {
    Write-Log 'Verification Result: LSA Package is ACTIVE and REGISTERED.' 'SUCCESS'
} else {
    Write-Log 'Verification Result: LSA Package is NOT ACTIVE (or uninstalled).' 'INFO'
}
Write-Log '============================================================'
