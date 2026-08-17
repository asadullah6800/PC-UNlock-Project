# ============================================================
# MobileFingerprintUnlock — Credential Provider State Verifier
# Phase 7 (Read-only — safe to run anywhere)
# ============================================================

$CLSID    = '{A82D1234-5678-90AB-CDEF-1234567890AB}'
$ClsidKey = "HKLM:\SOFTWARE\Classes\CLSID\$CLSID"
$InprocKey = "$ClsidKey\InprocServer32"
$CpKey    = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$CLSID"

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "[$ts] [$Level] $Message"
}

Write-Log '============================================================'
Write-Log "MobileFingerprintUnlock Credential Provider Verification"
Write-Log "CLSID: $CLSID"
Write-Log '============================================================'

$allOk = $true

# Check CLSID key
if (Test-Path $ClsidKey) {
    Write-Log "CLSID key present: $ClsidKey" 'SUCCESS'
} else {
    Write-Log "CLSID key MISSING: $ClsidKey" 'ERROR'
    $allOk = $false
}

# Check InprocServer32
if (Test-Path $InprocKey) {
    $dllPath  = (Get-ItemProperty -Path $InprocKey -Name '(Default)' -ErrorAction SilentlyContinue).'(Default)'
    $threading = (Get-ItemProperty -Path $InprocKey -Name 'ThreadingModel' -ErrorAction SilentlyContinue).ThreadingModel
    Write-Log "InprocServer32 DLL : $dllPath" 'SUCCESS'
    Write-Log "ThreadingModel     : $threading"

    if ($dllPath -and (Test-Path $dllPath)) {
        Write-Log "DLL file exists on disk: $dllPath" 'SUCCESS'
    } else {
        Write-Log "DLL file NOT found on disk: $dllPath" 'WARNING'
        $allOk = $false
    }
} else {
    Write-Log "InprocServer32 key MISSING" 'ERROR'
    $allOk = $false
}

# Check Credential Providers key
if (Test-Path $CpKey) {
    Write-Log "Credential Provider key present: $CpKey" 'SUCCESS'
} else {
    Write-Log "Credential Provider key MISSING: $CpKey" 'ERROR'
    $allOk = $false
}

Write-Log '============================================================'
if ($allOk) {
    Write-Log 'Verification PASSED — provider is registered correctly.' 'SUCCESS'
} else {
    Write-Log 'Verification FAILED — one or more keys are missing.' 'ERROR'
}
Write-Log '============================================================'
