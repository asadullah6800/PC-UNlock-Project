# MobileFingerprintUnlock — Disaster Recovery & Emergency Access Manual

## 1. Core Recovery Principle

> [!IMPORTANT]
> **Preservation of Standard Windows Logon Methods**: **MobileFingerprintUnlock** acts strictly as an **ADDITIONAL**, optional Credential Provider and LSA authentication mechanism. It **NEVER** disables, modifies, or replaces native Windows security options (Windows Hello PIN, Windows Password, Picture Password, Smart Card). In any failure scenario, normal Windows logon methods remain 100% available and uncompromised.

---

## 2. Emergency Recovery Matrix

| Scenario | Impact | Emergency Recovery Action |
| :--- | :--- | :--- |
| **Lost / Stolen Phone** | Phone unavailable for unlock. | 1. Log into Windows using regular **Windows Hello PIN** or **Password**.<br>2. Open Windows Registry (`HKLM\SOFTWARE\MobileFingerprintUnlock\Devices`).<br>3. Set device `Status` to `0` (REVOKED) or delete the device key. |
| **Broken Phone / Battery Dead** | Phone unable to power on or transmit signatures. | Simply unlock Windows using standard PIN or Password tile on Winlogon screen. |
| **Biometric Sensor Damage** | Android fingerprint sensor unresponsive. | Android App falls back to device PIN/Pattern prompt if configured, or user unlocks PC via standard Windows password/PIN tile. |
| **Corrupted Windows Service** | `MobileUnlockService` crashes or fails to start. | Winlogon UI detects service pipe closure; Credential Provider tile hides itself or displays "Service Unavailable". User logs in via standard PIN/Password. |
| **UserSessionAgent Crash** | `UserSessionAgent.exe` terminates unexpectedly. | Service attempts to restart agent in interactive user session. Remote lock fails gracefully with error payload. Manual unlock via PIN/Password unaffected. |
| **Credential Provider Failure** | Winlogon UI tile fails to load. | Winlogon isolates failing Credential Providers and defaults to standard Windows Password / PIN Credential Provider. |
| **LSA Package Failure** | Custom LSA DLL fails initialization. | LSA logs event in Windows System Log, skips package, and continues loading native `MSV1_0` and `Kerberos` packages. Native logon functions normally. (Requires Phase 9A VM testing for Safe Mode behavior). |
| **Complete System Lockout** | LSA registry entry corrupt causing boot issue. | 1. Boot Windows into **Safe Mode** (Shift + Restart -> Startup Settings -> Safe Mode).<br>2. Run `EmergencyRecovery.ps1` script to remove custom LSA package registry entry. |

---

## 3. Redesigned `EmergencyRecovery.ps1` Script Specification

The script located at `C:\Program Files\MobileFingerprintUnlock\Scripts\EmergencyRecovery.ps1` performs robust, non-destructive system recovery:

```powershell
[CmdletBinding()]
param (
    [switch]$DryRun,
    [string]$LogPath = "C:\ProgramData\MobileFingerprintUnlock\Logs\recovery.log",
    [string]$BackupDir = "C:\ProgramData\MobileFingerprintUnlock\Backup"
)

function Write-RecoveryLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logLine = "[$timestamp] [$Level] $Message"
    Write-Host $logLine
    if (-not $DryRun) {
        New-Item -ItemType Directory -Force -Path (Split-Path $LogPath) | Out-Null
        Add-Content -Path $LogPath -Value $logLine
    }
}

Write-RecoveryLog "Starting MobileFingerprintUnlock Emergency Recovery Procedure..." "INFO"

if ($DryRun) {
    Write-RecoveryLog "DRY-RUN MODE ENABLED: No system modifications will be made." "WARNING"
}

# 1. Create Backup Directory
if (-not $DryRun) {
    New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
}

# 2. Stop and Disable MobileUnlock Services & UserSessionAgent
$services = @("MobileUnlockService")
foreach ($svcName in $services) {
    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if ($svc) {
        Write-RecoveryLog "Found Service: $svcName (Status: $($svc.Status))" "INFO"
        if (-not $DryRun) {
            Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
            Set-Service -Name $svcName -StartupType Disabled
            Write-RecoveryLog "Stopped and Disabled Service: $svcName" "SUCCESS"
        }
    } else {
        Write-RecoveryLog "Service $svcName not found (Skipped)." "INFO"
    }
}

# Terminate UserSessionAgent processes if active
$agentProcesses = Get-Process -Name "UserSessionAgent" -ErrorAction SilentlyContinue
if ($agentProcesses) {
    Write-RecoveryLog "Found active UserSessionAgent process(es). Terminating..." "INFO"
    if (-not $DryRun) {
        $agentProcesses | Stop-Process -Force
    }
}

# 3. Clean LSA Package Registry Array Safely
$lsaRegKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
if (Test-Path $lsaRegKey) {
    $currentPackages = (Get-ItemProperty -Path $lsaRegKey -Name "Authentication Packages" -ErrorAction SilentlyContinue)."Authentication Packages"
    if ($currentPackages) {
        Write-RecoveryLog "Current LSA Authentication Packages: $($currentPackages -join ', ')" "INFO"
        
        # Backup LSA Registry Key
        if (-not $DryRun) {
            Get-ItemProperty -Path $lsaRegKey | Export-Clixml -Path "$BackupDir\LsaRegistryBackup.xml"
            Write-RecoveryLog "Backed up LSA registry key to $BackupDir\LsaRegistryBackup.xml" "SUCCESS"
        }

        # Filter ONLY MobileUnlockLsaPackage out, preserving all other LSA packages
        $updatedPackages = $currentPackages | Where-Object { $_ -ne "MobileUnlockLsaPackage" }
        
        if ($updatedPackages.Count -ne $currentPackages.Count) {
            Write-RecoveryLog "Removing MobileUnlockLsaPackage from LSA registry array..." "INFO"
            if (-not $DryRun) {
                Set-ItemProperty -Path $lsaRegKey -Name "Authentication Packages" -Value $updatedPackages
                Write-RecoveryLog "Successfully updated LSA Authentication Packages registry." "SUCCESS"
            }
        } else {
            Write-RecoveryLog "MobileUnlockLsaPackage was not present in LSA registry array." "INFO"
        }
    } else {
        Write-RecoveryLog "Could not read LSA Authentication Packages property." "ERROR"
    }
} else {
    Write-RecoveryLog "LSA Registry key path missing ($lsaRegKey)." "ERROR"
}

# 4. Remove Credential Provider Registry GUID
$cpGuid = "{A82D1234-5678-90AB-CDEF-1234567890AB}"
$cpRegKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$cpGuid"
if (Test-Path $cpRegKey) {
    Write-RecoveryLog "Found MobileUnlock Credential Provider GUID entry ($cpGuid)." "INFO"
    if (-not $DryRun) {
        # Backup CP key
        Get-ItemProperty -Path $cpRegKey | Export-Clixml -Path "$BackupDir\CPRegistryBackup.xml"
        Remove-Item -Path $cpRegKey -Recurse -Force
        Write-RecoveryLog "Removed MobileUnlock Credential Provider registry key." "SUCCESS"
    }
} else {
    Write-RecoveryLog "Credential Provider registry key not present." "INFO"
}

Write-RecoveryLog "Emergency Recovery Script Completed Successfully." "SUCCESS"
```
