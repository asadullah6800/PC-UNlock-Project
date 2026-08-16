# MobileFingerprintUnlock — Development Setup & Environment Guide

## 1. Required Tools & Extensions

### 1.1 Visual Studio 2022 Workloads
When installing Visual Studio 2022, select the following workloads:
- **Desktop development with C++**
- **MSVC v143 - VS 2022 C++ x64/x86 build tools**
- **Windows 11 SDK (10.0.22621.0 or newer)**
- **C++ CMake tools for Windows**

### 1.2 Android Studio & Flutter SDK
1. Install **Android Studio Jellyfish / Ladybug**.
2. Install Android SDK Platform 34 and Build-Tools 34.0.0.
3. Install **Flutter SDK 3.x** and add `flutter/bin` to your `PATH`.
4. Run `flutter doctor` to verify setup.

---

## 2. Test VM Environment Setup

> [!CAUTION]
> Credential Provider (`Phase 7`) and LSA Package (`Phase 8` & `Phase 9A`) testing must be conducted inside a dedicated Windows Virtual Machine (Hyper-V / VMware / VirtualBox).

### VM Configuration Steps
1. Create a clean Windows 11 Enterprise virtual machine.
2. Enable Hyper-V or VMware guest integration services.
3. Take an initial snapshot named `Pre-MobileUnlock-State`.
4. For Phase 1, development binaries can be run in console mode (`MobileUnlockService.exe -console`).

---

## 3. Repository Structure Quick Reference

- `/docs`: Complete 15-document architectural specification suite.
- `/windows`: C++20 core architecture (`MobileUnlockService`, `UserSessionAgent`, `SecureIPC`, `ConfigurationManager`, `SecurityAuditLogger`, `DiagnosticManager`).
- `/android/flutter_app`: Flutter UI application & native Kotlin bridge placeholders.
- `/shared`: Cross-platform C++ headers (`ProtocolTypes.h`, `SignedMessage.h`, `BleConstants.h`).
- `/scripts`: PowerShell build, test, and service management scripts.
