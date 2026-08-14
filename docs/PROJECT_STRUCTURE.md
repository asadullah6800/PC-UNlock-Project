# MobileFingerprintUnlock — Project Directory Structure Specification

## 1. Top-Level Repository Structure

```
/MobileFingerprintUnlock
├── /docs                            # Complete Architectural Specification Documentation
│   ├── ARCHITECTURE.md              # System Overview, Subsystems, State Machine, Sequence Diagrams
│   ├── SECURITY.md                  # Cryptography (ECDSA P-256 IEEE P1363), Least-Privilege, Audit Logs
│   ├── THREAT_MODEL.md              # STRIDE Analysis, Attack Surfaces, Mitigations Matrix
│   ├── PROTOCOL.md                  # Framing Protocol, Canonical SignedMessage Struct, Nonces
│   ├── WINDOWS_AUTHENTICATION.md    # Credential Provider v2 & Custom LSA Package Specification
│   ├── ANDROID_SECURITY.md          # BiometricPrompt, Keystore TEE, Storage & Flutter Channels
│   ├── NETWORKING.md                # Phase 1 Local Wi-Fi TCP/TLS 1.3 & mDNS Transport Specs
│   ├── BLUETOOTH.md                 # Phase 10 BLE GATT Profile (128-bit UUIDs) & RSSI Proximity Specs
│   ├── INTERNET_ARCHITECTURE.md     # Phase 12 Zero-Trust Inner E2EE Internet Relay Specifications
│   ├── IDENTITY_MAPPING.md          # Device ID -> Registry -> Account SID Mapping & Lifecycle
│   ├── RECOVERY.md                  # Emergency Access, Safe Mode Recovery, Recovery PowerShell Script
│   ├── DEVELOPMENT_ROADMAP.md       # 16 Sequential Phases (Phases 0 to 15, Phase 9A/9B Split)
│   ├── TEST_PLAN.md                 # Test VM Requirement, GoogleTest, Mock LSA & Phase 9A Lab Plan
│   ├── PROJECT_STRUCTURE.md         # Repository Layout & Build System Setup Guidelines
│   └── FINAL_DOCUMENTATION_AUDIT.md # Cross-Document Audit Summary & Implementation Prerequisites
│
├── /windows                         # Windows C++20 Core Architecture (16 Components)
│   ├── CMakeLists.txt               # Main Windows CMake Build Configuration
│   ├── /service                     # MobileUnlockService (Windows Service - NetworkService)
│   ├── /user_session_agent          # UserSessionAgent (Interactive Desktop Application Session 1+)
│   ├── /network                     # NetworkEngine (TCP Socket & TLS 1.3 Server)
│   ├── /bluetooth                   # BluetoothEngine (BLE GATT Server 128-bit UUIDs)
│   ├── /crypto                      # CryptoManager (Windows CNG BCrypt IEEE P1363 Wrappers)
│   ├── /pairing                     # PairingManager (Out-of-Band SAS Pairing Engine)
│   ├── /authentication              # AuthenticationManager (Challenge/Nonce Verification)
│   ├── /ipc                         # SecureIPC (Named Pipe Server & ACL Manager)
│   ├── /credential_provider         # CredentialProvider (ICredentialProvider DLL)
│   ├── /lsa_authentication_package  # LSAAuthenticationPackage (Custom LSA Package DLL)
│   ├── /configuration               # ConfigurationManager (HKLM\SOFTWARE Registry Manager)
│   ├── /logging                     # SecurityAuditLogger (Windows Security Event Log Writer)
│   ├── /diagnostics                 # DiagnosticManager (Health Checks & Status Reporter)
│   ├── /installer                   # Installer Scripts & Deployment Package
│   └── /tests                       # Windows GoogleTest Test Suites
│
├── /android                         # Android Mobile Application (Flutter + Native Kotlin)
│   └── /flutter_app
│       ├── pubspec.yaml             # Flutter Dependencies & Assets Configuration
│       ├── /lib
│       │   ├── main.dart            # Flutter App Entry Point
│       │   ├── /screens             # HomeScreen, DeviceDiscoveryScreen, SettingsScreen
│       │   ├── /services            # ConnectionManager, PairingService, AuthCoordinator
│       │   ├── /models              # DeviceModel, SessionState, CanonicalMessage
│       │   ├── /network             # WiFiTransport, BluetoothTransport, RelayTransport
│       │   ├── /security            # BiometricBridge, CryptoSigner, NonceVerifier
│       │   ├── /storage             # LocalAppStorage (SharedPreferences & Secure Config)
│       │   └── /widgets             # StatusIndicatorTile, ActionButton, DeviceCard
│       └── /android
│           └── /app/src/main/kotlin # Native Android Kotlin Implementation
│               └── /com/mobileunlock
│                   ├── MainActivity.kt
│                   ├── AndroidKeystoreManager.kt
│                   └── BiometricManager.kt
│
├── /shared                          # Cross-Platform Shared Definitions
│   ├── /protocol                    # Message Opcode Constants & CanonicalSignedMessage Struct
│   ├── /schemas                     # JSON Data Schemas
│   └── /constants                   # Version Constants & 128-bit BLE UUID Definitions
│
├── /scripts                         # PowerShell Build & Emergency Recovery Scripts
│   ├── Build_Windows.ps1            # Automates CMake Configure & MSBuild
│   ├── Run_VM_Tests.ps1             # Deploys binaries to Test VM & runs tests
│   └── EmergencyRecovery.ps1        # Robust Safe Mode uninstall script with -DryRun support
│
└── /tests                           # End-to-End Integration & Security Fuzzing Scripts
    ├── /integration                 # End-to-End Integration Test Suite
    └── /fuzzing                     # Python TCP Protocol Fuzzer
```

---

## 2. Windows Build Setup (CMake + MSVC C++20)

- **Minimum Toolchain**: MSVC v143 (Visual Studio 2022 / Windows SDK 10.0.22621+), CMake 3.22+.
- **Build Targets**:
  - `MobileUnlockService.exe`: Network Service executable (`NetworkService` identity).
  - `UserSessionAgent.exe`: Interactive desktop application.
  - `MobileUnlockCredentialProvider.dll`: Credential Provider v2 COM DLL.
  - `MobileUnlockLsaPackage.dll`: Custom LSA Authentication Package DLL.
  - `MobileUnlockTests.exe`: GoogleTest test binary.

---

## 3. Android Build Setup (Flutter + Kotlin)

- **Minimum Requirements**: Flutter SDK 3.x, Android SDK 34 (Android 14+), Kotlin 1.9+.
- **Key Flutter Dependencies**:
  - `flutter_mdns_plugin`: Local mDNS discovery.
  - `flutter_reactive_ble`: BLE GATT communication with custom 128-bit UUIDs.
  - `shared_preferences`: Non-secret configuration storage.
