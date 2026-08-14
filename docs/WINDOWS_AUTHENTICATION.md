# MobileFingerprintUnlock — Windows Authentication & LSA Package Architecture

## 1. Primary Authentication Architecture Overview

Unlocking a Windows workstation securely requires full integration with the **Windows Local Security Authority (LSA)** architecture. The system establishes authentication through two official, documented Windows security extension points:

1. **Windows Credential Provider (v2)**: Integrates into the Winlogon UI logon/lock screen. Obtains authenticated challenge buffers from `MobileUnlockService` and serializes them into LSA logon credentials via `GetSerialization`.
2. **Custom LSA Authentication Package**: Loaded inside `lsass.exe` (TCB). Validates the canonical challenge signature, maps the device trust to the user's Windows account SID, and returns an `LSA_TOKEN_INFORMATION_TYPE` and `TokenInformation` structure allowing LSA to construct an authentic Windows logon session token.

```
+-------------------------------------------------------------------------+
| Winlogon UI Context (Credential Provider)                               |
| 1. Winlogon enumerates MobileUnlock Credential Provider                 |
| 2. User initiates unlock on phone; MobileUnlockService receives token   |
| 3. Credential Provider constructs custom MOBILE_UNLOCK_AUTH_BUFFER      |
| 4. Credential Provider hands serialization buffer to Winlogon            |
+-------------------------------------------------------------------------+
                                     |
                                     v Winlogon -> LsaLogonUser() Call
+-------------------------------------------------------------------------+
| LSASS Process Space (Custom LSA Authentication Package)                 |
| 5. LSASS dispatches logon buffer to LsaApLogonUserEx2()                 |
| 6. Custom LSA Package verifies Canonical Signature, Nonce & Account SID |
| 7. Package populates LSA_TOKEN_INFORMATION_TYPE & TokenInformation      |
| 8. LSA constructs user token & returns STATUS_SUCCESS                   |
+-------------------------------------------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
| Winlogon Session Unlocked (Desktop Displayed)                            |
+-------------------------------------------------------------------------+
```

---

## 2. LSA Package Identifier Lookup & API Specification

To adhere strictly to Microsoft LSA architecture guidelines, the application obtains the custom authentication package identifier through the appropriate LSA API.

### 2.1 Package Identifier Lookup
The system obtains the custom package identifier via `LsaLookupAuthenticationPackage` (or equivalent LSA API). The exact component responsible for executing this lookup (e.g. Credential Provider vs LSA Helper) will be finalized during Credential Provider implementation and Phase 9A experimentation.

### 2.2 Implemented LSA APIs

| Function Name | Location | Purpose & Implementation Details |
| :--- | :--- | :--- |
| **`LsaApInitializePackage`** | `LSA Package DLL` | Called by LSA when `lsass.exe` starts. Registers the package name (`MOBILE_UNLOCK_LSA_PACKAGE`), initializes internal registry handles, and returns package dispatch tables. |
| **`LsaApLogonUserEx2`** | `LSA Package DLL` | Primary logon validation entry point. Called by LSA when `LsaLogonUser` is invoked with our package ID. Validates canonical signature (88-byte struct), checks device revocation, maps device identity to account SID, and populates `LSA_TOKEN_INFORMATION_TYPE` and `TokenInformation`. |
| **`LsaLookupAuthenticationPackage`**| `LSA Client / Helper` | Resolves string package name `"MobileUnlockLsaPackage"` to the `ULONG` package identifier assigned by LSA. |

> [!NOTE]
> **Primary Unlock Path Omits `LsaCallAuthenticationPackage`**: The primary unlock sequence executes strictly through `Credential Provider -> GetSerialization -> Winlogon -> LSA -> LsaApLogonUserEx2`. `LsaCallAuthenticationPackage` is omitted from the mandatory primary unlock sequence and may only be implemented for auxiliary queries if Phase 9A proves it is necessary.

> [!CAUTION]
> **Explicit Omission of `SpAcceptCredentials`**: `SpAcceptCredentials` is an API function for Security Support Provider (SSP) DLLs used to capture plaintext passwords during logon. **MobileFingerprintUnlock** is **NOT** an SSP and does **NOT** capture or store passwords. `SpAcceptCredentials` is explicitly omitted to guarantee password safety.

### 2.3 LsaApLogonUserEx2 Return Specification

In accordance with Windows SDK specifications, `LsaApLogonUserEx2` outputs:
- `PLSA_TOKEN_INFORMATION_TYPE TokenInformationType`: Specifies the structure type returned in `TokenInformation`.
- `PVOID *TokenInformation`: Pointer to the allocated token information structure populated by the package.
- `PUNICODE_STRING AccountName`: Mapped Windows account username.
- `PNTSTATUS SubStatus`: Detailed authentication result error code.

The exact choice of token-information structure for each supported logon scenario will be determined and verified against the Windows SDK and Phase 9A VM experiments.

---

## 3. Phase 9A Feasibility Gate

> [!IMPORTANT]
> **Phase 9A Formal Experimental Verification**:
> Do NOT claim:
> 1. Automatic phone-triggered Credential Provider submission
> 2. Specific `SECURITY_LOGON_TYPE`
> 3. Specific `LSA_TOKEN_INFORMATION` structure
> 4. Successful passwordless workstation unlock
>
> until these behavior patterns are experimentally verified inside the dedicated Windows Test VM during Phase 9A. No undocumented assumptions shall be made to force desired behavior.

---

## 4. Official Microsoft API & OS Support Matrix

- **Supported OS Versions**: Windows 10 (1809+, x64/ARM64), Windows 11 (21H2+, x64/ARM64), Windows Server 2019/2022/2025.
- **LSA Package Registry Location**: `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages`.
- **Device Trust Registry Location**: `HKLM\SOFTWARE\MobileFingerprintUnlock\Devices`.
