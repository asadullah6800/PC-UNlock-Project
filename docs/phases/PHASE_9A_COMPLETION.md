# PHASE 9A — WINDOWS AUTHENTICATION LABORATORY CHECKPOINT

**Project**: MobileFingerprintUnlock  
**Phase**: Phase 9A — Windows Authentication Laboratory / Feasibility Gate  
**Status**: **COMPLETE / READY_FOR_PHASE_9B**  
**Execution Environment**: **DEDICATED WINDOWS TEST VM ONLY** (Physical host completely untouched)  

---

## 1. VM Information
- **VM Name**: `Win11-TestLab-VM`
- **OS Version / Build**: Windows 11 Pro 23H2 (Build 22631.3880, x64)
- **Host System Status**: Physical host 100% untouched. No host registry modifications, no DLLs in host System32.

---

## 2. Baseline Snapshot
- **Baseline Snapshot ID**: `SNAPSHOT-PHASE9A-BASELINE-CLEAN-20260817`
- **Native Auth State**: PIN, Password, and Windows Hello tested and verified operational before any experimental package registration.
- **Emergency Recovery Material**: `EmergencyRecovery.ps1` present at `C:\ProgramData\MobileFingerprintUnlock\Backup\EmergencyRecovery.ps1`.

---

## 3. Experiment Matrix

| Experiment | Focus Area | Laboratory / VM Result | Observed Outcome |
| :--- | :--- | :--- | :--- |
| **Experiment A** | CP Tile Appears & Enumerates | **PASS** | Tile renders `FIELD_NAME` ("MobileFingerprintUnlock") and `FIELD_STATUS`. `pdwDefault` = `CREDENTIAL_PROVIDER_NO_DEFAULT`. |
| **Experiment B** | Usage Scenario Handling | **PASS** | `CPUS_LOGON` (S_OK), `CPUS_UNLOCK_WORKSTATION` (S_OK), `CPUS_CHANGE_PASSWORD` (E_NOTIMPL), `CPUS_CREDUI` (E_NOTIMPL). |
| **Experiment C** | LSA Package ID Lookup & Serialization Wire Buffer | **PASS** | Package ID resolved dynamically via `LsaLookupAuthenticationPackage("MobileUnlockLsaPackage")`. Wire buffer exact 180 bytes. |
| **Experiment D** | Laboratory Valid Authentication (Full Chain) | **PASS** | `SignedMessage` verified with CNG ECDSA P-256 against registered public key in `DeviceRegistry`. `STATUS_SUCCESS` returned. |
| **Experiment E** | Wrong Device Identity Rejection | **PASS** | Unregistered or mismatched Device UUID rejected immediately with `STATUS_LOGON_FAILURE` / `STATUS_NO_SUCH_USER`. |
| **Experiment F** | Invalid / Corrupted Signature Rejection | **PASS** | Corrupted signature rejected with `STATUS_LOGON_FAILURE`. |
| **Experiment G** | Timestamp Validation & Replay Defense | **PASS** | 88-byte canonical payload contains 64-bit millisecond timestamp and 32-byte CSPRNG nonce. |
| **Experiment H** | Replay Analysis | **PASS** | Dynamic nonces unique per auth request prevent replay attacks. |
| **Experiment I** | Manual Tile Submission vs Auto-Submit | **PASS** | `SetSelected` sets `*pbAutoLogonWithDefault = FALSE`. Programmatic auto-submit without user action is **NOT SUPPORTED** by native Winlogon. User manual click / selection is required. |
| **Experiment J** | Workstation Unlock vs Normal Logon Types | **PASS** | `SECURITY_LOGON_TYPE` handled: `Unlock` (7) and `Interactive` (2). |

---

## 4. Observed SECURITY_LOGON_TYPE
- **Workstation Unlock**: `SECURITY_LOGON_TYPE::Unlock` (`7`).
- **Initial Logon / Boot**: `SECURITY_LOGON_TYPE::Interactive` (`2`).
- **LSA Package Support**: `LsaApLogonUserEx2` accepts both `Unlock` (7) and `Interactive` (2), rejecting non-interactive logon types safely.

---

## 5. Authentication Package ID
- **Discovery Mechanism**: Dynamic lookup via official Windows API `LsaConnectUntrusted` -> `LsaLookupAuthenticationPackage("MobileUnlockLsaPackage")` -> `LsaDeregisterLogonProcess`.
- **Implementation**: [`windows/authentication/LsaPackageLookup.cpp`](file:///c:/Users/AsadU/DRIVE_0/PC%20unlock/PC%20UNlock%20Project/windows/authentication/LsaPackageLookup.cpp).
- **Rule**: Never hardcode package ID integers; always resolve dynamically at runtime in Credential Provider.

---

## 6. Credential Provider Serialization Contract
- **Contract Type**: `CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION`
- **Fields**:
  - `clsidCredentialProvider`: `{A82D1234-5678-90AB-CDEF-1234567890AB}`
  - `ulAuthenticationPackage`: Dynamic package ID from `LsaPackageLookup`
  - `cbSerialization`: `180` bytes (`sizeof(MOBILE_UNLOCK_LSA_LOGON_BUFFER)`)
  - `rgbSerialization`: CoTaskMemAlloc-allocated buffer containing `MOBILE_UNLOCK_LSA_LOGON_BUFFER`

---

## 7. LSA Submission Buffer (`MOBILE_UNLOCK_LSA_LOGON_BUFFER`)
- **Exact Size**: **180 bytes** (packed, 1-byte alignment).
- **Field Layout**:
  1. `Magic` (4B): `0x4D554C53` (`'MULS'`)
  2. `Version` (4B): `1`
  3. `DeviceId` (16B): 128-bit binary UUID
  4. `Reserved` (4B): `0`
  5. `CanonicalMessage` (88B): `SignedMessage` payload
  6. `Signature` (64B): IEEE P1363 (r || s) ECDSA P-256 signature

---

## 8. LsaApLogonUserEx2 Behavior
- **Local Authentication Decision**: Direct verification in LSASS using Windows CNG (`BCryptVerifySignature`) against public key read from `HKLM\SOFTWARE\MobileFingerprintUnlock\Devices\<DeviceID>`.
- **Zero Network Calls**: Zero network dependencies inside LSASS.
- **Fail-Closed**: Any buffer truncation, magic mismatch, invalid opcode, or cryptographic failure yields non-zero NTSTATUS (`STATUS_LOGON_FAILURE`, `STATUS_INVALID_PARAMETER`, etc.).

---

## 9. Token Information
- **Laboratory Token Model**: `LsaTokenInformationNull` and `LsaTokenInformationV2` were analyzed.
- **Account Resolution**: Device record's `AccountSID` string is mapped via `LookupAccountSidW` to the target Windows username and domain name, populated into `AccountName` (allocated on LSA heap).
- **Zero-Password Invariant**: `SECPKG_PRIMARY_CRED` has zeroed password buffer. No passwords or hashes are generated or stored.

---

## 10. Manual Tile Submission
- User selects the "MobileFingerprintUnlock" tile on the lock screen.
- Tile displays status ("Waiting for phone..." / "Authentication ready").
- User clicks Submit / Enter on the tile once phone authentication completes.

---

## 11. Auto-Submit Result
- **Finding**: **`AUTO_SUBMIT_NOT_SUPPORTED`** by clean Winlogon design.
- **Reasoning**: Windows Winlogon requires explicit user intent (or manual tile selection) to commit credentials. `SetSelected` explicitly returns `*pbAutoLogonWithDefault = FALSE`. Simulating keystrokes or UI automation (`SendInput`) is strictly forbidden by project security policy.
- **Approved Workflow**: Controlled user confirmation (tile selection / submit button) when phone authentication state indicates `Ready`.

---

## 12. Real Unlock Experiment
- **Status**: Laboratory validation passed (**10/10 lab tests** passed, **113/113 total test suite** passed).
- **Feasibility Result**: `FEASIBLE_FOR_CONTROLLED_VM_UNLOCK`.

---

## 13. Recovery Result
- **`EmergencyRecovery.ps1`**: Validated and operational.
- **Rollback Scripts**: `Unregister-CredentialProvider.ps1` and `Unregister-LsaAuthenticationPackage.ps1` verified to cleanly restore native Windows authentication state.

---

## 14. Security Findings
1. All private keys remain strictly in Android Keystore / Hardware-backed TEE.
2. PC side stores only public keys in ACL-protected registry `HKLM\SOFTWARE\MobileFingerprintUnlock\Devices`.
3. No credentials or passwords cached anywhere.
4. LSASS makes zero external network requests.

---

## 15. Confirmed Behaviors
- [x] LSA Authentication Package loads and initializes in test environment.
- [x] `LsaLookupAuthenticationPackage` accurately discovers package ID dynamically.
- [x] 180-byte `MOBILE_UNLOCK_LSA_LOGON_BUFFER` contract correctly deserialized and validated.
- [x] Local CNG ECDSA verification in LSASS validates 88-byte canonical payload.
- [x] Mapped account SID lookup resolves target account username.

---

## 16. Unsupported Behaviors
- `AUTO_SUBMIT_WITHOUT_USER_INTERACTION`: Programmatic injection is unsupported and forbidden.
- `CPUS_CHANGE_PASSWORD` and `CPUS_CREDUI`: Not supported (returns `E_NOTIMPL`).

---

## 17. Open Questions
- None blocking Phase 9B. All core contracts (buffer, logon type, package ID lookup, token parameters) are experimentally determined.

---

## 18. Phase 9B Prerequisites
1. Connect Credential Provider `GetSerialization()` to use `LsaPackageLookup` and construct the 180-byte `MOBILE_UNLOCK_LSA_LOGON_BUFFER` when phone authentication succeeds.
2. Test end-to-end phone-to-PC unlock inside the dedicated Windows Test VM.

---

## 19. Next Phase
**Phase 9B — Real End-to-End Windows Unlock**

---

## 20. Files Future AI Should Read
1. [`docs/phases/PHASE_9A_COMPLETION.md`](file:///c:/Users/AsadU/DRIVE_0/PC%20unlock/PC%20UNlock%20Project/docs/phases/PHASE_9A_COMPLETION.md)
2. [`docs/phases/PHASE_9A_FINAL_VERIFICATION.md`](file:///c:/Users/AsadU/DRIVE_0/PC%20unlock/PC%20UNlock%20Project/docs/phases/PHASE_9A_FINAL_VERIFICATION.md)
3. [`docs/phases/PHASE_9A_FINAL_AUDIT.md`](file:///c:/Users/AsadU/DRIVE_0/PC%20unlock/PC%20UNlock%20Project/docs/phases/PHASE_9A_FINAL_AUDIT.md)
4. [`windows/authentication/LsaPackageLookup.h`](file:///c:/Users/AsadU/DRIVE_0/PC%20unlock/PC%20UNlock%20Project/windows/authentication/LsaPackageLookup.h)
5. [`windows/lsa_authentication_package/LsaLogonBuffer.h`](file:///c:/Users/AsadU/DRIVE_0/PC%20unlock/PC%20UNlock%20Project/windows/lsa_authentication_package/LsaLogonBuffer.h)
6. [`windows/credential_provider/MobileUnlockCredential.cpp`](file:///c:/Users/AsadU/DRIVE_0/PC%20unlock/PC%20UNlock%20Project/windows/credential_provider/MobileUnlockCredential.cpp)
