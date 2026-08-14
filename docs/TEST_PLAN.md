# MobileFingerprintUnlock — Verification & Test Plan

## 1. Mandatory Test Environment Security Requirement

> [!CAUTION]
> **DEDICATED WINDOWS TEST VM REQUIREMENT**: All development, testing, and debugging of the **Windows Credential Provider** (`Phase 7`), **LSA Authentication Package** (`Phase 8`), and **Windows Authentication Laboratory** (`Phase 9A`) **MUST BE CONDUCTED EXCLUSIVELY INSIDE A DEDICATED WINDOWS VIRTUAL MACHINE (VM)** (Hyper-V, VMware, or VirtualBox). Under no circumstances should unverified LSA packages or Credential Providers be installed on a developer's primary host machine without prior VM validation.

### VM Test Environment Specifications
- **Host System**: Windows 11 x64 / Windows Server 2022.
- **VM Guest OS**: Clean Windows 11 Enterprise (x64) and Windows 10 Pro (x64).
- **Snapshot Requirement**: A baseline VM snapshot (`Pre-MobileUnlock-State`) MUST be created prior to registering LSA packages in the guest registry.
- **Rollback Procedure**: If an LSA package causes a guest boot failure (`BSOD`) or Winlogon hang, revert the VM to the `Pre-MobileUnlock-State` snapshot in one click or run `EmergencyRecovery.ps1`.

---

## 2. Windows C++ Unit Test Plan (GoogleTest)

Windows C++ components are unit-tested in isolation using **GoogleTest (gtest)**:

| Test Suite Name | Target Component | Test Coverage Scenarios |
| :--- | :--- | :--- |
| `CryptoManagerTest` | `CryptoManager` | ECDSA P-256 key generation, signature verification over Canonical SignedMessage (exactly 88 bytes, raw 64-byte IEEE P1363 $r \parallel s$), SHA-256 digest creation, `BCryptGenRandom` entropy. |
| `ProtocolFramingTest` | `NetworkEngine` | Wire frame encoding/decoding, header magic check (`0x4D55`), payload size bounds checking (> 4096 byte rejection), sequence number monotonicity. |
| `DeviceManagerTest` | `DeviceManager` | Device pair registry creation under `HKLM\SOFTWARE\MobileFingerprintUnlock\Devices`, public key retrieval, ACL enforcement, revocation status (`ACTIVE` vs `REVOKED`). |
| `AuthManagerTest` | `AuthenticationManager` | Nonce creation, 30-second TTL expiration enforcement, duplicate nonce rejection (anti-replay), rate limiting after 3 failed attempts. |
| `UserSessionAgentTest` | `UserSessionAgent` | Named pipe IPC dispatch from `MobileUnlockService`, `LockWorkStation()` execution in active user session, WTS session state event emission. |
| `SecureIPCTest` | `SecureIPC` | Named pipe creation (`\\.\pipe\MobileUnlockSecureIPC`), DACL validation (`SYSTEM`/`Admins` only), client process ID verification. |

---

## 3. Phase 9A Windows Authentication Laboratory Plan

Phase 9A executes dedicated laboratory tests inside the Windows VM:

1. **Package Identifier Lookup**: Validate package lookup via `LsaLookupAuthenticationPackage` and determine exact responsible component.
2. **Custom Auth Buffer Serialization**: Verify `CredentialProvider` serializes `MOBILE_UNLOCK_AUTH_BUFFER` using package ID.
3. **`LsaApLogonUserEx2` Token Creation**: Verify LSA package processes custom buffer, validates signature, populates `LSA_TOKEN_INFORMATION_TYPE` & `TokenInformation`, and LSA constructs valid user token.
4. **Phone-Only Unlock Experimental Feasibility Gate**:
   - Test `ICredentialProviderEvents::CredentialsChanged` auto-submit vs manual click on "Unlock with Phone" tile.
   - Document whether phone-only unlock can occur without human UI interaction.

---

## 4. Android Unit & Integration Test Plan

| Test Suite Name | Target Component | Test Scenarios |
| :--- | :--- | :--- |
| `KeystoreManagerTest` | `AndroidKeystoreManager` | Native Kotlin test verifying secp256r1 key creation, StrongBox feature query, key alias persistence. |
| `BiometricBindingTest` | `BiometricManager` | Verifies `CryptoObject` initialization with `Signature` instance over 88-byte payload; converts DER ASN.1 signature to 64-byte IEEE P1363 $r \parallel s$. |
| `ProtocolSerializerTest`| `WiFiTransport` | Dart unit test for Canonical SignedMessage byte serialization (88 bytes exact), sequence counter incrementing, binary UUID formatting. |
| `DeviceDiscoveryTest` | `DeviceDiscovery` | Mock mDNS broadcast discovery parsing; verifies PC IP address and friendly name extraction. |

---

## 5. Security Fuzzing & Penetration Testing

1. **Protocol Fuzzing**: Custom Python fuzzer sends malformed TCP packets, invalid magic headers, truncated payloads, and corrupted TLS frames to `MobileUnlockService`. Verification: Service must not crash, leak memory, or hang.
2. **Replay Attack Testing**: Intercept valid `AUTH_RESPONSE` frame and replay it 5 seconds later over TCP. Verification: Service rejects packet due to duplicate nonce / sequence counter check.
3. **Revoked Device Test**: Revoke paired device in `HKLM\SOFTWARE\MobileFingerprintUnlock\Devices`, then attempt unlock. Verification: Service immediately halts unlock pipeline and logs Security Event ID 2002.
