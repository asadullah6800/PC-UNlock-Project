# MobileFingerprintUnlock — Security Architecture Specification

## 1. Cryptographic Standard & Primitive Selection

To ensure robust cross-platform compatibility, mathematical security, and optimal performance, **MobileFingerprintUnlock** selects a single, standardized, hardware-accelerated cryptographic suite across Windows and Android.

### Approved Cryptographic Primitives

| Purpose | Selected Primitive | Windows Platform API | Android Platform API | Rationale & Justification |
| :--- | :--- | :--- | :--- | :--- |
| **Device Identity & Challenge Signing** | **ECDSA P-256** (secp256r1) with IEEE P1363 fixed 64-byte $r \parallel s$ encoding | Windows CNG (`BCrypt` with `BCRYPT_ECDSA_P256_ALGORITHM`) | Android Keystore (`KeyProperties.KEY_ALGORITHM_EC` with `KeyProperties.DIGEST_SHA256`) | Hardware-backed by Android TEE/StrongBox and Windows CNG. Fixed 64-byte IEEE P1363 $r \parallel s$ binary representation signed over exact 88-byte canonical struct prevents DER ASN.1 parsing ambiguities. |
| **Hash Digests & Nonces** | **SHA-256** | Windows CNG (`BCRYPT_SHA256_ALGORITHM`) | `java.security.MessageDigest` (SHA-256) | Standard 256-bit secure cryptographic hash for digest computation and HKDF key derivation. |
| **Secure Random Number Generation** | **Cryptographic RNG** | `BCryptGenRandom` (`BCRYPT_USE_SYSTEM_PREFERRED_RNG`) | `java.security.SecureRandom` | OS-provided hardware-entropy-seeded cryptographically secure pseudorandom generator. |
| **Transport Layer Security** | **TLS 1.3** | Windows Schannel / OpenSSL C++ | Android `SSLSocketFactory` / Conscrypt | Provides authenticated encryption (AEAD cipher suites `TLS_AES_256_GCM_SHA384` or `TLS_CHACHA20_POLY1305_SHA256`), perfect forward secrecy (PFS), and resistance to network interception. |

> [!IMPORTANT]
> **No Redundant Transport Encryption**: The application relies on TLS 1.3 for network transport security. No secondary custom AES-GCM or HMAC transport wrapper is added, avoiding redundant CPU overhead and custom protocol vulnerabilities. Application-level ECDSA signatures strictly validate user biometric authorization over the 88-byte canonical signed message struct.

---

## 2. Key Lifecycle & Hardware Isolation

```mermaid
graph TD
    subgraph Android TEE / StrongBox Hardware
        KeyGen[Key Pair Generation P-256] -->|setUserAuthenticationRequired: true| PrivKey[Private Key Stored in TEE]
        BioPrompt[Android BiometricPrompt] -->|Success| Authorize[Authorize CryptoObject]
        Authorize --> SignNonce[Sign 88-Byte Canonical Message with PrivKey]
    end

    subgraph Memory Isolation
        SignNonce -->|ECDSA Signature 64-byte r||s| TLS[TLS 1.3 Transport]
    end

    subgraph Windows Protected Storage
        TLS --> PCService[MobileUnlockService - NetworkService]
        PCService -->|Fetch Public Key| Registry[\HKLM\SOFTWARE\MobileFingerprintUnlock\Devices]
        Registry --> CNG[Windows CNG API]
        CNG -->|BCryptVerifySignature| Verification{Valid ECDSA Signature?}
    end
```

---

## 3. Biometric Authorization & Hardware Binding

### 3.1 Android Hardware Security Module (TEE / StrongBox)
1. **Key Generation**: The Android app requests `KeyGenerator` or `KeyPairGenerator` inside the Android Keystore provider using `KeyGenParameterSpec.Builder`.
2. **Biometric Requirement**: The key spec sets `.setUserAuthenticationRequired(true)` and `.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)`.
3. **CryptoObject Binding**: When an unlock action is requested, a `Signature` object is initialized with the private key and passed into `BiometricPrompt.CryptoObject(signature)`.
4. **Hardware Validation**: Only when the user provides a valid fingerprint does the Android TEE/StrongBox unlock the private key in hardware memory to perform the single ECDSA signing operation over the 88-byte canonical struct.
5. **Key Invalidation**: If new biometrics are enrolled or removed from the Android system, the Keystore automatically invalidates the stored key pair via `.setInvalidatedByBiometricEnrollment(true)`.

---

## 4. Windows Key Storage & Least-Privileged Service Isolation

### 4.1 Standardized Registry Architecture
Device trust records are stored exclusively under the software key:
`HKLM\SOFTWARE\MobileFingerprintUnlock\Devices\<DeviceID>`

**Access Control List (ACL)**:
- `SYSTEM`: Full Control (`KEY_ALL_ACCESS`).
- `Administrators`: Read/Write.
- `NT AUTHORITY\NetworkService`: Read Only (`KEY_READ`).
- `Users` / `Interactive`: No Access.

### 4.2 Service Privilege Minimization
`MobileUnlockService` runs under **`NT AUTHORITY\NetworkService`** rather than `LOCAL SYSTEM` to ensure that network-facing listeners do not operate with unrestricted system privileges.

---

## 5. Security Audit Logging & Non-Logging Rules

### Strict Non-Logging Directives
The system **MUST NEVER** log or persist:
- Raw fingerprint or biometric templates.
- Windows user account passwords or hashes.
- ECDSA private key material or raw secret tokens.
- Unencrypted challenge nonces or session keys.

### Security Audit Events

All security-critical actions are recorded in the **Windows Security Event Log** under Source `MobileFingerprintUnlock`:

| Event ID | Category | Description | Log Level |
| :--- | :--- | :--- | :--- |
| **1001** | `PAIRING` | Mobile device paired successfully (`DeviceID`, `DeviceName`, `ClientIP`). | Information |
| **1002** | `UNPAIR` | Mobile device unpaired / revoked (`DeviceID`). | Information |
| **2001** | `AUTH_SUCCESS` | Successful remote unlock (`DeviceID`, `AccountSID`, `TransportType`). | Information |
| **2002** | `AUTH_FAILURE` | Invalid signature or challenge mismatch (`DeviceID`, `Reason`). | Warning |
| **2003** | `AUTH_REPLAY` | Replayed or expired nonce detected (`DeviceID`, `NonceAge`). | Error / Alert |
| **3001** | `LOCK_EXECUTED` | Remote lock command executed by `UserSessionAgent`. | Information |
| **4001** | `SERVICE_FAULT`| LSA package or Credential Provider internal fault. | Error |

---

## 6. Fail-Closed & Fail-Safe Mechanisms

1. **Network Disconnection**: If Wi-Fi or Bluetooth disconnects during an authentication attempt, the Windows Credential Provider times out safely within 5 seconds and returns `STATUS_LOGON_FAILURE`.
2. **Phone Loss / Battery Depletion**: Normal Windows logon options (Windows Hello PIN, Password, Smart Card) remain 100% operational on the PC.
3. **Service Failure**: If `MobileUnlockService` crashes or stops, Windows Credential Provider falls back gracefully without hanging `Winlogon`.
4. **Rate Limiting**: After 3 consecutive failed signature validations within 60 seconds, the Windows Service temporarily blocks authentication from the specific `DeviceID` for 15 minutes.
