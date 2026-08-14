# MobileFingerprintUnlock — Network & Framing Protocol Specification

## 1. Protocol Architecture & Header Specification

The **MobileFingerprintUnlock Protocol** is a versioned, binary-framed protocol operating over TLS 1.3 TCP streams (Wi-Fi) or GATT Characteristics (Bluetooth BLE).

### 1.1 Wire Frame Layout

All network messages begin with a fixed **24-byte Header**, followed by a variable-length **Payload JSON/Binary Blob**.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Magic (0x4D55)       | Major Version | Minor Version |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Message Type         |         Reserved (0x0000)     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Message ID (32-bit)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Payload Length (Bytes)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                       Sequence Number (64-bit)                +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Payload Data...                       |
v                                                               v
```

### 1.2 Header Fields

| Field Name | Type | Size | Description |
| :--- | :--- | :--- | :--- |
| **Magic** | `uint16_t` | 2 Bytes | Protocol identifier constant: `0x4D55` ('M', 'U'). |
| **Major Version** | `uint8_t` | 1 Byte | Protocol major version (`0x01`). |
| **Minor Version** | `uint8_t` | 1 Byte | Protocol minor version (`0x00`). |
| **Message Type** | `uint16_t` | 2 Bytes | Message type opcode enum value. |
| **Reserved** | `uint16_t` | 2 Bytes | Alignment padding (must be `0x0000`). |
| **Message ID** | `uint32_t` | 4 Bytes | Monotonically increasing request identifier. |
| **Payload Length** | `uint32_t` | 4 Bytes | Size of following payload in bytes (Max `4096` bytes). |
| **Sequence Number**| `uint64_t` | 8 Bytes | Monotonic session sequence counter for anti-replay verification. |

---

## 2. Complete Message Catalogue

| Opcode | Message Enum | Direction | Description |
| :--- | :--- | :--- | :--- |
| `0x0001` | `DISCOVER` | Phone -> PC | UDP/mDNS broadcast packet querying online PCs. |
| `0x0002` | `DISCOVERY_RESPONSE` | PC -> Phone | Response containing PC hostname, service port, state, and server public key hash. |
| `0x0010` | `PAIR_REQUEST` | Phone -> PC | Initiates out-of-band pairing flow with device ID and client public key. |
| `0x0011` | `PAIR_RESPONSE` | PC -> Phone | Sends server public key and SAS (Short Authentication String) PIN prompt. |
| `0x0012` | `PAIR_CONFIRM` | Phone -> PC | Sends user-confirmed SAS signature digest. |
| `0x0013` | `PAIR_COMPLETE` | PC -> Phone | Confirms device added to trusted registry. |
| `0x0020` | `AUTH_REQUEST` | Phone -> PC | Requests unlock challenge from PC. |
| `0x0021` | `AUTH_CHALLENGE` | PC -> Phone | Returns 256-bit secure nonce, server timestamp, and session ID. |
| `0x0022` | `AUTH_RESPONSE` | Phone -> PC | Submits ECDSA P-256 canonical signed message response. |
| `0x0023` | `AUTH_SUCCESS` | PC -> Phone | Confirms successful Windows unlock. |
| `0x0024` | `AUTH_FAILURE` | PC -> Phone | Rejection message with error status code. |
| `0x0030` | `LOCK_REQUEST` | Phone -> PC | Requests workstation lock. |
| `0x0031` | `LOCK_RESPONSE` | PC -> Phone | Confirms workstation lock execution status. |
| `0x0040` | `STATUS_REQUEST` | Phone -> PC | Queries Windows session status (`LOCKED`, `UNLOCKED`, etc.). |
| `0x0041` | `STATUS_RESPONSE` | PC -> Phone | Returns detailed system status. |
| `0x0050` | `UNPAIR_REQUEST` | Phone -> PC | Requests revocation and deletion of device pair from registry. |
| `0x0051` | `UNPAIR_RESPONSE` | PC -> Phone | Confirms unpair deletion. |
| `0x00E0` | `PING` | Either | Keep-alive heartbeat message. |
| `0x00E1` | `PONG` | Either | Heartbeat response. |
| `0x00FF` | `ERROR` | Either | Protocol error payload. |

---

## 3. Single Canonical Signed Message Specification

All authentication and lock operations MUST sign the exact **Canonical SignedMessage** binary payload defined below. The total size of the canonical signed message is **exactly 88 Bytes**.

### 3.1 Field Ordering & Binary Serialization

Byte order is strictly **Big-Endian (Network Byte Order)** for integers.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       ProtocolVersion         |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                    ServerIdentity (16 Bytes)                  |
|                           (Binary UUID)                       |
+                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                    DeviceIdentity (16 Bytes)                  |
|                           (Binary UUID)                       |
+                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               |           Operation           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           RequestID                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           SessionID                           |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                     Nonce (32 Bytes Binary)                   +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Timestamp                           |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 3.2 Field Breakdown (Total 88 Bytes)

| Field Name | Type | Size | Description |
| :--- | :--- | :--- | :--- |
| **ProtocolVersion** | `uint16_t` | 2 Bytes | Protocol version (`0x0100`). |
| **ServerIdentity** | `uint8_t[16]` | 16 Bytes | Server 128-bit Binary UUID. |
| **DeviceIdentity** | `uint8_t[16]` | 16 Bytes | Client Device 128-bit Binary UUID. |
| **Operation** | `uint16_t` | 2 Bytes | Operation code (e.g., `0x0022` for `AUTH_RESPONSE`, `0x0030` for `LOCK_REQUEST`). |
| **RequestID** | `uint32_t` | 4 Bytes | Monotonic request counter. |
| **SessionID** | `uint64_t` | 8 Bytes | Active session identifier. |
| **Nonce** | `uint8_t[32]`| 32 Bytes | 256-bit random challenge nonce. |
| **Timestamp** | `uint64_t` | 8 Bytes | Client UNIX timestamp in milliseconds. |

> [!NOTE]
> **UUID Representation**: UUIDs may be formatted and displayed as 36-character hyphenated string representations (e.g. `123e4567-e89b-12d3-a456-426614174000`) in user interfaces or configuration files. However, the canonical signed and wire representation **MUST** use 16-byte raw binary UUIDs.

### 3.3 Hash & Signature Input

1. **Digest Calculation**:
   $$\text{MessageDigest} = \text{SHA-256}(\text{CanonicalSignedMessage88Bytes})$$
2. **Signature Encoding**:
   - Signature algorithm: **ECDSA P-256** (secp256r1).
   - Output format: **Fixed-width 64-byte IEEE P1363 raw $r \parallel s$ encoding** (32-byte $r$ Big-Endian + 32-byte $s$ Big-Endian).

---

## 4. Anti-Replay & Freshness Rules

1. **256-Bit Nonces**: Generated via `BCryptGenRandom` on PC for every `AUTH_CHALLENGE`.
2. **Strict Time Window (TTL)**: Nonces expire exactly **30 seconds** after creation.
3. **Monotonic Sequence Numbers**: Each message increments the 64-bit sequence counter. Duplicate sequence numbers trigger immediate connection teardown.
