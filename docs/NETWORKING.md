# MobileFingerprintUnlock — Wi-Fi Network Transport Specification

## 1. Network Transport Overview (Phase 1)

Phase 1 local network communication operates over standard local Wi-Fi networks using **TCP sockets wrapped in TLS 1.3**.

### Core Network Postulates
- **Zero Trust LAN**: The local Wi-Fi network is treated as inherently insecure. IP addresses and MAC addresses are **NEVER** trusted as device identity.
- **Port Allocation**: Default TCP port `8443` (configurable via `ConfigurationManager`).
- **Service Discovery**: Multicast DNS (mDNS) via `Bonjour` / `nsd` (`_mobileunlock._tcp.local.`) with UDP broadcast fallback on port `8444`.
- **Service Security**: `MobileUnlockService` executes under `NT AUTHORITY\NetworkService` to minimize privileges exposed to network sockets.

---

## 2. Wi-Fi Connection & Authentication Sequence

```mermaid
sequenceDiagram
    autonumber
    participant App as Android WiFiTransport
    participant mDNS as mDNS / LAN Broadcast
    participant PCNet as Windows NetworkEngine (TLS 1.3)
    participant AuthEngine as Windows AuthenticationManager

    App->>mDNS: Query _mobileunlock._tcp.local. (mDNS / UDP Broadcast)
    PCNet-->>App: Service Announcement (PC Name, IP:Port, Cert Fingerprint)
    
    App->>PCNet: Initiate TCP Connection (Port 8443)
    App<->>PCNet: Perform TLS 1.3 Handshake (Server Cert Pinned against Pair Registry)
    
    App->>PCNet: Send AUTH_REQUEST Frame (Header + Payload)
    PCNet->>AuthEngine: Validate Session Request & Generate 256-bit Nonce
    AuthEngine-->>App: Return AUTH_CHALLENGE (Nonce, Timestamp, Session ID)
    
    App->>App: Process Biometric & Sign Canonical SignedMessage
    App->>PCNet: Send AUTH_RESPONSE Frame (Canonical Signature Payload)
    
    PCNet->>AuthEngine: Verify Signature against HKLM\SOFTWARE\MobileFingerprintUnlock\Devices
    AuthEngine-->>PCNet: Return Authorization Valid
    PCNet-->>App: Return AUTH_SUCCESS Frame
```

---

## 3. Network Connection State Machine

```
   +--------------------+
   |    DISCONNECTED    |
   +--------------------+
             |
             | mDNS Discovery / IP Resolve
             v
   +--------------------+
   |  TCP_CONNECTING    |
   +--------------------+
             |
             | TCP Socket Established
             v
   +--------------------+
   |   TLS_HANDSHAKE    |  <-- TLS 1.3 Client Certificate Validation
   +--------------------+
             |
             | TLS Session Established
             v
   +--------------------+
   |  ACTIVE_SESSION    |  <-- Ping/Pong Heartbeat (Every 15 sec)
   +--------------------+
             |
             +--------------------+--------------------+
             |                    |                    |
             | Auth Action        | Network Drop       | Server Close
             v                    v                    v
   +--------------------+  +--------------------+  +--------------------+
   |   AUTHENTICATING   |  |     RECONNECTING   |  |     DISCONNECTED   |
   +--------------------+  +--------------------+  +--------------------+
```

---

## 4. Robustness & Resilience Features

1. **Malformed Packet Defense**:
   - Header magic verification (`0x4D55`).
   - Maximum Payload Enforcement: Any frame indicating a `PayloadLength` exceeding `4096` bytes is dropped immediately, and the TCP socket is closed.
2. **Rate Limiting**:
   - Max 5 connection attempts per minute per IP address.
   - Socket buffer limits prevent memory exhaustion.
3. **Keep-Alive & Timeout Rules**:
   - `PING` / `PONG` heartbeat sent every 15 seconds during active session.
   - Session marked stale and destroyed if no packet received within **30 seconds**.
