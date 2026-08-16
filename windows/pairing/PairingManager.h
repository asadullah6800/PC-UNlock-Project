#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <functional>
#include <atomic>

#include "DeviceIdentity.h"
#include "SasPin.h"
#include "DeviceRegistry.h"
#include "../../shared/protocol/ProtocolTypes.h"

namespace MobileUnlock::Pairing {

// Pairing state machine as specified in IDENTITY_MAPPING.md
enum class PairingState : uint32_t {
    UNPAIRED           = 0,
    PAIRING_REQUESTED  = 1,  // PAIR_REQUEST received, SAS generated, waiting for confirmation
    WAITING_FOR_SAS    = 2,  // PAIR_RESPONSE sent with SAS prompt
    SAS_VERIFIED       = 3,  // Correct SAS received via PAIR_CONFIRM
    PAIRING_CONFIRMED  = 4,  // Finalizing registry write
    PAIRED             = 5,  // Fully registered in HKLM
    EXPIRED            = 6,  // SAS or session timed out
    CANCELLED          = 7,  // User cancelled on either side
    FAILED             = 8,  // Wrong SAS / max attempts exceeded
    REVOKED            = 9   // Previously paired device that has been revoked
};

// Pairing session — one per pending phone connection
struct PairingSession {
    DeviceId    deviceId;
    std::string deviceName;
    std::string clientIp;
    std::string sasPin;            // Cleared after pairing completes or fails — NEVER log this
    FILETIME    sasGeneratedAt;
    int         sasAttempts;
    PairingState state;
    uint64_t    sessionClientId;   // NetworkEngine client identifier

    // Public key bytes from PAIR_REQUEST — ECDSA P-256 SPKI (used in Phase 4)
    std::vector<uint8_t> clientPublicKey;
};

// Callback invoked by PairingManager when a new SAS PIN is generated and should be displayed
// The caller must display this on screen and clear it from memory after use
// The PIN is passed as a value copy; the manager immediately clears its internal copy upon PAIRED or FAILED
using SasPinDisplayCallback = std::function<void(const std::string& pin, const std::string& deviceName)>;

// Callback invoked when pairing succeeds — allows MobileUnlockService to log Event 1001
using PairingSuccessCallback = std::function<void(const DeviceId& deviceId, const std::string& deviceName, const std::string& clientIp)>;

// Callback invoked when pairing fails or is cancelled
using PairingFailureCallback = std::function<void(const std::string& reason)>;

// --- PAIR_REQUEST payload (JSON keys per PROTOCOL.md)
// Parsed from incoming PAIR_REQUEST frame payload
struct PairRequestPayload {
    std::string deviceId;       // UUID string
    std::string deviceName;     // Human-readable phone name
    std::vector<uint8_t> publicKey; // ECDSA P-256 SPKI blob (hex-encoded in JSON)
    bool valid{false};
};

// --- PAIR_RESPONSE payload (sent to phone)
struct PairResponsePayload {
    std::string serverDeviceId; // PC's host device identifier
    bool sasRequired{true};     // Always true for this protocol
};

// --- PAIR_CONFIRM payload (from phone)
struct PairConfirmPayload {
    std::string deviceId;
    std::string sasPin;         // User-entered PIN — NEVER log
    bool valid{false};
};

// --- Error payload
struct ErrorPayload {
    uint32_t    errorCode;
    std::string message;
};

// Parses PAIR_REQUEST JSON payload; returns PairRequestPayload with valid=true on success
PairRequestPayload ParsePairRequest(const std::vector<uint8_t>& payloadBytes);

// Builds PAIR_RESPONSE JSON bytes
std::vector<uint8_t> BuildPairResponse(const std::string& serverHostname);

// Builds PAIR_COMPLETE JSON bytes
std::vector<uint8_t> BuildPairComplete(const std::string& deviceIdStr);

// Builds PROTO_ERROR JSON bytes
std::vector<uint8_t> BuildErrorPayload(uint32_t errorCode, const std::string& message);

// Parses PAIR_CONFIRM JSON payload
PairConfirmPayload ParsePairConfirm(const std::vector<uint8_t>& payloadBytes);

// Builds UNPAIR_RESPONSE JSON bytes
std::vector<uint8_t> BuildUnpairResponse(bool success, const std::string& deviceIdStr);

// -----------------------------------------------------------------------
// PairingManager
// Manages the full pairing state machine including SAS, registry write,
// rate limiting, duplicate handling, and revocation
// -----------------------------------------------------------------------
class PairingManager {
public:
    explicit PairingManager();
    ~PairingManager();

    PairingManager(const PairingManager&) = delete;
    PairingManager& operator=(const PairingManager&) = delete;

    void SetSasPinDisplayCallback(SasPinDisplayCallback cb) { m_onSasDisplay = std::move(cb); }
    void SetPairingSuccessCallback(PairingSuccessCallback cb) { m_onSuccess = std::move(cb); }
    void SetPairingFailureCallback(PairingFailureCallback cb) { m_onFailure = std::move(cb); }

    // Called from NetworkEngine when a PAIR_REQUEST frame arrives
    // Returns serialized PAIR_RESPONSE bytes, or PROTO_ERROR bytes on rejection
    // clientId is the NetworkEngine client identifier for response routing
    std::vector<uint8_t> HandlePairRequest(uint64_t clientId,
                                           const std::string& clientIp,
                                           const std::vector<uint8_t>& payloadBytes,
                                           Protocol::MessageType& outResponseType);

    // Called when a PAIR_CONFIRM frame arrives for an existing session
    std::vector<uint8_t> HandlePairConfirm(uint64_t clientId,
                                            const std::vector<uint8_t>& payloadBytes,
                                            Protocol::MessageType& outResponseType);

    // Called when UNPAIR_REQUEST arrives for a previously paired device
    std::vector<uint8_t> HandleUnpairRequest(uint64_t clientId,
                                              const std::vector<uint8_t>& payloadBytes,
                                              Protocol::MessageType& outResponseType);

    // Check if a device is currently in an active pairing session
    bool HasActivePairingSession(uint64_t clientId) const;

    // Cancel and clean up any pairing session associated with the given client
    void CancelPairingSession(uint64_t clientId);

    // Expire stale pairing sessions (called periodically by MobileUnlockService)
    void ExpireStaleSessions();

    // Returns the current pairing state for a client, or UNPAIRED if no session
    PairingState GetSessionState(uint64_t clientId) const;

    // Resolves account SID from active session's logon user (first interactive session)
    // Returns empty string if no logged-on user can be resolved
    static std::string ResolveCurrentAccountSid();

private:
    void ClearSession(uint64_t clientId);
    bool IsRateLimited(const std::string& deviceIdStr) const;
    void RecordFailedAttempt(const std::string& deviceIdStr);
    void ClearFailedAttempts(const std::string& deviceIdStr);

    mutable CRITICAL_SECTION m_cs;

    // Active pairing sessions: clientId -> PairingSession
    // Only one pairing session per client at a time
    std::map<uint64_t, PairingSession> m_sessions;

    // Rate-limiting for pairing attempts per DeviceID: deviceIdStr -> (count, windowStart)
    std::map<std::string, std::pair<int, FILETIME>> m_rateLimitMap;

    SasPinDisplayCallback  m_onSasDisplay;
    PairingSuccessCallback m_onSuccess;
    PairingFailureCallback m_onFailure;
};

} // namespace MobileUnlock::Pairing
