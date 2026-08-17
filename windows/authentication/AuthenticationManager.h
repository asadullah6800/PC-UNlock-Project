#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <string>
#include <vector>
#include <array>
#include <unordered_map>
#include <cstdint>

#include "protocol/ProtocolTypes.h"
#include "protocol/SignedMessage.h"
#include "pairing/DeviceIdentity.h"
#include "pairing/DeviceRegistry.h"
#include "crypto/CryptoManager.h"

namespace MobileUnlock::Auth {

constexpr uint32_t CHALLENGE_TTL_SECONDS = 30;
constexpr int      MAX_FAILED_ATTEMPTS   = 3;
constexpr uint32_t LOCKOUT_DURATION_SEC  = 900; // 15 minutes

struct ActiveChallenge {
    Pairing::DeviceId deviceId;
    uint64_t          sessionId;
    std::array<uint8_t, 32> nonce;
    uint64_t          createdAtMs;
    bool              isConsumed;
};

struct DeviceRateLimit {
    int      failedCount;
    uint64_t lockoutUntilMs;
};

enum class AuthResultCode : uint32_t {
    SUCCESS             = 0,
    UNKNOWN_DEVICE      = 1,
    DEVICE_REVOKED      = 2,
    MISSING_PUBLIC_KEY  = 3,
    INVALID_PAYLOAD     = 4,
    CHALLENGE_EXPIRED   = 5,
    CHALLENGE_MISMATCH  = 6,
    REPLAY_DETECTED     = 7,
    SIGNATURE_INVALID   = 8,
    RATE_LIMITED        = 9,
    INTERNAL_ERROR      = 99
};

class AuthenticationManager {
public:
    static AuthenticationManager& Instance();

    AuthenticationManager();
    ~AuthenticationManager();

    // Sets the Server Identity UUID for challenge generation
    void SetServerIdentity(const std::array<uint8_t, 16>& serverId);
    std::array<uint8_t, 16> GetServerIdentity() const;

    /**
     * Processes an incoming AUTH_REQUEST (0x0020).
     * Validates device registration, generates a fresh 256-bit challenge nonce and session ID,
     * and constructs the AUTH_CHALLENGE (0x0021) response payload.
     *
     * @param deviceId Device making the request.
     * @param requestHeader Header of the AUTH_REQUEST frame.
     * @param outChallengePayload Serialized JSON/binary payload for AUTH_CHALLENGE.
     * @param outHeader Header for AUTH_CHALLENGE response.
     * @return AuthResultCode indicating success or failure reason.
     */
    AuthResultCode HandleAuthRequest(const Pairing::DeviceId& deviceId,
                                    const Protocol::FrameHeader& requestHeader,
                                    std::vector<uint8_t>& outChallengePayload,
                                    Protocol::FrameHeader& outHeader);

    /**
     * Processes an incoming AUTH_RESPONSE (0x0022).
     * Validates challenge freshness, anti-replay, and performs Windows CNG ECDSA P-256
     * verification of the 64-byte signature over the canonical 88-byte message.
     *
     * @param requestHeader Header of AUTH_RESPONSE frame.
     * @param payloadPayload Raw bytes containing Canonical 88B SignedMessage + 64B Signature.
     * @param outResponsePayload Payload for AUTH_SUCCESS or AUTH_FAILURE.
     * @param outHeader Header for AUTH_SUCCESS (0x0023) or AUTH_FAILURE (0x0024).
     * @return AuthResultCode indicating verification outcome.
     */
    AuthResultCode HandleAuthResponse(const Protocol::FrameHeader& requestHeader,
                                     const std::vector<uint8_t>& payloadPayload,
                                     std::vector<uint8_t>& outResponsePayload,
                                     Protocol::FrameHeader& outHeader);

    // Clears all active challenges and rate limits (testing hook)
    void Reset();

    // Testing hook: inject active challenge manually
    void InjectChallengeForTesting(const ActiveChallenge& challenge);

    // Testing hook: override current time provider
    void SetTimeProviderForTesting(uint64_t (*timeProvider)());

private:
    std::array<uint8_t, 16> m_serverIdentity;
    uint64_t m_sessionCounter;
    std::unordered_map<std::string, ActiveChallenge> m_activeChallenges;
    std::unordered_map<std::string, DeviceRateLimit> m_rateLimits;
    mutable CRITICAL_SECTION m_mutex;

    uint64_t (*m_timeProvider)();

    uint64_t GetCurrentTimeMs() const;
    bool IsRateLimited(const std::string& deviceIdStr, uint64_t nowMs);
    void RecordFailure(const std::string& deviceIdStr, uint64_t nowMs);
    void RecordSuccess(const std::string& deviceIdStr);
};

} // namespace MobileUnlock::Auth
