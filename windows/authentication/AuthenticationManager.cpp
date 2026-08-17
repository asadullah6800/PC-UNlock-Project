#include "AuthenticationManager.h"
#include <chrono>
#include <sstream>
#include <iomanip>

namespace MobileUnlock::Auth {

static uint64_t DefaultTimeProvider() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

static std::string BytesToHex(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    return oss.str();
}

AuthenticationManager& AuthenticationManager::Instance() {
    static AuthenticationManager s_instance;
    return s_instance;
}

AuthenticationManager::AuthenticationManager()
    : m_sessionCounter(1),
      m_timeProvider(DefaultTimeProvider) {
    InitializeCriticalSection(&m_mutex);
    m_serverIdentity.fill(0xAA);
}

AuthenticationManager::~AuthenticationManager() {
    DeleteCriticalSection(&m_mutex);
}

void AuthenticationManager::SetServerIdentity(const std::array<uint8_t, 16>& serverId) {
    EnterCriticalSection(&m_mutex);
    m_serverIdentity = serverId;
    LeaveCriticalSection(&m_mutex);
}

std::array<uint8_t, 16> AuthenticationManager::GetServerIdentity() const {
    EnterCriticalSection(const_cast<CRITICAL_SECTION*>(&m_mutex));
    std::array<uint8_t, 16> copy = m_serverIdentity;
    LeaveCriticalSection(const_cast<CRITICAL_SECTION*>(&m_mutex));
    return copy;
}

uint64_t AuthenticationManager::GetCurrentTimeMs() const {
    return m_timeProvider ? m_timeProvider() : DefaultTimeProvider();
}

void AuthenticationManager::SetTimeProviderForTesting(uint64_t (*timeProvider)()) {
    EnterCriticalSection(&m_mutex);
    m_timeProvider = timeProvider;
    LeaveCriticalSection(&m_mutex);
}

void AuthenticationManager::Reset() {
    EnterCriticalSection(&m_mutex);
    m_activeChallenges.clear();
    m_rateLimits.clear();
    m_sessionCounter = 1;
    LeaveCriticalSection(&m_mutex);
}

void AuthenticationManager::InjectChallengeForTesting(const ActiveChallenge& challenge) {
    EnterCriticalSection(&m_mutex);
    std::string deviceIdStr = Pairing::DeviceIdToString(challenge.deviceId);
    m_activeChallenges[deviceIdStr] = challenge;
    LeaveCriticalSection(&m_mutex);
}

bool AuthenticationManager::IsRateLimited(const std::string& deviceIdStr, uint64_t nowMs) {
    auto it = m_rateLimits.find(deviceIdStr);
    if (it != m_rateLimits.end()) {
        if (nowMs < it->second.lockoutUntilMs) {
            return true;
        }
        if (it->second.lockoutUntilMs != 0 && nowMs >= it->second.lockoutUntilMs) {
            // Lockout expired, reset counter
            it->second.failedCount = 0;
            it->second.lockoutUntilMs = 0;
        }
    }
    return false;
}

void AuthenticationManager::RecordFailure(const std::string& deviceIdStr, uint64_t nowMs) {
    auto& limit = m_rateLimits[deviceIdStr];
    limit.failedCount++;
    if (limit.failedCount >= MAX_FAILED_ATTEMPTS) {
        limit.lockoutUntilMs = nowMs + (LOCKOUT_DURATION_SEC * 1000ULL);
    }
}

void AuthenticationManager::RecordSuccess(const std::string& deviceIdStr) {
    m_rateLimits.erase(deviceIdStr);
}

AuthResultCode AuthenticationManager::HandleAuthRequest(const Pairing::DeviceId& deviceId,
                                                        const Protocol::FrameHeader& requestHeader,
                                                        std::vector<uint8_t>& outChallengePayload,
                                                        Protocol::FrameHeader& outHeader) {
    EnterCriticalSection(&m_mutex);

    std::string deviceIdStr = Pairing::DeviceIdToString(deviceId);
    uint64_t nowMs = GetCurrentTimeMs();
    AuthResultCode resultCode = AuthResultCode::INTERNAL_ERROR;

    do {
        // 1. Check rate limiting
        if (IsRateLimited(deviceIdStr, nowMs)) {
            outHeader.MessageType   = static_cast<uint16_t>(Protocol::MessageType::AUTH_FAILURE);
            outHeader.MessageID     = requestHeader.MessageID;
            outHeader.SequenceNumber = requestHeader.SequenceNumber + 1;
            std::string err = "{\"status\":\"ERROR\",\"reason\":\"RATE_LIMITED\"}";
            outChallengePayload.assign(err.begin(), err.end());
            outHeader.PayloadLength = static_cast<uint32_t>(outChallengePayload.size());
            resultCode = AuthResultCode::RATE_LIMITED;
            break;
        }

        // 2. Lookup device in DeviceRegistry
        Pairing::DeviceRecord record;
        LONG res = Pairing::ReadDeviceRecord(deviceIdStr, record);
        if (res != ERROR_SUCCESS) {
            outHeader.MessageType   = static_cast<uint16_t>(Protocol::MessageType::AUTH_FAILURE);
            outHeader.MessageID     = requestHeader.MessageID;
            outHeader.SequenceNumber = requestHeader.SequenceNumber + 1;
            std::string err = "{\"status\":\"ERROR\",\"reason\":\"UNKNOWN_DEVICE\"}";
            outChallengePayload.assign(err.begin(), err.end());
            outHeader.PayloadLength = static_cast<uint32_t>(outChallengePayload.size());
            resultCode = AuthResultCode::UNKNOWN_DEVICE;
            break;
        }

        if (record.pairStatus != Pairing::kStatusActive) {
            outHeader.MessageType   = static_cast<uint16_t>(Protocol::MessageType::AUTH_FAILURE);
            outHeader.MessageID     = requestHeader.MessageID;
            outHeader.SequenceNumber = requestHeader.SequenceNumber + 1;
            std::string err = "{\"status\":\"ERROR\",\"reason\":\"DEVICE_REVOKED\"}";
            outChallengePayload.assign(err.begin(), err.end());
            outHeader.PayloadLength = static_cast<uint32_t>(outChallengePayload.size());
            resultCode = AuthResultCode::DEVICE_REVOKED;
            break;
        }

        if (record.publicKey.empty()) {
            outHeader.MessageType   = static_cast<uint16_t>(Protocol::MessageType::AUTH_FAILURE);
            outHeader.MessageID     = requestHeader.MessageID;
            outHeader.SequenceNumber = requestHeader.SequenceNumber + 1;
            std::string err = "{\"status\":\"ERROR\",\"reason\":\"MISSING_PUBLIC_KEY\"}";
            outChallengePayload.assign(err.begin(), err.end());
            outHeader.PayloadLength = static_cast<uint32_t>(outChallengePayload.size());
            resultCode = AuthResultCode::MISSING_PUBLIC_KEY;
            break;
        }

        // 3. Generate fresh 32-byte cryptographic random nonce
        ActiveChallenge challenge;
        challenge.deviceId    = deviceId;
        challenge.sessionId   = m_sessionCounter++;
        challenge.createdAtMs = nowMs;
        challenge.isConsumed  = false;

        if (!Crypto::CryptoManager::GenerateRandomBytes(challenge.nonce.data(), challenge.nonce.size())) {
            outHeader.MessageType = static_cast<uint16_t>(Protocol::MessageType::AUTH_FAILURE);
            outHeader.MessageID   = requestHeader.MessageID;
            outHeader.SequenceNumber = requestHeader.SequenceNumber + 1;
            std::string err = "{\"status\":\"ERROR\",\"reason\":\"INTERNAL_ERROR\"}";
            outChallengePayload.assign(err.begin(), err.end());
            outHeader.PayloadLength = static_cast<uint32_t>(outChallengePayload.size());
            resultCode = AuthResultCode::INTERNAL_ERROR;
            break;
        }

        // Save active challenge
        m_activeChallenges[deviceIdStr] = challenge;

        // 4. Construct JSON payload for AUTH_CHALLENGE
        std::string nonceHex = BytesToHex(challenge.nonce.data(), challenge.nonce.size());
        std::string serverIdHex = BytesToHex(m_serverIdentity.data(), m_serverIdentity.size());

        std::ostringstream oss;
        oss << "{"
            << "\"sessionId\":" << challenge.sessionId << ","
            << "\"nonce\":\"" << nonceHex << "\","
            << "\"serverIdentity\":\"" << serverIdHex << "\","
            << "\"timestamp\":" << challenge.createdAtMs
            << "}";

        std::string jsonStr = oss.str();
        outChallengePayload.assign(jsonStr.begin(), jsonStr.end());

        outHeader.Magic          = Protocol::PROTOCOL_MAGIC;
        outHeader.MajorVersion   = Protocol::PROTOCOL_MAJOR_VERSION;
        outHeader.MinorVersion   = Protocol::PROTOCOL_MINOR_VERSION;
        outHeader.MessageType    = static_cast<uint16_t>(Protocol::MessageType::AUTH_CHALLENGE);
        outHeader.Reserved       = 0;
        outHeader.MessageID      = requestHeader.MessageID;
        outHeader.PayloadLength  = static_cast<uint32_t>(outChallengePayload.size());
        outHeader.SequenceNumber = requestHeader.SequenceNumber + 1;

        resultCode = AuthResultCode::SUCCESS;
    } while (false);

    LeaveCriticalSection(&m_mutex);
    return resultCode;
}

AuthResultCode AuthenticationManager::HandleAuthResponse(const Protocol::FrameHeader& requestHeader,
                                                         const std::vector<uint8_t>& payload,
                                                         std::vector<uint8_t>& outResponsePayload,
                                                         Protocol::FrameHeader& outHeader) {
    EnterCriticalSection(&m_mutex);

    uint64_t nowMs = GetCurrentTimeMs();
    AuthResultCode resultCode = AuthResultCode::INTERNAL_ERROR;

    outHeader.Magic          = Protocol::PROTOCOL_MAGIC;
    outHeader.MajorVersion   = Protocol::PROTOCOL_MAJOR_VERSION;
    outHeader.MinorVersion   = Protocol::PROTOCOL_MINOR_VERSION;
    outHeader.Reserved       = 0;
    outHeader.MessageID      = requestHeader.MessageID;
    outHeader.SequenceNumber = requestHeader.SequenceNumber + 1;

    std::string currentDevId;

    do {
        // 1. Validate payload length
        if (payload.size() < Protocol::CANONICAL_SIGNED_MESSAGE_SIZE + Crypto::P1363_SIGNATURE_SIZE) {
            outHeader.MessageType = static_cast<uint16_t>(Protocol::MessageType::AUTH_FAILURE);
            std::string err = "{\"status\":\"FAILURE\",\"reason\":\"INVALID_PAYLOAD_SIZE\"}";
            outResponsePayload.assign(err.begin(), err.end());
            outHeader.PayloadLength = static_cast<uint32_t>(outResponsePayload.size());
            resultCode = AuthResultCode::INVALID_PAYLOAD;
            break;
        }

        const uint8_t* msgBytes = payload.data();
        const uint8_t* sigBytes = payload.data() + Protocol::CANONICAL_SIGNED_MESSAGE_SIZE;
        size_t sigLen = payload.size() - Protocol::CANONICAL_SIGNED_MESSAGE_SIZE;

        if (sigLen != Crypto::P1363_SIGNATURE_SIZE) {
            outHeader.MessageType = static_cast<uint16_t>(Protocol::MessageType::AUTH_FAILURE);
            std::string err = "{\"status\":\"FAILURE\",\"reason\":\"INVALID_SIGNATURE_LENGTH\"}";
            outResponsePayload.assign(err.begin(), err.end());
            outHeader.PayloadLength = static_cast<uint32_t>(outResponsePayload.size());
            resultCode = AuthResultCode::INVALID_PAYLOAD;
            break;
        }

        // 2. Deserialize canonical SignedMessage
        auto parseRes = Protocol::DeserializeSignedMessage(msgBytes, Protocol::CANONICAL_SIGNED_MESSAGE_SIZE);
        if (!parseRes.has_value()) {
            outHeader.MessageType = static_cast<uint16_t>(Protocol::MessageType::AUTH_FAILURE);
            std::string err = "{\"status\":\"FAILURE\",\"reason\":\"INVALID_SIGNED_MESSAGE\"}";
            outResponsePayload.assign(err.begin(), err.end());
            outHeader.PayloadLength = static_cast<uint32_t>(outResponsePayload.size());
            resultCode = AuthResultCode::INVALID_PAYLOAD;
            break;
        }

        const Protocol::SignedMessage& signedMsg = parseRes.value;

        // 3. Resolve DeviceIdentity
        Pairing::DeviceId deviceId;
        std::memcpy(deviceId.data(), signedMsg.DeviceIdentity, 16);
        currentDevId = Pairing::DeviceIdToString(deviceId);

        // 4. Check rate limiting
        if (IsRateLimited(currentDevId, nowMs)) {
            outHeader.MessageType = static_cast<uint16_t>(Protocol::MessageType::AUTH_FAILURE);
            std::string err = "{\"status\":\"FAILURE\",\"reason\":\"RATE_LIMITED\"}";
            outResponsePayload.assign(err.begin(), err.end());
            outHeader.PayloadLength = static_cast<uint32_t>(outResponsePayload.size());
            resultCode = AuthResultCode::RATE_LIMITED;
            break;
        }

        // 5. Lookup device record in registry
        Pairing::DeviceRecord record;
        LONG regRes = Pairing::ReadDeviceRecord(currentDevId, record);
        if (regRes != ERROR_SUCCESS) {
            outHeader.MessageType = static_cast<uint16_t>(Protocol::MessageType::AUTH_FAILURE);
            std::string err = "{\"status\":\"FAILURE\",\"reason\":\"UNKNOWN_DEVICE\"}";
            outResponsePayload.assign(err.begin(), err.end());
            outHeader.PayloadLength = static_cast<uint32_t>(outResponsePayload.size());
            RecordFailure(currentDevId, nowMs);
            resultCode = AuthResultCode::UNKNOWN_DEVICE;
            break;
        }

        if (record.pairStatus != Pairing::kStatusActive) {
            outHeader.MessageType = static_cast<uint16_t>(Protocol::MessageType::AUTH_FAILURE);
            std::string err = "{\"status\":\"FAILURE\",\"reason\":\"DEVICE_REVOKED\"}";
            outResponsePayload.assign(err.begin(), err.end());
            outHeader.PayloadLength = static_cast<uint32_t>(outResponsePayload.size());
            RecordFailure(currentDevId, nowMs);
            resultCode = AuthResultCode::DEVICE_REVOKED;
            break;
        }

        if (record.publicKey.empty()) {
            outHeader.MessageType = static_cast<uint16_t>(Protocol::MessageType::AUTH_FAILURE);
            std::string err = "{\"status\":\"FAILURE\",\"reason\":\"MISSING_PUBLIC_KEY\"}";
            outResponsePayload.assign(err.begin(), err.end());
            outHeader.PayloadLength = static_cast<uint32_t>(outResponsePayload.size());
            RecordFailure(currentDevId, nowMs);
            resultCode = AuthResultCode::MISSING_PUBLIC_KEY;
            break;
        }

        // 6. Match active challenge
        auto it = m_activeChallenges.find(currentDevId);
        if (it == m_activeChallenges.end()) {
            outHeader.MessageType = static_cast<uint16_t>(Protocol::MessageType::AUTH_FAILURE);
            std::string err = "{\"status\":\"FAILURE\",\"reason\":\"NO_ACTIVE_CHALLENGE\"}";
            outResponsePayload.assign(err.begin(), err.end());
            outHeader.PayloadLength = static_cast<uint32_t>(outResponsePayload.size());
            RecordFailure(currentDevId, nowMs);
            resultCode = AuthResultCode::REPLAY_DETECTED;
            break;
        }

        ActiveChallenge& challenge = it->second;

        if (challenge.isConsumed) {
            outHeader.MessageType = static_cast<uint16_t>(Protocol::MessageType::AUTH_FAILURE);
            std::string err = "{\"status\":\"FAILURE\",\"reason\":\"CHALLENGE_ALREADY_CONSUMED\"}";
            outResponsePayload.assign(err.begin(), err.end());
            outHeader.PayloadLength = static_cast<uint32_t>(outResponsePayload.size());
            RecordFailure(currentDevId, nowMs);
            resultCode = AuthResultCode::REPLAY_DETECTED;
            break;
        }

        if (nowMs < challenge.createdAtMs || (nowMs - challenge.createdAtMs) > (CHALLENGE_TTL_SECONDS * 1000ULL)) {
            challenge.isConsumed = true;
            outHeader.MessageType = static_cast<uint16_t>(Protocol::MessageType::AUTH_FAILURE);
            std::string err = "{\"status\":\"FAILURE\",\"reason\":\"NONCE_EXPIRED\"}";
            outResponsePayload.assign(err.begin(), err.end());
            outHeader.PayloadLength = static_cast<uint32_t>(outResponsePayload.size());
            RecordFailure(currentDevId, nowMs);
            resultCode = AuthResultCode::CHALLENGE_EXPIRED;
            break;
        }

        if (signedMsg.SessionID != challenge.sessionId) {
            challenge.isConsumed = true;
            outHeader.MessageType = static_cast<uint16_t>(Protocol::MessageType::AUTH_FAILURE);
            std::string err = "{\"status\":\"FAILURE\",\"reason\":\"SESSION_ID_MISMATCH\"}";
            outResponsePayload.assign(err.begin(), err.end());
            outHeader.PayloadLength = static_cast<uint32_t>(outResponsePayload.size());
            RecordFailure(currentDevId, nowMs);
            resultCode = AuthResultCode::CHALLENGE_MISMATCH;
            break;
        }

        if (std::memcmp(signedMsg.Nonce, challenge.nonce.data(), challenge.nonce.size()) != 0) {
            challenge.isConsumed = true;
            outHeader.MessageType = static_cast<uint16_t>(Protocol::MessageType::AUTH_FAILURE);
            std::string err = "{\"status\":\"FAILURE\",\"reason\":\"NONCE_MISMATCH\"}";
            outResponsePayload.assign(err.begin(), err.end());
            outHeader.PayloadLength = static_cast<uint32_t>(outResponsePayload.size());
            RecordFailure(currentDevId, nowMs);
            resultCode = AuthResultCode::CHALLENGE_MISMATCH;
            break;
        }

        // Mark challenge consumed before crypto verification
        challenge.isConsumed = true;

        // 7. Verify ECDSA P-256 signature using Windows CNG
        bool sigValid = Crypto::CryptoManager::VerifyCanonicalSignedMessage(
            record.publicKey,
            signedMsg,
            sigBytes,
            sigLen
        );

        if (!sigValid) {
            outHeader.MessageType = static_cast<uint16_t>(Protocol::MessageType::AUTH_FAILURE);
            std::string err = "{\"status\":\"FAILURE\",\"reason\":\"SIGNATURE_VERIFICATION_FAILED\"}";
            outResponsePayload.assign(err.begin(), err.end());
            outHeader.PayloadLength = static_cast<uint32_t>(outResponsePayload.size());
            RecordFailure(currentDevId, nowMs);
            resultCode = AuthResultCode::SIGNATURE_INVALID;
            break;
        }

        // 8. Authentication Succeeded
        RecordSuccess(currentDevId);
        Pairing::UpdateLastSeen(currentDevId);

        outHeader.MessageType = static_cast<uint16_t>(Protocol::MessageType::AUTH_SUCCESS);
        std::string successPayload = "{\"status\":\"SUCCESS\",\"accountSid\":\"" + record.accountSid + "\"}";
        outResponsePayload.assign(successPayload.begin(), successPayload.end());
        outHeader.PayloadLength = static_cast<uint32_t>(outResponsePayload.size());
        resultCode = AuthResultCode::SUCCESS;
    } while (false);

    LeaveCriticalSection(&m_mutex);
    return resultCode;
}

} // namespace MobileUnlock::Auth
