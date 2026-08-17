#include <gtest/gtest.h>
#include "authentication/AuthenticationManager.h"
#include "pairing/DeviceRegistry.h"
#include "pairing/DeviceIdentity.h"
#include "crypto/CryptoManager.h"
#include "protocol/SignedMessage.h"
#include "protocol/ProtocolTypes.h"
#include <vector>
#include <cstring>

using namespace MobileUnlock::Auth;
using namespace MobileUnlock::Pairing;
using namespace MobileUnlock::Crypto;
using namespace MobileUnlock::Protocol;

static uint64_t g_mockTimeMs = 1000000000ULL;
static uint64_t MockTimeProvider() {
    return g_mockTimeMs;
}

class AuthenticationManagerTest : public ::testing::Test {
protected:
    BCRYPT_KEY_HANDLE m_hPrivKey = nullptr;
    std::vector<uint8_t> m_pubKeyBlob;
    DeviceId m_testDeviceId;
    std::string m_testDeviceIdStr;
    const std::string m_testAccountSid = "S-1-5-21-1234567890-1234567890-1234567890-1001";

    void SetUp() override {
        // Use HKCU for non-elevated testing
        SetRegistryRootForTesting(HKEY_CURRENT_USER);
        ASSERT_TRUE(CryptoManager::Initialize());

        // Setup mock time
        g_mockTimeMs = 1000000000ULL;
        AuthenticationManager::Instance().SetTimeProviderForTesting(MockTimeProvider);
        AuthenticationManager::Instance().Reset();

        // Generate test P-256 key pair using CryptoManager helper
        ASSERT_TRUE(CryptoManager::GenerateTestKeyPair(&m_hPrivKey, m_pubKeyBlob));

        // Generate test device identity
        m_testDeviceId = GenerateDeviceId();
        m_testDeviceIdStr = DeviceIdToString(m_testDeviceId);

        // Register device in test registry as ACTIVE
        DeviceRecord record;
        record.deviceId = m_testDeviceId;
        record.deviceName = "Test-TECNO-KI7";
        record.accountSid = m_testAccountSid;
        record.publicKey = m_pubKeyBlob;
        record.pairStatus = kStatusActive;
        record.pairedTime = { 0, 0 };
        record.lastSeen = { 0, 0 };
        ASSERT_EQ(WriteDeviceRecord(record), ERROR_SUCCESS);
    }

    void TearDown() override {
        if (m_hPrivKey) {
            CryptoManager::DestroyKey(m_hPrivKey);
            m_hPrivKey = nullptr;
        }
        DeleteDeviceRecord(m_testDeviceIdStr);
        AuthenticationManager::Instance().Reset();
    }

    // Helper to sign canonical message with private key
    bool SignCanonicalMessage(const SignedMessage& msg, std::vector<uint8_t>& outSig) {
        std::vector<uint8_t> serialized = SerializeSignedMessage(msg);
        std::vector<uint8_t> digest;
        if (!CryptoManager::ComputeSha256(serialized.data(), serialized.size(), digest)) return false;
        return CryptoManager::SignHashForTesting(m_hPrivKey, digest.data(), digest.size(), outSig);
    }
};

// 1. Full valid AUTH_REQUEST -> AUTH_CHALLENGE -> AUTH_RESPONSE -> AUTH_SUCCESS flow
TEST_F(AuthenticationManagerTest, FullValidAuthenticationFlowSucceeds) {
    auto& authMgr = AuthenticationManager::Instance();

    // Step 1: Client sends AUTH_REQUEST
    FrameHeader reqHeader;
    reqHeader.MessageType = static_cast<uint16_t>(MessageType::AUTH_REQUEST);
    reqHeader.MessageID = 100;
    reqHeader.SequenceNumber = 1;

    std::vector<uint8_t> challengePayload;
    FrameHeader challengeHeader;
    AuthResultCode res = authMgr.HandleAuthRequest(m_testDeviceId, reqHeader, challengePayload, challengeHeader);

    ASSERT_EQ(res, AuthResultCode::SUCCESS);
    EXPECT_EQ(challengeHeader.MessageType, static_cast<uint16_t>(MessageType::AUTH_CHALLENGE));
    EXPECT_EQ(challengeHeader.MessageID, 100u);
    EXPECT_EQ(challengeHeader.SequenceNumber, 2u);
    EXPECT_FALSE(challengePayload.empty());

    // Step 2: Client builds SignedMessage with challenge context
    SignedMessage signedMsg;
    signedMsg.ProtocolVersion = 0x0100;
    std::memcpy(signedMsg.ServerIdentity, authMgr.GetServerIdentity().data(), 16);
    std::memcpy(signedMsg.DeviceIdentity, m_testDeviceId.data(), 16);
    signedMsg.Operation = static_cast<uint16_t>(MessageType::AUTH_RESPONSE);
    signedMsg.RequestID = 100;
    signedMsg.SessionID = 1; // sessionCounter starts at 1
    signedMsg.Timestamp = g_mockTimeMs;

    // Inject active challenge with known nonce
    ActiveChallenge activeChal;
    activeChal.deviceId = m_testDeviceId;
    activeChal.sessionId = 1;
    activeChal.createdAtMs = g_mockTimeMs;
    activeChal.isConsumed = false;
    for (size_t i = 0; i < 32; i++) {
        activeChal.nonce[i] = static_cast<uint8_t>(i + 1);
        signedMsg.Nonce[i] = static_cast<uint8_t>(i + 1);
    }
    authMgr.InjectChallengeForTesting(activeChal);

    // Step 3: Sign canonical SignedMessage
    std::vector<uint8_t> signature;
    ASSERT_TRUE(SignCanonicalMessage(signedMsg, signature));
    EXPECT_EQ(signature.size(), 64u);

    // Step 4: Build AUTH_RESPONSE payload (88B canonical serialized struct + 64B signature = 152B)
    std::vector<uint8_t> responsePayload = SerializeSignedMessage(signedMsg);
    responsePayload.insert(responsePayload.end(), signature.begin(), signature.end());
    EXPECT_EQ(responsePayload.size(), 152u);

    FrameHeader respHeader;
    respHeader.MessageType = static_cast<uint16_t>(MessageType::AUTH_RESPONSE);
    respHeader.MessageID = 101;
    respHeader.SequenceNumber = 3;

    std::vector<uint8_t> outcomePayload;
    FrameHeader outcomeHeader;
    AuthResultCode authRes = authMgr.HandleAuthResponse(respHeader, responsePayload, outcomePayload, outcomeHeader);

    EXPECT_EQ(authRes, AuthResultCode::SUCCESS);
    EXPECT_EQ(outcomeHeader.MessageType, static_cast<uint16_t>(MessageType::AUTH_SUCCESS));
    EXPECT_EQ(outcomeHeader.MessageID, 101u);

    std::string outcomeStr(outcomePayload.begin(), outcomePayload.end());
    EXPECT_NE(outcomeStr.find("SUCCESS"), std::string::npos);
    EXPECT_NE(outcomeStr.find(m_testAccountSid), std::string::npos);
}

// 2. Replay attack rejection: cannot replay consumed response
TEST_F(AuthenticationManagerTest, ReplayAttackIsRejected) {
    auto& authMgr = AuthenticationManager::Instance();

    SignedMessage signedMsg;
    signedMsg.ProtocolVersion = 0x0100;
    std::memcpy(signedMsg.ServerIdentity, authMgr.GetServerIdentity().data(), 16);
    std::memcpy(signedMsg.DeviceIdentity, m_testDeviceId.data(), 16);
    signedMsg.Operation = static_cast<uint16_t>(MessageType::AUTH_RESPONSE);
    signedMsg.RequestID = 100;
    signedMsg.SessionID = 10;
    signedMsg.Timestamp = g_mockTimeMs;

    ActiveChallenge activeChal;
    activeChal.deviceId = m_testDeviceId;
    activeChal.sessionId = 10;
    activeChal.createdAtMs = g_mockTimeMs;
    activeChal.isConsumed = false;
    for (size_t i = 0; i < 32; i++) {
        activeChal.nonce[i] = static_cast<uint8_t>(i + 5);
        signedMsg.Nonce[i] = static_cast<uint8_t>(i + 5);
    }
    authMgr.InjectChallengeForTesting(activeChal);

    std::vector<uint8_t> signature;
    ASSERT_TRUE(SignCanonicalMessage(signedMsg, signature));

    std::vector<uint8_t> responsePayload = SerializeSignedMessage(signedMsg);
    responsePayload.insert(responsePayload.end(), signature.begin(), signature.end());

    FrameHeader respHeader;
    respHeader.MessageType = static_cast<uint16_t>(MessageType::AUTH_RESPONSE);
    respHeader.MessageID = 101;
    respHeader.SequenceNumber = 3;

    std::vector<uint8_t> outcomePayload;
    FrameHeader outcomeHeader;

    // First attempt -> SUCCESS
    AuthResultCode res1 = authMgr.HandleAuthResponse(respHeader, responsePayload, outcomePayload, outcomeHeader);
    EXPECT_EQ(res1, AuthResultCode::SUCCESS);
    EXPECT_EQ(outcomeHeader.MessageType, static_cast<uint16_t>(MessageType::AUTH_SUCCESS));

    // Replay attempt 5 seconds later with exact same payload -> FAIL
    g_mockTimeMs += 5000;
    AuthResultCode res2 = authMgr.HandleAuthResponse(respHeader, responsePayload, outcomePayload, outcomeHeader);
    EXPECT_EQ(res2, AuthResultCode::REPLAY_DETECTED);
    EXPECT_EQ(outcomeHeader.MessageType, static_cast<uint16_t>(MessageType::AUTH_FAILURE));
}

// 3. Expired challenge rejection (> 30s TTL)
TEST_F(AuthenticationManagerTest, ExpiredChallengeIsRejected) {
    auto& authMgr = AuthenticationManager::Instance();

    SignedMessage signedMsg;
    std::memcpy(signedMsg.ServerIdentity, authMgr.GetServerIdentity().data(), 16);
    std::memcpy(signedMsg.DeviceIdentity, m_testDeviceId.data(), 16);
    signedMsg.Operation = static_cast<uint16_t>(MessageType::AUTH_RESPONSE);
    signedMsg.SessionID = 20;
    signedMsg.Timestamp = g_mockTimeMs;

    ActiveChallenge activeChal;
    activeChal.deviceId = m_testDeviceId;
    activeChal.sessionId = 20;
    activeChal.createdAtMs = g_mockTimeMs;
    activeChal.isConsumed = false;
    authMgr.InjectChallengeForTesting(activeChal);

    std::vector<uint8_t> signature;
    ASSERT_TRUE(SignCanonicalMessage(signedMsg, signature));

    std::vector<uint8_t> responsePayload = SerializeSignedMessage(signedMsg);
    responsePayload.insert(responsePayload.end(), signature.begin(), signature.end());

    FrameHeader respHeader;
    respHeader.MessageType = static_cast<uint16_t>(MessageType::AUTH_RESPONSE);

    // Advance clock by 31 seconds (> 30s TTL)
    g_mockTimeMs += 31000;

    std::vector<uint8_t> outcomePayload;
    FrameHeader outcomeHeader;
    AuthResultCode res = authMgr.HandleAuthResponse(respHeader, responsePayload, outcomePayload, outcomeHeader);
    EXPECT_EQ(res, AuthResultCode::CHALLENGE_EXPIRED);
    EXPECT_EQ(outcomeHeader.MessageType, static_cast<uint16_t>(MessageType::AUTH_FAILURE));
}

// 4. Unknown device rejection
TEST_F(AuthenticationManagerTest, UnknownDeviceIsRejected) {
    auto& authMgr = AuthenticationManager::Instance();
    DeviceId unknownDevice = GenerateDeviceId();

    FrameHeader reqHeader;
    reqHeader.MessageType = static_cast<uint16_t>(MessageType::AUTH_REQUEST);
    reqHeader.MessageID = 1;

    std::vector<uint8_t> payload;
    FrameHeader outHeader;
    AuthResultCode res = authMgr.HandleAuthRequest(unknownDevice, reqHeader, payload, outHeader);
    EXPECT_EQ(res, AuthResultCode::UNKNOWN_DEVICE);
    EXPECT_EQ(outHeader.MessageType, static_cast<uint16_t>(MessageType::AUTH_FAILURE));
}

// 5. Revoked device rejection
TEST_F(AuthenticationManagerTest, RevokedDeviceIsRejected) {
    auto& authMgr = AuthenticationManager::Instance();
    ASSERT_EQ(SetDeviceStatus(m_testDeviceIdStr, kStatusRevoked), ERROR_SUCCESS);

    FrameHeader reqHeader;
    reqHeader.MessageType = static_cast<uint16_t>(MessageType::AUTH_REQUEST);
    reqHeader.MessageID = 1;

    std::vector<uint8_t> payload;
    FrameHeader outHeader;
    AuthResultCode res = authMgr.HandleAuthRequest(m_testDeviceId, reqHeader, payload, outHeader);
    EXPECT_EQ(res, AuthResultCode::DEVICE_REVOKED);
    EXPECT_EQ(outHeader.MessageType, static_cast<uint16_t>(MessageType::AUTH_FAILURE));
}

// 6. Rate limiting after 3 consecutive failures
TEST_F(AuthenticationManagerTest, RateLimitingAfterThreeFailures) {
    auto& authMgr = AuthenticationManager::Instance();

    // Prepare invalid signature response
    SignedMessage signedMsg;
    std::memcpy(signedMsg.DeviceIdentity, m_testDeviceId.data(), 16);
    signedMsg.Operation = static_cast<uint16_t>(MessageType::AUTH_RESPONSE);
    signedMsg.SessionID = 30;

    ActiveChallenge chal;
    chal.deviceId = m_testDeviceId;
    chal.sessionId = 30;
    chal.createdAtMs = g_mockTimeMs;
    chal.isConsumed = false;
    authMgr.InjectChallengeForTesting(chal);

    std::vector<uint8_t> badSig(64, 0xFF);
    std::vector<uint8_t> responsePayload = SerializeSignedMessage(signedMsg);
    responsePayload.insert(responsePayload.end(), badSig.begin(), badSig.end());

    FrameHeader respHeader;
    respHeader.MessageType = static_cast<uint16_t>(MessageType::AUTH_RESPONSE);

    std::vector<uint8_t> outPayload;
    FrameHeader outHeader;

    // Fail 1
    authMgr.HandleAuthResponse(respHeader, responsePayload, outPayload, outHeader);
    chal.isConsumed = false;
    authMgr.InjectChallengeForTesting(chal);

    // Fail 2
    authMgr.HandleAuthResponse(respHeader, responsePayload, outPayload, outHeader);
    chal.isConsumed = false;
    authMgr.InjectChallengeForTesting(chal);

    // Fail 3 -> triggers rate limiting lockout
    authMgr.HandleAuthResponse(respHeader, responsePayload, outPayload, outHeader);

    // Subsequent request is blocked by rate limiting
    FrameHeader reqHeader;
    reqHeader.MessageType = static_cast<uint16_t>(MessageType::AUTH_REQUEST);
    AuthResultCode rateLimitRes = authMgr.HandleAuthRequest(m_testDeviceId, reqHeader, outPayload, outHeader);
    EXPECT_EQ(rateLimitRes, AuthResultCode::RATE_LIMITED);
    EXPECT_EQ(outHeader.MessageType, static_cast<uint16_t>(MessageType::AUTH_FAILURE));
}
