#include <gtest/gtest.h>
#include "crypto/CryptoManager.h"
#include "authentication/AuthenticationManager.h"
#include "pairing/DeviceRegistry.h"
#include "pairing/DeviceIdentity.h"
#include "protocol/SignedMessage.h"
#include "protocol/ProtocolTypes.h"
#include <vector>
#include <array>
#include <cstring>

using namespace MobileUnlock::Crypto;
using namespace MobileUnlock::Auth;
using namespace MobileUnlock::Pairing;
using namespace MobileUnlock::Protocol;

// Static Deterministic Interoperability Test Vector
// Generated with standard SECP256R1 / ECDSA P-256 and SHA-256 over Canonical 88-byte SignedMessage
namespace DeterministicVector {

// 65-byte uncompressed EC Point (0x04 || X(32) || Y(32))
const uint8_t kRawUncompressedPubKey[65] = {
    0x04,
    // X (32 bytes)
    0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47,
    0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
    0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0,
    0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
    // Y (32 bytes)
    0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b,
    0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
    0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce,
    0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5
};

// 91-byte standard X.509 SubjectPublicKeyInfo (DER) containing the above P-256 public key
const uint8_t kSpkiDerPubKey[91] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
    // X
    0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
    0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
    // Y
    0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
    0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5
};

// Canonical 88-byte SignedMessage binary layout (Big-Endian network order)
// ProtocolVersion: 0x0100 (2B)
// ServerIdentity: 16 bytes (0xAA...)
// DeviceIdentity: 16 bytes (0xBB...)
// Operation: 0x0022 (AUTH_RESPONSE) (2B)
// RequestID: 1001 (0x000003E9) (4B)
// SessionID: 5005 (0x000000000000138D) (8B)
// Nonce: 32 bytes (0x01, 0x02, ..., 0x20)
// Timestamp: 1700000000000 ms (0x0000018BC86AA700) (8B)
const uint8_t kCanonicalMessage88B[88] = {
    0x01, 0x00,                                                             // Version 0x0100
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,                         // ServerIdentity (16B)
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,                         // DeviceIdentity (16B)
    0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
    0x00, 0x22,                                                             // Operation 0x0022 (AUTH_RESPONSE)
    0x00, 0x00, 0x03, 0xe9,                                                 // RequestID 1001
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x8d,                         // SessionID 5005
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,                         // Nonce (32B)
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    0x00, 0x00, 0x01, 0x8b, 0xc8, 0x6a, 0xa7, 0x00                          // Timestamp
};

} // namespace DeterministicVector

class InteroperabilityTest : public ::testing::Test {
protected:
    BCRYPT_KEY_HANDLE m_hPrivKey = nullptr;
    std::vector<uint8_t> m_pubKeyBlob;
    SignedMessage m_canonicalMsg;
    std::vector<uint8_t> m_validSignature;
    DeviceId m_deviceId;
    std::string m_deviceIdStr;

    void SetUp() override {
        SetRegistryRootForTesting(HKEY_CURRENT_USER);
        ASSERT_TRUE(CryptoManager::Initialize());

        // Generate matching key pair
        ASSERT_TRUE(CryptoManager::GenerateTestKeyPair(&m_hPrivKey, m_pubKeyBlob));

        // Setup canonical SignedMessage matching the deterministic layout
        m_canonicalMsg.ProtocolVersion = 0x0100;
        std::memset(m_canonicalMsg.ServerIdentity, 0xAA, 16);
        std::memset(m_canonicalMsg.DeviceIdentity, 0xBB, 16);
        m_canonicalMsg.Operation = static_cast<uint16_t>(MessageType::AUTH_RESPONSE);
        m_canonicalMsg.RequestID = 1001;
        m_canonicalMsg.SessionID = 5005;
        for (int i = 0; i < 32; i++) {
            m_canonicalMsg.Nonce[i] = static_cast<uint8_t>(i + 1);
        }
        m_canonicalMsg.Timestamp = 1700000000000ULL;

        // Produce 64-byte IEEE P1363 (r || s) signature over exact 88-byte canonical payload
        std::vector<uint8_t> serialized = SerializeSignedMessage(m_canonicalMsg);
        ASSERT_EQ(serialized.size(), 88u);

        std::vector<uint8_t> digest;
        ASSERT_TRUE(CryptoManager::ComputeSha256(serialized.data(), serialized.size(), digest));
        ASSERT_TRUE(CryptoManager::SignHashForTesting(m_hPrivKey, digest.data(), digest.size(), m_validSignature));
        ASSERT_EQ(m_validSignature.size(), 64u);

        // Setup device in registry
        std::memcpy(m_deviceId.data(), m_canonicalMsg.DeviceIdentity, 16);
        m_deviceIdStr = DeviceIdToString(m_deviceId);

        DeviceRecord record;
        record.deviceId = m_deviceId;
        record.deviceName = "Interoperability-Device";
        record.accountSid = "S-1-5-21-9999999999-1001";
        record.publicKey = m_pubKeyBlob;
        record.pairStatus = kStatusActive;
        record.pairedTime = { 0, 0 };
        record.lastSeen = { 0, 0 };
        ASSERT_EQ(WriteDeviceRecord(record), ERROR_SUCCESS);

        AuthenticationManager::Instance().Reset();
        AuthenticationManager::Instance().SetServerIdentity({
            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA
        });
    }

    void TearDown() override {
        if (m_hPrivKey) {
            CryptoManager::DestroyKey(m_hPrivKey);
            m_hPrivKey = nullptr;
        }
        DeleteDeviceRecord(m_deviceIdStr);
        AuthenticationManager::Instance().Reset();
    }
};

// Requirement 12 - Test A: Original payload + original signature -> PASS
TEST_F(InteroperabilityTest, TestA_OriginalPayloadAndSignaturePasses) {
    EXPECT_TRUE(CryptoManager::VerifyCanonicalSignedMessage(
        m_pubKeyBlob,
        m_canonicalMsg,
        m_validSignature.data(),
        m_validSignature.size()
    ));
}

// Requirement 12 - Test B: Modified payload + original signature -> FAIL
TEST_F(InteroperabilityTest, TestB_ModifiedPayloadFails) {
    SignedMessage tamperedMsg = m_canonicalMsg;
    tamperedMsg.Nonce[10] ^= 0xFF; // Modify 1 byte in nonce

    EXPECT_FALSE(CryptoManager::VerifyCanonicalSignedMessage(
        m_pubKeyBlob,
        tamperedMsg,
        m_validSignature.data(),
        m_validSignature.size()
    ));
}

// Requirement 12 - Test C: Original payload + modified signature -> FAIL
TEST_F(InteroperabilityTest, TestC_ModifiedSignatureFails) {
    std::vector<uint8_t> tamperedSig = m_validSignature;
    tamperedSig[20] ^= 0x01; // Flip 1 bit in r

    EXPECT_FALSE(CryptoManager::VerifyCanonicalSignedMessage(
        m_pubKeyBlob,
        m_canonicalMsg,
        tamperedSig.data(),
        tamperedSig.size()
    ));
}

// Requirement 12 - Test D: Wrong public key + original signature -> FAIL
TEST_F(InteroperabilityTest, TestD_WrongPublicKeyFails) {
    BCRYPT_KEY_HANDLE hWrongKey = nullptr;
    std::vector<uint8_t> wrongPubKeyBlob;
    ASSERT_TRUE(CryptoManager::GenerateTestKeyPair(&hWrongKey, wrongPubKeyBlob));

    EXPECT_FALSE(CryptoManager::VerifyCanonicalSignedMessage(
        wrongPubKeyBlob,
        m_canonicalMsg,
        m_validSignature.data(),
        m_validSignature.size()
    ));

    CryptoManager::DestroyKey(hWrongKey);
}

// Requirement 12 - Test E: Wrong DeviceIdentity -> FAIL
TEST_F(InteroperabilityTest, TestE_WrongDeviceIdentityFails) {
    SignedMessage wrongDevMsg = m_canonicalMsg;
    wrongDevMsg.DeviceIdentity[0] ^= 0xEE; // Change device identity

    std::vector<uint8_t> wrongDevSig;
    std::vector<uint8_t> serialized = SerializeSignedMessage(wrongDevMsg);
    std::vector<uint8_t> digest;
    ASSERT_TRUE(CryptoManager::ComputeSha256(serialized.data(), serialized.size(), digest));
    ASSERT_TRUE(CryptoManager::SignHashForTesting(m_hPrivKey, digest.data(), digest.size(), wrongDevSig));

    // Try processing AUTH_RESPONSE with unregistered device identity
    std::vector<uint8_t> payload = serialized;
    payload.insert(payload.end(), wrongDevSig.begin(), wrongDevSig.end());

    FrameHeader header;
    header.MessageType = static_cast<uint16_t>(MessageType::AUTH_RESPONSE);
    header.MessageID = 1;

    std::vector<uint8_t> outPayload;
    FrameHeader outHeader;
    AuthResultCode res = AuthenticationManager::Instance().HandleAuthResponse(header, payload, outPayload, outHeader);

    EXPECT_EQ(res, AuthResultCode::UNKNOWN_DEVICE);
    EXPECT_EQ(outHeader.MessageType, static_cast<uint16_t>(MessageType::AUTH_FAILURE));
}

// Requirement 12 - Test F: Expired challenge -> FAIL
TEST_F(InteroperabilityTest, TestF_ExpiredChallengeFails) {
    ActiveChallenge challenge;
    challenge.deviceId = m_deviceId;
    challenge.sessionId = m_canonicalMsg.SessionID;
    challenge.createdAtMs = 1000000; // Old timestamp
    challenge.isConsumed = false;
    std::memcpy(challenge.nonce.data(), m_canonicalMsg.Nonce, 32);

    AuthenticationManager::Instance().InjectChallengeForTesting(challenge);

    std::vector<uint8_t> serialized = SerializeSignedMessage(m_canonicalMsg);
    std::vector<uint8_t> payload = serialized;
    payload.insert(payload.end(), m_validSignature.begin(), m_validSignature.end());

    FrameHeader header;
    header.MessageType = static_cast<uint16_t>(MessageType::AUTH_RESPONSE);

    std::vector<uint8_t> outPayload;
    FrameHeader outHeader;
    AuthResultCode res = AuthenticationManager::Instance().HandleAuthResponse(header, payload, outPayload, outHeader);

    EXPECT_EQ(res, AuthResultCode::CHALLENGE_EXPIRED);
    EXPECT_EQ(outHeader.MessageType, static_cast<uint16_t>(MessageType::AUTH_FAILURE));
}

// Requirement 12 - Test G: Replayed response -> FAIL
TEST_F(InteroperabilityTest, TestG_ReplayedResponseFails) {
    ActiveChallenge challenge;
    challenge.deviceId = m_deviceId;
    challenge.sessionId = m_canonicalMsg.SessionID;
    challenge.createdAtMs = 1700000000000ULL;
    challenge.isConsumed = false;
    std::memcpy(challenge.nonce.data(), m_canonicalMsg.Nonce, 32);

    static uint64_t mockTime = 1700000001000ULL;
    AuthenticationManager::Instance().SetTimeProviderForTesting([]() -> uint64_t { return mockTime; });
    AuthenticationManager::Instance().InjectChallengeForTesting(challenge);

    std::vector<uint8_t> serialized = SerializeSignedMessage(m_canonicalMsg);
    std::vector<uint8_t> payload = serialized;
    payload.insert(payload.end(), m_validSignature.begin(), m_validSignature.end());

    FrameHeader header;
    header.MessageType = static_cast<uint16_t>(MessageType::AUTH_RESPONSE);

    std::vector<uint8_t> outPayload;
    FrameHeader outHeader;

    // First attempt -> SUCCESS
    AuthResultCode res1 = AuthenticationManager::Instance().HandleAuthResponse(header, payload, outPayload, outHeader);
    EXPECT_EQ(res1, AuthResultCode::SUCCESS);
    EXPECT_EQ(outHeader.MessageType, static_cast<uint16_t>(MessageType::AUTH_SUCCESS));

    // Second (replayed) attempt -> FAIL
    mockTime += 2000;
    AuthResultCode res2 = AuthenticationManager::Instance().HandleAuthResponse(header, payload, outPayload, outHeader);
    EXPECT_EQ(res2, AuthResultCode::REPLAY_DETECTED);
    EXPECT_EQ(outHeader.MessageType, static_cast<uint16_t>(MessageType::AUTH_FAILURE));
}
