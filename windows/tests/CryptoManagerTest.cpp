#include <gtest/gtest.h>
#include "crypto/CryptoManager.h"
#include "protocol/SignedMessage.h"
#include <vector>
#include <array>
#include <cstring>

using namespace MobileUnlock::Crypto;
using namespace MobileUnlock::Protocol;

class CryptoManagerTest : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_TRUE(CryptoManager::Initialize());
    }

    void TearDown() override {
        // CryptoManager remains available
    }

    // Helper: signs a message using private key to produce 64-byte IEEE P1363 (r || s)
    bool SignMessage(BCRYPT_KEY_HANDLE hPrivKey, const uint8_t* msg, size_t msgLen, std::vector<uint8_t>& outSig) {
        std::vector<uint8_t> digest;
        if (!CryptoManager::ComputeSha256(msg, msgLen, digest)) return false;
        return CryptoManager::SignHashForTesting(hPrivKey, digest.data(), digest.size(), outSig);
    }
};

// 1. Test RNG generation
TEST_F(CryptoManagerTest, GenerateRandomBytesProducesEntropy) {
    uint8_t buf1[32] = {0};
    uint8_t buf2[32] = {0};

    EXPECT_TRUE(CryptoManager::GenerateRandomBytes(buf1, sizeof(buf1)));
    EXPECT_TRUE(CryptoManager::GenerateRandomBytes(buf2, sizeof(buf2)));

    // Non-zero check
    bool buf1NonZero = false;
    for (int i = 0; i < 32; i++) {
        if (buf1[i] != 0) buf1NonZero = true;
    }
    EXPECT_TRUE(buf1NonZero);

    // Independence check
    EXPECT_NE(std::memcmp(buf1, buf2, 32), 0);
}

// 2. Test SHA-256 digest computation (NIST test vector: "abc")
TEST_F(CryptoManagerTest, ComputeSha256MatchesKnownVector) {
    const char* input = "abc";
    std::vector<uint8_t> digest;
    EXPECT_TRUE(CryptoManager::ComputeSha256(reinterpret_cast<const uint8_t*>(input), 3, digest));
    EXPECT_EQ(digest.size(), 32u);

    // Expected SHA-256 for "abc": ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad
    const uint8_t expected[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    EXPECT_EQ(std::memcmp(digest.data(), expected, 32), 0);
}

// 3. Test Public Key Normalization from all supported formats
TEST_F(CryptoManagerTest, NormalizePublicKeyFormats) {
    BCRYPT_KEY_HANDLE hPrivKey = nullptr;
    std::vector<uint8_t> cngBlob;
    ASSERT_TRUE(CryptoManager::GenerateTestKeyPair(&hPrivKey, cngBlob));

    // A. Direct BCRYPT_ECCKEY_BLOB (72 bytes)
    std::vector<uint8_t> normBlob1;
    EXPECT_TRUE(CryptoManager::NormalizePublicKeyToEccBlob(cngBlob, normBlob1));
    EXPECT_EQ(normBlob1, cngBlob);

    // B. Raw 64 bytes coordinates (X || Y)
    std::vector<uint8_t> rawCoords(cngBlob.begin() + sizeof(BCRYPT_ECCKEY_BLOB), cngBlob.end());
    EXPECT_EQ(rawCoords.size(), 64u);
    std::vector<uint8_t> normBlob2;
    EXPECT_TRUE(CryptoManager::NormalizePublicKeyToEccBlob(rawCoords, normBlob2));
    EXPECT_EQ(normBlob2, cngBlob);

    // C. Raw 65 bytes uncompressed point (0x04 || X || Y)
    std::vector<uint8_t> rawPoint(1, 0x04);
    rawPoint.insert(rawPoint.end(), rawCoords.begin(), rawCoords.end());
    EXPECT_EQ(rawPoint.size(), 65u);
    std::vector<uint8_t> normBlob3;
    EXPECT_TRUE(CryptoManager::NormalizePublicKeyToEccBlob(rawPoint, normBlob3));
    EXPECT_EQ(normBlob3, cngBlob);

    CryptoManager::DestroyKey(hPrivKey);
}

// 4. Test Valid Signature Verification over Canonical SignedMessage (88B)
TEST_F(CryptoManagerTest, ValidCanonicalMessageSignatureVerifies) {
    BCRYPT_KEY_HANDLE hPrivKey = nullptr;
    std::vector<uint8_t> pubKeyBlob;
    ASSERT_TRUE(CryptoManager::GenerateTestKeyPair(&hPrivKey, pubKeyBlob));

    SignedMessage msg;
    msg.ProtocolVersion = 0x0100;
    std::memset(msg.ServerIdentity, 0xAA, 16);
    std::memset(msg.DeviceIdentity, 0xBB, 16);
    msg.Operation = static_cast<uint16_t>(MessageType::AUTH_RESPONSE);
    msg.RequestID = 1001;
    msg.SessionID = 5005;
    for (int i = 0; i < 32; i++) msg.Nonce[i] = static_cast<uint8_t>(i);
    msg.Timestamp = 1700000000000ULL;

    std::vector<uint8_t> serialized = SerializeSignedMessage(msg);
    EXPECT_EQ(serialized.size(), 88u);

    std::vector<uint8_t> signature;
    ASSERT_TRUE(SignMessage(hPrivKey, serialized.data(), serialized.size(), signature));
    EXPECT_EQ(signature.size(), 64u);

    // Verification must PASS
    EXPECT_TRUE(CryptoManager::VerifyCanonicalSignedMessage(pubKeyBlob, msg, signature.data(), signature.size()));

    CryptoManager::DestroyKey(hPrivKey);
}

// 5. Test Modified Payload Rejection (1 byte altered in canonical struct)
TEST_F(CryptoManagerTest, ModifiedCanonicalPayloadFailsVerification) {
    BCRYPT_KEY_HANDLE hPrivKey = nullptr;
    std::vector<uint8_t> pubKeyBlob;
    ASSERT_TRUE(CryptoManager::GenerateTestKeyPair(&hPrivKey, pubKeyBlob));

    SignedMessage msg;
    msg.ProtocolVersion = 0x0100;
    std::memset(msg.ServerIdentity, 0x11, 16);
    std::memset(msg.DeviceIdentity, 0x22, 16);
    msg.Operation = static_cast<uint16_t>(MessageType::AUTH_RESPONSE);
    msg.RequestID = 42;
    msg.SessionID = 999;
    std::memset(msg.Nonce, 0x77, 32);
    msg.Timestamp = 123456789ULL;

    std::vector<uint8_t> serialized = SerializeSignedMessage(msg);
    std::vector<uint8_t> signature;
    ASSERT_TRUE(SignMessage(hPrivKey, serialized.data(), serialized.size(), signature));

    // A. Alter Timestamp
    SignedMessage tamperedMsg = msg;
    tamperedMsg.Timestamp += 1;
    EXPECT_FALSE(CryptoManager::VerifyCanonicalSignedMessage(pubKeyBlob, tamperedMsg, signature.data(), signature.size()));

    // B. Alter Nonce (1 byte)
    tamperedMsg = msg;
    tamperedMsg.Nonce[0] ^= 0xFF;
    EXPECT_FALSE(CryptoManager::VerifyCanonicalSignedMessage(pubKeyBlob, tamperedMsg, signature.data(), signature.size()));

    // C. Alter DeviceIdentity
    tamperedMsg = msg;
    tamperedMsg.DeviceIdentity[5] ^= 0x01;
    EXPECT_FALSE(CryptoManager::VerifyCanonicalSignedMessage(pubKeyBlob, tamperedMsg, signature.data(), signature.size()));

    // D. Alter RequestID
    tamperedMsg = msg;
    tamperedMsg.RequestID++;
    EXPECT_FALSE(CryptoManager::VerifyCanonicalSignedMessage(pubKeyBlob, tamperedMsg, signature.data(), signature.size()));

    CryptoManager::DestroyKey(hPrivKey);
}

// 6. Test Modified Signature Rejection (1 byte flipped in r or s)
TEST_F(CryptoManagerTest, ModifiedSignatureFailsVerification) {
    BCRYPT_KEY_HANDLE hPrivKey = nullptr;
    std::vector<uint8_t> pubKeyBlob;
    ASSERT_TRUE(CryptoManager::GenerateTestKeyPair(&hPrivKey, pubKeyBlob));

    SignedMessage msg;
    std::vector<uint8_t> serialized = SerializeSignedMessage(msg);
    std::vector<uint8_t> signature;
    ASSERT_TRUE(SignMessage(hPrivKey, serialized.data(), serialized.size(), signature));

    // Flip byte in r
    std::vector<uint8_t> badSigR = signature;
    badSigR[10] ^= 0x55;
    EXPECT_FALSE(CryptoManager::VerifyCanonicalSignedMessage(pubKeyBlob, msg, badSigR.data(), badSigR.size()));

    // Flip byte in s
    std::vector<uint8_t> badSigS = signature;
    badSigS[45] ^= 0xAA;
    EXPECT_FALSE(CryptoManager::VerifyCanonicalSignedMessage(pubKeyBlob, msg, badSigS.data(), badSigS.size()));

    CryptoManager::DestroyKey(hPrivKey);
}

// 7. Test Wrong Public Key Rejection
TEST_F(CryptoManagerTest, WrongPublicKeyFailsVerification) {
    BCRYPT_KEY_HANDLE hPrivKey1 = nullptr;
    std::vector<uint8_t> pubKeyBlob1;
    ASSERT_TRUE(CryptoManager::GenerateTestKeyPair(&hPrivKey1, pubKeyBlob1));

    BCRYPT_KEY_HANDLE hPrivKey2 = nullptr;
    std::vector<uint8_t> pubKeyBlob2;
    ASSERT_TRUE(CryptoManager::GenerateTestKeyPair(&hPrivKey2, pubKeyBlob2));

    SignedMessage msg;
    std::vector<uint8_t> serialized = SerializeSignedMessage(msg);
    std::vector<uint8_t> signature1;
    ASSERT_TRUE(SignMessage(hPrivKey1, serialized.data(), serialized.size(), signature1));

    // Verify signature 1 with key 2 must FAIL
    EXPECT_FALSE(CryptoManager::VerifyCanonicalSignedMessage(pubKeyBlob2, msg, signature1.data(), signature1.size()));

    CryptoManager::DestroyKey(hPrivKey1);
    CryptoManager::DestroyKey(hPrivKey2);
}

// 8. Test Invalid Signature Lengths and All-Zero Scalars
TEST_F(CryptoManagerTest, InvalidSignatureLengthsAndZeroScalarsFail) {
    BCRYPT_KEY_HANDLE hPrivKey = nullptr;
    std::vector<uint8_t> pubKeyBlob;
    ASSERT_TRUE(CryptoManager::GenerateTestKeyPair(&hPrivKey, pubKeyBlob));

    SignedMessage msg;

    // 63 bytes (too short)
    std::vector<uint8_t> shortSig(63, 0x11);
    EXPECT_FALSE(CryptoManager::VerifyCanonicalSignedMessage(pubKeyBlob, msg, shortSig.data(), shortSig.size()));

    // 65 bytes (too long)
    std::vector<uint8_t> longSig(65, 0x11);
    EXPECT_FALSE(CryptoManager::VerifyCanonicalSignedMessage(pubKeyBlob, msg, longSig.data(), longSig.size()));

    // 64 bytes all zeros
    std::vector<uint8_t> zeroSig(64, 0x00);
    EXPECT_FALSE(CryptoManager::VerifyCanonicalSignedMessage(pubKeyBlob, msg, zeroSig.data(), zeroSig.size()));

    CryptoManager::DestroyKey(hPrivKey);
}
