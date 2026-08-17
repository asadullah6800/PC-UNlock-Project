// ============================================================
// MobileFingerprintUnlock — LSA Authentication Package Tests
// Phase 8
// ============================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <gtest/gtest.h>
#include <vector>
#include <string>
#include <cstring>
#include <memory>

#include "../lsa_authentication_package/LsaPackageCompat.h"
#include "../lsa_authentication_package/LsaLogonBuffer.h"
#include "../lsa_authentication_package/LsaPackage.h"
#include "../pairing/DeviceIdentity.h"
#include "../pairing/DeviceRegistry.h"
#include "../crypto/CryptoManager.h"
#include "../../shared/protocol/SignedMessage.h"
#include "../../shared/protocol/ProtocolTypes.h"

using namespace MobileUnlock::Lsa;
using namespace MobileUnlock::Pairing;
using namespace MobileUnlock::Crypto;
using namespace MobileUnlock::Protocol;

// ============================================================
// Helpers
// ============================================================

// Build a valid 88-byte serialized SignedMessage with device identity set.
// DeviceIdentity is uint8_t[16] (plain C array in SignedMessage).
static std::vector<uint8_t> BuildSignedMessageBytes(
    const DeviceId& devId,
    uint16_t operation = static_cast<uint16_t>(MessageType::AUTH_RESPONSE))
{
    SignedMessage msg{};
    msg.ProtocolVersion = 0x0100;
    std::memcpy(msg.DeviceIdentity, devId.data(), 16);
    msg.Operation = operation;
    return SerializeSignedMessage(msg);
}

// ============================================================
// Test Fixture & Mock Dispatch Table
// ============================================================

static std::vector<void*> s_lsaAllocations;

static PVOID NTAPI MockAllocateLsaHeap(ULONG length) {
    void* ptr = LocalAlloc(LPTR, length);
    if (ptr) s_lsaAllocations.push_back(ptr);
    return ptr;
}

static VOID NTAPI MockFreeLsaHeap(PVOID base) {
    if (base) {
        LocalFree(base);
    }
}

class LsaAuthenticationPackageTest : public ::testing::Test {
protected:
    void SetUp() override {
        s_lsaAllocations.clear();

        // Route registry operations to HKCU — avoids admin requirement in tests
        SetRegistryRootForTesting(HKEY_CURRENT_USER);

        m_dispatchTable.AllocateLsaHeap       = MockAllocateLsaHeap;
        m_dispatchTable.FreeLsaHeap           = MockFreeLsaHeap;
        m_dispatchTable.AllocateClientBuffer  = nullptr;
        m_dispatchTable.FreeClientBuffer      = nullptr;
        m_dispatchTable.CopyToClientBuffer    = nullptr;
        m_dispatchTable.CopyFromClientBuffer  = nullptr;

        LsaPackage::Instance().SetDispatchTableForTesting(&m_dispatchTable);

        // Generate test device identity — DeviceId is std::array<uint8_t,16>
        m_testDeviceId = GenerateDeviceId();
        m_deviceIdStr  = DeviceIdToString(m_testDeviceId);

        // Register active device in DeviceRegistry with stub public key
        DeviceRecord record{};
        record.deviceId   = m_testDeviceId;
        record.deviceName = "TestPhone";
        record.pairStatus = kStatusActive;
        // 65-byte uncompressed P-256 point: 0x04 || X(32) || Y(32)
        record.publicKey.assign(65, 0x11);
        record.publicKey[0] = 0x04;
        record.accountSid   = "S-1-5-18"; // Local System — valid SID for test
        std::memset(&record.pairedTime, 0, sizeof(record.pairedTime));
        std::memset(&record.lastSeen,   0, sizeof(record.lastSeen));

        WriteDeviceRecord(record);
    }

    void TearDown() override {
        DeleteDeviceRecord(m_deviceIdStr);
        SetRegistryRootForTesting(HKEY_LOCAL_MACHINE); // restore for other suites

        for (void* p : s_lsaAllocations) {
            LocalFree(p);
        }
        s_lsaAllocations.clear();
    }

    LSA_DISPATCH_TABLE m_dispatchTable{};
    DeviceId           m_testDeviceId;
    std::string        m_deviceIdStr;
};

// ============================================================
// Test 1: PackageInitialization
// ============================================================
TEST_F(LsaAuthenticationPackageTest, PackageInitialization) {
    PLSA_STRING pkgName = nullptr;
    NTSTATUS status = LsaPackage::Instance().Initialize(
        42,
        &m_dispatchTable,
        nullptr,
        nullptr,
        &pkgName);

    EXPECT_EQ(status, STATUS_SUCCESS);
    ASSERT_NE(pkgName, nullptr);
    EXPECT_STREQ(pkgName->Buffer, LSA_PACKAGE_NAME_A);
    EXPECT_EQ(pkgName->Length, static_cast<USHORT>(std::strlen(LSA_PACKAGE_NAME_A)));
    EXPECT_EQ(LsaPackage::Instance().GetPackageId(), 42u);
    EXPECT_TRUE(LsaPackage::Instance().IsInitialized());
}

// ============================================================
// Test 2: PackageInitializationNullOutputRejection
// ============================================================
TEST_F(LsaAuthenticationPackageTest, PackageInitializationNullOutputRejection) {
    NTSTATUS status = LsaPackage::Instance().Initialize(
        42,
        &m_dispatchTable,
        nullptr,
        nullptr,
        nullptr);

    EXPECT_EQ(status, STATUS_INVALID_PARAMETER);
}

// ============================================================
// Test 3: NullSubmitBufferRejection
// ============================================================
TEST_F(LsaAuthenticationPackageTest, NullSubmitBufferRejection) {
    NTSTATUS subStatus = STATUS_SUCCESS;
    NTSTATUS status = LsaPackage::Instance().LogonUserEx2(
        nullptr, Interactive,
        nullptr, nullptr,
        sizeof(MOBILE_UNLOCK_LSA_LOGON_BUFFER),
        nullptr, nullptr, nullptr,
        &subStatus,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

    EXPECT_EQ(status, STATUS_INVALID_PARAMETER);
    EXPECT_EQ(subStatus, STATUS_INVALID_PARAMETER);
}

// ============================================================
// Test 4: TruncatedSubmitBufferRejection
// ============================================================
TEST_F(LsaAuthenticationPackageTest, TruncatedSubmitBufferRejection) {
    std::vector<uint8_t> shortBuf(sizeof(MOBILE_UNLOCK_LSA_LOGON_BUFFER) - 1, 0);
    NTSTATUS subStatus = STATUS_SUCCESS;

    NTSTATUS status = LsaPackage::Instance().LogonUserEx2(
        nullptr, Interactive,
        shortBuf.data(), nullptr,
        static_cast<ULONG>(shortBuf.size()),
        nullptr, nullptr, nullptr,
        &subStatus,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

    EXPECT_EQ(status, STATUS_BUFFER_TOO_SMALL);
    EXPECT_EQ(subStatus, STATUS_BUFFER_TOO_SMALL);
}

// ============================================================
// Test 5: UnknownMagicRejection
// ============================================================
TEST_F(LsaAuthenticationPackageTest, UnknownMagicRejection) {
    MOBILE_UNLOCK_LSA_LOGON_BUFFER buf{};
    buf.Magic   = 0xDEADBEEF;
    buf.Version = LSA_SUBMIT_BUFFER_VERSION;

    NTSTATUS subStatus = STATUS_SUCCESS;
    NTSTATUS status = LsaPackage::Instance().LogonUserEx2(
        nullptr, Interactive,
        &buf, nullptr, sizeof(buf),
        nullptr, nullptr, nullptr,
        &subStatus,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

    EXPECT_EQ(status, STATUS_INVALID_PARAMETER);
    EXPECT_EQ(subStatus, STATUS_INVALID_PARAMETER);
}

// ============================================================
// Test 6: UnsupportedVersionRejection
// ============================================================
TEST_F(LsaAuthenticationPackageTest, UnsupportedVersionRejection) {
    MOBILE_UNLOCK_LSA_LOGON_BUFFER buf{};
    buf.Magic   = LSA_SUBMIT_BUFFER_MAGIC;
    buf.Version = 99;

    NTSTATUS subStatus = STATUS_SUCCESS;
    NTSTATUS status = LsaPackage::Instance().LogonUserEx2(
        nullptr, Interactive,
        &buf, nullptr, sizeof(buf),
        nullptr, nullptr, nullptr,
        &subStatus,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

    EXPECT_EQ(status, STATUS_INVALID_PARAMETER);
    EXPECT_EQ(subStatus, STATUS_INVALID_PARAMETER);
}

// ============================================================
// Test 7: NonZeroReservedRejection
// ============================================================
TEST_F(LsaAuthenticationPackageTest, NonZeroReservedRejection) {
    MOBILE_UNLOCK_LSA_LOGON_BUFFER buf{};
    buf.Magic    = LSA_SUBMIT_BUFFER_MAGIC;
    buf.Version  = LSA_SUBMIT_BUFFER_VERSION;
    buf.Reserved = 1;

    NTSTATUS subStatus = STATUS_SUCCESS;
    NTSTATUS status = LsaPackage::Instance().LogonUserEx2(
        nullptr, Interactive,
        &buf, nullptr, sizeof(buf),
        nullptr, nullptr, nullptr,
        &subStatus,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

    EXPECT_EQ(status, STATUS_INVALID_PARAMETER);
    EXPECT_EQ(subStatus, STATUS_INVALID_PARAMETER);
}

// ============================================================
// Test 8: UnknownDeviceIdentityRejection
// ============================================================
TEST_F(LsaAuthenticationPackageTest, UnknownDeviceIdentityRejection) {
    DeviceId unknownId = GenerateDeviceId();
    auto msgBytes = BuildSignedMessageBytes(unknownId);

    MOBILE_UNLOCK_LSA_LOGON_BUFFER buf{};
    buf.Magic   = LSA_SUBMIT_BUFFER_MAGIC;
    buf.Version = LSA_SUBMIT_BUFFER_VERSION;
    std::memcpy(buf.DeviceId, unknownId.data(), 16);
    std::memcpy(buf.CanonicalMessage, msgBytes.data(), LSA_CANONICAL_MESSAGE_SIZE);

    NTSTATUS subStatus = STATUS_SUCCESS;
    NTSTATUS status = LsaPackage::Instance().LogonUserEx2(
        nullptr, Interactive,
        &buf, nullptr, sizeof(buf),
        nullptr, nullptr, nullptr,
        &subStatus,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

    EXPECT_EQ(status, STATUS_NO_SUCH_USER);
}

// ============================================================
// Test 9: RevokedDeviceIdentityRejection
// ============================================================
TEST_F(LsaAuthenticationPackageTest, RevokedDeviceIdentityRejection) {
    SetDeviceStatus(m_deviceIdStr, kStatusRevoked);

    auto msgBytes = BuildSignedMessageBytes(m_testDeviceId);

    MOBILE_UNLOCK_LSA_LOGON_BUFFER buf{};
    buf.Magic   = LSA_SUBMIT_BUFFER_MAGIC;
    buf.Version = LSA_SUBMIT_BUFFER_VERSION;
    std::memcpy(buf.DeviceId, m_testDeviceId.data(), 16);
    std::memcpy(buf.CanonicalMessage, msgBytes.data(), LSA_CANONICAL_MESSAGE_SIZE);

    NTSTATUS subStatus = STATUS_SUCCESS;
    NTSTATUS status = LsaPackage::Instance().LogonUserEx2(
        nullptr, Interactive,
        &buf, nullptr, sizeof(buf),
        nullptr, nullptr, nullptr,
        &subStatus,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

    EXPECT_EQ(status, STATUS_ACCOUNT_RESTRICTION);
}

// ============================================================
// Test 10: MissingPublicKeyRejection
// ============================================================
TEST_F(LsaAuthenticationPackageTest, MissingPublicKeyRejection) {
    DeviceRecord rec{};
    LONG r = ReadDeviceRecord(m_deviceIdStr, rec);
    ASSERT_EQ(r, ERROR_SUCCESS);
    rec.publicKey.clear();
    WriteDeviceRecord(rec);

    auto msgBytes = BuildSignedMessageBytes(m_testDeviceId);

    MOBILE_UNLOCK_LSA_LOGON_BUFFER buf{};
    buf.Magic   = LSA_SUBMIT_BUFFER_MAGIC;
    buf.Version = LSA_SUBMIT_BUFFER_VERSION;
    std::memcpy(buf.DeviceId, m_testDeviceId.data(), 16);
    std::memcpy(buf.CanonicalMessage, msgBytes.data(), LSA_CANONICAL_MESSAGE_SIZE);

    NTSTATUS subStatus = STATUS_SUCCESS;
    NTSTATUS status = LsaPackage::Instance().LogonUserEx2(
        nullptr, Interactive,
        &buf, nullptr, sizeof(buf),
        nullptr, nullptr, nullptr,
        &subStatus,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

    EXPECT_EQ(status, STATUS_LOGON_FAILURE);
}

// ============================================================
// Test 11: InvalidSignatureRejection
// ============================================================
TEST_F(LsaAuthenticationPackageTest, InvalidSignatureRejection) {
    auto msgBytes = BuildSignedMessageBytes(m_testDeviceId);

    MOBILE_UNLOCK_LSA_LOGON_BUFFER buf{};
    buf.Magic   = LSA_SUBMIT_BUFFER_MAGIC;
    buf.Version = LSA_SUBMIT_BUFFER_VERSION;
    std::memcpy(buf.DeviceId, m_testDeviceId.data(), 16);
    std::memcpy(buf.CanonicalMessage, msgBytes.data(), LSA_CANONICAL_MESSAGE_SIZE);
    std::memset(buf.Signature, 0xFF, LSA_SIGNATURE_SIZE); // Corrupted

    NTSTATUS subStatus = STATUS_SUCCESS;
    NTSTATUS status = LsaPackage::Instance().LogonUserEx2(
        nullptr, Interactive,
        &buf, nullptr, sizeof(buf),
        nullptr, nullptr, nullptr,
        &subStatus,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

    EXPECT_EQ(status, STATUS_LOGON_FAILURE);
}

// ============================================================
// Test 12: DeviceIdMismatchRejection
// ============================================================
TEST_F(LsaAuthenticationPackageTest, DeviceIdMismatchRejection) {
    // CanonicalMessage contains otherId but buf.DeviceId is m_testDeviceId
    DeviceId otherId = GenerateDeviceId();
    auto msgBytes    = BuildSignedMessageBytes(otherId);

    MOBILE_UNLOCK_LSA_LOGON_BUFFER buf{};
    buf.Magic   = LSA_SUBMIT_BUFFER_MAGIC;
    buf.Version = LSA_SUBMIT_BUFFER_VERSION;
    std::memcpy(buf.DeviceId, m_testDeviceId.data(), 16);          // buffer DeviceId
    std::memcpy(buf.CanonicalMessage, msgBytes.data(), LSA_CANONICAL_MESSAGE_SIZE); // signed with otherId

    NTSTATUS subStatus = STATUS_SUCCESS;
    NTSTATUS status = LsaPackage::Instance().LogonUserEx2(
        nullptr, Interactive,
        &buf, nullptr, sizeof(buf),
        nullptr, nullptr, nullptr,
        &subStatus,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

    EXPECT_EQ(status, STATUS_LOGON_FAILURE);
}

// ============================================================
// Test 13: NonAuthOpcodeRejection
// ============================================================
TEST_F(LsaAuthenticationPackageTest, NonAuthOpcodeRejection) {
    auto msgBytes = BuildSignedMessageBytes(
        m_testDeviceId,
        static_cast<uint16_t>(MessageType::LOCK_REQUEST)); // Wrong opcode

    MOBILE_UNLOCK_LSA_LOGON_BUFFER buf{};
    buf.Magic   = LSA_SUBMIT_BUFFER_MAGIC;
    buf.Version = LSA_SUBMIT_BUFFER_VERSION;
    std::memcpy(buf.DeviceId, m_testDeviceId.data(), 16);
    std::memcpy(buf.CanonicalMessage, msgBytes.data(), LSA_CANONICAL_MESSAGE_SIZE);

    NTSTATUS subStatus = STATUS_SUCCESS;
    NTSTATUS status = LsaPackage::Instance().LogonUserEx2(
        nullptr, Interactive,
        &buf, nullptr, sizeof(buf),
        nullptr, nullptr, nullptr,
        &subStatus,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

    EXPECT_EQ(status, STATUS_LOGON_FAILURE);
}

// ============================================================
// Test 14: ValidCanonicalSignatureAcceptance
// ============================================================
TEST_F(LsaAuthenticationPackageTest, ValidCanonicalSignatureAcceptance) {
    // Generate valid ECDSA P-256 test keypair
    BCRYPT_KEY_HANDLE hPrivKey = nullptr;
    std::vector<uint8_t> pubKeyBlob;
    bool keyGen = CryptoManager::GenerateTestKeyPair(&hPrivKey, pubKeyBlob);
    ASSERT_TRUE(keyGen);

    // Update DeviceRegistry with real public key blob
    DeviceRecord rec{};
    LONG r = ReadDeviceRecord(m_deviceIdStr, rec);
    ASSERT_EQ(r, ERROR_SUCCESS);
    rec.publicKey = pubKeyBlob;
    WriteDeviceRecord(rec);

    // Build signed message
    SignedMessage msg{};
    msg.ProtocolVersion = 0x0100;
    std::memcpy(msg.DeviceIdentity, m_testDeviceId.data(), 16);
    msg.Operation = static_cast<uint16_t>(MessageType::AUTH_RESPONSE);
    msg.RequestID = 100;
    msg.SessionID = 200;
    msg.Timestamp = 300;
    std::memset(msg.Nonce, 0x42, 32);

    auto msgBytes = SerializeSignedMessage(msg);
    ASSERT_EQ(msgBytes.size(), LSA_CANONICAL_MESSAGE_SIZE);

    // VerifySignature (called inside VerifyCanonicalSignedMessage) hashes the
    // serialized message bytes internally before verifying.  SignHashForTesting
    // signs a raw hash, so we must pre-hash once here — matching what the verifier does.
    std::vector<uint8_t> digest;
    ASSERT_TRUE(CryptoManager::ComputeSha256(msgBytes.data(), msgBytes.size(), digest));

    std::vector<uint8_t> signature;
    bool signOk = CryptoManager::SignHashForTesting(hPrivKey, digest.data(), digest.size(), signature);
    CryptoManager::DestroyKey(hPrivKey);
    ASSERT_TRUE(signOk);
    ASSERT_EQ(signature.size(), LSA_SIGNATURE_SIZE);

    MOBILE_UNLOCK_LSA_LOGON_BUFFER buf{};
    buf.Magic   = LSA_SUBMIT_BUFFER_MAGIC;
    buf.Version = LSA_SUBMIT_BUFFER_VERSION;
    std::memcpy(buf.DeviceId, m_testDeviceId.data(), 16);
    std::memcpy(buf.CanonicalMessage, msgBytes.data(), LSA_CANONICAL_MESSAGE_SIZE);
    std::memcpy(buf.Signature, signature.data(), LSA_SIGNATURE_SIZE);

    PUNICODE_STRING accountName = nullptr;
    PUNICODE_STRING authority   = nullptr;
    LSA_TOKEN_INFORMATION_TYPE tokenType = LsaTokenInformationNull;
    SECPKG_PRIMARY_CRED primaryCred{};
    NTSTATUS subStatus = STATUS_UNSUCCESSFUL;

    NTSTATUS status = LsaPackage::Instance().LogonUserEx2(
        nullptr, Interactive,
        &buf, nullptr, sizeof(buf),
        nullptr, nullptr, nullptr,
        &subStatus,
        &tokenType, nullptr,
        &accountName, &authority, nullptr,
        &primaryCred, nullptr);

    EXPECT_EQ(status, STATUS_SUCCESS);
    EXPECT_EQ(subStatus, STATUS_SUCCESS);

    ASSERT_NE(accountName, nullptr);
    EXPECT_GT(accountName->Length, 0u);

    ASSERT_NE(authority, nullptr);
    EXPECT_NE(authority->Buffer, nullptr);

    // Zero-password invariant
    EXPECT_EQ(primaryCred.Password.Length, 0u);
    EXPECT_EQ(primaryCred.Password.Buffer, nullptr);
}

// ============================================================
// Test 15: NoPasswordInvariantCheck
// ============================================================
TEST_F(LsaAuthenticationPackageTest, NoPasswordInvariantCheck) {
    SECPKG_PRIMARY_CRED cred{};
    std::memset(&cred, 0xCC, sizeof(cred));

    NTSTATUS subStatus = STATUS_SUCCESS;
    LsaPackage::Instance().LogonUserEx2(
        nullptr, Interactive,
        nullptr, nullptr, 0,
        nullptr, nullptr, nullptr,
        &subStatus,
        nullptr, nullptr, nullptr, nullptr, nullptr,
        &cred, nullptr);

    // PrimaryCredentials must be zeroed regardless of outcome
    EXPECT_EQ(cred.Password.Length, 0u);
    EXPECT_EQ(cred.Password.Buffer, nullptr);
}

// ============================================================
// Test 16: LogonTerminatedCallbackSafe
// ============================================================
TEST_F(LsaAuthenticationPackageTest, LogonTerminatedCallbackSafe) {
    LUID luid{};
    luid.LowPart  = 123;
    luid.HighPart = 456;
    EXPECT_NO_FATAL_FAILURE({
        LsaPackage::Instance().LogonTerminated(&luid);
    });
}
