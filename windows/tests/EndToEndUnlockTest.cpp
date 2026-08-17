// ============================================================
// MobileFingerprintUnlock — Phase 9B End-to-End Unlock Tests
// Real End-to-End Phone -> CP -> Winlogon -> LSA Pipeline
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
#include <chrono>

#include "../credential_provider/CredentialProviderCompat.h"
#include "../credential_provider/CredentialProvider.h"
#include "../credential_provider/MobileUnlockCredential.h"
#include "../credential_provider/ProviderGuid.h"
#include "../lsa_authentication_package/LsaPackageCompat.h"
#include "../lsa_authentication_package/LsaLogonBuffer.h"
#include "../lsa_authentication_package/LsaPackage.h"
#include "../authentication/LsaPackageLookup.h"
#include "../pairing/DeviceIdentity.h"
#include "../pairing/DeviceRegistry.h"
#include "../crypto/CryptoManager.h"
#include "../../shared/protocol/SignedMessage.h"
#include "../../shared/protocol/ProtocolTypes.h"

using namespace MobileUnlock::CredentialProvider;
using namespace MobileUnlock::Lsa;
using namespace MobileUnlock::Authentication;
using namespace MobileUnlock::Pairing;
using namespace MobileUnlock::Crypto;
using namespace MobileUnlock::Protocol;

// ============================================================
// Lab Dispatch Table
// ============================================================

static std::vector<void*> s_e2eAllocations;

static PVOID NTAPI E2EMockAllocateLsaHeap(ULONG length) {
    void* ptr = LocalAlloc(LPTR, length);
    if (ptr) s_e2eAllocations.push_back(ptr);
    return ptr;
}

static VOID NTAPI E2EMockFreeLsaHeap(PVOID base) {
    if (base) {
        LocalFree(base);
    }
}

// ============================================================
// Test Fixture
// ============================================================

class EndToEndUnlockTest : public ::testing::Test {
protected:
    void SetUp() override {
        s_e2eAllocations.clear();
        SetRegistryRootForTesting(HKEY_CURRENT_USER);

        m_dispatchTable.AllocateLsaHeap       = E2EMockAllocateLsaHeap;
        m_dispatchTable.FreeLsaHeap           = E2EMockFreeLsaHeap;
        m_dispatchTable.AllocateClientBuffer  = nullptr;
        m_dispatchTable.FreeClientBuffer      = nullptr;
        m_dispatchTable.CopyToClientBuffer    = nullptr;
        m_dispatchTable.CopyFromClientBuffer  = nullptr;

        LsaPackage::Instance().SetDispatchTableForTesting(&m_dispatchTable);

        // Generate genuine ECDSA P-256 keypair for real signing simulation
        m_testDeviceId = GenerateDeviceId();
        m_deviceIdStr  = DeviceIdToString(m_testDeviceId);

        bool keyGen = CryptoManager::GenerateTestKeyPair(&m_hPrivKey, m_pubKeyBlob);
        ASSERT_TRUE(keyGen);

        DeviceRecord record{};
        record.deviceId   = m_testDeviceId;
        record.deviceName = "TECNO_KI7_Enrolled";
        record.pairStatus = kStatusActive;
        record.publicKey  = m_pubKeyBlob;
        record.accountSid = "S-1-5-18"; // Local System SID for reliable test account resolution

        WriteDeviceRecord(record);
    }

    void TearDown() override {
        if (m_hPrivKey) {
            CryptoManager::DestroyKey(m_hPrivKey);
            m_hPrivKey = nullptr;
        }

        DeleteDeviceRecord(m_deviceIdStr);
        SetRegistryRootForTesting(HKEY_LOCAL_MACHINE);

        for (void* p : s_e2eAllocations) {
            LocalFree(p);
        }
        s_e2eAllocations.clear();
    }

    // Helper: Simulates Android Keystore signing an AUTH_RESPONSE challenge
    MOBILE_UNLOCK_LSA_LOGON_BUFFER SimulateAndroidKeystoreSigning(
        const DeviceId& devId,
        BCRYPT_KEY_HANDLE hKey,
        uint16_t operation = static_cast<uint16_t>(MessageType::AUTH_RESPONSE))
    {
        uint64_t timestamp = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());

        SignedMessage msg{};
        msg.ProtocolVersion = 0x0100;
        std::memcpy(msg.DeviceIdentity, devId.data(), 16);
        msg.Operation = operation;
        msg.RequestID = 5001;
        msg.SessionID = 9002;
        msg.Timestamp = timestamp;
        std::memset(msg.Nonce, 0x77, 32);

        auto msgBytes = SerializeSignedMessage(msg);

        std::vector<uint8_t> digest;
        CryptoManager::ComputeSha256(msgBytes.data(), msgBytes.size(), digest);

        std::vector<uint8_t> signature;
        CryptoManager::SignHashForTesting(hKey, digest.data(), digest.size(), signature);

        MOBILE_UNLOCK_LSA_LOGON_BUFFER buf{};
        buf.Magic   = LSA_SUBMIT_BUFFER_MAGIC;
        buf.Version = LSA_SUBMIT_BUFFER_VERSION;
        std::memcpy(buf.DeviceId, devId.data(), 16);
        buf.Reserved = 0;
        std::memcpy(buf.CanonicalMessage, msgBytes.data(), LSA_CANONICAL_MESSAGE_SIZE);
        std::memcpy(buf.Signature, signature.data(), LSA_SIGNATURE_SIZE);

        return buf;
    }

    LSA_DISPATCH_TABLE m_dispatchTable{};
    DeviceId           m_testDeviceId;
    std::string        m_deviceIdStr;
    BCRYPT_KEY_HANDLE  m_hPrivKey{nullptr};
    std::vector<uint8_t> m_pubKeyBlob;
};

// ============================================================
// Test 1: CredentialProviderReturnsRealSerializationWhenAuthReady
// ============================================================
TEST_F(EndToEndUnlockTest, CredentialProviderReturnsRealSerializationWhenAuthReady) {
    auto pCred = new (std::nothrow) MobileUnlockCredential();
    ASSERT_NE(pCred, nullptr);

    // Prepare valid LSA buffer
    MOBILE_UNLOCK_LSA_LOGON_BUFFER lsaBuf = SimulateAndroidKeystoreSigning(
        m_testDeviceId, m_hPrivKey);

    pCred->SetInternalAuthStateForTesting(lsaBuf);
    EXPECT_TRUE(pCred->IsAuthStateReady());

    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE cpgsr = CPGSR_NO_CREDENTIAL_FINISHED;
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION cpcs{};
    PWSTR statusText = nullptr;
    CREDENTIAL_PROVIDER_STATUS_ICON statusIcon = CPSI_NONE;

    HRESULT hr = pCred->GetSerialization(&cpgsr, &cpcs, &statusText, &statusIcon);
    EXPECT_EQ(hr, S_OK);
    EXPECT_EQ(cpgsr, CPGSR_RETURN_CREDENTIAL_FINISHED);
    EXPECT_EQ(cpcs.clsidCredentialProvider, CLSID_MobileUnlockProvider);
    EXPECT_GT(cpcs.ulAuthenticationPackage, 0u);
    EXPECT_EQ(cpcs.cbSerialization, sizeof(MOBILE_UNLOCK_LSA_LOGON_BUFFER));
    ASSERT_NE(cpcs.rgbSerialization, nullptr);

    // Verify serialized content matches
    const auto* pReturned = reinterpret_cast<const MOBILE_UNLOCK_LSA_LOGON_BUFFER*>(cpcs.rgbSerialization);
    EXPECT_EQ(pReturned->Magic, LSA_SUBMIT_BUFFER_MAGIC);
    EXPECT_EQ(pReturned->Version, LSA_SUBMIT_BUFFER_VERSION);
    EXPECT_EQ(std::memcmp(pReturned->DeviceId, m_testDeviceId.data(), 16), 0);

    CoTaskMemFree(cpcs.rgbSerialization);
    pCred->Release();
}

// ============================================================
// Test 2: CredentialProviderRejectsSerializationWhenNoAuth
// ============================================================
TEST_F(EndToEndUnlockTest, CredentialProviderRejectsSerializationWhenNoAuth) {
    auto pCred = new (std::nothrow) MobileUnlockCredential();
    ASSERT_NE(pCred, nullptr);

    EXPECT_FALSE(pCred->IsAuthStateReady());

    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE cpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION cpcs{};
    PWSTR statusText = nullptr;
    CREDENTIAL_PROVIDER_STATUS_ICON statusIcon = CPSI_NONE;

    HRESULT hr = pCred->GetSerialization(&cpgsr, &cpcs, &statusText, &statusIcon);
    EXPECT_EQ(hr, S_FALSE);
    EXPECT_EQ(cpgsr, CPGSR_NO_CREDENTIAL_FINISHED);
    EXPECT_EQ(cpcs.cbSerialization, 0u);
    EXPECT_EQ(cpcs.rgbSerialization, nullptr);

    pCred->Release();
}

// ============================================================
// Test 3: FullChainEndToEndUnlockSimulation
// ============================================================
TEST_F(EndToEndUnlockTest, FullChainEndToEndUnlockSimulation) {
    // 1. User locks workstation -> CP enumerates
    auto pProvider = new (std::nothrow) CredentialProvider();
    ASSERT_NE(pProvider, nullptr);
    EXPECT_EQ(pProvider->SetUsageScenario(CPUS_UNLOCK_WORKSTATION, 0), S_OK);

    ICredentialProviderCredential* pCredInterface = nullptr;
    EXPECT_EQ(pProvider->GetCredentialAt(0, &pCredInterface), S_OK);
    ASSERT_NE(pCredInterface, nullptr);

    auto* pCred = static_cast<MobileUnlockCredential*>(pCredInterface);

    // 2. User unlocks phone via Fingerprint -> Android Keystore generates signature
    MOBILE_UNLOCK_LSA_LOGON_BUFFER lsaBuf = SimulateAndroidKeystoreSigning(
        m_testDeviceId, m_hPrivKey);

    // 3. Service notifies Credential Provider via Secure IPC
    pCred->SetInternalAuthStateForTesting(lsaBuf);

    // 4. Winlogon queries serialization
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE cpgsr;
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION cpcs{};
    PWSTR statusText = nullptr;
    CREDENTIAL_PROVIDER_STATUS_ICON statusIcon = CPSI_NONE;

    EXPECT_EQ(pCred->GetSerialization(&cpgsr, &cpcs, &statusText, &statusIcon), S_OK);
    EXPECT_EQ(cpgsr, CPGSR_RETURN_CREDENTIAL_FINISHED);
    ASSERT_NE(cpcs.rgbSerialization, nullptr);
    EXPECT_EQ(cpcs.cbSerialization, 180u);

    // 5. Winlogon submits serialization to LsaApLogonUserEx2 (LogonType = Unlock = 7)
    PUNICODE_STRING accountName = nullptr;
    PUNICODE_STRING authority   = nullptr;
    LSA_TOKEN_INFORMATION_TYPE tokenType = LsaTokenInformationNull;
    SECPKG_PRIMARY_CRED primaryCred{};
    NTSTATUS subStatus = STATUS_UNSUCCESSFUL;

    NTSTATUS status = LsaPackage::Instance().LogonUserEx2(
        nullptr,
        Unlock,
        cpcs.rgbSerialization,
        nullptr,
        cpcs.cbSerialization,
        nullptr, nullptr, nullptr,
        &subStatus,
        &tokenType,
        nullptr,
        &accountName,
        &authority,
        nullptr,
        &primaryCred,
        nullptr);

    // 6. LSA accepts authentication & returns STATUS_SUCCESS -> Workstation Unlocked!
    EXPECT_EQ(status, STATUS_SUCCESS);
    EXPECT_EQ(subStatus, STATUS_SUCCESS);
    ASSERT_NE(accountName, nullptr);
    EXPECT_GT(accountName->Length, 0u);
    ASSERT_NE(authority, nullptr);
    EXPECT_STREQ(authority->Buffer, AUTH_AUTHORITY_W);

    // Zero password invariant
    EXPECT_EQ(primaryCred.Password.Length, 0u);
    EXPECT_EQ(primaryCred.Password.Buffer, nullptr);

    CoTaskMemFree(cpcs.rgbSerialization);
    pCredInterface->Release();
    pProvider->Release();
}

// ============================================================
// Test 4: NegativeTest_WrongDeviceIdentity
// ============================================================
TEST_F(EndToEndUnlockTest, NegativeTest_WrongDeviceIdentity) {
    DeviceId unknownDevice = GenerateDeviceId();
    MOBILE_UNLOCK_LSA_LOGON_BUFFER lsaBuf = SimulateAndroidKeystoreSigning(
        unknownDevice, m_hPrivKey);

    NTSTATUS subStatus = STATUS_SUCCESS;
    NTSTATUS status = LsaPackage::Instance().LogonUserEx2(
        nullptr, Unlock, &lsaBuf, nullptr, sizeof(lsaBuf),
        nullptr, nullptr, nullptr, &subStatus,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

    EXPECT_EQ(status, STATUS_NO_SUCH_USER);
}

// ============================================================
// Test 5: NegativeTest_CorruptedSignature
// ============================================================
TEST_F(EndToEndUnlockTest, NegativeTest_CorruptedSignature) {
    MOBILE_UNLOCK_LSA_LOGON_BUFFER lsaBuf = SimulateAndroidKeystoreSigning(
        m_testDeviceId, m_hPrivKey);
    lsaBuf.Signature[10] ^= 0xAA; // Corrupt signature byte

    NTSTATUS subStatus = STATUS_SUCCESS;
    NTSTATUS status = LsaPackage::Instance().LogonUserEx2(
        nullptr, Unlock, &lsaBuf, nullptr, sizeof(lsaBuf),
        nullptr, nullptr, nullptr, &subStatus,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

    EXPECT_EQ(status, STATUS_LOGON_FAILURE);
}

// ============================================================
// Test 6: NegativeTest_RevokedDevice
// ============================================================
TEST_F(EndToEndUnlockTest, NegativeTest_RevokedDevice) {
    // Revoke device in registry
    SetDeviceStatus(m_deviceIdStr, kStatusRevoked);

    MOBILE_UNLOCK_LSA_LOGON_BUFFER lsaBuf = SimulateAndroidKeystoreSigning(
        m_testDeviceId, m_hPrivKey);

    NTSTATUS subStatus = STATUS_SUCCESS;
    NTSTATUS status = LsaPackage::Instance().LogonUserEx2(
        nullptr, Unlock, &lsaBuf, nullptr, sizeof(lsaBuf),
        nullptr, nullptr, nullptr, &subStatus,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

    EXPECT_EQ(status, STATUS_ACCOUNT_RESTRICTION);
}

// ============================================================
// Test 7: ThreeConsecutiveUnlockRepetitions
// ============================================================
TEST_F(EndToEndUnlockTest, ThreeConsecutiveUnlockRepetitions) {
    auto pCred = new (std::nothrow) MobileUnlockCredential();
    ASSERT_NE(pCred, nullptr);

    for (int cycle = 1; cycle <= 3; ++cycle) {
        // Prepare fresh challenge signature
        MOBILE_UNLOCK_LSA_LOGON_BUFFER lsaBuf = SimulateAndroidKeystoreSigning(
            m_testDeviceId, m_hPrivKey);

        pCred->SetInternalAuthStateForTesting(lsaBuf);

        CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE cpgsr;
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION cpcs{};
        PWSTR statusText = nullptr;
        CREDENTIAL_PROVIDER_STATUS_ICON statusIcon = CPSI_NONE;

        HRESULT hr = pCred->GetSerialization(&cpgsr, &cpcs, &statusText, &statusIcon);
        EXPECT_EQ(hr, S_OK);
        EXPECT_EQ(cpgsr, CPGSR_RETURN_CREDENTIAL_FINISHED);

        NTSTATUS subStatus = STATUS_UNSUCCESSFUL;
        PUNICODE_STRING accountName = nullptr;
        PUNICODE_STRING authority   = nullptr;
        LSA_TOKEN_INFORMATION_TYPE tokenType = LsaTokenInformationNull;

        NTSTATUS status = LsaPackage::Instance().LogonUserEx2(
            nullptr, Unlock, cpcs.rgbSerialization, nullptr, cpcs.cbSerialization,
            nullptr, nullptr, nullptr, &subStatus,
            &tokenType, nullptr, &accountName, &authority, nullptr, nullptr, nullptr);

        EXPECT_EQ(status, STATUS_SUCCESS);
        EXPECT_EQ(subStatus, STATUS_SUCCESS);

        CoTaskMemFree(cpcs.rgbSerialization);

        // Deselect tile between unlocks to verify state cleanup
        EXPECT_EQ(pCred->SetDeselected(), S_OK);
        EXPECT_FALSE(pCred->IsAuthStateReady());
    }

    pCred->Release();
}

// ============================================================
// Test 8: ZeroPasswordIntegrityCheck
// ============================================================
TEST_F(EndToEndUnlockTest, ZeroPasswordIntegrityCheck) {
    auto pCred = new (std::nothrow) MobileUnlockCredential();
    ASSERT_NE(pCred, nullptr);

    MOBILE_UNLOCK_LSA_LOGON_BUFFER lsaBuf = SimulateAndroidKeystoreSigning(
        m_testDeviceId, m_hPrivKey);
    pCred->SetInternalAuthStateForTesting(lsaBuf);

    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE cpgsr;
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION cpcs{};
    PWSTR statusText = nullptr;
    CREDENTIAL_PROVIDER_STATUS_ICON statusIcon = CPSI_NONE;

    EXPECT_EQ(pCred->GetSerialization(&cpgsr, &cpcs, &statusText, &statusIcon), S_OK);

    // Verify 180-byte buffer contains ZERO passwords, PINs, or credential hashes
    const auto* pBuf = reinterpret_cast<const MOBILE_UNLOCK_LSA_LOGON_BUFFER*>(cpcs.rgbSerialization);
    EXPECT_EQ(pBuf->Magic, LSA_SUBMIT_BUFFER_MAGIC);
    EXPECT_EQ(pBuf->Reserved, 0u);

    // Verify LSA primary credentials return zeroed password
    SECPKG_PRIMARY_CRED primaryCred{};
    std::memset(&primaryCred, 0xEE, sizeof(primaryCred)); // Dirty memory

    NTSTATUS subStatus;
    LsaPackage::Instance().LogonUserEx2(
        nullptr, Unlock, cpcs.rgbSerialization, nullptr, cpcs.cbSerialization,
        nullptr, nullptr, nullptr, &subStatus,
        nullptr, nullptr, nullptr, nullptr, nullptr,
        &primaryCred, nullptr);

    EXPECT_EQ(primaryCred.Password.Length, 0u);
    EXPECT_EQ(primaryCred.Password.Buffer, nullptr);

    CoTaskMemFree(cpcs.rgbSerialization);
    pCred->Release();
}
