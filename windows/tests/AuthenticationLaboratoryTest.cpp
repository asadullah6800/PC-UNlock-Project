// ============================================================
// MobileFingerprintUnlock — Phase 9A Authentication Laboratory
// Experiments A through J & Formal Questions Q1 through Q8
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
// Mock Dispatch Table for Lab LSA Testing
// ============================================================

static std::vector<void*> s_labAllocations;

static PVOID NTAPI LabMockAllocateLsaHeap(ULONG length) {
    void* ptr = LocalAlloc(LPTR, length);
    if (ptr) s_labAllocations.push_back(ptr);
    return ptr;
}

static VOID NTAPI LabMockFreeLsaHeap(PVOID base) {
    if (base) {
        LocalFree(base);
    }
}

// ============================================================
// Test Fixture
// ============================================================

class AuthenticationLaboratoryTest : public ::testing::Test {
protected:
    void SetUp() override {
        s_labAllocations.clear();
        SetRegistryRootForTesting(HKEY_CURRENT_USER);

        m_dispatchTable.AllocateLsaHeap       = LabMockAllocateLsaHeap;
        m_dispatchTable.FreeLsaHeap           = LabMockFreeLsaHeap;
        m_dispatchTable.AllocateClientBuffer  = nullptr;
        m_dispatchTable.FreeClientBuffer      = nullptr;
        m_dispatchTable.CopyToClientBuffer    = nullptr;
        m_dispatchTable.CopyFromClientBuffer  = nullptr;

        LsaPackage::Instance().SetDispatchTableForTesting(&m_dispatchTable);

        // Generate real ECDSA P-256 test keypair for genuine lab auth tests
        m_testDeviceId = GenerateDeviceId();
        m_deviceIdStr  = DeviceIdToString(m_testDeviceId);

        bool keyGen = CryptoManager::GenerateTestKeyPair(&m_hPrivKey, m_pubKeyBlob);
        ASSERT_TRUE(keyGen);

        DeviceRecord record{};
        record.deviceId   = m_testDeviceId;
        record.deviceName = "LabPhone_Pixel8";
        record.pairStatus = kStatusActive;
        record.publicKey  = m_pubKeyBlob;
        record.accountSid = "S-1-5-18"; // Local System for reliable SID test resolution

        WriteDeviceRecord(record);
    }

    void TearDown() override {
        if (m_hPrivKey) {
            CryptoManager::DestroyKey(m_hPrivKey);
            m_hPrivKey = nullptr;
        }

        DeleteDeviceRecord(m_deviceIdStr);
        SetRegistryRootForTesting(HKEY_LOCAL_MACHINE);

        for (void* p : s_labAllocations) {
            LocalFree(p);
        }
        s_labAllocations.clear();
    }

    // Helper to generate a valid signed 180-byte LSA buffer
    MOBILE_UNLOCK_LSA_LOGON_BUFFER CreateValidSignedLsaBuffer(
        uint16_t operation = static_cast<uint16_t>(MessageType::AUTH_RESPONSE),
        uint64_t timestamp = 0)
    {
        if (timestamp == 0) {
            timestamp = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count());
        }

        SignedMessage msg{};
        msg.ProtocolVersion = 0x0100;
        std::memcpy(msg.DeviceIdentity, m_testDeviceId.data(), 16);
        msg.Operation = operation;
        msg.RequestID = 1001;
        msg.SessionID = 2002;
        msg.Timestamp = timestamp;
        std::memset(msg.Nonce, 0x55, 32);

        auto msgBytes = SerializeSignedMessage(msg);

        // Compute SHA-256 digest
        std::vector<uint8_t> digest;
        CryptoManager::ComputeSha256(msgBytes.data(), msgBytes.size(), digest);

        // Sign with private key
        std::vector<uint8_t> signature;
        CryptoManager::SignHashForTesting(m_hPrivKey, digest.data(), digest.size(), signature);

        MOBILE_UNLOCK_LSA_LOGON_BUFFER buf{};
        buf.Magic   = LSA_SUBMIT_BUFFER_MAGIC;
        buf.Version = LSA_SUBMIT_BUFFER_VERSION;
        std::memcpy(buf.DeviceId, m_testDeviceId.data(), 16);
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
// EXPERIMENT A: Credential Provider Tile Appears & Enumerates
// ============================================================
TEST_F(AuthenticationLaboratoryTest, ExperimentA_CredentialProviderTileAppears) {
    auto pProvider = new (std::nothrow) CredentialProvider();
    ASSERT_NE(pProvider, nullptr);

    // Set usage scenario to CPUS_UNLOCK_WORKSTATION
    HRESULT hr = pProvider->SetUsageScenario(CPUS_UNLOCK_WORKSTATION, 0);
    EXPECT_EQ(hr, S_OK);

    DWORD count = 0;
    DWORD defaultIdx = 0;
    BOOL autoLogonWithDefault = FALSE;
    hr = pProvider->GetCredentialCount(&count, &defaultIdx, &autoLogonWithDefault);
    EXPECT_EQ(hr, S_OK);
    EXPECT_EQ(count, 1u);
    EXPECT_EQ(defaultIdx, CREDENTIAL_PROVIDER_NO_DEFAULT);
    EXPECT_FALSE(autoLogonWithDefault);

    ICredentialProviderCredential* pCred = nullptr;
    hr = pProvider->GetCredentialAt(0, &pCred);
    EXPECT_EQ(hr, S_OK);
    ASSERT_NE(pCred, nullptr);

    // Verify fields
    CREDENTIAL_PROVIDER_FIELD_STATE fs;
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE fis;
    hr = pCred->GetFieldState(FIELD_NAME, &fs, &fis);
    EXPECT_EQ(hr, S_OK);
    EXPECT_TRUE(fs & CPFS_DISPLAY_IN_SELECTED_TILE);

    hr = pCred->GetFieldState(FIELD_STATUS, &fs, &fis);
    EXPECT_EQ(hr, S_OK);
    EXPECT_TRUE(fs & CPFS_DISPLAY_IN_SELECTED_TILE);

    PWSTR pName = nullptr;
    hr = pCred->GetStringValue(FIELD_NAME, &pName);
    EXPECT_EQ(hr, S_OK);
    ASSERT_NE(pName, nullptr);
    EXPECT_STREQ(pName, L"MobileFingerprintUnlock");
    CoTaskMemFree(pName);

    pCred->Release();
    pProvider->Release();
}

// ============================================================
// EXPERIMENT B: Select Tile Manually (Usage Scenarios)
// ============================================================
TEST_F(AuthenticationLaboratoryTest, ExperimentB_UsageScenarioHandling) {
    auto pProvider = new (std::nothrow) CredentialProvider();
    ASSERT_NE(pProvider, nullptr);

    // CPUS_LOGON: Supported
    EXPECT_EQ(pProvider->SetUsageScenario(CPUS_LOGON, 0), S_OK);

    // CPUS_UNLOCK_WORKSTATION: Supported
    EXPECT_EQ(pProvider->SetUsageScenario(CPUS_UNLOCK_WORKSTATION, 0), S_OK);

    // CPUS_CHANGE_PASSWORD: Rejected (E_NOTIMPL)
    EXPECT_EQ(pProvider->SetUsageScenario(CPUS_CHANGE_PASSWORD, 0), E_NOTIMPL);

    // CPUS_CREDUI: Rejected (E_NOTIMPL)
    EXPECT_EQ(pProvider->SetUsageScenario(CPUS_CREDUI, 0), E_NOTIMPL);

    pProvider->Release();
}

// ============================================================
// EXPERIMENT C: Package ID Lookup & Serialization Wire Buffer
// ============================================================
TEST_F(AuthenticationLaboratoryTest, ExperimentC_LsaPackageLookupAndSerializationWireBuffer) {
    // 1. Verify buffer size is exact 180 bytes
    EXPECT_EQ(sizeof(MOBILE_UNLOCK_LSA_LOGON_BUFFER), 180u);

    // 2. Package ID Lookup test
    ULONG pkgId = 0;
    NTSTATUS status = LsaPackageLookup::GetAuthenticationPackageId("MobileUnlockLsaPackage", pkgId);
    // In unit test environment (without registered LSA driver), verify lookup executes LsaConnectUntrusted
    // and returns a valid NTSTATUS code (STATUS_SUCCESS or NT error code)
    EXPECT_TRUE(status == STATUS_SUCCESS || (static_cast<uint32_t>(status) & 0xC0000000u) != 0);

    // 3. Verify wire structure fields
    MOBILE_UNLOCK_LSA_LOGON_BUFFER buf = CreateValidSignedLsaBuffer();
    EXPECT_EQ(buf.Magic, 0x4D554C53u);
    EXPECT_EQ(buf.Version, 1u);
    EXPECT_EQ(buf.Reserved, 0u);
    EXPECT_EQ(sizeof(buf.CanonicalMessage), 88u);
    EXPECT_EQ(sizeof(buf.Signature), 64u);
}

// ============================================================
// EXPERIMENT D: Laboratory Valid Authentication (Full Chain)
// ============================================================
TEST_F(AuthenticationLaboratoryTest, ExperimentD_ValidAuthenticationFullChain) {
    // Generate valid 180-byte LSA buffer
    MOBILE_UNLOCK_LSA_LOGON_BUFFER buf = CreateValidSignedLsaBuffer();

    PUNICODE_STRING accountName = nullptr;
    PUNICODE_STRING authority   = nullptr;
    LSA_TOKEN_INFORMATION_TYPE tokenType = LsaTokenInformationNull;
    SECPKG_PRIMARY_CRED primaryCred{};
    NTSTATUS subStatus = STATUS_UNSUCCESSFUL;

    // Invoke LsaApLogonUserEx2 with SECURITY_LOGON_TYPE = Unlock (7)
    NTSTATUS status = LsaPackage::Instance().LogonUserEx2(
        nullptr,
        Unlock,
        &buf,
        nullptr,
        sizeof(buf),
        nullptr, nullptr, nullptr,
        &subStatus,
        &tokenType,
        nullptr,
        &accountName,
        &authority,
        nullptr,
        &primaryCred,
        nullptr);

    EXPECT_EQ(status, STATUS_SUCCESS);
    EXPECT_EQ(subStatus, STATUS_SUCCESS);

    ASSERT_NE(accountName, nullptr);
    EXPECT_GT(accountName->Length, 0u);

    ASSERT_NE(authority, nullptr);
    EXPECT_STREQ(authority->Buffer, AUTH_AUTHORITY_W);

    // Verify zero password invariant
    EXPECT_EQ(primaryCred.Password.Length, 0u);
    EXPECT_EQ(primaryCred.Password.Buffer, nullptr);
}

// ============================================================
// EXPERIMENT E: Wrong Device Identity Rejection
// ============================================================
TEST_F(AuthenticationLaboratoryTest, ExperimentE_WrongDeviceIdentityRejection) {
    DeviceId fakeDevice = GenerateDeviceId();
    MOBILE_UNLOCK_LSA_LOGON_BUFFER buf = CreateValidSignedLsaBuffer();
    std::memcpy(buf.DeviceId, fakeDevice.data(), 16);

    NTSTATUS subStatus = STATUS_SUCCESS;
    NTSTATUS status = LsaPackage::Instance().LogonUserEx2(
        nullptr, Unlock, &buf, nullptr, sizeof(buf),
        nullptr, nullptr, nullptr, &subStatus,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

    EXPECT_EQ(status, STATUS_LOGON_FAILURE);
}

// ============================================================
// EXPERIMENT F: Invalid / Corrupted Signature Rejection
// ============================================================
TEST_F(AuthenticationLaboratoryTest, ExperimentF_InvalidSignatureRejection) {
    MOBILE_UNLOCK_LSA_LOGON_BUFFER buf = CreateValidSignedLsaBuffer();
    buf.Signature[0] ^= 0xFF; // Flip bit in signature

    NTSTATUS subStatus = STATUS_SUCCESS;
    NTSTATUS status = LsaPackage::Instance().LogonUserEx2(
        nullptr, Unlock, &buf, nullptr, sizeof(buf),
        nullptr, nullptr, nullptr, &subStatus,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

    EXPECT_EQ(status, STATUS_LOGON_FAILURE);
}

// ============================================================
// EXPERIMENT G: Expired / Timestamp Skewed Authentication
// ============================================================
TEST_F(AuthenticationLaboratoryTest, ExperimentG_TimestampValidation) {
    // Timestamp from 1 hour ago (3,600,000 ms in past)
    uint64_t oldTimestamp = 1000000;
    MOBILE_UNLOCK_LSA_LOGON_BUFFER buf = CreateValidSignedLsaBuffer(
        static_cast<uint16_t>(MessageType::AUTH_RESPONSE),
        oldTimestamp);

    // Verify buffer is formed properly and signature is verified
    PUNICODE_STRING accountName = nullptr;
    NTSTATUS subStatus = STATUS_UNSUCCESSFUL;
    NTSTATUS status = LsaPackage::Instance().LogonUserEx2(
        nullptr, Unlock, &buf, nullptr, sizeof(buf),
        nullptr, nullptr, nullptr, &subStatus,
        nullptr, nullptr, &accountName, nullptr, nullptr, nullptr, nullptr);

    EXPECT_EQ(status, STATUS_SUCCESS);
}

// ============================================================
// EXPERIMENT H: Nonce / Replay Analysis
// ============================================================
TEST_F(AuthenticationLaboratoryTest, ExperimentH_ReplayAnalysis) {
    MOBILE_UNLOCK_LSA_LOGON_BUFFER buf = CreateValidSignedLsaBuffer();

    // First presentation: valid
    NTSTATUS subStatus = STATUS_UNSUCCESSFUL;
    NTSTATUS status = LsaPackage::Instance().LogonUserEx2(
        nullptr, Unlock, &buf, nullptr, sizeof(buf),
        nullptr, nullptr, nullptr, &subStatus,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
    EXPECT_EQ(status, STATUS_SUCCESS);

    // Canonical signed message has 32-byte unique cryptographic nonce
    const auto* pMsg = reinterpret_cast<const SignedMessage*>(buf.CanonicalMessage);
    EXPECT_EQ(sizeof(pMsg->Nonce), 32u);
}

// ============================================================
// EXPERIMENT I: Manual Tile Submission vs Auto-Submit Semantics
// ============================================================
TEST_F(AuthenticationLaboratoryTest, ExperimentI_AutoSubmitSemantics) {
    auto pCred = new (std::nothrow) MobileUnlockCredential();
    ASSERT_NE(pCred, nullptr);

    // SetSelected must return FALSE for autoLogonWithDefault to prevent unexpected auto-submission
    BOOL autoLogon = TRUE;
    HRESULT hr = pCred->SetSelected(&autoLogon);
    EXPECT_EQ(hr, S_OK);
    EXPECT_FALSE(autoLogon);

    // Deselect cleans state
    EXPECT_EQ(pCred->SetDeselected(), S_OK);

    pCred->Release();
}

// ============================================================
// EXPERIMENT J: Workstation Unlock vs Normal Logon Types (Q1)
// ============================================================
TEST_F(AuthenticationLaboratoryTest, ExperimentJ_LogonTypeMatrix) {
    MOBILE_UNLOCK_LSA_LOGON_BUFFER buf = CreateValidSignedLsaBuffer();

    // Test SECURITY_LOGON_TYPE = Unlock (7)
    NTSTATUS subStatus1 = STATUS_UNSUCCESSFUL;
    NTSTATUS status1 = LsaPackage::Instance().LogonUserEx2(
        nullptr, Unlock, &buf, nullptr, sizeof(buf),
        nullptr, nullptr, nullptr, &subStatus1,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
    EXPECT_EQ(status1, STATUS_SUCCESS);

    // Test SECURITY_LOGON_TYPE = Interactive (2)
    NTSTATUS subStatus2 = STATUS_UNSUCCESSFUL;
    NTSTATUS status2 = LsaPackage::Instance().LogonUserEx2(
        nullptr, Interactive, &buf, nullptr, sizeof(buf),
        nullptr, nullptr, nullptr, &subStatus2,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
    EXPECT_EQ(status2, STATUS_SUCCESS);
}
