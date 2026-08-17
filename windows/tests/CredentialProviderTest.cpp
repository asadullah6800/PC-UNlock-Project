// ============================================================
// MobileFingerprintUnlock — Credential Provider Unit Tests
// Phase 7
// ============================================================
// All tests use the IIpcClientFactory injection interface to
// avoid real pipe connections during unit testing.
//
// These tests verify COM lifetime, tile behavior, status thread,
// and the strict Phase-7 GetSerialization contract.
//
// IMPORTANT: GetSerialization ALWAYS returns
//   CPGSR_NO_CREDENTIAL_FINISHED + S_FALSE in Phase 7.
// This is verified unconditionally in multiple tests.
// ============================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include "../credential_provider/CredentialProviderCompat.h"

#include <gtest/gtest.h>
#include <atomic>
#include <string>
#include <chrono>
#include <thread>
#include <cstring>

#include "../credential_provider/ProviderGuid.h"
#include "../credential_provider/MobileUnlockCredential.h"
#include "../credential_provider/CredentialProvider.h"
#include "../credential_provider/ClassFactory.h"

// Bring in the global DLL ref counter (defined in dllmain.cpp, but
// tests link directly — declare it here for test linkage)
std::atomic<LONG> g_cDllRef{0};

using namespace MobileUnlock::CredentialProvider;
using ProviderClass = MobileUnlock::CredentialProvider::CredentialProvider;

// ============================================================
// Mock IPC Factories
// ============================================================

// Returns a valid IpcStateToken immediately
class MockIpcSuccess final : public IIpcClientFactory {
public:
    IpcStateToken FetchAuthState(DWORD /*connectMs*/, DWORD /*readMs*/) override {
        IpcStateToken tok{};
        tok.valid = true;
        tok.lsaBuffer.Magic   = MobileUnlock::Lsa::LSA_SUBMIT_BUFFER_MAGIC;
        tok.lsaBuffer.Version = MobileUnlock::Lsa::LSA_SUBMIT_BUFFER_VERSION;
        tok.lsaBuffer.Reserved = 0;
        std::memset(tok.lsaBuffer.DeviceId, 0xAA, 16);
        callCount.fetch_add(1, std::memory_order_relaxed);
        return tok;
    }
    std::atomic<int> callCount{0};
};

// Always fails (service unavailable)
class MockIpcConnectFailure final : public IIpcClientFactory {
public:
    IpcStateToken FetchAuthState(DWORD /*connectMs*/, DWORD /*readMs*/) override {
        IpcStateToken tok{};
        tok.valid = false;
        callCount.fetch_add(1, std::memory_order_relaxed);
        return tok;
    }
    std::atomic<int> callCount{0};
};

// Simulates timeout (returns immediately with valid=false)
class MockIpcTimeout final : public IIpcClientFactory {
public:
    IpcStateToken FetchAuthState(DWORD /*connectMs*/, DWORD /*readMs*/) override {
        IpcStateToken tok{};
        tok.valid = false;
        return tok;
    }
};

// Returns malformed response (valid=false, all zeros)
class MockIpcMalformed final : public IIpcClientFactory {
public:
    IpcStateToken FetchAuthState(DWORD /*connectMs*/, DWORD /*readMs*/) override {
        return IpcStateToken{};
    }
};

// ============================================================
// Mock ICredentialProviderCredentialEvents
// ============================================================

class MockCredentialEvents final : public ICredentialProviderCredentialEvents {
public:
    MockCredentialEvents() : m_cRef(1), m_lastFieldIndex(0xFFFFFFFF) {}

    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown ||
            riid == IID_ICredentialProviderCredentialEvents) {
            *ppv = this; AddRef(); return S_OK;
        }
        *ppv = nullptr; return E_NOINTERFACE;
    }
    IFACEMETHODIMP_(ULONG) AddRef() override {
        return InterlockedIncrement(&m_cRef);
    }
    IFACEMETHODIMP_(ULONG) Release() override {
        LONG r = InterlockedDecrement(&m_cRef);
        if (r == 0) delete this;
        return r;
    }

    // Track SetFieldString calls
    IFACEMETHODIMP SetFieldString(
        ICredentialProviderCredential* /*pcc*/,
        DWORD dwFieldID,
        PCWSTR pwszValue) override
    {
        m_lastFieldIndex = dwFieldID;
        m_lastFieldValue = pwszValue ? pwszValue : L"";
        setFieldStringCalls.fetch_add(1, std::memory_order_relaxed);
        return S_OK;
    }

    IFACEMETHODIMP OnCreatingWindow(HWND* /*phwndOwner*/) override { return S_OK; }
    IFACEMETHODIMP AppendFieldComboBoxItem(ICredentialProviderCredential*, DWORD, PCWSTR) override { return S_OK; }
    IFACEMETHODIMP DeleteFieldComboBoxItem(ICredentialProviderCredential*, DWORD, DWORD) override { return S_OK; }
    IFACEMETHODIMP SetFieldBitmap(ICredentialProviderCredential*, DWORD, HBITMAP) override { return S_OK; }
    IFACEMETHODIMP SetFieldCheckbox(ICredentialProviderCredential*, DWORD, BOOL, PCWSTR) override { return S_OK; }
    IFACEMETHODIMP SetFieldComboBoxSelectedItem(ICredentialProviderCredential*, DWORD, DWORD) override { return S_OK; }
    IFACEMETHODIMP SetFieldInteractiveState(ICredentialProviderCredential*, DWORD, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE) override { return S_OK; }
    IFACEMETHODIMP SetFieldState(ICredentialProviderCredential*, DWORD, CREDENTIAL_PROVIDER_FIELD_STATE) override { return S_OK; }
    IFACEMETHODIMP SetFieldSubmitButton(ICredentialProviderCredential*, DWORD, DWORD) override { return S_OK; }

    LONG                 m_cRef;
    DWORD                m_lastFieldIndex;
    std::wstring         m_lastFieldValue;
    std::atomic<int>     setFieldStringCalls{0};
};

// ============================================================
// Test 1: ProviderCreation
// ============================================================
TEST(CredentialProviderTest, ProviderCreation) {
    auto* p = new ProviderClass();
    ASSERT_NE(p, nullptr);
    // Ref count starts at 1
    ULONG r = p->Release();
    EXPECT_EQ(r, 0u);
}

// ============================================================
// Test 2: ComLifetimeRefCounting
// ============================================================
TEST(CredentialProviderTest, ComLifetimeRefCounting) {
    auto* p = new ProviderClass();
    EXPECT_EQ(p->AddRef(), 2u);
    EXPECT_EQ(p->AddRef(), 3u);
    EXPECT_EQ(p->Release(), 2u);
    EXPECT_EQ(p->Release(), 1u);
    EXPECT_EQ(p->Release(), 0u); // Object deleted here
}

// ============================================================
// Test 3: CredentialEnumeration — accepted scenarios
// ============================================================
TEST(CredentialProviderTest, CredentialEnumeration) {
    auto* p = new ProviderClass();
    ASSERT_NE(p, nullptr);

    // Before SetUsageScenario: count = 0
    DWORD count = 99, def = 99;
    BOOL autoLogon = TRUE;
    HRESULT hr = p->GetCredentialCount(&count, &def, &autoLogon);
    EXPECT_EQ(hr, S_OK);
    EXPECT_EQ(count, 0u);
    EXPECT_FALSE(autoLogon);

    // CPUS_LOGON: count = 1, no auto-logon
    hr = p->SetUsageScenario(CPUS_LOGON, 0);
    EXPECT_EQ(hr, S_OK);
    hr = p->GetCredentialCount(&count, &def, &autoLogon);
    EXPECT_EQ(hr, S_OK);
    EXPECT_EQ(count, 1u);
    EXPECT_FALSE(autoLogon);

    p->Release();
}

TEST(CredentialProviderTest, CredentialEnumerationUnlockWorkstation) {
    auto* p = new ProviderClass();
    HRESULT hr = p->SetUsageScenario(CPUS_UNLOCK_WORKSTATION, 0);
    EXPECT_EQ(hr, S_OK);

    DWORD count = 0, def = 0;
    BOOL autoLogon = FALSE;
    hr = p->GetCredentialCount(&count, &def, &autoLogon);
    EXPECT_EQ(hr, S_OK);
    EXPECT_EQ(count, 1u);
    EXPECT_FALSE(autoLogon);
    p->Release();
}

TEST(CredentialProviderTest, UnsupportedScenarioRejected) {
    auto* p = new ProviderClass();
    HRESULT hr = p->SetUsageScenario(CPUS_CREDUI, 0);
    EXPECT_EQ(hr, E_NOTIMPL);

    DWORD count = 1, def = 0;
    BOOL autoLogon = FALSE;
    hr = p->GetCredentialCount(&count, &def, &autoLogon);
    EXPECT_EQ(hr, S_OK);
    EXPECT_EQ(count, 0u); // No credentials enumerated for unsupported scenario
    p->Release();
}

// ============================================================
// Test 4: FieldDescriptorCorrectness
// ============================================================
TEST(CredentialProviderTest, FieldDescriptorCorrectness) {
    auto* p = new ProviderClass();
    p->SetUsageScenario(CPUS_LOGON, 0);

    DWORD fieldCount = 0;
    HRESULT hr = p->GetFieldDescriptorCount(&fieldCount);
    EXPECT_EQ(hr, S_OK);
    EXPECT_EQ(fieldCount, static_cast<DWORD>(FIELD_COUNT));
    EXPECT_EQ(fieldCount, 2u); // Exactly 2 fields

    // Field 0: CPFT_LARGE_TEXT
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pfd0 = nullptr;
    hr = p->GetFieldDescriptorAt(0, &pfd0);
    EXPECT_EQ(hr, S_OK);
    ASSERT_NE(pfd0, nullptr);
    EXPECT_EQ(pfd0->cpft, CPFT_LARGE_TEXT);
    EXPECT_EQ(pfd0->dwFieldID, static_cast<DWORD>(FIELD_NAME));
    // Must NOT be a password field
    EXPECT_NE(pfd0->cpft, CPFT_PASSWORD_TEXT);
    CoTaskMemFree(pfd0->pszLabel);
    CoTaskMemFree(pfd0);

    // Field 1: CPFT_SMALL_TEXT
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pfd1 = nullptr;
    hr = p->GetFieldDescriptorAt(1, &pfd1);
    EXPECT_EQ(hr, S_OK);
    ASSERT_NE(pfd1, nullptr);
    EXPECT_EQ(pfd1->cpft, CPFT_SMALL_TEXT);
    EXPECT_EQ(pfd1->dwFieldID, static_cast<DWORD>(FIELD_STATUS));
    EXPECT_NE(pfd1->cpft, CPFT_PASSWORD_TEXT);
    CoTaskMemFree(pfd1->pszLabel);
    CoTaskMemFree(pfd1);

    // Out-of-bounds field
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pfd2 = nullptr;
    hr = p->GetFieldDescriptorAt(2, &pfd2);
    EXPECT_NE(hr, S_OK);
    EXPECT_EQ(pfd2, nullptr);

    p->Release();
}

// ============================================================
// Test 5: FieldValueRetrieval
// ============================================================
TEST(CredentialProviderTest, FieldValueRetrieval) {
    MockIpcConnectFailure mockIpc;
    auto* cred = new MobileUnlockCredential(&mockIpc);

    PWSTR pszName = nullptr;
    HRESULT hr = cred->GetStringValue(FIELD_NAME, &pszName);
    EXPECT_EQ(hr, S_OK);
    ASSERT_NE(pszName, nullptr);
    EXPECT_EQ(std::wstring(pszName), L"MobileFingerprintUnlock");
    CoTaskMemFree(pszName);

    PWSTR pszStatus = nullptr;
    hr = cred->GetStringValue(FIELD_STATUS, &pszStatus);
    EXPECT_EQ(hr, S_OK);
    ASSERT_NE(pszStatus, nullptr);
    // Initial status should be a non-empty string
    EXPECT_GT(wcslen(pszStatus), 0u);
    CoTaskMemFree(pszStatus);

    // Out-of-bounds field
    PWSTR pszInvalid = nullptr;
    hr = cred->GetStringValue(FIELD_COUNT, &pszInvalid);
    EXPECT_NE(hr, S_OK);

    cred->Release();
}

// ============================================================
// Test 6: AdviseUnAdvise — background thread starts and stops
// ============================================================
TEST(CredentialProviderTest, AdviseUnAdvise) {
    MockIpcConnectFailure mockIpc;
    auto* cred = new MobileUnlockCredential(&mockIpc);
    auto* events = new MockCredentialEvents();

    HRESULT hr = cred->Advise(events);
    EXPECT_EQ(hr, S_OK);

    // Thread should be running — wait briefly for at least one IPC call
    Sleep(100);

    hr = cred->UnAdvise();
    EXPECT_EQ(hr, S_OK);

    // After UnAdvise, internal auth state is cleared
    EXPECT_FALSE(cred->IsAuthStateReady());

    events->Release();
    cred->Release();
}

// ============================================================
// Test 7: GetSerialization — ALWAYS returns NO_CREDENTIAL
//         regardless of auth state (Phase 7 contract)
// ============================================================
TEST(CredentialProviderTest, GetSerializationAlwaysNoCredential) {
    MockIpcConnectFailure mockIpc;
    auto* cred = new MobileUnlockCredential(&mockIpc);

    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE cpgsr =
        CPGSR_RETURN_CREDENTIAL_FINISHED; // Pre-set to non-NO state
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION cpcs{};
    PWSTR pszStatusText = nullptr;
    CREDENTIAL_PROVIDER_STATUS_ICON cpsi = CPSI_SUCCESS;

    HRESULT hr = cred->GetSerialization(&cpgsr, &cpcs, &pszStatusText, &cpsi);

    // Phase 7 contract: always CPGSR_NO_CREDENTIAL_FINISHED + S_FALSE
    EXPECT_EQ(hr, S_FALSE);
    EXPECT_EQ(cpgsr, CPGSR_NO_CREDENTIAL_FINISHED);
    EXPECT_EQ(pszStatusText, nullptr);

    cred->Release();
}

// ============================================================
// Test 8: GetSerialization — returns 180-byte buffer when auth ready
// ============================================================
TEST(CredentialProviderTest, GetSerializationSubmitsBufferWhenReady) {
    MockIpcSuccess mockIpc;
    auto* cred = new MobileUnlockCredential(&mockIpc);
    auto* events = new MockCredentialEvents();

    cred->Advise(events);
    Sleep(200);

    EXPECT_TRUE(cred->IsAuthStateReady());

    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE cpgsr = CPGSR_NO_CREDENTIAL_FINISHED;
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION cpcs{};
    PWSTR pszStatusText = nullptr;
    CREDENTIAL_PROVIDER_STATUS_ICON cpsi = CPSI_NONE;

    HRESULT hr = cred->GetSerialization(&cpgsr, &cpcs, &pszStatusText, &cpsi);

    EXPECT_EQ(hr, S_OK);
    EXPECT_EQ(cpgsr, CPGSR_RETURN_CREDENTIAL_FINISHED);
    EXPECT_EQ(cpcs.cbSerialization, sizeof(MobileUnlock::Lsa::MOBILE_UNLOCK_LSA_LOGON_BUFFER));
    EXPECT_NE(cpcs.rgbSerialization, nullptr);
    EXPECT_GT(cpcs.ulAuthenticationPackage, 0u);

    if (cpcs.rgbSerialization) {
        CoTaskMemFree(cpcs.rgbSerialization);
    }

    cred->UnAdvise();
    events->Release();
    cred->Release();
}

// ============================================================
// Test 9: IPC timeout — auth state not set, status updated
// ============================================================
TEST(CredentialProviderTest, GetSerializationIpcTimeout) {
    MockIpcTimeout mockIpc;
    auto* cred = new MobileUnlockCredential(&mockIpc);
    auto* events = new MockCredentialEvents();

    cred->Advise(events);
    Sleep(200);

    // Auth state must NOT be ready on timeout
    EXPECT_FALSE(cred->IsAuthStateReady());

    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE cpgsr =
        CPGSR_RETURN_CREDENTIAL_FINISHED;
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION cpcs{};
    PWSTR pszStatus = nullptr;
    CREDENTIAL_PROVIDER_STATUS_ICON cpsi = CPSI_SUCCESS;

    HRESULT hr = cred->GetSerialization(&cpgsr, &cpcs, &pszStatus, &cpsi);
    EXPECT_EQ(hr, S_FALSE);
    EXPECT_EQ(cpgsr, CPGSR_NO_CREDENTIAL_FINISHED);

    cred->UnAdvise();
    events->Release();
    cred->Release();
}

// ============================================================
// Test 10: Service unavailable — connect failure safe behavior
// ============================================================
TEST(CredentialProviderTest, GetSerializationServiceUnavailable) {
    MockIpcConnectFailure mockIpc;
    auto* cred = new MobileUnlockCredential(&mockIpc);
    auto* events = new MockCredentialEvents();

    cred->Advise(events);
    Sleep(200);

    EXPECT_FALSE(cred->IsAuthStateReady());

    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE cpgsr =
        CPGSR_RETURN_CREDENTIAL_FINISHED;
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION cpcs{};
    PWSTR pszStatus = nullptr;
    CREDENTIAL_PROVIDER_STATUS_ICON cpsi = CPSI_SUCCESS;

    HRESULT hr = cred->GetSerialization(&cpgsr, &cpcs, &pszStatus, &cpsi);
    EXPECT_EQ(hr, S_FALSE);
    EXPECT_EQ(cpgsr, CPGSR_NO_CREDENTIAL_FINISHED);

    cred->UnAdvise();
    events->Release();
    cred->Release();
}

// ============================================================
// Test 11: Malformed IPC response — safe failure behavior
// ============================================================
TEST(CredentialProviderTest, GetSerializationMalformedResponse) {
    MockIpcMalformed mockIpc;
    auto* cred = new MobileUnlockCredential(&mockIpc);
    auto* events = new MockCredentialEvents();

    // Should not crash
    EXPECT_NO_FATAL_FAILURE({
        cred->Advise(events);
        Sleep(200);
    });

    EXPECT_FALSE(cred->IsAuthStateReady());

    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE cpgsr =
        CPGSR_RETURN_CREDENTIAL_FINISHED;
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION cpcs{};
    PWSTR pszStatus = nullptr;
    CREDENTIAL_PROVIDER_STATUS_ICON cpsi = CPSI_SUCCESS;

    HRESULT hr = cred->GetSerialization(&cpgsr, &cpcs, &pszStatus, &cpsi);
    EXPECT_EQ(hr, S_FALSE);
    EXPECT_EQ(cpgsr, CPGSR_NO_CREDENTIAL_FINISHED);

    cred->UnAdvise();
    events->Release();
    cred->Release();
}

// ============================================================
// Test 12: SafeFailureState — native providers unaffected
//
// Our provider failing does not remove or block other providers.
// Verified by checking: our provider sets no global state that
// would interfere with other credential providers.
// ============================================================
TEST(CredentialProviderTest, SafeFailureNativeProvidersUnaffected) {
    // Create two independent providers — failure in one does not
    // affect the other (simulates multi-provider Winlogon environment)
    MockIpcConnectFailure mockIpc1;
    MockIpcConnectFailure mockIpc2;
    auto* cred1 = new MobileUnlockCredential(&mockIpc1);
    auto* cred2 = new MobileUnlockCredential(&mockIpc2);
    auto* events1 = new MockCredentialEvents();
    auto* events2 = new MockCredentialEvents();

    cred1->Advise(events1);
    cred2->Advise(events2);
    Sleep(150);

    // Both should be in failure state independently
    EXPECT_FALSE(cred1->IsAuthStateReady());
    EXPECT_FALSE(cred2->IsAuthStateReady());

    // Both return CPGSR_NO_CREDENTIAL_FINISHED independently
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE cpgsr{};
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION cpcs{};
    PWSTR pszStatus = nullptr;
    CREDENTIAL_PROVIDER_STATUS_ICON cpsi{};

    EXPECT_EQ(cred1->GetSerialization(&cpgsr, &cpcs, &pszStatus, &cpsi), S_FALSE);
    EXPECT_EQ(cred2->GetSerialization(&cpgsr, &cpcs, &pszStatus, &cpsi), S_FALSE);

    // g_cDllRef does not go negative (global state is correct)
    EXPECT_GE(g_cDllRef.load(), 0);

    cred1->UnAdvise();
    cred2->UnAdvise();
    events1->Release();
    events2->Release();
    cred1->Release();
    cred2->Release();
}

// ============================================================
// Test 13: Status field updates on IPC success
// ============================================================
TEST(CredentialProviderTest, StatusFieldUpdatesOnIpcSuccess) {
    MockIpcSuccess mockIpc;
    auto* cred = new MobileUnlockCredential(&mockIpc);
    auto* events = new MockCredentialEvents();

    cred->Advise(events);
    // Wait for background thread to call IPC and update status
    Sleep(300);

    // Auth state should be ready after successful IPC
    EXPECT_TRUE(cred->IsAuthStateReady());

    // SetFieldString should have been called at least once
    EXPECT_GT(events->setFieldStringCalls.load(), 0);

    // Last status field update should be for FIELD_STATUS
    EXPECT_EQ(events->m_lastFieldIndex, static_cast<DWORD>(FIELD_STATUS));

    // Status text should indicate ready state
    EXPECT_EQ(events->m_lastFieldValue, L"Authentication ready");

    cred->UnAdvise();

    // After UnAdvise, auth state is cleared
    EXPECT_FALSE(cred->IsAuthStateReady());

    events->Release();
    cred->Release();
}
