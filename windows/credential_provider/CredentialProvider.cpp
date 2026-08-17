// ============================================================
// MobileFingerprintUnlock — ICredentialProvider Implementation
// Phase 7 — Windows Credential Provider (Test VM Only)
// ============================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include "CredentialProviderCompat.h"
#include <new>
#include <cstring>

#include "CredentialProvider.h"
#include "MobileUnlockCredential.h"

// External DLL reference counter (defined in dllmain.cpp)
extern std::atomic<LONG> g_cDllRef;

namespace MobileUnlock::CredentialProvider {

static const WCHAR s_szDisplayName[] = L"Display Name";
static const WCHAR s_szStatus[]      = L"Status";

static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_rgFieldDescriptors[] = {
    { FIELD_NAME,   CPFT_LARGE_TEXT, const_cast<LPWSTR>(s_szDisplayName), CPFG_CREDENTIAL_PROVIDER_LABEL },
    { FIELD_STATUS, CPFT_SMALL_TEXT, const_cast<LPWSTR>(s_szStatus),      CPFG_CREDENTIAL_PROVIDER_LOGO  },
};
static_assert(sizeof(s_rgFieldDescriptors)/sizeof(s_rgFieldDescriptors[0]) == FIELD_COUNT,
    "Field descriptor count mismatch");

// ============================================================
// Construction / Destruction
// ============================================================

CredentialProvider::CredentialProvider()
    : m_cRef(1)
    , m_cpus(CPUS_INVALID)
    , m_usageScenarioSet(false)
    , m_pCredential(nullptr)
    , m_pCredentialProviderEvents(nullptr)
    , m_upAdviseContext(0)
{
    g_cDllRef.fetch_add(1, std::memory_order_relaxed);
}

CredentialProvider::~CredentialProvider() {
    if (m_pCredential) {
        m_pCredential->Release();
        m_pCredential = nullptr;
    }
    if (m_pCredentialProviderEvents) {
        m_pCredentialProviderEvents->Release();
        m_pCredentialProviderEvents = nullptr;
    }
    g_cDllRef.fetch_sub(1, std::memory_order_relaxed);
}

// ============================================================
// IUnknown
// ============================================================

IFACEMETHODIMP CredentialProvider::QueryInterface(REFIID riid, void** ppv) {
    if (!ppv) return E_POINTER;
    if (riid == IID_IUnknown || riid == IID_ICredentialProvider) {
        *ppv = static_cast<ICredentialProvider*>(this);
        AddRef();
        return S_OK;
    }
    *ppv = nullptr;
    return E_NOINTERFACE;
}

IFACEMETHODIMP_(ULONG) CredentialProvider::AddRef() {
    return InterlockedIncrement(&m_cRef);
}

IFACEMETHODIMP_(ULONG) CredentialProvider::Release() {
    LONG cRef = InterlockedDecrement(&m_cRef);
    if (cRef == 0) delete this;
    return cRef;
}

// ============================================================
// ICredentialProvider::SetUsageScenario
//
// Accept only CPUS_LOGON and CPUS_UNLOCK_WORKSTATION.
// Reject all other scenarios (CPUS_CREDUI, CPUS_CHANGE_PASSWORD,
// CPUS_PLAP, etc.) with E_NOTIMPL.
// ============================================================

IFACEMETHODIMP CredentialProvider::SetUsageScenario(
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD /*dwFlags*/)
{
    switch (cpus) {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:
        m_cpus = cpus;
        m_usageScenarioSet = true;

        // Create the single credential tile if not yet created.
        if (!m_pCredential) {
            m_pCredential = new (std::nothrow) MobileUnlockCredential();
            if (!m_pCredential) return E_OUTOFMEMORY;
        }
        return S_OK;

    default:
        // Unsupported scenario — do not enumerate any credentials.
        m_usageScenarioSet = false;
        return E_NOTIMPL;
    }
}

// ============================================================
// ICredentialProvider::SetSerialization
//
// Called by Winlogon to pre-fill credentials (e.g., auto-logon).
// Phase 7: not used. Return S_OK safely.
// ============================================================

IFACEMETHODIMP CredentialProvider::SetSerialization(
    const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* /*pcpcs*/)
{
    return S_OK;
}

// ============================================================
// ICredentialProvider::Advise / UnAdvise
// ============================================================

IFACEMETHODIMP CredentialProvider::Advise(
    ICredentialProviderEvents* pcpe, UINT_PTR upAdviseContext)
{
    if (m_pCredentialProviderEvents) {
        m_pCredentialProviderEvents->Release();
    }
    m_pCredentialProviderEvents = pcpe;
    if (m_pCredentialProviderEvents) {
        m_pCredentialProviderEvents->AddRef();
    }
    m_upAdviseContext = upAdviseContext;
    return S_OK;
}

IFACEMETHODIMP CredentialProvider::UnAdvise() {
    if (m_pCredentialProviderEvents) {
        m_pCredentialProviderEvents->Release();
        m_pCredentialProviderEvents = nullptr;
    }
    m_upAdviseContext = 0;
    return S_OK;
}

// ============================================================
// ICredentialProvider::GetFieldDescriptorCount
// ============================================================

IFACEMETHODIMP CredentialProvider::GetFieldDescriptorCount(DWORD* pdwCount) {
    if (!pdwCount) return E_POINTER;
    *pdwCount = FIELD_COUNT;
    return S_OK;
}

// ============================================================
// ICredentialProvider::GetFieldDescriptorAt
// ============================================================

IFACEMETHODIMP CredentialProvider::GetFieldDescriptorAt(
    DWORD dwIndex, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd)
{
    if (!ppcpfd) return E_POINTER;
    if (dwIndex >= FIELD_COUNT) return E_INVALIDARG;

    // CoTaskMemAlloc the descriptor — caller frees it.
    auto* pfd = static_cast<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*>(
        CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR)));
    if (!pfd) return E_OUTOFMEMORY;

    *pfd = s_rgFieldDescriptors[dwIndex];

    // Deep-copy the label string into CoTaskMem
    if (s_rgFieldDescriptors[dwIndex].pszLabel) {
        SIZE_T cbLabel = (wcslen(s_rgFieldDescriptors[dwIndex].pszLabel) + 1) * sizeof(WCHAR);
        pfd->pszLabel = static_cast<LPWSTR>(CoTaskMemAlloc(cbLabel));
        if (!pfd->pszLabel) {
            CoTaskMemFree(pfd);
            return E_OUTOFMEMORY;
        }
        memcpy(pfd->pszLabel, s_rgFieldDescriptors[dwIndex].pszLabel, cbLabel);
    }

    *ppcpfd = pfd;
    return S_OK;
}

// ============================================================
// ICredentialProvider::GetCredentialCount
// ============================================================

IFACEMETHODIMP CredentialProvider::GetCredentialCount(
    DWORD* pdwCount, DWORD* pdwDefault, BOOL* pbAutoLogonWithDefault)
{
    if (!pdwCount || !pdwDefault || !pbAutoLogonWithDefault) return E_POINTER;

    if (!m_usageScenarioSet || !m_pCredential) {
        *pdwCount = 0;
        *pdwDefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
        *pbAutoLogonWithDefault = FALSE;
        return S_OK;
    }

    *pdwCount = 1;
    *pdwDefault = CREDENTIAL_PROVIDER_NO_DEFAULT; // No auto-logon
    *pbAutoLogonWithDefault = FALSE;              // Never auto-submit
    return S_OK;
}

// ============================================================
// ICredentialProvider::GetCredentialAt
// ============================================================

IFACEMETHODIMP CredentialProvider::GetCredentialAt(
    DWORD dwIndex, ICredentialProviderCredential** ppcpc)
{
    if (!ppcpc) return E_POINTER;
    if (dwIndex != 0 || !m_pCredential) return E_INVALIDARG;

    *ppcpc = m_pCredential;
    m_pCredential->AddRef();
    return S_OK;
}

} // namespace MobileUnlock::CredentialProvider
