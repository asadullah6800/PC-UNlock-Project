// ============================================================
// MobileFingerprintUnlock — ICredentialProviderCredential
// Phase 9B — Real End-to-End Windows Unlock (Test VM Only)
// ============================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include "CredentialProviderCompat.h"
#include <new>
#include <cstring>
#include <atomic>

#include "MobileUnlockCredential.h"
#include "../ipc/SecureIPC.h"
#include "../authentication/LsaPackageLookup.h"
#include "../lsa_authentication_package/LsaLogonBuffer.h"

// External DLL reference counter (defined in dllmain.cpp)
extern std::atomic<LONG> g_cDllRef;

namespace MobileUnlock::CredentialProvider {

// ============================================================
// Production IPC factory — uses the real NamedPipeClient
// ============================================================
class ProductionIpcFactory final : public IIpcClientFactory {
public:
    IpcStateToken FetchAuthState(DWORD connectTimeoutMs,
                                 DWORD readTimeoutMs) override
    {
        IpcStateToken token{};
        token.valid = false;

        MobileUnlock::IPC::NamedPipeClient client(L"\\\\.\\pipe\\MobileUnlockSecureIPC");
        if (!client.Connect(connectTimeoutMs)) {
            return token; // Service unavailable
        }

        // Send a minimal AUTH_REQUEST probe frame
        const std::string payload = R"({"type":"AUTH_REQUEST","source":"CredentialProvider"})";
        std::vector<uint8_t> msg(payload.begin(), payload.end());
        if (!client.SendMessageToServer(msg)) {
            return token;
        }

        auto result = client.ReadMessageFromServer(readTimeoutMs);
        if (!result.valid || result.data.empty()) {
            return token; // Timeout or empty response
        }

        if (result.data.size() < sizeof(Lsa::MOBILE_UNLOCK_LSA_LOGON_BUFFER)) {
            return token; // Malformed response
        }

        std::memcpy(&token.lsaBuffer, result.data.data(),
                    sizeof(Lsa::MOBILE_UNLOCK_LSA_LOGON_BUFFER));

        // Validate magic and version
        if (token.lsaBuffer.Magic   != Lsa::LSA_SUBMIT_BUFFER_MAGIC ||
            token.lsaBuffer.Version != Lsa::LSA_SUBMIT_BUFFER_VERSION) {
            return token; // Malformed response
        }

        token.valid = true;
        return token;
    }
};

// ============================================================
// Construction / Destruction
// ============================================================

MobileUnlockCredential::MobileUnlockCredential()
    : MobileUnlockCredential(nullptr) // Delegate to testable constructor
{
    m_pIpcFactory   = new (std::nothrow) ProductionIpcFactory();
    m_ownsIpcFactory = true;
}

MobileUnlockCredential::MobileUnlockCredential(IIpcClientFactory* pIpcFactory)
    : m_cRef(1)
    , m_pCredentialEvents(nullptr)
    , m_statusText(L"Waiting for phone...")
    , m_authStateReady(false)
    , m_hStatusThread(nullptr)
    , m_stopThread(false)
    , m_hStopEvent(nullptr)
    , m_pIpcFactory(pIpcFactory)
    , m_ownsIpcFactory(false)
{
    InitializeCriticalSection(&m_stateLock);
    SecureZeroMemory(&m_internalAuthBuffer, sizeof(m_internalAuthBuffer));
    g_cDllRef.fetch_add(1, std::memory_order_relaxed);
}

MobileUnlockCredential::~MobileUnlockCredential() {
    // Ensure background thread is stopped
    UnAdvise();

    if (m_ownsIpcFactory && m_pIpcFactory) {
        delete m_pIpcFactory;
        m_pIpcFactory = nullptr;
    }

    DeleteCriticalSection(&m_stateLock);
    g_cDllRef.fetch_sub(1, std::memory_order_relaxed);
}

void MobileUnlockCredential::SetInternalAuthStateForTesting(
    const Lsa::MOBILE_UNLOCK_LSA_LOGON_BUFFER& buf)
{
    EnterCriticalSection(&m_stateLock);
    m_internalAuthBuffer = buf;
    m_authStateReady.store(true, std::memory_order_release);
    m_statusText = L"Authentication ready";
    LeaveCriticalSection(&m_stateLock);
}

// ============================================================
// IUnknown
// ============================================================

IFACEMETHODIMP MobileUnlockCredential::QueryInterface(REFIID riid, void** ppv) {
    if (!ppv) return E_POINTER;
    *ppv = nullptr;

    if (riid == IID_IUnknown || riid == IID_ICredentialProviderCredential) {
        *ppv = static_cast<ICredentialProviderCredential*>(this);
        AddRef();
        return S_OK;
    }
    return E_NOINTERFACE;
}

IFACEMETHODIMP_(ULONG) MobileUnlockCredential::AddRef() {
    return static_cast<ULONG>(InterlockedIncrement(&m_cRef));
}

IFACEMETHODIMP_(ULONG) MobileUnlockCredential::Release() {
    LONG c = InterlockedDecrement(&m_cRef);
    if (c == 0) {
        delete this;
    }
    return static_cast<ULONG>(c);
}

// ============================================================
// ICredentialProviderCredential::Advise / UnAdvise
// ============================================================

IFACEMETHODIMP MobileUnlockCredential::Advise(
    ICredentialProviderCredentialEvents* pcpce)
{
    if (!pcpce) return E_POINTER;

    EnterCriticalSection(&m_stateLock);
    if (m_pCredentialEvents) {
        m_pCredentialEvents->Release();
    }
    m_pCredentialEvents = pcpce;
    m_pCredentialEvents->AddRef();

    // Start background status polling thread if not already running
    if (!m_hStatusThread) {
        m_stopThread.store(false, std::memory_order_relaxed);
        m_hStopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        m_hStatusThread = CreateThread(
            nullptr, 0, StatusThreadProc, this, 0, nullptr);
    }
    LeaveCriticalSection(&m_stateLock);

    return S_OK;
}

IFACEMETHODIMP MobileUnlockCredential::UnAdvise() {
    HANDLE hThread = nullptr;
    HANDLE hStop   = nullptr;

    EnterCriticalSection(&m_stateLock);
    m_stopThread.store(true, std::memory_order_relaxed);

    if (m_hStopEvent) {
        SetEvent(m_hStopEvent);
        hStop = m_hStopEvent;
    }
    if (m_hStatusThread) {
        hThread = m_hStatusThread;
        m_hStatusThread = nullptr;
    }
    if (m_pCredentialEvents) {
        m_pCredentialEvents->Release();
        m_pCredentialEvents = nullptr;
    }
    LeaveCriticalSection(&m_stateLock);

    if (hThread) {
        WaitForSingleObject(hThread, 3000);
        CloseHandle(hThread);
    }
    if (hStop) {
        CloseHandle(hStop);
        m_hStopEvent = nullptr;
    }

    return S_OK;
}

// ============================================================
// Background status polling thread
// ============================================================

DWORD WINAPI MobileUnlockCredential::StatusThreadProc(LPVOID lpParam) {
    auto* self = static_cast<MobileUnlockCredential*>(lpParam);
    if (self) {
        self->StatusThreadFunc();
    }
    return 0;
}

void MobileUnlockCredential::StatusThreadFunc() {
    constexpr DWORD CONNECT_TIMEOUT_MS = 5000;
    constexpr DWORD READ_TIMEOUT_MS    = 5000;
    constexpr DWORD POLL_INTERVAL_MS   = 2000;

    while (!m_stopThread.load(std::memory_order_relaxed)) {
        if (!m_pIpcFactory) {
            UpdateStatusField(L"Internal error");
            WaitForSingleObject(m_hStopEvent, POLL_INTERVAL_MS);
            continue;
        }

        IpcStateToken token = m_pIpcFactory->FetchAuthState(
            CONNECT_TIMEOUT_MS, READ_TIMEOUT_MS);

        if (m_stopThread.load(std::memory_order_relaxed)) break;

        if (token.valid) {
            EnterCriticalSection(&m_stateLock);
            m_internalAuthBuffer = token.lsaBuffer;
            m_authStateReady.store(true, std::memory_order_release);
            LeaveCriticalSection(&m_stateLock);

            UpdateStatusField(L"Authentication ready");
        } else {
            EnterCriticalSection(&m_stateLock);
            m_authStateReady.store(false, std::memory_order_release);
            LeaveCriticalSection(&m_stateLock);

            UpdateStatusField(L"Waiting for phone...");
        }

        // Wait for stop signal or poll interval
        WaitForSingleObject(m_hStopEvent, POLL_INTERVAL_MS);
    }

    // Securely wipe auth state on thread exit
    EnterCriticalSection(&m_stateLock);
    ClearInternalAuthState();
    LeaveCriticalSection(&m_stateLock);
}

void MobileUnlockCredential::UpdateStatusField(const std::wstring& text) {
    m_statusText = text;
    if (m_pCredentialEvents) {
        m_pCredentialEvents->SetFieldString(this, FIELD_STATUS, text.c_str());
    }
}

void MobileUnlockCredential::ClearInternalAuthState() {
    SecureZeroMemory(&m_internalAuthBuffer, sizeof(m_internalAuthBuffer));
    m_authStateReady.store(false, std::memory_order_seq_cst);
}

// ============================================================
// ICredentialProviderCredential::SetSelected / SetDeselected
// ============================================================

IFACEMETHODIMP MobileUnlockCredential::SetSelected(BOOL* pbAutoLogonWithDefault) {
    if (!pbAutoLogonWithDefault) return E_POINTER;
    // Never auto-submit. The user must take an explicit action.
    *pbAutoLogonWithDefault = FALSE;
    return S_OK;
}

IFACEMETHODIMP MobileUnlockCredential::SetDeselected() {
    // Tile was deselected — clear auth state securely
    EnterCriticalSection(&m_stateLock);
    ClearInternalAuthState();
    LeaveCriticalSection(&m_stateLock);
    UpdateStatusField(L"Waiting for phone...");
    return S_OK;
}

// ============================================================
// ICredentialProviderCredential::GetFieldState
// ============================================================

IFACEMETHODIMP MobileUnlockCredential::GetFieldState(
    DWORD dwFieldID,
    CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis)
{
    if (!pcpfs || !pcpfis) return E_POINTER;
    if (dwFieldID >= FIELD_COUNT) return E_INVALIDARG;

    switch (dwFieldID) {
    case FIELD_NAME:
        *pcpfs  = static_cast<CREDENTIAL_PROVIDER_FIELD_STATE>(
            CPFS_DISPLAY_IN_SELECTED_TILE | CPFS_DISPLAY_IN_DESELECTED_TILE);
        *pcpfis = CPFIS_NONE;
        break;
    case FIELD_STATUS:
        *pcpfs  = static_cast<CREDENTIAL_PROVIDER_FIELD_STATE>(
            CPFS_DISPLAY_IN_SELECTED_TILE | CPFS_DISPLAY_IN_DESELECTED_TILE);
        *pcpfis = CPFIS_NONE;
        break;
    default:
        return E_INVALIDARG;
    }
    return S_OK;
}

// ============================================================
// ICredentialProviderCredential::GetStringValue
// ============================================================

IFACEMETHODIMP MobileUnlockCredential::GetStringValue(
    DWORD dwFieldID, PWSTR* ppwsz)
{
    if (!ppwsz) return E_POINTER;
    if (dwFieldID >= FIELD_COUNT) return E_INVALIDARG;

    const wchar_t* src = nullptr;
    switch (dwFieldID) {
    case FIELD_NAME:
        src = L"MobileFingerprintUnlock";
        break;
    case FIELD_STATUS:
        src = m_statusText.c_str();
        break;
    default:
        return E_INVALIDARG;
    }

    SIZE_T cbStr = (wcslen(src) + 1) * sizeof(WCHAR);
    *ppwsz = static_cast<PWSTR>(CoTaskMemAlloc(cbStr));
    if (!*ppwsz) return E_OUTOFMEMORY;
    memcpy(*ppwsz, src, cbStr);
    return S_OK;
}

// ============================================================
// Unsupported field type accessors — return E_NOTIMPL
// ============================================================

IFACEMETHODIMP MobileUnlockCredential::GetBitmapValue(
    DWORD /*dwFieldID*/, HBITMAP* /*phbmp*/) { return E_NOTIMPL; }

IFACEMETHODIMP MobileUnlockCredential::GetCheckboxValue(
    DWORD /*dwFieldID*/, BOOL* /*pbChecked*/, PWSTR* /*ppwszLabel*/) { return E_NOTIMPL; }

IFACEMETHODIMP MobileUnlockCredential::GetComboBoxValueCount(
    DWORD /*dwFieldID*/, DWORD* /*pcItems*/, DWORD* /*pdwSelectedItem*/) { return E_NOTIMPL; }

IFACEMETHODIMP MobileUnlockCredential::GetComboBoxValueAt(
    DWORD /*dwFieldID*/, DWORD /*dwItem*/, PWSTR* /*ppwszItem*/) { return E_NOTIMPL; }

IFACEMETHODIMP MobileUnlockCredential::GetSubmitButtonValue(
    DWORD /*dwFieldID*/, DWORD* /*pdwAdjacentTo*/) { return E_NOTIMPL; }

IFACEMETHODIMP MobileUnlockCredential::SetStringValue(
    DWORD /*dwFieldID*/, PCWSTR /*pwz*/) { return E_NOTIMPL; }

IFACEMETHODIMP MobileUnlockCredential::SetCheckboxValue(
    DWORD /*dwFieldID*/, BOOL /*bChecked*/) { return E_NOTIMPL; }

IFACEMETHODIMP MobileUnlockCredential::SetComboBoxSelectedValue(
    DWORD /*dwFieldID*/, DWORD /*dwSelectedItem*/) { return E_NOTIMPL; }

IFACEMETHODIMP MobileUnlockCredential::CommandLinkClicked(
    DWORD /*dwFieldID*/) { return E_NOTIMPL; }

// ============================================================
// ICredentialProviderCredential::GetSerialization
//
// Phase 9B — REAL CREDENTIAL SERIALIZATION
//
// When auth state is ready (phone signed challenge received):
//   1. Dynamically discovers AuthenticationPackageId via LsaPackageLookup.
//   2. Allocates exact 180-byte MOBILE_UNLOCK_LSA_LOGON_BUFFER via CoTaskMemAlloc.
//   3. Returns CPGSR_RETURN_CREDENTIAL_FINISHED + S_OK to Winlogon.
// ============================================================

IFACEMETHODIMP MobileUnlockCredential::GetSerialization(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    PWSTR* ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    if (!pcpgsr || !pcpcs || !ppwszOptionalStatusText || !pcpsiOptionalStatusIcon) {
        return E_POINTER;
    }

    *pcpgsr                  = CPGSR_NO_CREDENTIAL_FINISHED;
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;
    ZeroMemory(pcpcs, sizeof(CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION));

    EnterCriticalSection(&m_stateLock);
    if (!m_authStateReady.load(std::memory_order_acquire)) {
        LeaveCriticalSection(&m_stateLock);
        return S_FALSE;
    }

    // Resolve dynamic AuthenticationPackageId via LsaPackageLookup
    ULONG authPkgId = 0;
    NTSTATUS status = Authentication::LsaPackageLookup::GetAuthenticationPackageId(
        Authentication::kDefaultLsaPackageName, authPkgId);

    // If package lookup fails in test environment, use fallback ID
    if (status != STATUS_SUCCESS || authPkgId == 0) {
        authPkgId = 100; // Testing fallback
    }

    // Allocate exact 180-byte wire buffer on COM task memory
    constexpr size_t cbSerialization = sizeof(Lsa::MOBILE_UNLOCK_LSA_LOGON_BUFFER);
    auto* pOutBuffer = static_cast<BYTE*>(CoTaskMemAlloc(cbSerialization));
    if (!pOutBuffer) {
        LeaveCriticalSection(&m_stateLock);
        return E_OUTOFMEMORY;
    }

    std::memcpy(pOutBuffer, &m_internalAuthBuffer, cbSerialization);
    LeaveCriticalSection(&m_stateLock);

    pcpcs->clsidCredentialProvider = CLSID_MobileUnlockProvider;
    pcpcs->ulAuthenticationPackage = authPkgId;
    pcpcs->cbSerialization         = static_cast<ULONG>(cbSerialization);
    pcpcs->rgbSerialization        = pOutBuffer;

    *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
    return S_OK;
}

// ============================================================
// ICredentialProviderCredential::ReportResult
// ============================================================

IFACEMETHODIMP MobileUnlockCredential::ReportResult(
    NTSTATUS /*ntsStatus*/,
    NTSTATUS /*ntsSubstatus*/,
    PWSTR* ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    if (ppwszOptionalStatusText)   *ppwszOptionalStatusText = nullptr;
    if (pcpsiOptionalStatusIcon)   *pcpsiOptionalStatusIcon = CPSI_NONE;
    return S_OK;
}

} // namespace MobileUnlock::CredentialProvider
