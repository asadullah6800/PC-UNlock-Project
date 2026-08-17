// ============================================================
// MobileFingerprintUnlock — ICredentialProviderCredential
// Phase 7 — Windows Credential Provider (Test VM Only)
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

        // Send a minimal AUTH_REQUEST probe frame (JSON payload)
        const std::string payload = R"({"type":"AUTH_REQUEST","source":"CredentialProvider"})";
        std::vector<uint8_t> msg(payload.begin(), payload.end());
        if (!client.SendMessageToServer(msg)) {
            return token;
        }

        auto result = client.ReadMessageFromServer(readTimeoutMs);
        if (!result.valid || result.data.empty()) {
            return token; // Timeout or empty response
        }

        // Expect at least device ID (32 bytes) + nonce (32 bytes) = 64 bytes minimum
        if (result.data.size() < sizeof(MOBILE_UNLOCK_PHASE7_BUFFER)) {
            return token; // Malformed response
        }

        MOBILE_UNLOCK_PHASE7_BUFFER buf{};
        std::memcpy(&buf, result.data.data(),
                    sizeof(MOBILE_UNLOCK_PHASE7_BUFFER));

        // Validate magic and version
        if (buf.Magic   != PHASE7_BUFFER_MAGIC ||
            buf.Version != PHASE7_BUFFER_VERSION) {
            return token; // Malformed response
        }

        std::memcpy(token.deviceId,     buf.DeviceId,     sizeof(token.deviceId));
        std::memcpy(token.sessionNonce, buf.SessionNonce, sizeof(token.sessionNonce));
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
    m_stopThread.store(true, std::memory_order_seq_cst);
    if (m_hStopEvent) SetEvent(m_hStopEvent);
    if (m_hStatusThread) {
        WaitForSingleObject(m_hStatusThread, 6000);
        CloseHandle(m_hStatusThread);
        m_hStatusThread = nullptr;
    }
    if (m_hStopEvent) {
        CloseHandle(m_hStopEvent);
        m_hStopEvent = nullptr;
    }

    // Securely wipe internal auth state
    ClearInternalAuthState();

    if (m_pCredentialEvents) {
        m_pCredentialEvents->Release();
        m_pCredentialEvents = nullptr;
    }

    if (m_ownsIpcFactory && m_pIpcFactory) {
        delete m_pIpcFactory;
        m_pIpcFactory = nullptr;
    }

    DeleteCriticalSection(&m_stateLock);
    g_cDllRef.fetch_sub(1, std::memory_order_relaxed);
}

// ============================================================
// IUnknown
// ============================================================

IFACEMETHODIMP MobileUnlockCredential::QueryInterface(REFIID riid, void** ppv) {
    if (!ppv) return E_POINTER;
    if (riid == IID_IUnknown || riid == IID_ICredentialProviderCredential) {
        *ppv = static_cast<ICredentialProviderCredential*>(this);
        AddRef();
        return S_OK;
    }
    *ppv = nullptr;
    return E_NOINTERFACE;
}

IFACEMETHODIMP_(ULONG) MobileUnlockCredential::AddRef() {
    return InterlockedIncrement(&m_cRef);
}

IFACEMETHODIMP_(ULONG) MobileUnlockCredential::Release() {
    LONG cRef = InterlockedDecrement(&m_cRef);
    if (cRef == 0) delete this;
    return cRef;
}

// ============================================================
// ICredentialProviderCredential::Advise
//
// Called by Winlogon when the credential is first enumerated.
// Stores the events pointer and starts the background status thread.
// ============================================================

IFACEMETHODIMP MobileUnlockCredential::Advise(
    ICredentialProviderCredentialEvents* pcpce)
{
    if (m_pCredentialEvents) {
        m_pCredentialEvents->Release();
    }
    m_pCredentialEvents = pcpce;
    if (m_pCredentialEvents) {
        m_pCredentialEvents->AddRef();
    }

    // Create stop event and start background status thread
    if (!m_hStopEvent) {
        m_hStopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!m_hStopEvent) return E_OUTOFMEMORY;
    } else {
        ResetEvent(m_hStopEvent);
    }

    m_stopThread.store(false, std::memory_order_seq_cst);
    m_authStateReady.store(false, std::memory_order_seq_cst);

    if (m_hStatusThread) {
        CloseHandle(m_hStatusThread);
        m_hStatusThread = nullptr;
    }

    m_hStatusThread = CreateThread(nullptr, 0,
        StatusThreadProc, this, 0, nullptr);
    if (!m_hStatusThread) {
        return E_FAIL;
    }

    return S_OK;
}

// ============================================================
// ICredentialProviderCredential::UnAdvise
//
// Called when the tile is being discarded.
// Stops the background thread and clears internal state securely.
// ============================================================

IFACEMETHODIMP MobileUnlockCredential::UnAdvise() {
    // Signal the background thread to stop
    m_stopThread.store(true, std::memory_order_seq_cst);
    if (m_hStopEvent) SetEvent(m_hStopEvent);

    if (m_hStatusThread) {
        WaitForSingleObject(m_hStatusThread, 6000);
        CloseHandle(m_hStatusThread);
        m_hStatusThread = nullptr;
    }

    // Securely wipe internal auth state on deselect
    ClearInternalAuthState();

    if (m_pCredentialEvents) {
        m_pCredentialEvents->Release();
        m_pCredentialEvents = nullptr;
    }

    return S_OK;
}

// ============================================================
// Background Status Thread
//
// Runs while the tile is active (Advise..UnAdvise).
// Polls MobileUnlockService via IPC.
// Updates FIELD_STATUS via ICredentialProviderCredentialEvents.
// Stores result in m_internalAuthBuffer ONLY (never to Winlogon).
// ============================================================

DWORD WINAPI MobileUnlockCredential::StatusThreadProc(LPVOID lpParam) {
    auto* pThis = static_cast<MobileUnlockCredential*>(lpParam);
    pThis->StatusThreadFunc();
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
            // Store internal buffer — NEVER presented to Winlogon
            EnterCriticalSection(&m_stateLock);
            SecureZeroMemory(&m_internalAuthBuffer, sizeof(m_internalAuthBuffer));
            m_internalAuthBuffer.Magic   = PHASE7_BUFFER_MAGIC;
            m_internalAuthBuffer.Version = PHASE7_BUFFER_VERSION;
            std::memcpy(m_internalAuthBuffer.DeviceId,
                        token.deviceId, sizeof(token.deviceId));
            std::memcpy(m_internalAuthBuffer.SessionNonce,
                        token.sessionNonce, sizeof(token.sessionNonce));
            m_internalAuthBuffer.Reserved = 0;
            m_authStateReady.store(true, std::memory_order_release);
            LeaveCriticalSection(&m_stateLock);

            UpdateStatusField(L"Authentication ready");
        } else {
            // Distinguish service unreachable vs timeout by checking if
            // we got any response (FetchAuthState returns !valid for both).
            // Both are safe failure states — update status accordingly.
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
// *** PHASE 7 — NO CREDENTIAL SERIALIZATION ***
//
// There is no custom LSA authentication package in Phase 7.
// There is no legitimate authentication-package serialization contract.
// We do NOT invent an authentication package ID.
// We do NOT submit MOBILE_UNLOCK_PHASE7_BUFFER to Winlogon.
// We do NOT return CPGSR_RETURN_CREDENTIAL_FINISHED.
//
// Phase 8 will introduce the LSA authentication package.
// Phase 9A will experimentally determine:
//   - the correct authentication package ID
//   - the exact serialization format for the LSA package
//   - the required SECURITY_LOGON_TYPE
//   - LSA_TOKEN_INFORMATION structure
//   - auto-submit vs. tile-click behavior
//
// Until those contracts are established, this method always
// returns CPGSR_NO_CREDENTIAL_FINISHED + S_FALSE.
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

    // Phase 7: No authentication package exists. No serialization submitted.
    *pcpgsr                  = CPGSR_NO_CREDENTIAL_FINISHED;
    pcpcs->ulAuthenticationPackage = 0;  // Not used — no package
    pcpcs->cbSerialization         = 0;
    pcpcs->rgbSerialization        = nullptr;
    *ppwszOptionalStatusText       = nullptr;
    *pcpsiOptionalStatusIcon       = CPSI_NONE;

    return S_FALSE; // Inform Winlogon: no credential submitted this round
}

// ============================================================
// ICredentialProviderCredential::ReportResult
//
// Phase 7: Not applicable — we never submit a credential.
// No-op implementation.
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
