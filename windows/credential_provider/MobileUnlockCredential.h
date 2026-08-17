#pragma once

// ============================================================
// MobileFingerprintUnlock — ICredentialProviderCredential
// Phase 9B — Real End-to-End Windows Unlock (Test VM Only)
// ============================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include "CredentialProviderCompat.h"
#include <unknwn.h>

#include <atomic>
#include <string>
#include <cstdint>
#include <cstring>

#include "ProviderGuid.h"
#include "../lsa_authentication_package/LsaLogonBuffer.h"

namespace MobileUnlock::CredentialProvider {

// ============================================================
// IIpcClientFactory
//
// Dependency-injection interface for IPC client creation.
// In production: creates a real NamedPipeClient.
// In tests:      creates a mock client returning controlled results.
// ============================================================
struct IpcStateToken {
    bool                                valid;
    Lsa::MOBILE_UNLOCK_LSA_LOGON_BUFFER lsaBuffer;
};

class IIpcClientFactory {
public:
    virtual ~IIpcClientFactory() = default;

    // Attempt to connect and retrieve an auth state token from MobileUnlockService.
    // connectTimeoutMs: maximum time to wait for pipe connection.
    // readTimeoutMs:    maximum time to wait for IPC response.
    // Returns IpcStateToken with valid=true on success, valid=false on any failure.
    virtual IpcStateToken FetchAuthState(DWORD connectTimeoutMs,
                                         DWORD readTimeoutMs) = 0;
};

// ============================================================
// MobileUnlockCredential
//
// Implements ICredentialProviderCredential — the tile shown to
// the user at the Winlogon logon/lock screen.
//
// Tile fields:
//   FIELD_NAME   (CPFT_LARGE_TEXT): "MobileFingerprintUnlock"
//   FIELD_STATUS (CPFT_SMALL_TEXT): Dynamic status string
//
// Background status thread:
//   Started in Advise(). Stopped in UnAdvise().
//   Polls MobileUnlockService via IPC (5-second timeout per attempt).
//   Updates FIELD_STATUS via ICredentialProviderCredentialEvents.
//   Stores received MOBILE_UNLOCK_LSA_LOGON_BUFFER internally.
//
// GetSerialization():
//   Phase 9B: Resolves dynamic AuthenticationPackageId and returns
//   CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION containing the
//   180-byte MOBILE_UNLOCK_LSA_LOGON_BUFFER when auth state is ready.
// ============================================================
class MobileUnlockCredential final : public ICredentialProviderCredential {
public:
    // Production constructor — uses real NamedPipeClient.
    MobileUnlockCredential();

    // Testable constructor — accepts injected IPC factory.
    explicit MobileUnlockCredential(IIpcClientFactory* pIpcFactory);

    // IUnknown
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override;
    IFACEMETHODIMP_(ULONG) AddRef() override;
    IFACEMETHODIMP_(ULONG) Release() override;

    // ICredentialProviderCredential
    IFACEMETHODIMP Advise(
        ICredentialProviderCredentialEvents* pcpce) override;

    IFACEMETHODIMP UnAdvise() override;

    IFACEMETHODIMP SetSelected(BOOL* pbAutoLogonWithDefault) override;

    IFACEMETHODIMP SetDeselected() override;

    IFACEMETHODIMP GetFieldState(
        DWORD dwFieldID,
        CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
        CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis) override;

    IFACEMETHODIMP GetStringValue(
        DWORD dwFieldID,
        PWSTR* ppwsz) override;

    IFACEMETHODIMP GetBitmapValue(
        DWORD dwFieldID,
        HBITMAP* phbmp) override;

    IFACEMETHODIMP GetCheckboxValue(
        DWORD dwFieldID,
        BOOL* pbChecked,
        PWSTR* ppwszLabel) override;

    IFACEMETHODIMP GetComboBoxValueCount(
        DWORD dwFieldID,
        DWORD* pcItems,
        DWORD* pdwSelectedItem) override;

    IFACEMETHODIMP GetComboBoxValueAt(
        DWORD dwFieldID,
        DWORD dwItem,
        PWSTR* ppwszItem) override;

    IFACEMETHODIMP GetSubmitButtonValue(
        DWORD dwFieldID,
        DWORD* pdwAdjacentTo) override;

    IFACEMETHODIMP SetStringValue(
        DWORD dwFieldID,
        PCWSTR pwz) override;

    IFACEMETHODIMP SetCheckboxValue(
        DWORD dwFieldID,
        BOOL bChecked) override;

    IFACEMETHODIMP SetComboBoxSelectedValue(
        DWORD dwFieldID,
        DWORD dwSelectedItem) override;

    IFACEMETHODIMP CommandLinkClicked(DWORD dwFieldID) override;

    // --------------------------------------------------------
    // GetSerialization
    //
    // Returns CPGSR_RETURN_CREDENTIAL_FINISHED when auth is ready,
    // populating CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION with
    // the 180-byte MOBILE_UNLOCK_LSA_LOGON_BUFFER.
    // --------------------------------------------------------
    IFACEMETHODIMP GetSerialization(
        CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
        PWSTR* ppwszOptionalStatusText,
        CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon) override;

    IFACEMETHODIMP ReportResult(
        NTSTATUS ntsStatus,
        NTSTATUS ntsSubstatus,
        PWSTR* ppwszOptionalStatusText,
        CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon) override;

    // --------------------------------------------------------
    // Testing Hooks
    // --------------------------------------------------------
    bool IsAuthStateReady() const { return m_authStateReady.load(); }
    const std::wstring& GetCurrentStatus() const { return m_statusText; }
    void SetInternalAuthStateForTesting(const Lsa::MOBILE_UNLOCK_LSA_LOGON_BUFFER& buf);

private:
    ~MobileUnlockCredential();

    void StatusThreadFunc();
    static DWORD WINAPI StatusThreadProc(LPVOID lpParam);

    void UpdateStatusField(const std::wstring& text);
    void ClearInternalAuthState();

    LONG                                       m_cRef;
    ICredentialProviderCredentialEvents*       m_pCredentialEvents;
    std::wstring                               m_statusText;

    // Internal auth state (180-byte LSA submission buffer)
    CRITICAL_SECTION                           m_stateLock;
    std::atomic<bool>                          m_authStateReady;
    Lsa::MOBILE_UNLOCK_LSA_LOGON_BUFFER        m_internalAuthBuffer;

    // Background thread management
    HANDLE                                     m_hStatusThread;
    std::atomic<bool>                          m_stopThread;
    HANDLE                                     m_hStopEvent;

    // IPC factory (injected for tests; owned externally)
    IIpcClientFactory*                         m_pIpcFactory;
    bool                                       m_ownsIpcFactory;
};

} // namespace MobileUnlock::CredentialProvider
