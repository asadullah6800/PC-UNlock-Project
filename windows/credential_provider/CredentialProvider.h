#pragma once

// ============================================================
// MobileFingerprintUnlock — ICredentialProvider implementation
// Phase 7 — Windows Credential Provider (Test VM Only)
// ============================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <unknwn.h>

#include "CredentialProviderCompat.h"
#include "ProviderGuid.h"

namespace MobileUnlock::CredentialProvider {

// Forward declaration
class MobileUnlockCredential;

// ============================================================
// CredentialProvider
//
// Implements ICredentialProvider — the factory object that
// Winlogon enumerates. Creates and owns one MobileUnlockCredential.
//
// Supported usage scenarios:
//   CPUS_LOGON
//   CPUS_UNLOCK_WORKSTATION
//
// All other scenarios (CPUS_CREDUI, CPUS_CHANGE_PASSWORD,
// CPUS_PLAP, etc.) return E_NOTIMPL.
// ============================================================
class CredentialProvider final : public ICredentialProvider {
public:
    CredentialProvider();

    // IUnknown
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override;
    IFACEMETHODIMP_(ULONG) AddRef() override;
    IFACEMETHODIMP_(ULONG) Release() override;

    // ICredentialProvider
    IFACEMETHODIMP SetUsageScenario(
        CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
        DWORD dwFlags) override;

    IFACEMETHODIMP SetSerialization(
        const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs) override;

    IFACEMETHODIMP Advise(
        ICredentialProviderEvents* pcpe,
        UINT_PTR upAdviseContext) override;

    IFACEMETHODIMP UnAdvise() override;

    IFACEMETHODIMP GetFieldDescriptorCount(DWORD* pdwCount) override;

    IFACEMETHODIMP GetFieldDescriptorAt(
        DWORD dwIndex,
        CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd) override;

    IFACEMETHODIMP GetCredentialCount(
        DWORD* pdwCount,
        DWORD* pdwDefault,
        BOOL* pbAutoLogonWithDefault) override;

    IFACEMETHODIMP GetCredentialAt(
        DWORD dwIndex,
        ICredentialProviderCredential** ppcpc) override;

private:
    ~CredentialProvider();

    LONG                                   m_cRef;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO     m_cpus;
    bool                                   m_usageScenarioSet;
    MobileUnlockCredential*                m_pCredential;
    ICredentialProviderEvents*             m_pCredentialProviderEvents;
    UINT_PTR                               m_upAdviseContext;
};

} // namespace MobileUnlock::CredentialProvider
