#pragma once

// ============================================================
// MobileFingerprintUnlock — IClassFactory
// Phase 7 — Windows Credential Provider (Test VM Only)
// ============================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <unknwn.h>
#include <atomic>
#include "CredentialProviderCompat.h"

extern std::atomic<LONG> g_cDllRef;

namespace MobileUnlock::CredentialProvider {

class ClassFactory final : public IClassFactory {
public:
    ClassFactory();

    // IUnknown
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override;
    IFACEMETHODIMP_(ULONG) AddRef() override;
    IFACEMETHODIMP_(ULONG) Release() override;

    // IClassFactory
    IFACEMETHODIMP CreateInstance(
        IUnknown* pUnkOuter, REFIID riid, void** ppv) override;

    IFACEMETHODIMP LockServer(BOOL fLock) override;

private:
    ~ClassFactory() = default;
    LONG m_cRef;
};

} // namespace MobileUnlock::CredentialProvider
