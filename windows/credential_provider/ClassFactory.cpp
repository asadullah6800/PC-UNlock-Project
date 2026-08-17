// ============================================================
// MobileFingerprintUnlock — IClassFactory Implementation
// Phase 7 — Windows Credential Provider (Test VM Only)
// ============================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <new>

#include "ClassFactory.h"
#include "CredentialProvider.h"

namespace MobileUnlock::CredentialProvider {

ClassFactory::ClassFactory()
    : m_cRef(1)
{
    g_cDllRef.fetch_add(1, std::memory_order_relaxed);
}

// IUnknown

IFACEMETHODIMP ClassFactory::QueryInterface(REFIID riid, void** ppv) {
    if (!ppv) return E_POINTER;
    if (riid == IID_IUnknown || riid == IID_IClassFactory) {
        *ppv = static_cast<IClassFactory*>(this);
        AddRef();
        return S_OK;
    }
    *ppv = nullptr;
    return E_NOINTERFACE;
}

IFACEMETHODIMP_(ULONG) ClassFactory::AddRef() {
    return InterlockedIncrement(&m_cRef);
}

IFACEMETHODIMP_(ULONG) ClassFactory::Release() {
    LONG cRef = InterlockedDecrement(&m_cRef);
    if (cRef == 0) {
        g_cDllRef.fetch_sub(1, std::memory_order_relaxed);
        delete this;
    }
    return cRef;
}

// IClassFactory

IFACEMETHODIMP ClassFactory::CreateInstance(
    IUnknown* pUnkOuter, REFIID riid, void** ppv)
{
    if (!ppv) return E_POINTER;
    if (pUnkOuter) return CLASS_E_NOAGGREGATION; // No aggregation

    auto* pProvider = new (std::nothrow) CredentialProvider();
    if (!pProvider) return E_OUTOFMEMORY;

    HRESULT hr = pProvider->QueryInterface(riid, ppv);
    pProvider->Release();
    return hr;
}

IFACEMETHODIMP ClassFactory::LockServer(BOOL fLock) {
    if (fLock) {
        g_cDllRef.fetch_add(1, std::memory_order_relaxed);
    } else {
        g_cDllRef.fetch_sub(1, std::memory_order_relaxed);
    }
    return S_OK;
}

} // namespace MobileUnlock::CredentialProvider
