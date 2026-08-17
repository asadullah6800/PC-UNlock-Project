// ============================================================
// MobileFingerprintUnlock — DLL Entry Point
// Phase 7 — Windows Credential Provider (Test VM Only)
// ============================================================
// DO NOT register this DLL on the physical host machine.
// Registration is strictly limited to the dedicated Windows Test VM.
// ============================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <atomic>
#include <new>

#include "ClassFactory.h"
#include "ProviderGuid.h"

// Global DLL reference count.
// Incremented by each live COM object and LockServer(TRUE).
// Decremented on Release() and LockServer(FALSE).
std::atomic<LONG> g_cDllRef{0};

// ============================================================
// DllMain
// ============================================================

BOOL APIENTRY DllMain(HMODULE /*hModule*/, DWORD dwReason, LPVOID /*lpReserved*/) {
    switch (dwReason) {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

// ============================================================
// DllGetClassObject
//
// Called by COM to obtain a class factory for CLSID_MobileUnlockProvider.
// ============================================================

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv) {
    if (!ppv) return E_POINTER;
    *ppv = nullptr;

    if (rclsid != CLSID_MobileUnlockProvider) {
        return CLASS_E_CLASSNOTAVAILABLE;
    }

    auto* pFactory = new (std::nothrow) MobileUnlock::CredentialProvider::ClassFactory();
    if (!pFactory) return E_OUTOFMEMORY;

    HRESULT hr = pFactory->QueryInterface(riid, ppv);
    pFactory->Release();
    return hr;
}

// ============================================================
// DllCanUnloadNow
//
// Returns S_OK if no COM objects are alive (safe to unload).
// ============================================================

STDAPI DllCanUnloadNow() {
    return (g_cDllRef.load(std::memory_order_acquire) == 0) ? S_OK : S_FALSE;
}
