// ============================================================
// MobileFingerprintUnlock — LSA Package ID Resolver
// Phase 9A — Windows Authentication Laboratory
// ============================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstring>

#include "LsaPackageLookup.h"

namespace MobileUnlock::Authentication {

typedef NTSTATUS (NTAPI *pfnLsaConnectUntrusted)(PHANDLE LsaHandle);
typedef NTSTATUS (NTAPI *pfnLsaLookupAuthenticationPackage)(
    HANDLE LsaHandle,
    PLSA_STRING PackageName,
    PULONG PackageId);
typedef NTSTATUS (NTAPI *pfnLsaDeregisterLogonProcess)(HANDLE LsaHandle);

NTSTATUS LsaPackageLookup::GetAuthenticationPackageId(
    const std::string& packageName,
    ULONG& outPackageId)
{
    outPackageId = 0;

    HMODULE hSecur32 = LoadLibraryW(L"secur32.dll");
    if (!hSecur32) {
        return STATUS_UNSUCCESSFUL;
    }

    auto fnConnect = reinterpret_cast<pfnLsaConnectUntrusted>(
        GetProcAddress(hSecur32, "LsaConnectUntrusted"));
    auto fnLookup = reinterpret_cast<pfnLsaLookupAuthenticationPackage>(
        GetProcAddress(hSecur32, "LsaLookupAuthenticationPackage"));
    auto fnDeregister = reinterpret_cast<pfnLsaDeregisterLogonProcess>(
        GetProcAddress(hSecur32, "LsaDeregisterLogonProcess"));

    if (!fnConnect || !fnLookup || !fnDeregister) {
        FreeLibrary(hSecur32);
        return STATUS_NOT_SUPPORTED;
    }

    HANDLE hLsa = nullptr;
    NTSTATUS status = fnConnect(&hLsa);
    if (status != STATUS_SUCCESS || !hLsa) {
        FreeLibrary(hSecur32);
        return status;
    }

    LSA_STRING lsaName{};
    lsaName.Length        = static_cast<USHORT>(packageName.length());
    lsaName.MaximumLength = static_cast<USHORT>(packageName.length() + 1);
    lsaName.Buffer        = const_cast<PCHAR>(packageName.c_str());

    ULONG packageId = 0;
    status = fnLookup(hLsa, &lsaName, &packageId);

    fnDeregister(hLsa);
    FreeLibrary(hSecur32);

    if (status == STATUS_SUCCESS) {
        outPackageId = packageId;
    }

    return status;
}

bool LsaPackageLookup::IsPackageRegistered(const std::string& packageName) {
    ULONG packageId = 0;
    NTSTATUS status = GetAuthenticationPackageId(packageName, packageId);
    return (status == STATUS_SUCCESS && packageId != 0);
}

} // namespace MobileUnlock::Authentication
