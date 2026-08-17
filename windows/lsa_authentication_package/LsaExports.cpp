// ============================================================
// MobileFingerprintUnlock — LSA Authentication Package Exports
// Phase 8 — Custom LSA Authentication Package (Test VM Only)
// ============================================================
// Exports the official Windows Authentication Package callbacks:
//   - LsaApInitializePackage
//   - LsaApLogonUserEx2
//   - LsaApLogonTerminated
// ============================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "LsaPackageCompat.h"
#include "LsaPackage.h"

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
// LsaApInitializePackage
// ============================================================

extern "C" NTSTATUS NTAPI LsaApInitializePackage(
    ULONG AuthenticationPackageId,
    PLSA_DISPATCH_TABLE LsaDispatchTable,
    PLSA_STRING Database,
    PLSA_STRING Confidentiality,
    PLSA_STRING *AuthenticationPackageName)
{
    return MobileUnlock::Lsa::LsaPackage::Instance().Initialize(
        AuthenticationPackageId,
        LsaDispatchTable,
        Database,
        Confidentiality,
        AuthenticationPackageName);
}

// ============================================================
// LsaApLogonUserEx2
// ============================================================

extern "C" NTSTATUS NTAPI LsaApLogonUserEx2(
    PLSA_CLIENT_REQUEST ClientRequest,
    SECURITY_LOGON_TYPE LogonType,
    PVOID ProtocolSubmitBuffer,
    PVOID ClientBufferBase,
    ULONG SubmitBufferLength,
    PVOID *ProfileBuffer,
    PULONG ProfileBufferLength,
    PLUID LogonId,
    PNTSTATUS SubStatus,
    PLSA_TOKEN_INFORMATION_TYPE TokenInformationType,
    PVOID *TokenInformation,
    PUNICODE_STRING *AccountName,
    PUNICODE_STRING *AuthenticatingAuthority,
    PUNICODE_STRING *MachineName,
    PSECPKG_PRIMARY_CRED PrimaryCredentials,
    PSECPKG_SUPPLEMENTAL_CRED_ARRAY *SupplementalCredentials)
{
    return MobileUnlock::Lsa::LsaPackage::Instance().LogonUserEx2(
        ClientRequest,
        LogonType,
        ProtocolSubmitBuffer,
        ClientBufferBase,
        SubmitBufferLength,
        ProfileBuffer,
        ProfileBufferLength,
        LogonId,
        SubStatus,
        TokenInformationType,
        TokenInformation,
        AccountName,
        AuthenticatingAuthority,
        MachineName,
        PrimaryCredentials,
        SupplementalCredentials);
}

// ============================================================
// LsaApLogonTerminated
// ============================================================

extern "C" VOID NTAPI LsaApLogonTerminated(PLUID LogonId) {
    MobileUnlock::Lsa::LsaPackage::Instance().LogonTerminated(LogonId);
}
