#pragma once

// ============================================================
// MobileFingerprintUnlock — LSA Authentication Package Engine
// Phase 8 — Custom LSA Authentication Package (Test VM Only)
// ============================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string>
#include <vector>
#include <array>
#include <cstdint>

#include "LsaPackageCompat.h"
#include "LsaLogonBuffer.h"
#include "../crypto/CryptoManager.h"
#include "../pairing/DeviceIdentity.h"
#include "../pairing/DeviceRegistry.h"

namespace MobileUnlock::Lsa {

constexpr const char*    LSA_PACKAGE_NAME_A = "MobileUnlockLsaPackage";
constexpr const wchar_t* LSA_PACKAGE_NAME_W = L"MobileUnlockLsaPackage";
constexpr const wchar_t* AUTH_AUTHORITY_W   = L"MobileFingerprintUnlock";

// ============================================================
// LsaPackage
//
// Core implementation of the LSA Authentication Package.
// Handles initialization, submission buffer validation,
// registry lookup, cryptographic ECDSA verification, and
// LSA token information construction.
// ============================================================
class LsaPackage {
public:
    static LsaPackage& Instance();

    LsaPackage();
    ~LsaPackage();

    LsaPackage(const LsaPackage&) = delete;
    LsaPackage& operator=(const LsaPackage&) = delete;

    // --------------------------------------------------------
    // LsaApInitializePackage handler
    // --------------------------------------------------------
    NTSTATUS Initialize(
        ULONG authenticationPackageId,
        PLSA_DISPATCH_TABLE lsaDispatchTable,
        PLSA_STRING database,
        PLSA_STRING confidentiality,
        PLSA_STRING* authenticationPackageName);

    // --------------------------------------------------------
    // LsaApLogonUserEx2 handler
    // --------------------------------------------------------
    NTSTATUS LogonUserEx2(
        PLSA_CLIENT_REQUEST clientRequest,
        SECURITY_LOGON_TYPE logonType,
        PVOID protocolSubmitBuffer,
        PVOID clientBufferBase,
        ULONG submitBufferLength,
        PVOID* profileBuffer,
        PULONG profileBufferLength,
        PLUID logonId,
        PNTSTATUS subStatus,
        PLSA_TOKEN_INFORMATION_TYPE tokenInformationType,
        PVOID* tokenInformation,
        PUNICODE_STRING* accountName,
        PUNICODE_STRING* authenticatingAuthority,
        PUNICODE_STRING* machineName,
        PSECPKG_PRIMARY_CRED primaryCredentials,
        PSECPKG_SUPPLEMENTAL_CRED_ARRAY* supplementalCredentials);

    // --------------------------------------------------------
    // LsaApLogonTerminated handler
    // --------------------------------------------------------
    VOID LogonTerminated(PLUID logonId);

    // --------------------------------------------------------
    // Test Hooks
    // --------------------------------------------------------
    void SetDispatchTableForTesting(PLSA_DISPATCH_TABLE dispatchTable);
    bool IsInitialized() const { return m_isInitialized; }
    ULONG GetPackageId() const { return m_packageId; }

private:
    PVOID AllocateHeap(ULONG length);
    VOID FreeHeap(PVOID base);

    // Helpers to construct UNICODE_STRINGs allocated on LSA heap
    PUNICODE_STRING CreateUnicodeStringOnLsaHeap(const std::wstring& str);

    ULONG               m_packageId;
    LSA_DISPATCH_TABLE  m_dispatchTable;
    bool                m_hasDispatchTable;
    bool                m_isInitialized;
    CRITICAL_SECTION    m_lock;
};

} // namespace MobileUnlock::Lsa
