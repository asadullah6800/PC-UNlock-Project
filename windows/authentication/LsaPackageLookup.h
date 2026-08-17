#pragma once

// ============================================================
// MobileFingerprintUnlock — LSA Package ID Resolver
// Phase 9A — Windows Authentication Laboratory
// ============================================================
// Queries the Local Security Authority (LSA) for the dynamic
// AuthenticationPackageId assigned to "MobileUnlockLsaPackage".
// Uses official Windows APIs:
//   - LsaConnectUntrusted
//   - LsaLookupAuthenticationPackage
//   - LsaDeregisterLogonProcess
// ============================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string>
#include <cstdint>

#include "../lsa_authentication_package/LsaPackageCompat.h"

namespace MobileUnlock::Authentication {

constexpr const char* kDefaultLsaPackageName = "MobileUnlockLsaPackage";

class LsaPackageLookup {
public:
    /**
     * Resolves the numeric Authentication Package ID assigned by LSA to the given package name.
     * 
     * @param packageName ASCII package name (defaults to "MobileUnlockLsaPackage").
     * @param outPackageId Output variable receiving the numeric package ID.
     * @return NTSTATUS STATUS_SUCCESS (0) on success, or LSA error code.
     */
    static NTSTATUS GetAuthenticationPackageId(
        const std::string& packageName,
        ULONG& outPackageId);

    /**
     * Helper to check if the custom LSA package is currently registered and loaded in LSA.
     */
    static bool IsPackageRegistered(const std::string& packageName = kDefaultLsaPackageName);
};

} // namespace MobileUnlock::Authentication
