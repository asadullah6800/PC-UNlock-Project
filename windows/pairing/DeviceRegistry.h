#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>

#include <string>
#include <vector>
#include <cstdint>

#include "DeviceIdentity.h"

namespace MobileUnlock::Pairing {

// Registry root for all device records per SECURITY.md and IDENTITY_MAPPING.md
// HKLM\SOFTWARE\MobileFingerprintUnlock\Devices\<DeviceID>
constexpr wchar_t kDeviceRegistryRoot[] = L"SOFTWARE\\MobileFingerprintUnlock\\Devices";

// Registry value names for a single device record
constexpr wchar_t kRegValPairStatus[]    = L"PairStatus";    // DWORD:  1=ACTIVE, 0=REVOKED
constexpr wchar_t kRegValDeviceName[]    = L"DeviceName";    // SZ
constexpr wchar_t kRegValAccountSid[]    = L"AccountSID";    // SZ
constexpr wchar_t kRegValPublicKey[]     = L"PublicKey";     // BINARY (ECDSA P-256 SPKI)
constexpr wchar_t kRegValPairedTime[]    = L"PairedTime";    // QWORD (FILETIME)
constexpr wchar_t kRegValLastSeen[]      = L"LastSeen";      // QWORD (FILETIME)
constexpr wchar_t kRegValDeviceVersion[] = L"DeviceVersion"; // SZ (Android OS version)

// Pair status values
constexpr DWORD kStatusActive  = 1;
constexpr DWORD kStatusRevoked = 0;

// Maximum devices per Windows account (from IDENTITY_MAPPING.md)
constexpr int kMaxDevicesPerAccount = 5;

// Represents a trusted device record in the Windows registry
struct DeviceRecord {
    DeviceId    deviceId;
    std::string deviceName;
    std::string accountSid;       // Mapped Windows Account SID string
    std::vector<uint8_t> publicKey; // ECDSA P-256 SPKI blob (will be used in Phase 4)
    DWORD       pairStatus;       // kStatusActive or kStatusRevoked
    FILETIME    pairedTime;
    FILETIME    lastSeen;
};

// Writes a new paired device record into HKLM\SOFTWARE\MobileFingerprintUnlock\Devices\<DeviceID>
// Creates and sets key permissions per SECURITY.md ACL requirements
// Returns ERROR_SUCCESS on success, Win32 error code otherwise
LONG WriteDeviceRecord(const DeviceRecord& record);

// Reads a device record from the registry by DeviceID string
// Returns ERROR_SUCCESS and fills outRecord on success
// Returns ERROR_FILE_NOT_FOUND if the device is not registered
LONG ReadDeviceRecord(const std::string& deviceIdStr, DeviceRecord& outRecord);

// Updates the PairStatus value of an existing device record (ACTIVE or REVOKED)
LONG SetDeviceStatus(const std::string& deviceIdStr, DWORD status);

// Updates the LastSeen FILETIME of an existing device record
LONG UpdateLastSeen(const std::string& deviceIdStr);

// Deletes the device registry key entirely (used by UNPAIR_REQUEST)
LONG DeleteDeviceRecord(const std::string& deviceIdStr);

// Returns true if the device exists in the registry and is ACTIVE
bool IsDeviceActive(const std::string& deviceIdStr);

// Counts how many ACTIVE devices are mapped to a given account SID
int CountActiveDevicesForAccount(const std::string& accountSid);

// Enumerates all device IDs registered under the registry root
// Returns device ID strings (hyphenated UUID format)
std::vector<std::string> EnumerateDeviceIds();

// Applies security ACL to the registry key per SECURITY.md:
// SYSTEM: Full, Administrators: Read+Write, NetworkService: Read, Users/Interactive: No access
LONG ApplyRegistryAcl(HKEY hKey);

// Testing hook to override registry root key (e.g. HKEY_CURRENT_USER for unprivileged unit tests)
void SetRegistryRootForTesting(HKEY root);
HKEY GetRegistryRoot();

} // namespace MobileUnlock::Pairing
