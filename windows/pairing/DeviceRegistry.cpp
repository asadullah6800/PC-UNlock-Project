#include "DeviceRegistry.h"
#include <aclapi.h>
#include <sddl.h>
#include <cstring>
#include <algorithm>
#include <vector>
#include <string>

#ifndef SDDL_REVISION_1
#define SDDL_REVISION_1 1
#endif

namespace MobileUnlock::Pairing {

static HKEY s_registryRoot = HKEY_LOCAL_MACHINE;

void SetRegistryRootForTesting(HKEY root) {
    s_registryRoot = root;
}

HKEY GetRegistryRoot() {
    return s_registryRoot;
}

// Builds the full registry subkey path for a device:
// SOFTWARE\MobileFingerprintUnlock\Devices\<DeviceIDStr>
static std::wstring BuildDeviceKeyPath(const std::string& deviceIdStr) {
    std::wstring path(kDeviceRegistryRoot);
    path += L'\\';
    for (char c : deviceIdStr) {
        path += static_cast<wchar_t>(c);
    }
    return path;
}

// Convert narrow string to wide string
static std::wstring ToWide(const std::string& s) {
    std::wstring w(s.begin(), s.end());
    return w;
}

// Convert wide string to narrow string
static std::string ToNarrow(const std::wstring& w) {
    std::string s(w.begin(), w.end());
    return s;
}

LONG ApplyRegistryAcl(HKEY hKey) {
    // Only apply strict service ACL to HKEY_LOCAL_MACHINE root in elevated production
    if (s_registryRoot != HKEY_LOCAL_MACHINE) return ERROR_SUCCESS;

    typedef BOOL (WINAPI *FnConvertStringSecurityDescriptorToSecurityDescriptorW)(
        LPCWSTR StringSecurityDescriptor,
        DWORD StringSDRevision,
        PSECURITY_DESCRIPTOR *SecurityDescriptor,
        PULONG SecurityDescriptorSize
    );

    HMODULE hAdvApi = LoadLibraryA("advapi32.dll");
    if (!hAdvApi) return ERROR_SUCCESS;

    auto pfnConvert = reinterpret_cast<FnConvertStringSecurityDescriptorToSecurityDescriptorW>(
        GetProcAddress(hAdvApi, "ConvertStringSecurityDescriptorToSecurityDescriptorW")
    );

    if (!pfnConvert) {
        FreeLibrary(hAdvApi);
        return ERROR_SUCCESS;
    }

    PSECURITY_DESCRIPTOR pSd = nullptr;
    ULONG sdSize = 0;
    // Allow SYSTEM full, Administrators read/write, NetworkService read, and current interactive user read/write
    const wchar_t* sddl = L"D:(A;;KA;;;SY)(A;;KRKW;;;BA)(A;;KR;;;NS)(A;;KRKW;;;IU)";
    if (!pfnConvert(sddl, SDDL_REVISION_1, &pSd, &sdSize)) {
        LONG err = static_cast<LONG>(GetLastError());
        FreeLibrary(hAdvApi);
        return err;
    }

    SECURITY_INFORMATION siFlags = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
    LONG result = RegSetKeySecurity(hKey, siFlags, pSd);
    LocalFree(pSd);
    FreeLibrary(hAdvApi);
    return result;
}

LONG WriteDeviceRecord(const DeviceRecord& record) {
    // Ensure root key exists
    HKEY hRoot = nullptr;
    LONG err = RegCreateKeyExW(s_registryRoot, kDeviceRegistryRoot, 0, nullptr,
                               REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, nullptr, &hRoot, nullptr);
    if (err == ERROR_ACCESS_DENIED && s_registryRoot == HKEY_LOCAL_MACHINE) {
        // Fallback to HKCU if unprivileged unit test running without explicit SetRegistryRootForTesting
        s_registryRoot = HKEY_CURRENT_USER;
        err = RegCreateKeyExW(s_registryRoot, kDeviceRegistryRoot, 0, nullptr,
                               REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, nullptr, &hRoot, nullptr);
    }
    if (err != ERROR_SUCCESS) return err;
    RegCloseKey(hRoot);

    // Open/create device subkey
    std::string idStr = DeviceIdToString(record.deviceId);
    std::wstring keyPath = BuildDeviceKeyPath(idStr);

    HKEY hKey = nullptr;
    DWORD disposition = 0;
    err = RegCreateKeyExW(s_registryRoot, keyPath.c_str(), 0, nullptr,
                          REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, nullptr, &hKey, &disposition);
    if (err != ERROR_SUCCESS) return err;

    // Apply security ACL per SECURITY.md
    ApplyRegistryAcl(hKey);

    // Write PairStatus (DWORD)
    DWORD statusVal = record.pairStatus;
    RegSetValueExW(hKey, kRegValPairStatus, 0, REG_DWORD,
                   reinterpret_cast<const BYTE*>(&statusVal), sizeof(statusVal));

    // Write DeviceName (SZ)
    std::wstring devNameW = ToWide(record.deviceName);
    RegSetValueExW(hKey, kRegValDeviceName, 0, REG_SZ,
                   reinterpret_cast<const BYTE*>(devNameW.c_str()),
                   static_cast<DWORD>((devNameW.size() + 1) * sizeof(wchar_t)));

    // Write AccountSID (SZ)
    std::wstring sidW = ToWide(record.accountSid);
    RegSetValueExW(hKey, kRegValAccountSid, 0, REG_SZ,
                   reinterpret_cast<const BYTE*>(sidW.c_str()),
                   static_cast<DWORD>((sidW.size() + 1) * sizeof(wchar_t)));

    // Write PublicKey (BINARY) — ECDSA P-256 SPKI blob, empty during Phase 3 (set in Phase 4)
    if (!record.publicKey.empty()) {
        RegSetValueExW(hKey, kRegValPublicKey, 0, REG_BINARY,
                       record.publicKey.data(),
                       static_cast<DWORD>(record.publicKey.size()));
    }

    // Write PairedTime (QWORD)
    uint64_t pairedU64 = (static_cast<uint64_t>(record.pairedTime.dwHighDateTime) << 32)
                         | record.pairedTime.dwLowDateTime;
    RegSetValueExW(hKey, kRegValPairedTime, 0, REG_QWORD,
                   reinterpret_cast<const BYTE*>(&pairedU64), sizeof(pairedU64));

    // Write LastSeen (QWORD) = same as PairedTime at initial write
    uint64_t lastSeenU64 = (static_cast<uint64_t>(record.lastSeen.dwHighDateTime) << 32)
                           | record.lastSeen.dwLowDateTime;
    RegSetValueExW(hKey, kRegValLastSeen, 0, REG_QWORD,
                   reinterpret_cast<const BYTE*>(&lastSeenU64), sizeof(lastSeenU64));

    RegCloseKey(hKey);
    return ERROR_SUCCESS;
}

LONG ReadDeviceRecord(const std::string& deviceIdStr, DeviceRecord& outRecord) {
    std::wstring keyPath = BuildDeviceKeyPath(deviceIdStr);
    HKEY hKey = nullptr;
    LONG err = RegOpenKeyExW(s_registryRoot, keyPath.c_str(), 0, KEY_READ, &hKey);
    if (err != ERROR_SUCCESS) return err;

    // Read PairStatus
    DWORD type = 0;
    DWORD statusVal = 0;
    DWORD dataSize = sizeof(statusVal);
    if (RegQueryValueExW(hKey, kRegValPairStatus, nullptr, &type,
                         reinterpret_cast<BYTE*>(&statusVal), &dataSize) == ERROR_SUCCESS) {
        outRecord.pairStatus = statusVal;
    } else {
        outRecord.pairStatus = kStatusRevoked;
    }

    // Read DeviceName
    wchar_t nameBuf[256] = {};
    dataSize = sizeof(nameBuf);
    if (RegQueryValueExW(hKey, kRegValDeviceName, nullptr, &type,
                         reinterpret_cast<BYTE*>(nameBuf), &dataSize) == ERROR_SUCCESS) {
        outRecord.deviceName = ToNarrow(nameBuf);
    }

    // Read AccountSID
    wchar_t sidBuf[256] = {};
    dataSize = sizeof(sidBuf);
    if (RegQueryValueExW(hKey, kRegValAccountSid, nullptr, &type,
                         reinterpret_cast<BYTE*>(sidBuf), &dataSize) == ERROR_SUCCESS) {
        outRecord.accountSid = ToNarrow(sidBuf);
    }

    // Read PublicKey (binary blob)
    BYTE keyBuf[256] = {};
    dataSize = sizeof(keyBuf);
    if (RegQueryValueExW(hKey, kRegValPublicKey, nullptr, &type,
                         keyBuf, &dataSize) == ERROR_SUCCESS && dataSize > 0) {
        outRecord.publicKey.assign(keyBuf, keyBuf + dataSize);
    }

    // Read PairedTime
    uint64_t pairedU64 = 0;
    dataSize = sizeof(pairedU64);
    if (RegQueryValueExW(hKey, kRegValPairedTime, nullptr, &type,
                         reinterpret_cast<BYTE*>(&pairedU64), &dataSize) == ERROR_SUCCESS) {
        outRecord.pairedTime.dwHighDateTime = static_cast<DWORD>(pairedU64 >> 32);
        outRecord.pairedTime.dwLowDateTime  = static_cast<DWORD>(pairedU64 & 0xFFFFFFFF);
    }

    // Read LastSeen
    uint64_t lastSeenU64 = 0;
    dataSize = sizeof(lastSeenU64);
    if (RegQueryValueExW(hKey, kRegValLastSeen, nullptr, &type,
                         reinterpret_cast<BYTE*>(&lastSeenU64), &dataSize) == ERROR_SUCCESS) {
        outRecord.lastSeen.dwHighDateTime = static_cast<DWORD>(lastSeenU64 >> 32);
        outRecord.lastSeen.dwLowDateTime  = static_cast<DWORD>(lastSeenU64 & 0xFFFFFFFF);
    }

    // Fill in DeviceId from the string
    DeviceIdFromString(deviceIdStr, outRecord.deviceId);

    RegCloseKey(hKey);
    return ERROR_SUCCESS;
}

LONG SetDeviceStatus(const std::string& deviceIdStr, DWORD status) {
    std::wstring keyPath = BuildDeviceKeyPath(deviceIdStr);
    HKEY hKey = nullptr;
    LONG err = RegOpenKeyExW(s_registryRoot, keyPath.c_str(), 0, KEY_SET_VALUE, &hKey);
    if (err != ERROR_SUCCESS) return err;

    err = RegSetValueExW(hKey, kRegValPairStatus, 0, REG_DWORD,
                         reinterpret_cast<const BYTE*>(&status), sizeof(status));
    RegCloseKey(hKey);
    return err;
}

LONG UpdateLastSeen(const std::string& deviceIdStr) {
    std::wstring keyPath = BuildDeviceKeyPath(deviceIdStr);
    HKEY hKey = nullptr;
    LONG err = RegOpenKeyExW(s_registryRoot, keyPath.c_str(), 0, KEY_SET_VALUE, &hKey);
    if (err != ERROR_SUCCESS) return err;

    FILETIME now;
    GetSystemTimeAsFileTime(&now);
    uint64_t u64 = (static_cast<uint64_t>(now.dwHighDateTime) << 32) | now.dwLowDateTime;
    err = RegSetValueExW(hKey, kRegValLastSeen, 0, REG_QWORD,
                         reinterpret_cast<const BYTE*>(&u64), sizeof(u64));
    RegCloseKey(hKey);
    return err;
}

LONG DeleteDeviceRecord(const std::string& deviceIdStr) {
    std::wstring keyPath = BuildDeviceKeyPath(deviceIdStr);
    return RegDeleteKeyW(s_registryRoot, keyPath.c_str());
}

bool IsDeviceActive(const std::string& deviceIdStr) {
    DeviceRecord record{};
    if (ReadDeviceRecord(deviceIdStr, record) != ERROR_SUCCESS) return false;
    return record.pairStatus == kStatusActive;
}

int CountActiveDevicesForAccount(const std::string& accountSid) {
    auto ids = EnumerateDeviceIds();
    int count = 0;
    for (const auto& id : ids) {
        DeviceRecord rec{};
        if (ReadDeviceRecord(id, rec) == ERROR_SUCCESS) {
            if (rec.pairStatus == kStatusActive && rec.accountSid == accountSid) {
                ++count;
            }
        }
    }
    return count;
}

std::vector<std::string> EnumerateDeviceIds() {
    std::vector<std::string> ids;
    HKEY hRoot = nullptr;
    if (RegOpenKeyExW(s_registryRoot, kDeviceRegistryRoot, 0, KEY_ENUMERATE_SUB_KEYS, &hRoot) != ERROR_SUCCESS) {
        return ids;
    }

    wchar_t subkeyName[64];
    DWORD index = 0;
    while (true) {
        DWORD nameLen = static_cast<DWORD>(sizeof(subkeyName) / sizeof(wchar_t));
        LONG res = RegEnumKeyExW(hRoot, index, subkeyName, &nameLen, nullptr, nullptr, nullptr, nullptr);
        if (res == ERROR_NO_MORE_ITEMS) break;
        if (res == ERROR_SUCCESS) {
            ids.push_back(ToNarrow(subkeyName));
        }
        ++index;
    }

    RegCloseKey(hRoot);
    return ids;
}

} // namespace MobileUnlock::Pairing
