#include "DeviceIdentity.h"
#include <cstdio>
#include <cstring>

namespace MobileUnlock::Pairing {

std::string DeviceIdToString(const DeviceId& id) {
    char buf[37];
    std::snprintf(buf, sizeof(buf),
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        id[0],  id[1],  id[2],  id[3],
        id[4],  id[5],
        id[6],  id[7],
        id[8],  id[9],
        id[10], id[11], id[12], id[13], id[14], id[15]
    );
    return std::string(buf);
}

bool DeviceIdFromString(const std::string& str, DeviceId& outId) {
    if (str.size() != 36) return false;
    // Validate dash positions
    if (str[8] != '-' || str[13] != '-' || str[18] != '-' || str[23] != '-') return false;

    // Strip dashes and parse 32 hex chars into 16 bytes
    std::string hex;
    hex.reserve(32);
    for (char c : str) {
        if (c != '-') hex += c;
    }
    if (hex.size() != 32) return false;

    for (int i = 0; i < 16; ++i) {
        unsigned int byte;
        if (std::sscanf(hex.c_str() + 2 * i, "%02x", &byte) != 1) return false;
        outId[i] = static_cast<uint8_t>(byte);
    }
    return true;
}

DeviceId GenerateDeviceId() {
    DeviceId id{};
    // Use RtlGenRandom (advapi32) which is available even without full BCrypt linkage in MinGW
    typedef BOOLEAN (WINAPI *RtlGenRandomFn)(PVOID, ULONG);
    HMODULE hAdvApi = LoadLibraryA("advapi32.dll");
    if (hAdvApi) {
        auto pfn = reinterpret_cast<RtlGenRandomFn>(GetProcAddress(hAdvApi, "SystemFunction036"));
        if (pfn) {
            pfn(id.data(), static_cast<ULONG>(id.size()));
        }
        FreeLibrary(hAdvApi);
    }
    // Mark as UUID version 4 and variant 1 per RFC 4122
    id[6] = (id[6] & 0x0F) | 0x40; // version 4
    id[8] = (id[8] & 0x3F) | 0x80; // variant 1
    return id;
}

bool DeviceIdEqual(const DeviceId& a, const DeviceId& b) {
    return a == b;
}

bool DeviceIdIsEmpty(const DeviceId& id) {
    for (auto b : id) {
        if (b != 0) return false;
    }
    return true;
}

} // namespace MobileUnlock::Pairing
