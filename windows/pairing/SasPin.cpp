#include "SasPin.h"
#include <cstring>
#include <cstdio>
#include <cstdlib>

namespace MobileUnlock::Pairing {

std::string GenerateSasPin() {
    // Use RtlGenRandom for cryptographically secure random bytes
    uint32_t randomVal = 0;
    typedef BOOLEAN (WINAPI *RtlGenRandomFn)(PVOID, ULONG);
    HMODULE hAdvApi = LoadLibraryA("advapi32.dll");
    bool generated = false;
    if (hAdvApi) {
        auto pfn = reinterpret_cast<RtlGenRandomFn>(GetProcAddress(hAdvApi, "SystemFunction036"));
        if (pfn) {
            pfn(&randomVal, sizeof(randomVal));
            generated = true;
        }
        FreeLibrary(hAdvApi);
    }
    if (!generated) return std::string();

    // Map to [0, 999999] using rejection sampling to avoid modulo bias
    // Maximum iterations is bounded (< 8 in practice)
    uint32_t range = 1000000u;
    uint32_t limit = (0xFFFFFFFFu / range) * range;
    int iterations = 0;
    while (randomVal >= limit && iterations < 32) {
        HMODULE h = LoadLibraryA("advapi32.dll");
        if (h) {
            auto pfn2 = reinterpret_cast<RtlGenRandomFn>(GetProcAddress(h, "SystemFunction036"));
            if (pfn2) pfn2(&randomVal, sizeof(randomVal));
            FreeLibrary(h);
        }
        ++iterations;
    }

    uint32_t pin = randomVal % range;
    char pinStr[7];
    std::snprintf(pinStr, sizeof(pinStr), "%06u", pin);
    return std::string(pinStr);
}

bool IsValidPinFormat(const std::string& pin) {
    if (pin.size() != static_cast<size_t>(SAS_PIN_LENGTH)) return false;
    for (char c : pin) {
        if (c < '0' || c > '9') return false;
    }
    return true;
}

bool SasPinExpired(FILETIME generatedAt) {
    FILETIME now;
    GetSystemTimeAsFileTime(&now);

    // Convert FILETIME to 100-nanosecond intervals as uint64
    auto toU64 = [](FILETIME ft) -> uint64_t {
        return (static_cast<uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
    };

    uint64_t genU64 = toU64(generatedAt);
    uint64_t nowU64 = toU64(now);
    if (nowU64 < genU64) return true; // clock skew — treat as expired

    // SAS_EXPIRY_SECONDS in 100-ns units: 1s = 10,000,000 units
    uint64_t elapsed100ns = nowU64 - genU64;
    uint64_t limitUnits = static_cast<uint64_t>(SAS_EXPIRY_SECONDS) * 10000000ULL;
    return elapsed100ns > limitUnits;
}

bool ValidateSasPin(const std::string& candidatePin, const std::string& storedPin,
                    FILETIME generatedAt, int attemptsSoFar) {
    if (attemptsSoFar >= SAS_MAX_ATTEMPTS) return false;
    if (SasPinExpired(generatedAt)) return false;
    if (!IsValidPinFormat(candidatePin)) return false;
    if (storedPin.size() != static_cast<size_t>(SAS_PIN_LENGTH)) return false;

    // Constant-time comparison to prevent timing side channels
    uint8_t diff = 0;
    for (int i = 0; i < SAS_PIN_LENGTH; ++i) {
        diff |= static_cast<uint8_t>(candidatePin[i]) ^ static_cast<uint8_t>(storedPin[i]);
    }
    return diff == 0;
}

int64_t FileTimeToUnixMs(FILETIME ft) {
    // FILETIME is in 100-ns intervals since Jan 1, 1601
    // Offset from 1601 to 1970 epoch = 116444736000000000 * 100ns
    uint64_t u64 = (static_cast<uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
    const uint64_t epochOffset = 116444736000000000ULL;
    if (u64 < epochOffset) return 0;
    return static_cast<int64_t>((u64 - epochOffset) / 10000);
}

} // namespace MobileUnlock::Pairing
