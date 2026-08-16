#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <rpc.h>

#include <array>
#include <string>
#include <cstdint>

namespace MobileUnlock::Pairing {

// 16-byte binary UUID as defined in PROTOCOL.md
using DeviceId = std::array<uint8_t, 16>;

// Converts a UUID to its 36-character hyphenated string representation
// Format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
std::string DeviceIdToString(const DeviceId& id);

// Parses a 36-character UUID string into binary DeviceId
// Returns false if the string is malformed
bool DeviceIdFromString(const std::string& str, DeviceId& outId);

// Generates a random DeviceId using BCryptGenRandom (via Windows CNG or RtlGenRandom fallback)
// Returns a zero-filled ID on failure (all zeros = invalid)
DeviceId GenerateDeviceId();

// Compares two device IDs for equality
bool DeviceIdEqual(const DeviceId& a, const DeviceId& b);

// Returns true if the device ID is all-zero (invalid/unset)
bool DeviceIdIsEmpty(const DeviceId& id);

} // namespace MobileUnlock::Pairing
