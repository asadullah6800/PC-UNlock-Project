#pragma once

#include <cstdint>

namespace MobileUnlock::Constants {

// Dedicated 128-bit Bluetooth Low Energy (BLE) UUID Definitions
constexpr const char* BLE_SERVICE_UUID           = "a4c95f10-1849-4180-a352-87db3d928200";
constexpr const char* BLE_STATUS_CHAR_UUID    = "a4c95f11-1849-4180-a352-87db3d928200";
constexpr const char* BLE_CHALLENGE_CHAR_UUID = "a4c95f12-1849-4180-a352-87db3d928200";
constexpr const char* BLE_RESPONSE_CHAR_UUID  = "a4c95f13-1849-4180-a352-87db3d928200";
constexpr const char* BLE_COMMAND_CHAR_UUID   = "a4c95f14-1849-4180-a352-87db3d928200";

// Default Network Configuration
constexpr uint16_t DEFAULT_WIFI_PORT = 8443;
constexpr uint16_t DEFAULT_MDNS_PORT = 8444;
constexpr const char* MDNS_SERVICE_TYPE = "_mobileunlock._tcp.local.";

// Registry Configuration Paths
constexpr const wchar_t* REG_KEY_DEVICES  = L"SOFTWARE\\MobileFingerprintUnlock\\Devices";
constexpr const wchar_t* REG_KEY_SETTINGS = L"SOFTWARE\\MobileFingerprintUnlock\\Settings";

// Secure Named Pipe Path
constexpr const wchar_t* SECURE_IPC_PIPE_NAME = L"\\\\.\\pipe\\MobileUnlockSecureIPC";

} // namespace MobileUnlock::Constants
