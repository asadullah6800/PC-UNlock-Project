#include "ConfigurationManager.h"
#include <iostream>

namespace MobileUnlock::Configuration {

ConfigurationManager::ConfigurationManager() {
    LoadConfiguration();
}

bool ConfigurationManager::ValidateConfiguration(const AppConfig& config) {
    if (config.WifiPort == 0 || config.MdnsPort == 0) {
        return false;
    }
    if (config.RateLimitMaxAttempts == 0 || config.RateLimitWindowSeconds == 0) {
        return false;
    }
    if (config.ChallengeTtlSeconds == 0 || config.ChallengeTtlSeconds > 300) {
        return false;
    }
    if (config.ServicePipeName.empty()) {
        return false;
    }
    return true;
}

bool ConfigurationManager::LoadConfiguration() {
    HKEY hKey = nullptr;
    LONG status = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        Constants::REG_KEY_SETTINGS,
        0,
        KEY_READ,
        &hKey
    );

    if (status != ERROR_SUCCESS) {
        // Registry key not present; use valid default configuration
        m_config = AppConfig{};
        return true;
    }

    DWORD dwType = 0;
    DWORD dwData = 0;
    DWORD cbData = sizeof(DWORD);

    if (RegQueryValueExW(hKey, L"WifiPort", nullptr, &dwType, reinterpret_cast<LPBYTE>(&dwData), &cbData) == ERROR_SUCCESS) {
        m_config.WifiPort = static_cast<uint16_t>(dwData);
    }
    if (RegQueryValueExW(hKey, L"RequireFingerprintForLock", nullptr, &dwType, reinterpret_cast<LPBYTE>(&dwData), &cbData) == ERROR_SUCCESS) {
        m_config.RequireFingerprintForLock = (dwData != 0);
    }
    if (RegQueryValueExW(hKey, L"EnableBleDiscovery", nullptr, &dwType, reinterpret_cast<LPBYTE>(&dwData), &cbData) == ERROR_SUCCESS) {
        m_config.EnableBleDiscovery = (dwData != 0);
    }

    RegCloseKey(hKey);
    return ValidateConfiguration(m_config);
}

bool ConfigurationManager::SaveConfiguration(const AppConfig& config) {
    if (!ValidateConfiguration(config)) {
        return false;
    }

    HKEY hKey = nullptr;
    DWORD dwDisposition = 0;
    LONG status = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,
        Constants::REG_KEY_SETTINGS,
        0,
        nullptr,
        REG_OPTION_NON_VOLATILE,
        KEY_WRITE,
        nullptr,
        &hKey,
        &dwDisposition
    );

    if (status != ERROR_SUCCESS) {
        return false;
    }

    DWORD dwPort = config.WifiPort;
    DWORD dwReqFingerprint = config.RequireFingerprintForLock ? 1 : 0;
    DWORD dwBle = config.EnableBleDiscovery ? 1 : 0;

    RegSetValueExW(hKey, L"WifiPort", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&dwPort), sizeof(DWORD));
    RegSetValueExW(hKey, L"RequireFingerprintForLock", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&dwReqFingerprint), sizeof(DWORD));
    RegSetValueExW(hKey, L"EnableBleDiscovery", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&dwBle), sizeof(DWORD));

    RegCloseKey(hKey);
    m_config = config;
    return true;
}

} // namespace MobileUnlock::Configuration
