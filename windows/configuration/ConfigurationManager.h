#pragma once

#include <string>
#include <cstdint>
#include <memory>
#include <windows.h>
#include "../../shared/constants/BleConstants.h"

namespace MobileUnlock::Configuration {

struct AppConfig {
    uint16_t WifiPort{Constants::DEFAULT_WIFI_PORT};
    uint16_t MdnsPort{Constants::DEFAULT_MDNS_PORT};
    bool RequireFingerprintForLock{false};
    bool EnableBleDiscovery{true};
    bool EnableInternetRelay{false};
    uint32_t RateLimitMaxAttempts{5};
    uint32_t RateLimitWindowSeconds{60};
    uint32_t RateLimitBlockSeconds{900}; // 15 mins
    uint32_t ChallengeTtlSeconds{30};
    std::wstring ServicePipeName{Constants::SECURE_IPC_PIPE_NAME};
};

class ConfigurationManager {
public:
    ConfigurationManager();
    ~ConfigurationManager() = default;

    // Load configuration from registry (falls back to defaults if registry key missing)
    bool LoadConfiguration();

    // Save configuration to HKLM\SOFTWARE\MobileFingerprintUnlock\Settings
    bool SaveConfiguration(const AppConfig& config);

    // Validate configuration boundaries
    static bool ValidateConfiguration(const AppConfig& config);

    // Access current configuration
    const AppConfig& GetConfig() const noexcept { return m_config; }

private:
    AppConfig m_config;
};

} // namespace MobileUnlock::Configuration
