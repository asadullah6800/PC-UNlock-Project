#include <gtest/gtest.h>
#include "../configuration/ConfigurationManager.h"

using namespace MobileUnlock::Configuration;

TEST(ConfigurationTest, DefaultValidation) {
    AppConfig config;
    EXPECT_TRUE(ConfigurationManager::ValidateConfiguration(config));
}

TEST(ConfigurationTest, InvalidPortValidation) {
    AppConfig config;
    config.WifiPort = 0;
    EXPECT_FALSE(ConfigurationManager::ValidateConfiguration(config));
}

TEST(ConfigurationTest, InvalidTtlValidation) {
    AppConfig config;
    config.ChallengeTtlSeconds = 0;
    EXPECT_FALSE(ConfigurationManager::ValidateConfiguration(config));

    config.ChallengeTtlSeconds = 500; // > 300
    EXPECT_FALSE(ConfigurationManager::ValidateConfiguration(config));
}
