cmake_minimum_required(VERSION 3.22)
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)
project(MobileFingerprintUnlock VERSION 1.0.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)

add_compile_definitions(
    _WIN32_WINNT=0x0600
    WINVER=0x0600
    WIN32_LEAN_AND_MEAN
    UNICODE
    _UNICODE
    _MAX_PATH=260
    _OUT_TO_STDERR=2
)

if(MSVC)
    add_compile_options(/W4 /EHsc /permissive-)
elseif(CMAKE_COMPILER_IS_GNUCXX)
    add_compile_options(-Wall -Wextra)
endif()

# Fetch GoogleTest
include(FetchContent)
set(FETCHCONTENT_UPDATES_DISCONNECTED ON)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/refs/tags/release-1.11.0.zip
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
set(gtest_disable_pthreads ON CACHE BOOL "" FORCE)
set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

if(TARGET gtest)
    set_target_properties(gtest gtest_main PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON CXX_EXTENSIONS ON)
endif()

# Common shared files
set(SHARED_HEADERS
    shared/protocol/ProtocolTypes.h
    shared/protocol/SignedMessage.h
    shared/constants/BleConstants.h
)

# Common Windows library sources
set(WINDOWS_COMMON_SOURCES
    windows/configuration/ConfigurationManager.cpp
    windows/configuration/ConfigurationManager.h
    windows/logging/SecurityAuditLogger.cpp
    windows/logging/SecurityAuditLogger.h
    windows/diagnostics/DiagnosticManager.cpp
    windows/diagnostics/DiagnosticManager.h
    windows/ipc/SecureIPC.cpp
    windows/ipc/SecureIPC.h
    windows/network/TlsContext.cpp
    windows/network/TlsContext.h
    windows/network/NetworkEngine.cpp
    windows/network/NetworkEngine.h
    windows/network/MdnsResponder.cpp
    windows/network/MdnsResponder.h
    windows/pairing/DeviceIdentity.cpp
    windows/pairing/DeviceIdentity.h
    windows/pairing/SasPin.cpp
    windows/pairing/SasPin.h
    windows/pairing/DeviceRegistry.cpp
    windows/pairing/DeviceRegistry.h
    windows/pairing/PairingManager.cpp
    windows/pairing/PairingManager.h
    windows/crypto/CryptoManager.cpp
    windows/crypto/CryptoManager.h
    windows/authentication/AuthenticationManager.cpp
    windows/authentication/AuthenticationManager.h
)

add_library(MobileUnlockCommon STATIC ${WINDOWS_COMMON_SOURCES} ${SHARED_HEADERS})
target_include_directories(MobileUnlockCommon PUBLIC windows shared)
target_link_libraries(MobileUnlockCommon PUBLIC advapi32 wtsapi32 shell32 ws2_32 crypt32 secur32)

# Target 1: MobileUnlockService
add_executable(MobileUnlockService
    windows/service/main.cpp
    windows/service/MobileUnlockService.cpp
    windows/service/MobileUnlockService.h
)
target_link_libraries(MobileUnlockService PRIVATE MobileUnlockCommon)

# Target 2: UserSessionAgent
add_executable(UserSessionAgent
    windows/user_session_agent/main.cpp
    windows/user_session_agent/UserSessionAgent.cpp
    windows/user_session_agent/UserSessionAgent.h
)
target_link_libraries(UserSessionAgent PRIVATE MobileUnlockCommon)

# Target 3: GoogleTest Test Executable
enable_testing()
add_executable(MobileUnlockTests
    windows/tests/main.cpp
    windows/tests/ProtocolTest.cpp
    windows/tests/ConfigurationTest.cpp
    windows/tests/IPCTest.cpp
    windows/tests/NetworkEngineTest.cpp
    windows/tests/MdnsTest.cpp
    windows/tests/PairingTest.cpp
    windows/tests/CryptoManagerTest.cpp
    windows/tests/AuthenticationManagerTest.cpp
    windows/tests/DeterministicInteroperabilityTest.cpp
)
target_link_libraries(MobileUnlockTests PRIVATE MobileUnlockCommon gtest gtest_main)

include(GoogleTest)
gtest_discover_tests(MobileUnlockTests)
