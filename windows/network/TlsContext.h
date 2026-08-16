#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#define SECURITY_WIN32
#include <security.h>
#include <schannel.h>
#include <wincrypt.h>

#include <string>
#include <vector>
#include <memory>
#include <cstdint>

#ifndef SEC_E_UNSUPPORTED_PRE_SHAREDKEY
#define SEC_E_UNSUPPORTED_PRE_SHAREDKEY ((SECURITY_STATUS)0x8009034EL)
#endif
#ifndef SEC_E_ALGORITHM_MISMATCH
#define SEC_E_ALGORITHM_MISMATCH ((SECURITY_STATUS)0x80090331L)
#endif
#ifndef SEC_I_CONTEXT_EXPIRED
#define SEC_I_CONTEXT_EXPIRED ((SECURITY_STATUS)0x00090317L)
#endif

namespace MobileUnlock::Network {

enum class TlsStatus {
    SUCCESS,
    CONTINUE_NEEDED,
    INCOMPLETE_DATA,
    HANDSHAKE_FAILED,
    PROTOCOL_VERSION_REJECTED,
    CLOSED,
    ERROR_GENERAL
};

struct TlsConfig {
    bool EnableTls13{true};
    bool EnableTls12{false}; // Strict TLS 1.3 enforced: TLS 1.2 disabled
    bool RequireClientCert{false};
    std::wstring CertificateSubject{L"CN=MobileFingerprintUnlock"};
};

class TlsContext {
public:
    explicit TlsContext(const TlsConfig& config = TlsConfig{});
    ~TlsContext();

    TlsContext(const TlsContext&) = delete;
    TlsContext& operator=(const TlsContext&) = delete;

    // Initializes server credential handle using SChannel
    bool InitializeServerCredentials();

    // Acquire self-signed in-memory certificate for local secure transport if none in store
    bool EnsureServerCertificate();

    // Process incoming TLS handshake data from client (Server side)
    TlsStatus AcceptHandshake(const uint8_t* inData, size_t inLen, std::vector<uint8_t>& outData, size_t& bytesConsumed);

    // Encrypt application payload into TLS record
    TlsStatus EncryptPayload(const uint8_t* plainData, size_t plainLen, std::vector<uint8_t>& encryptedData);

    // Decrypt TLS record into plain application payload
    TlsStatus DecryptPayload(const uint8_t* encryptedData, size_t encryptedLen, std::vector<uint8_t>& plainData, size_t& bytesConsumed);

    bool IsHandshakeComplete() const noexcept { return m_handshakeComplete; }
    const TlsConfig& GetConfig() const noexcept { return m_config; }
    void Reset();

private:
    TlsConfig m_config;
    CredHandle m_hCreds;
    CtxtHandle m_hContext;
    PCCERT_CONTEXT m_pCertContext{nullptr};
    bool m_credsInitialized{false};
    bool m_contextInitialized{false};
    bool m_handshakeComplete{false};
    SecPkgContext_StreamSizes m_streamSizes{};
};

} // namespace MobileUnlock::Network
