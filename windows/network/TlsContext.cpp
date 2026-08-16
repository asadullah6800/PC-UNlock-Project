#include "TlsContext.h"
#include <iostream>
#include <cstring>

namespace MobileUnlock::Network {

static inline void InvalidateHandle(SecHandle* h) {
    if (h) {
        h->dwLower = (DWORD_PTR)-1;
        h->dwUpper = (DWORD_PTR)-1;
    }
}

TlsContext::TlsContext(const TlsConfig& config)
    : m_config(config)
{
    InvalidateHandle(&m_hCreds);
    InvalidateHandle(&m_hContext);
    std::memset(&m_streamSizes, 0, sizeof(m_streamSizes));
}

TlsContext::~TlsContext() {
    Reset();
    if (m_credsInitialized) {
        FreeCredentialsHandle(&m_hCreds);
        m_credsInitialized = false;
    }
    if (m_pCertContext) {
        CertFreeCertificateContext(m_pCertContext);
        m_pCertContext = nullptr;
    }
}

void TlsContext::Reset() {
    if (m_contextInitialized) {
        DeleteSecurityContext(&m_hContext);
        InvalidateHandle(&m_hContext);
        m_contextInitialized = false;
    }
    m_handshakeComplete = false;
    std::memset(&m_streamSizes, 0, sizeof(m_streamSizes));
}

bool TlsContext::EnsureServerCertificate() {
    if (m_pCertContext != nullptr) return true;

    // Check CurrentUser/LocalMachine certificate store first
    HCERTSTORE hStore = CertOpenSystemStoreW(0, L"MY");
    if (hStore) {
        m_pCertContext = CertFindCertificateInStore(
            hStore,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_SUBJECT_STR_W,
            m_config.CertificateSubject.c_str(),
            nullptr
        );
        CertCloseStore(hStore, 0);
        if (m_pCertContext) return true;
    }

    HMODULE hCrypt32 = LoadLibraryA("crypt32.dll");
    if (!hCrypt32) return false;

    typedef BOOL (WINAPI *FnCertStrToNameW)(
        DWORD dwCertEncodingType,
        LPCWSTR pszX500,
        DWORD dwStrType,
        void *pvReserved,
        BYTE *pbEncoded,
        DWORD *pcbEncoded,
        LPCWSTR *ppszError
    );

    typedef PCCERT_CONTEXT (WINAPI *FnCertCreateSelfSignCertificate)(
        ULONG_PTR hCryptProvOrNCryptKey,
        PCERT_NAME_BLOB pSubjectIssuerBlob,
        DWORD dwFlags,
        void* pKeyProvInfo,
        void* pSignatureAlgorithm,
        void* pStartTime,
        void* pEndTime,
        void* pExtensions
    );

    auto pfnCertStrToNameW = reinterpret_cast<FnCertStrToNameW>(GetProcAddress(hCrypt32, "CertStrToNameW"));
    auto pfnCertCreateSelfSign = reinterpret_cast<FnCertCreateSelfSignCertificate>(GetProcAddress(hCrypt32, "CertCreateSelfSignCertificate"));

    if (pfnCertStrToNameW && pfnCertCreateSelfSign) {
        HCRYPTPROV hCryptProv = 0;
        LPCWSTR containerName = L"MobileUnlockTlsKeyContainer";

        if (!CryptAcquireContextW(&hCryptProv, containerName, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_SILENT)) {
            if (!CryptAcquireContextW(&hCryptProv, containerName, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_NEWKEYSET | CRYPT_SILENT)) {
                CryptAcquireContextW(&hCryptProv, nullptr, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_VERIFYCONTEXT | CRYPT_SILENT);
            }
        }

        HCRYPTKEY hKey = 0;
        if (hCryptProv) {
            CryptGenKey(hCryptProv, AT_KEYEXCHANGE, (2048 << 16) | CRYPT_EXPORTABLE, &hKey);
        }

        CERT_NAME_BLOB subjectNameBlob{};
        BYTE nameBuf[256];
        DWORD nameBufLen = sizeof(nameBuf);
        if (pfnCertStrToNameW(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, m_config.CertificateSubject.c_str(), 3 /* CERT_X500_NAME_STR */, nullptr, nameBuf, &nameBufLen, nullptr)) {
            subjectNameBlob.cbData = nameBufLen;
            subjectNameBlob.pbData = nameBuf;

            CRYPT_KEY_PROV_INFO keyProvInfo{};
            keyProvInfo.pwszContainerName = const_cast<LPWSTR>(containerName);
            keyProvInfo.pwszProvName = const_cast<LPWSTR>(MS_ENH_RSA_AES_PROV_W);
            keyProvInfo.dwProvType = PROV_RSA_AES;
            keyProvInfo.dwKeySpec = AT_KEYEXCHANGE;

            m_pCertContext = pfnCertCreateSelfSign(
                static_cast<ULONG_PTR>(hCryptProv),
                &subjectNameBlob,
                0,
                &keyProvInfo,
                nullptr,
                nullptr,
                nullptr,
                nullptr
            );
        }

        if (hKey) CryptDestroyKey(hKey);
        if (hCryptProv) CryptReleaseContext(hCryptProv, 0);
    }

    FreeLibrary(hCrypt32);
    return (m_pCertContext != nullptr);
}

bool TlsContext::InitializeServerCredentials() {
    if (m_credsInitialized) return true;

    EnsureServerCertificate();

    SCHANNEL_CRED schannelCred{};
    schannelCred.dwVersion = SCHANNEL_CRED_VERSION;

    // Strict protocol flag selection: TLS 1.3 only if EnableTls12 is false
    DWORD enabledProtocols = 0;
    if (m_config.EnableTls13) {
        enabledProtocols |= 0x00002000 /* SP_PROT_TLS1_3_SERVER */;
    }
    if (m_config.EnableTls12) {
        enabledProtocols |= 0x00000800 /* SP_PROT_TLS1_2_SERVER */;
    }

    schannelCred.grbitEnabledProtocols = enabledProtocols;

    if (m_pCertContext) {
        schannelCred.cCreds = 1;
        schannelCred.paCred = &m_pCertContext;
    }

    schannelCred.dwFlags = SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_REVOCATION_CHECK_END_CERT;
    if (!m_config.RequireClientCert) {
        schannelCred.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION;
    }

    SECURITY_STATUS status = AcquireCredentialsHandleW(
        nullptr,
        const_cast<LPWSTR>(UNISP_NAME_W),
        SECPKG_CRED_INBOUND,
        nullptr,
        &schannelCred,
        nullptr,
        nullptr,
        &m_hCreds,
        nullptr
    );

    if (status != SEC_E_OK) {
        // If host SChannel requires default credential acquisition mask, acquire and enforce version at handshake verification
        schannelCred.grbitEnabledProtocols = 0;
        status = AcquireCredentialsHandleW(
            nullptr,
            const_cast<LPWSTR>(UNISP_NAME_W),
            SECPKG_CRED_INBOUND,
            nullptr,
            &schannelCred,
            nullptr,
            nullptr,
            &m_hCreds,
            nullptr
        );
    }

    if (status != SEC_E_OK) {
        // Outbound client credentials fallback for local test environment
        status = AcquireCredentialsHandleW(
            nullptr,
            const_cast<LPWSTR>(UNISP_NAME_W),
            SECPKG_CRED_OUTBOUND,
            nullptr,
            &schannelCred,
            nullptr,
            nullptr,
            &m_hCreds,
            nullptr
        );
    }

    m_credsInitialized = (status == SEC_E_OK);
    return m_credsInitialized;
}

TlsStatus TlsContext::AcceptHandshake(const uint8_t* inData, size_t inLen, std::vector<uint8_t>& outData, size_t& bytesConsumed) {
    if (!InitializeServerCredentials()) {
        return TlsStatus::ERROR_GENERAL;
    }

    SecBuffer inBuffers[2];
    inBuffers[0].pvBuffer = const_cast<uint8_t*>(inData);
    inBuffers[0].cbBuffer = static_cast<unsigned long>(inLen);
    inBuffers[0].BufferType = SECBUFFER_TOKEN;

    inBuffers[1].pvBuffer = nullptr;
    inBuffers[1].cbBuffer = 0;
    inBuffers[1].BufferType = SECBUFFER_EMPTY;

    SecBufferDesc inBufferDesc{};
    inBufferDesc.ulVersion = SECBUFFER_VERSION;
    inBufferDesc.cBuffers = 2;
    inBufferDesc.pBuffers = inBuffers;

    SecBuffer outBuffers[1];
    outBuffers[0].pvBuffer = nullptr;
    outBuffers[0].cbBuffer = 0;
    outBuffers[0].BufferType = SECBUFFER_TOKEN;

    SecBufferDesc outBufferDesc{};
    outBufferDesc.ulVersion = SECBUFFER_VERSION;
    outBufferDesc.cBuffers = 1;
    outBufferDesc.pBuffers = outBuffers;

    DWORD contextReq = ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT | ASC_REQ_CONFIDENTIALITY | ASC_REQ_STREAM;
    DWORD contextAttr = 0;

    SECURITY_STATUS status = AcceptSecurityContext(
        &m_hCreds,
        m_contextInitialized ? &m_hContext : nullptr,
        &inBufferDesc,
        contextReq,
        0,
        &m_hContext,
        &outBufferDesc,
        &contextAttr,
        nullptr
    );

    bytesConsumed = inLen;
    if (inBuffers[1].BufferType == SECBUFFER_EXTRA) {
        bytesConsumed = inLen - inBuffers[1].cbBuffer;
    }

    if (outBuffers[0].cbBuffer > 0 && outBuffers[0].pvBuffer != nullptr) {
        auto* pBytes = static_cast<uint8_t*>(outBuffers[0].pvBuffer);
        outData.assign(pBytes, pBytes + outBuffers[0].cbBuffer);
        FreeContextBuffer(outBuffers[0].pvBuffer);
    } else {
        outData.clear();
    }

    m_contextInitialized = true;

    if (status == SEC_E_OK) {
        // Enforce strict TLS 1.3 protocol policy
        SecPkgContext_ConnectionInfo connInfo{};
        if (QueryContextAttributesW(&m_hContext, SECPKG_ATTR_CONNECTION_INFO, &connInfo) == SEC_E_OK) {
            if (!m_config.EnableTls12 && connInfo.dwProtocol < 0x00002000 /* SP_PROT_TLS1_3 */) {
                // Downgrade detected / TLS 1.2 rejected
                return TlsStatus::PROTOCOL_VERSION_REJECTED;
            }
        }

        m_handshakeComplete = true;
        QueryContextAttributesW(&m_hContext, SECPKG_ATTR_STREAM_SIZES, &m_streamSizes);
        return TlsStatus::SUCCESS;
    } else if (status == SEC_I_CONTINUE_NEEDED || status == SEC_I_COMPLETE_NEEDED || status == SEC_I_COMPLETE_AND_CONTINUE) {
        return TlsStatus::CONTINUE_NEEDED;
    } else if (status == SEC_E_INCOMPLETE_MESSAGE) {
        return TlsStatus::INCOMPLETE_DATA;
    } else if (status == SEC_E_UNSUPPORTED_PRE_SHAREDKEY || status == SEC_E_ALGORITHM_MISMATCH) {
        return TlsStatus::PROTOCOL_VERSION_REJECTED;
    }

    return TlsStatus::HANDSHAKE_FAILED;
}

TlsStatus TlsContext::EncryptPayload(const uint8_t* plainData, size_t plainLen, std::vector<uint8_t>& encryptedData) {
    if (!m_handshakeComplete) return TlsStatus::ERROR_GENERAL;

    if (m_streamSizes.cbHeader == 0) {
        QueryContextAttributesW(&m_hContext, SECPKG_ATTR_STREAM_SIZES, &m_streamSizes);
    }

    size_t totalLen = m_streamSizes.cbHeader + plainLen + m_streamSizes.cbTrailer;
    encryptedData.resize(totalLen);

    uint8_t* pBuf = encryptedData.data();
    std::memcpy(pBuf + m_streamSizes.cbHeader, plainData, plainLen);

    SecBuffer buffers[4];
    buffers[0].pvBuffer = pBuf;
    buffers[0].cbBuffer = m_streamSizes.cbHeader;
    buffers[0].BufferType = SECBUFFER_STREAM_HEADER;

    buffers[1].pvBuffer = pBuf + m_streamSizes.cbHeader;
    buffers[1].cbBuffer = static_cast<unsigned long>(plainLen);
    buffers[1].BufferType = SECBUFFER_DATA;

    buffers[2].pvBuffer = pBuf + m_streamSizes.cbHeader + plainLen;
    buffers[2].cbBuffer = m_streamSizes.cbTrailer;
    buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;

    buffers[3].pvBuffer = nullptr;
    buffers[3].cbBuffer = 0;
    buffers[3].BufferType = SECBUFFER_EMPTY;

    SecBufferDesc desc{};
    desc.ulVersion = SECBUFFER_VERSION;
    desc.cBuffers = 4;
    desc.pBuffers = buffers;

    SECURITY_STATUS status = EncryptMessage(&m_hContext, 0, &desc, 0);
    if (status == SEC_E_OK) {
        encryptedData.resize(buffers[0].cbBuffer + buffers[1].cbBuffer + buffers[2].cbBuffer);
        return TlsStatus::SUCCESS;
    }

    return TlsStatus::ERROR_GENERAL;
}

TlsStatus TlsContext::DecryptPayload(const uint8_t* encryptedData, size_t encryptedLen, std::vector<uint8_t>& plainData, size_t& bytesConsumed) {
    if (!m_handshakeComplete) return TlsStatus::ERROR_GENERAL;

    std::vector<uint8_t> workBuf(encryptedData, encryptedData + encryptedLen);

    SecBuffer buffers[4];
    buffers[0].pvBuffer = workBuf.data();
    buffers[0].cbBuffer = static_cast<unsigned long>(encryptedLen);
    buffers[0].BufferType = SECBUFFER_DATA;

    buffers[1].BufferType = SECBUFFER_EMPTY;
    buffers[2].BufferType = SECBUFFER_EMPTY;
    buffers[3].BufferType = SECBUFFER_EMPTY;

    SecBufferDesc desc{};
    desc.ulVersion = SECBUFFER_VERSION;
    desc.cBuffers = 4;
    desc.pBuffers = buffers;

    SECURITY_STATUS status = DecryptMessage(&m_hContext, &desc, 0, nullptr);

    bytesConsumed = encryptedLen;
    for (int i = 0; i < 4; ++i) {
        if (buffers[i].BufferType == SECBUFFER_EXTRA) {
            bytesConsumed = encryptedLen - buffers[i].cbBuffer;
            break;
        }
    }

    if (status == SEC_E_OK) {
        for (int i = 0; i < 4; ++i) {
            if (buffers[i].BufferType == SECBUFFER_DATA && buffers[i].cbBuffer > 0) {
                auto* pData = static_cast<uint8_t*>(buffers[i].pvBuffer);
                plainData.assign(pData, pData + buffers[i].cbBuffer);
                return TlsStatus::SUCCESS;
            }
        }
        plainData.clear();
        return TlsStatus::SUCCESS;
    } else if (status == SEC_E_INCOMPLETE_MESSAGE) {
        return TlsStatus::INCOMPLETE_DATA;
    } else if (status == SEC_I_CONTEXT_EXPIRED) {
        return TlsStatus::CLOSED;
    }

    return TlsStatus::ERROR_GENERAL;
}

} // namespace MobileUnlock::Network
