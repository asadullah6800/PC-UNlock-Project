#include "CryptoManager.h"
#include <cstring>
#include <algorithm>

namespace MobileUnlock::Crypto {

// Typedefs for dynamic BCrypt API bindings
typedef LONG (WINAPI *pfnBCryptOpenAlgorithmProvider)(BCRYPT_ALG_HANDLE*, LPCWSTR, LPCWSTR, ULONG);
typedef LONG (WINAPI *pfnBCryptCloseAlgorithmProvider)(BCRYPT_ALG_HANDLE, ULONG);
typedef LONG (WINAPI *pfnBCryptGenRandom)(BCRYPT_ALG_HANDLE, PUCHAR, ULONG, ULONG);
typedef LONG (WINAPI *pfnBCryptCreateHash)(BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
typedef LONG (WINAPI *pfnBCryptHashData)(BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
typedef LONG (WINAPI *pfnBCryptFinishHash)(BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
typedef LONG (WINAPI *pfnBCryptDestroyHash)(BCRYPT_HASH_HANDLE);
typedef LONG (WINAPI *pfnBCryptImportKeyPair)(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE, LPCWSTR, BCRYPT_KEY_HANDLE*, PUCHAR, ULONG, ULONG);
typedef LONG (WINAPI *pfnBCryptDestroyKey)(BCRYPT_KEY_HANDLE);
typedef LONG (WINAPI *pfnBCryptVerifySignature)(BCRYPT_KEY_HANDLE, VOID*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
typedef LONG (WINAPI *pfnBCryptGenerateKeyPair)(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE*, ULONG, ULONG);
typedef LONG (WINAPI *pfnBCryptFinalizeKeyPair)(BCRYPT_KEY_HANDLE, ULONG);
typedef LONG (WINAPI *pfnBCryptExportKey)(BCRYPT_KEY_HANDLE, BCRYPT_KEY_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG*, ULONG);
typedef LONG (WINAPI *pfnBCryptSignHash)(BCRYPT_KEY_HANDLE, VOID*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG);

static pfnBCryptOpenAlgorithmProvider  fnBCryptOpenAlgorithmProvider  = nullptr;
static pfnBCryptCloseAlgorithmProvider fnBCryptCloseAlgorithmProvider = nullptr;
static pfnBCryptGenRandom              fnBCryptGenRandom              = nullptr;
static pfnBCryptCreateHash             fnBCryptCreateHash             = nullptr;
static pfnBCryptHashData               fnBCryptHashData               = nullptr;
static pfnBCryptFinishHash             fnBCryptFinishHash             = nullptr;
static pfnBCryptDestroyHash            fnBCryptDestroyHash            = nullptr;
static pfnBCryptImportKeyPair          fnBCryptImportKeyPair          = nullptr;
static pfnBCryptDestroyKey             fnBCryptDestroyKey             = nullptr;
static pfnBCryptVerifySignature        fnBCryptVerifySignature        = nullptr;
static pfnBCryptGenerateKeyPair        fnBCryptGenerateKeyPair        = nullptr;
static pfnBCryptFinalizeKeyPair        fnBCryptFinalizeKeyPair        = nullptr;
static pfnBCryptExportKey              fnBCryptExportKey              = nullptr;
static pfnBCryptSignHash               fnBCryptSignHash               = nullptr;

static HMODULE    s_hBcryptDll = nullptr;  // module-level; accessible to LoadBcryptFunctions
BCRYPT_ALG_HANDLE CryptoManager::s_hEcdsaAlg   = nullptr;
BCRYPT_ALG_HANDLE CryptoManager::s_hSha256Alg  = nullptr;
BCRYPT_ALG_HANDLE CryptoManager::s_hRngAlg     = nullptr;
bool              CryptoManager::s_initialized = false;

static bool LoadBcryptFunctions() {
    if (!s_hBcryptDll) {
        s_hBcryptDll = LoadLibraryW(L"bcrypt.dll");
        if (!s_hBcryptDll) return false;
    }

    fnBCryptOpenAlgorithmProvider  = (pfnBCryptOpenAlgorithmProvider)GetProcAddress(s_hBcryptDll, "BCryptOpenAlgorithmProvider");
    fnBCryptCloseAlgorithmProvider = (pfnBCryptCloseAlgorithmProvider)GetProcAddress(s_hBcryptDll, "BCryptCloseAlgorithmProvider");
    fnBCryptGenRandom              = (pfnBCryptGenRandom)GetProcAddress(s_hBcryptDll, "BCryptGenRandom");
    fnBCryptCreateHash             = (pfnBCryptCreateHash)GetProcAddress(s_hBcryptDll, "BCryptCreateHash");
    fnBCryptHashData               = (pfnBCryptHashData)GetProcAddress(s_hBcryptDll, "BCryptHashData");
    fnBCryptFinishHash             = (pfnBCryptFinishHash)GetProcAddress(s_hBcryptDll, "BCryptFinishHash");
    fnBCryptDestroyHash            = (pfnBCryptDestroyHash)GetProcAddress(s_hBcryptDll, "BCryptDestroyHash");
    fnBCryptImportKeyPair          = (pfnBCryptImportKeyPair)GetProcAddress(s_hBcryptDll, "BCryptImportKeyPair");
    fnBCryptDestroyKey             = (pfnBCryptDestroyKey)GetProcAddress(s_hBcryptDll, "BCryptDestroyKey");
    fnBCryptVerifySignature        = (pfnBCryptVerifySignature)GetProcAddress(s_hBcryptDll, "BCryptVerifySignature");
    fnBCryptGenerateKeyPair        = (pfnBCryptGenerateKeyPair)GetProcAddress(s_hBcryptDll, "BCryptGenerateKeyPair");
    fnBCryptFinalizeKeyPair        = (pfnBCryptFinalizeKeyPair)GetProcAddress(s_hBcryptDll, "BCryptFinalizeKeyPair");
    fnBCryptExportKey              = (pfnBCryptExportKey)GetProcAddress(s_hBcryptDll, "BCryptExportKey");
    fnBCryptSignHash               = (pfnBCryptSignHash)GetProcAddress(s_hBcryptDll, "BCryptSignHash");

    return (fnBCryptOpenAlgorithmProvider && fnBCryptCloseAlgorithmProvider &&
            fnBCryptGenRandom && fnBCryptCreateHash && fnBCryptHashData &&
            fnBCryptFinishHash && fnBCryptDestroyHash && fnBCryptImportKeyPair &&
            fnBCryptDestroyKey && fnBCryptVerifySignature);
}

bool CryptoManager::Initialize() {
    if (s_initialized) {
        return true;
    }

    if (!LoadBcryptFunctions()) {
        return false;
    }

    LONG status;

    // 1. Open ECDSA P-256 algorithm provider
    status = fnBCryptOpenAlgorithmProvider(&s_hEcdsaAlg, BCRYPT_ECDSA_P256_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);
    if (!BCRYPT_SUCCESS(status)) {
        Shutdown();
        return false;
    }

    // 2. Open SHA-256 algorithm provider
    status = fnBCryptOpenAlgorithmProvider(&s_hSha256Alg, BCRYPT_SHA256_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);
    if (!BCRYPT_SUCCESS(status)) {
        Shutdown();
        return false;
    }

    // 3. Open RNG algorithm provider
    status = fnBCryptOpenAlgorithmProvider(&s_hRngAlg, BCRYPT_RNG_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);
    if (!BCRYPT_SUCCESS(status)) {
        Shutdown();
        return false;
    }

    s_initialized = true;
    return true;
}

void CryptoManager::Shutdown() {
    if (s_hEcdsaAlg && fnBCryptCloseAlgorithmProvider) {
        fnBCryptCloseAlgorithmProvider(s_hEcdsaAlg, 0);
        s_hEcdsaAlg = nullptr;
    }
    if (s_hSha256Alg && fnBCryptCloseAlgorithmProvider) {
        fnBCryptCloseAlgorithmProvider(s_hSha256Alg, 0);
        s_hSha256Alg = nullptr;
    }
    if (s_hRngAlg && fnBCryptCloseAlgorithmProvider) {
        fnBCryptCloseAlgorithmProvider(s_hRngAlg, 0);
        s_hRngAlg = nullptr;
    }
    if (s_hBcryptDll) {
        FreeLibrary(s_hBcryptDll);
        s_hBcryptDll = nullptr;
    }
    s_initialized = false;
}

bool CryptoManager::IsInitialized() {
    return s_initialized;
}

bool CryptoManager::GenerateRandomBytes(uint8_t* buffer, size_t len) {
    if (!buffer || len == 0) return false;
    if (!s_initialized && !Initialize()) return false;

    LONG status = fnBCryptGenRandom(s_hRngAlg, buffer, static_cast<ULONG>(len), 0);
    return BCRYPT_SUCCESS(status);
}

bool CryptoManager::ComputeSha256(const uint8_t* data, size_t len, std::vector<uint8_t>& outDigest) {
    if (!s_initialized && !Initialize()) return false;

    outDigest.resize(SHA256_DIGEST_SIZE);

    BCRYPT_HASH_HANDLE hHash = nullptr;
    LONG status = fnBCryptCreateHash(s_hSha256Alg, &hHash, nullptr, 0, nullptr, 0, 0);
    if (!BCRYPT_SUCCESS(status)) {
        return false;
    }

    if (data && len > 0) {
        status = fnBCryptHashData(hHash, const_cast<PUCHAR>(data), static_cast<ULONG>(len), 0);
        if (!BCRYPT_SUCCESS(status)) {
            fnBCryptDestroyHash(hHash);
            return false;
        }
    }

    status = fnBCryptFinishHash(hHash, outDigest.data(), static_cast<ULONG>(outDigest.size()), 0);
    fnBCryptDestroyHash(hHash);

    return BCRYPT_SUCCESS(status);
}

bool CryptoManager::ParseSpkiDer(const uint8_t* der, size_t derLen, std::vector<uint8_t>& outX, std::vector<uint8_t>& outY) {
    if (!der || derLen < 30) return false;

    size_t offset = 0;

    // 1. Root SEQUENCE
    if (der[offset++] != 0x30) return false;

    // Skip root length
    if (offset >= derLen) return false;
    if (der[offset] & 0x80) {
        size_t numLenBytes = der[offset++] & 0x7F;
        if (offset + numLenBytes > derLen) return false;
        offset += numLenBytes;
    } else {
        offset++;
    }

    // 2. AlgorithmIdentifier SEQUENCE
    if (offset >= derLen || der[offset++] != 0x30) return false;
    size_t algSeqLen = 0;
    if (der[offset] & 0x80) {
        size_t numLenBytes = der[offset++] & 0x7F;
        if (offset + numLenBytes > derLen) return false;
        for (size_t i = 0; i < numLenBytes; i++) {
            algSeqLen = (algSeqLen << 8) | der[offset++];
        }
    } else {
        algSeqLen = der[offset++];
    }
    offset += algSeqLen;
    if (offset >= derLen) return false;

    // 3. SubjectPublicKey BIT STRING (tag 0x03)
    if (der[offset++] != 0x03) return false;
    size_t bitStrLen = 0;
    if (offset >= derLen) return false;
    if (der[offset] & 0x80) {
        size_t numLenBytes = der[offset++] & 0x7F;
        if (offset + numLenBytes > derLen) return false;
        for (size_t i = 0; i < numLenBytes; i++) {
            bitStrLen = (bitStrLen << 8) | der[offset++];
        }
    } else {
        bitStrLen = der[offset++];
    }

    if (offset + bitStrLen > derLen || bitStrLen < 66) return false;

    // First byte of BIT STRING payload is unused bits (must be 0x00)
    uint8_t unusedBits = der[offset++];
    if (unusedBits != 0x00) return false;

    // Point format must be uncompressed (0x04)
    uint8_t pointFormat = der[offset++];
    if (pointFormat != 0x04) return false;

    // Next 32 bytes: X, following 32 bytes: Y
    if (offset + 2 * P256_COORDINATE_SIZE > derLen) return false;

    outX.assign(der + offset, der + offset + P256_COORDINATE_SIZE);
    offset += P256_COORDINATE_SIZE;
    outY.assign(der + offset, der + offset + P256_COORDINATE_SIZE);

    return true;
}

bool CryptoManager::NormalizePublicKeyToEccBlob(const std::vector<uint8_t>& inputKey, std::vector<uint8_t>& outBlob) {
    if (inputKey.empty()) return false;

    // Case 1: Already BCRYPT_ECCKEY_BLOB (72 bytes)
    if (inputKey.size() == BCRYPT_ECC_BLOB_SIZE) {
        const BCRYPT_ECCKEY_BLOB* header = reinterpret_cast<const BCRYPT_ECCKEY_BLOB*>(inputKey.data());
        if (header->dwMagic == BCRYPT_ECDSA_PUBLIC_P256_MAGIC && header->cbKey == P256_COORDINATE_SIZE) {
            outBlob = inputKey;
            return true;
        }
    }

    // Case 2: Raw 64 bytes (X || Y)
    if (inputKey.size() == P256_RAW_COORDS_SIZE) {
        outBlob.resize(BCRYPT_ECC_BLOB_SIZE);
        BCRYPT_ECCKEY_BLOB* header = reinterpret_cast<BCRYPT_ECCKEY_BLOB*>(outBlob.data());
        header->dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
        header->cbKey   = static_cast<ULONG>(P256_COORDINATE_SIZE);
        std::memcpy(outBlob.data() + sizeof(BCRYPT_ECCKEY_BLOB), inputKey.data(), P256_RAW_COORDS_SIZE);
        return true;
    }

    // Case 3: Raw 65 bytes uncompressed point (0x04 || X || Y)
    if (inputKey.size() == P256_RAW_POINT_SIZE && inputKey[0] == 0x04) {
        outBlob.resize(BCRYPT_ECC_BLOB_SIZE);
        BCRYPT_ECCKEY_BLOB* header = reinterpret_cast<BCRYPT_ECCKEY_BLOB*>(outBlob.data());
        header->dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
        header->cbKey   = static_cast<ULONG>(P256_COORDINATE_SIZE);
        std::memcpy(outBlob.data() + sizeof(BCRYPT_ECCKEY_BLOB), inputKey.data() + 1, P256_RAW_COORDS_SIZE);
        return true;
    }

    // Case 4: ASN.1 DER SubjectPublicKeyInfo
    if (inputKey[0] == 0x30) {
        std::vector<uint8_t> x, y;
        if (ParseSpkiDer(inputKey.data(), inputKey.size(), x, y)) {
            outBlob.resize(BCRYPT_ECC_BLOB_SIZE);
            BCRYPT_ECCKEY_BLOB* header = reinterpret_cast<BCRYPT_ECCKEY_BLOB*>(outBlob.data());
            header->dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
            header->cbKey   = static_cast<ULONG>(P256_COORDINATE_SIZE);
            std::memcpy(outBlob.data() + sizeof(BCRYPT_ECCKEY_BLOB), x.data(), P256_COORDINATE_SIZE);
            std::memcpy(outBlob.data() + sizeof(BCRYPT_ECCKEY_BLOB) + P256_COORDINATE_SIZE, y.data(), P256_COORDINATE_SIZE);
            return true;
        }
    }

    return false;
}

bool CryptoManager::ImportPublicKey(const std::vector<uint8_t>& inputKey, BCRYPT_KEY_HANDLE* phKey) {
    if (!phKey) return false;
    *phKey = nullptr;

    if (!s_initialized && !Initialize()) return false;

    std::vector<uint8_t> eccBlob;
    if (!NormalizePublicKeyToEccBlob(inputKey, eccBlob)) {
        return false;
    }

    LONG status = fnBCryptImportKeyPair(
        s_hEcdsaAlg,
        nullptr,
        BCRYPT_ECCPUBLIC_BLOB,
        phKey,
        eccBlob.data(),
        static_cast<ULONG>(eccBlob.size()),
        0
    );

    return BCRYPT_SUCCESS(status);
}

void CryptoManager::DestroyKey(BCRYPT_KEY_HANDLE hKey) {
    if (hKey && fnBCryptDestroyKey) {
        fnBCryptDestroyKey(hKey);
    }
}

bool CryptoManager::ValidateAndAdaptSignature(const uint8_t* signature, size_t sigLen, std::vector<uint8_t>& outAdapted) {
    if (!signature || sigLen != P1363_SIGNATURE_SIZE) {
        return false;
    }

    // Split r (32 bytes) and s (32 bytes)
    const uint8_t* r = signature;
    const uint8_t* s = signature + P256_COORDINATE_SIZE;

    // Validate that r is not all zeros
    bool rNonZero = false;
    for (size_t i = 0; i < P256_COORDINATE_SIZE; i++) {
        if (r[i] != 0) {
            rNonZero = true;
            break;
        }
    }
    if (!rNonZero) return false;

    // Validate that s is not all zeros
    bool sNonZero = false;
    for (size_t i = 0; i < P256_COORDINATE_SIZE; i++) {
        if (s[i] != 0) {
            sNonZero = true;
            break;
        }
    }
    if (!sNonZero) return false;

    outAdapted.assign(signature, signature + P1363_SIGNATURE_SIZE);
    return true;
}

bool CryptoManager::VerifySignature(BCRYPT_KEY_HANDLE hKey,
                                    const uint8_t* message, size_t messageLen,
                                    const uint8_t* signature, size_t sigLen) {
    if (!hKey || !message || messageLen == 0 || !signature || sigLen != P1363_SIGNATURE_SIZE) {
        return false;
    }

    // 1. Compute SHA-256 digest of canonical message
    std::vector<uint8_t> digest;
    if (!ComputeSha256(message, messageLen, digest)) {
        return false;
    }

    // 2. Validate and adapt signature format
    std::vector<uint8_t> adaptedSig;
    if (!ValidateAndAdaptSignature(signature, sigLen, adaptedSig)) {
        return false;
    }

    // 3. Verify signature using Windows CNG
    LONG status = fnBCryptVerifySignature(
        hKey,
        nullptr,
        digest.data(),
        static_cast<ULONG>(digest.size()),
        adaptedSig.data(),
        static_cast<ULONG>(adaptedSig.size()),
        0
    );

    return BCRYPT_SUCCESS(status);
}

bool CryptoManager::VerifyCanonicalSignedMessage(const std::vector<uint8_t>& publicKey,
                                                const Protocol::SignedMessage& msg,
                                                const uint8_t* signature, size_t sigLen) {
    BCRYPT_KEY_HANDLE hKey = nullptr;
    if (!ImportPublicKey(publicKey, &hKey)) {
        return false;
    }

    std::vector<uint8_t> serializedMsg = Protocol::SerializeSignedMessage(msg);
    if (serializedMsg.size() != Protocol::CANONICAL_SIGNED_MESSAGE_SIZE) {
        DestroyKey(hKey);
        return false;
    }

    bool valid = VerifySignature(hKey, serializedMsg.data(), serializedMsg.size(), signature, sigLen);
    DestroyKey(hKey);
    return valid;
}

bool CryptoManager::GenerateTestKeyPair(BCRYPT_KEY_HANDLE* phPrivKey, std::vector<uint8_t>& outPubBlob) {
    if (!phPrivKey) return false;
    *phPrivKey = nullptr;

    if (!s_initialized && !Initialize()) return false;
    if (!fnBCryptGenerateKeyPair || !fnBCryptFinalizeKeyPair || !fnBCryptExportKey) return false;

    LONG status = fnBCryptGenerateKeyPair(s_hEcdsaAlg, phPrivKey, 256, 0);
    if (!BCRYPT_SUCCESS(status)) return false;

    status = fnBCryptFinalizeKeyPair(*phPrivKey, 0);
    if (!BCRYPT_SUCCESS(status)) {
        DestroyKey(*phPrivKey);
        *phPrivKey = nullptr;
        return false;
    }

    ULONG blobLen = 0;
    status = fnBCryptExportKey(*phPrivKey, nullptr, BCRYPT_ECCPUBLIC_BLOB, nullptr, 0, &blobLen, 0);
    if (!BCRYPT_SUCCESS(status) || blobLen != BCRYPT_ECC_BLOB_SIZE) {
        DestroyKey(*phPrivKey);
        *phPrivKey = nullptr;
        return false;
    }

    outPubBlob.resize(blobLen);
    status = fnBCryptExportKey(*phPrivKey, nullptr, BCRYPT_ECCPUBLIC_BLOB, outPubBlob.data(), blobLen, &blobLen, 0);
    if (!BCRYPT_SUCCESS(status)) {
        DestroyKey(*phPrivKey);
        *phPrivKey = nullptr;
        return false;
    }

    return true;
}

bool CryptoManager::SignHashForTesting(BCRYPT_KEY_HANDLE hPrivKey, const uint8_t* hash, size_t hashLen, std::vector<uint8_t>& outSig) {
    if (!hPrivKey || !hash || hashLen == 0 || !fnBCryptSignHash) return false;

    ULONG sigLen = 0;
    LONG status = fnBCryptSignHash(hPrivKey, nullptr, const_cast<PUCHAR>(hash), static_cast<ULONG>(hashLen), nullptr, 0, &sigLen, 0);
    if (!BCRYPT_SUCCESS(status) || sigLen != P1363_SIGNATURE_SIZE) return false;

    outSig.resize(sigLen);
    status = fnBCryptSignHash(hPrivKey, nullptr, const_cast<PUCHAR>(hash), static_cast<ULONG>(hashLen), outSig.data(), sigLen, &sigLen, 0);
    return BCRYPT_SUCCESS(status);
}

} // namespace MobileUnlock::Crypto
