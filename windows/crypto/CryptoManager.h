#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <vector>
#include <cstdint>
#include <cstddef>
#include <string>

#include "protocol/SignedMessage.h"

namespace MobileUnlock::Crypto {

// CNG Type definitions
typedef PVOID BCRYPT_ALG_HANDLE;
typedef PVOID BCRYPT_KEY_HANDLE;
typedef PVOID BCRYPT_HASH_HANDLE;

#pragma pack(push, 1)
typedef struct _BCRYPT_ECCKEY_BLOB {
    ULONG dwMagic;
    ULONG cbKey;
} BCRYPT_ECCKEY_BLOB;
#pragma pack(pop)

#ifndef BCRYPT_ECDSA_PUBLIC_P256_MAGIC
#define BCRYPT_ECDSA_PUBLIC_P256_MAGIC  0x31534345 // "ECS1"
#endif

#ifndef BCRYPT_ECDSA_PRIVATE_P256_MAGIC
#define BCRYPT_ECDSA_PRIVATE_P256_MAGIC 0x32534345 // "ECS2"
#endif

#ifndef BCRYPT_ECDSA_P256_ALGORITHM
#define BCRYPT_ECDSA_P256_ALGORITHM     L"ECDSA_P256"
#endif

#ifndef BCRYPT_SHA256_ALGORITHM
#define BCRYPT_SHA256_ALGORITHM         L"SHA256"
#endif

#ifndef BCRYPT_RNG_ALGORITHM
#define BCRYPT_RNG_ALGORITHM            L"RNG"
#endif

#ifndef BCRYPT_ECCPUBLIC_BLOB
#define BCRYPT_ECCPUBLIC_BLOB           L"ECCPUBLICBLOB"
#endif

#ifndef MS_PRIMITIVE_PROVIDER
#define MS_PRIMITIVE_PROVIDER           L"Microsoft Primitive Provider"
#endif

#ifndef BCRYPT_SUCCESS
#define BCRYPT_SUCCESS(Status)          (((LONG)(Status)) >= 0)
#endif

// Expected sizes
constexpr size_t P256_COORDINATE_SIZE   = 32;
constexpr size_t P256_RAW_POINT_SIZE    = 65; // 0x04 || X(32) || Y(32)
constexpr size_t P256_RAW_COORDS_SIZE   = 64; // X(32) || Y(32)
constexpr size_t BCRYPT_ECC_BLOB_SIZE   = sizeof(BCRYPT_ECCKEY_BLOB) + 2 * P256_COORDINATE_SIZE; // 72 bytes
constexpr size_t P1363_SIGNATURE_SIZE   = 64; // r(32) || s(32)
constexpr size_t SHA256_DIGEST_SIZE     = 32;

/**
 * Windows Cryptography Next Generation (CNG / BCrypt) Manager.
 * Handles ECDSA P-256 public-key import, SHA-256 hashing, CSPRNG, and signature verification.
 */
class CryptoManager {
public:
    static bool Initialize();
    static void Shutdown();
    static bool IsInitialized();

    /**
     * Generates cryptographically secure random bytes using Windows CNG.
     */
    static bool GenerateRandomBytes(uint8_t* buffer, size_t len);

    /**
     * Computes SHA-256 digest of input buffer.
     */
    static bool ComputeSha256(const uint8_t* data, size_t len, std::vector<uint8_t>& outDigest);

    /**
     * Normalizes any supported public key format (SPKI DER, 65B uncompressed point, 64B raw coords,
     * or existing 72B BCRYPT_ECCPUBLIC_BLOB) into canonical BCRYPT_ECCPUBLIC_BLOB (72 bytes).
     */
    static bool NormalizePublicKeyToEccBlob(const std::vector<uint8_t>& inputKey, std::vector<uint8_t>& outBlob);

    /**
     * Imports an ECDSA P-256 public key into a CNG BCRYPT_KEY_HANDLE.
     */
    static bool ImportPublicKey(const std::vector<uint8_t>& inputKey, BCRYPT_KEY_HANDLE* phKey);

    /**
     * Destroys a CNG key handle safely.
     */
    static void DestroyKey(BCRYPT_KEY_HANDLE hKey);

    /**
     * Validates and adapts a 64-byte IEEE P1363 (r || s) signature for CNG verification.
     */
    static bool ValidateAndAdaptSignature(const uint8_t* signature, size_t sigLen, std::vector<uint8_t>& outAdapted);

    /**
     * Verifies an ECDSA P-256 signature against an unhashed message (e.g. 88-byte canonical message).
     */
    static bool VerifySignature(BCRYPT_KEY_HANDLE hKey,
                                const uint8_t* message, size_t messageLen,
                                const uint8_t* signature, size_t sigLen);

    /**
     * High-level helper: verifies a Canonical SignedMessage struct against a public key buffer.
     */
    static bool VerifyCanonicalSignedMessage(const std::vector<uint8_t>& publicKey,
                                            const Protocol::SignedMessage& msg,
                                            const uint8_t* signature, size_t sigLen);

    // Helpers used by tests to generate CNG test keys and sign hashes
    static bool GenerateTestKeyPair(BCRYPT_KEY_HANDLE* phPrivKey, std::vector<uint8_t>& outPubBlob);
    static bool SignHashForTesting(BCRYPT_KEY_HANDLE hPrivKey, const uint8_t* hash, size_t hashLen, std::vector<uint8_t>& outSig);

private:
    static BCRYPT_ALG_HANDLE s_hEcdsaAlg;
    static BCRYPT_ALG_HANDLE s_hSha256Alg;
    static BCRYPT_ALG_HANDLE s_hRngAlg;
    static bool s_initialized;

    static bool ParseSpkiDer(const uint8_t* der, size_t derLen, std::vector<uint8_t>& outX, std::vector<uint8_t>& outY);
};

} // namespace MobileUnlock::Crypto
