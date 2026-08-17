#pragma once

// ============================================================
// MobileFingerprintUnlock — LSA Logon Submission Buffer
// Phase 8 — Custom LSA Authentication Package (Test VM Only)
// ============================================================
// Defines the authoritative wire buffer submitted to the LSA
// Authentication Package (via Winlogon / LsaLogonUser).
//
// This structure contains the exact information required by
// LsaApLogonUserEx2 to make an authoritative local authentication
// decision WITHOUT network communication from inside LSASS.
// ============================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>

namespace MobileUnlock::Lsa {

constexpr uint32_t LSA_SUBMIT_BUFFER_MAGIC   = 0x4D554C53u; // 'MULS' (Mobile Unlock LSA Submit)
constexpr uint32_t LSA_SUBMIT_BUFFER_VERSION = 1u;          // Version 1 (Phase 8 contract)

constexpr size_t LSA_DEVICE_ID_SIZE         = 16;
constexpr size_t LSA_CANONICAL_MESSAGE_SIZE = 88;
constexpr size_t LSA_SIGNATURE_SIZE         = 64;

#pragma pack(push, 1)
struct MOBILE_UNLOCK_LSA_LOGON_BUFFER {
    uint32_t Magic;                                   // 0x4D554C53 ('MULS')
    uint32_t Version;                                 // 1 (Phase 8 format)
    uint8_t  DeviceId[LSA_DEVICE_ID_SIZE];            // 128-bit Binary Device UUID
    uint32_t Reserved;                                // Must be 0
    uint8_t  CanonicalMessage[LSA_CANONICAL_MESSAGE_SIZE]; // Exact 88-byte canonical SignedMessage struct
    uint8_t  Signature[LSA_SIGNATURE_SIZE];           // 64-byte IEEE P1363 (r || s) ECDSA P-256 signature
};
#pragma pack(pop)

static_assert(sizeof(MOBILE_UNLOCK_LSA_LOGON_BUFFER) == 180,
    "MOBILE_UNLOCK_LSA_LOGON_BUFFER must be exactly 180 bytes");

} // namespace MobileUnlock::Lsa
