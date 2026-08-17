#pragma once

// ============================================================
// MobileFingerprintUnlock — Credential Provider CLSID
// Phase 7 — Windows Credential Provider (Test VM Only)
// ============================================================
// DO NOT register this DLL on the physical host machine.
// Registration is strictly limited to the dedicated Windows Test VM.
// ============================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#ifndef DECLSPEC_SELECTANY
#define DECLSPEC_SELECTANY __declspec(selectany)
#endif

// {A82D1234-5678-90AB-CDEF-1234567890AB}
// Matches the GUID already referenced in RECOVERY.md / EmergencyRecovery.ps1
EXTERN_C const GUID DECLSPEC_SELECTANY CLSID_MobileUnlockProvider =
    { 0xA82D1234, 0x5678, 0x90AB, { 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB } };

namespace MobileUnlock::CredentialProvider {

// ============================================================
// MOBILE_UNLOCK_PHASE7_BUFFER
//
// INTERNAL IPC structure exchanged between the Credential Provider
// background status thread and MobileUnlockService.
//
// THIS STRUCTURE IS NEVER PRESENTED TO WINLOGON.
// THIS STRUCTURE IS NEVER PLACED IN
//   CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION.
// THIS STRUCTURE IS NEVER ASSOCIATED WITH ulAuthenticationPackage.
//
// Phase 8 will introduce the custom LSA authentication package.
// Phase 9A will determine the exact serialization contract.
// ============================================================
#pragma pack(push, 1)
struct MOBILE_UNLOCK_PHASE7_BUFFER {
    uint32_t Magic;            // 0x4D554350 ('M','U','C','P')
    uint32_t Version;          // 7 (Phase 7)
    uint8_t  DeviceId[32];     // Device identity bytes from IPC state
    uint8_t  SessionNonce[32]; // Challenge nonce bytes from IPC state
    uint32_t Reserved;         // Must be 0
};
#pragma pack(pop)

static_assert(sizeof(MOBILE_UNLOCK_PHASE7_BUFFER) == 76,
    "MOBILE_UNLOCK_PHASE7_BUFFER must be exactly 76 bytes");

constexpr uint32_t PHASE7_BUFFER_MAGIC   = 0x4D554350u; // 'MUCP'
constexpr uint32_t PHASE7_BUFFER_VERSION = 7u;

// Field indices for the credential tile
constexpr DWORD FIELD_NAME   = 0; // CPFT_LARGE_TEXT — "MobileFingerprintUnlock"
constexpr DWORD FIELD_STATUS = 1; // CPFT_SMALL_TEXT — dynamic status string
constexpr DWORD FIELD_COUNT  = 2;

} // namespace MobileUnlock::CredentialProvider
