// ============================================================
// MobileFingerprintUnlock — LSA Authentication Package Engine
// Phase 8 — Custom LSA Authentication Package (Test VM Only)
// ============================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <sddl.h>
#include <cstring>
#include <new>

#include "LsaPackage.h"
#include "../../shared/protocol/SignedMessage.h"

namespace MobileUnlock::Lsa {

LsaPackage& LsaPackage::Instance() {
    static LsaPackage s_instance;
    return s_instance;
}

LsaPackage::LsaPackage()
    : m_packageId(0)
    , m_hasDispatchTable(false)
    , m_isInitialized(false)
{
    InitializeCriticalSection(&m_lock);
    std::memset(&m_dispatchTable, 0, sizeof(m_dispatchTable));
}

LsaPackage::~LsaPackage() {
    DeleteCriticalSection(&m_lock);
}

void LsaPackage::SetDispatchTableForTesting(PLSA_DISPATCH_TABLE dispatchTable) {
    EnterCriticalSection(&m_lock);
    if (dispatchTable) {
        m_dispatchTable = *dispatchTable;
        m_hasDispatchTable = true;
    } else {
        m_hasDispatchTable = false;
        std::memset(&m_dispatchTable, 0, sizeof(m_dispatchTable));
    }
    LeaveCriticalSection(&m_lock);
}

PVOID LsaPackage::AllocateHeap(ULONG length) {
    if (length == 0) return nullptr;

    if (m_hasDispatchTable && m_dispatchTable.AllocateLsaHeap) {
        return m_dispatchTable.AllocateLsaHeap(length);
    }
    // Fallback for user-mode unit testing harness
    return LocalAlloc(LPTR, length);
}

VOID LsaPackage::FreeHeap(PVOID base) {
    if (!base) return;

    if (m_hasDispatchTable && m_dispatchTable.FreeLsaHeap) {
        m_dispatchTable.FreeLsaHeap(base);
        return;
    }
    LocalFree(base);
}

PUNICODE_STRING LsaPackage::CreateUnicodeStringOnLsaHeap(const std::wstring& str) {
    ULONG cbBuffer = static_cast<ULONG>((str.length() + 1) * sizeof(WCHAR));
    ULONG cbTotal  = static_cast<ULONG>(sizeof(UNICODE_STRING) + cbBuffer);

    auto* pLsaStr = static_cast<PUNICODE_STRING>(AllocateHeap(cbTotal));
    if (!pLsaStr) return nullptr;

    auto* pBuf = reinterpret_cast<PWSTR>(reinterpret_cast<BYTE*>(pLsaStr) + sizeof(UNICODE_STRING));
    std::memcpy(pBuf, str.c_str(), str.length() * sizeof(WCHAR));
    pBuf[str.length()] = L'\0';

    pLsaStr->Length        = static_cast<USHORT>(str.length() * sizeof(WCHAR));
    pLsaStr->MaximumLength = static_cast<USHORT>(cbBuffer);
    pLsaStr->Buffer        = pBuf;

    return pLsaStr;
}

// ============================================================
// LsaApInitializePackage
// ============================================================

NTSTATUS LsaPackage::Initialize(
    ULONG authenticationPackageId,
    PLSA_DISPATCH_TABLE lsaDispatchTable,
    PLSA_STRING /*database*/,
    PLSA_STRING /*confidentiality*/,
    PLSA_STRING* authenticationPackageName)
{
    if (!authenticationPackageName) {
        return STATUS_INVALID_PARAMETER;
    }

    EnterCriticalSection(&m_lock);
    m_packageId = authenticationPackageId;

    if (lsaDispatchTable) {
        m_dispatchTable = *lsaDispatchTable;
        m_hasDispatchTable = true;
    }

    // Allocate package name LSA_STRING on LSA heap
    size_t nameLen = std::strlen(LSA_PACKAGE_NAME_A);
    ULONG cbBuffer = static_cast<ULONG>(nameLen + 1);
    ULONG cbTotal  = static_cast<ULONG>(sizeof(LSA_STRING) + cbBuffer);

    auto* pPkgName = static_cast<PLSA_STRING>(AllocateHeap(cbTotal));
    if (!pPkgName) {
        LeaveCriticalSection(&m_lock);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    auto* pBuf = reinterpret_cast<PCHAR>(reinterpret_cast<BYTE*>(pPkgName) + sizeof(LSA_STRING));
    std::memcpy(pBuf, LSA_PACKAGE_NAME_A, nameLen);
    pBuf[nameLen] = '\0';

    pPkgName->Length        = static_cast<USHORT>(nameLen);
    pPkgName->MaximumLength = static_cast<USHORT>(cbBuffer);
    pPkgName->Buffer        = pBuf;

    *authenticationPackageName = pPkgName;
    m_isInitialized = true;

    LeaveCriticalSection(&m_lock);
    return STATUS_SUCCESS;
}

// ============================================================
// LsaApLogonUserEx2
// ============================================================

NTSTATUS LsaPackage::LogonUserEx2(
    PLSA_CLIENT_REQUEST /*clientRequest*/,
    SECURITY_LOGON_TYPE /*logonType*/,
    PVOID protocolSubmitBuffer,
    PVOID /*clientBufferBase*/,
    ULONG submitBufferLength,
    PVOID* profileBuffer,
    PULONG profileBufferLength,
    PLUID /*logonId*/,
    PNTSTATUS subStatus,
    PLSA_TOKEN_INFORMATION_TYPE tokenInformationType,
    PVOID* tokenInformation,
    PUNICODE_STRING* accountName,
    PUNICODE_STRING* authenticatingAuthority,
    PUNICODE_STRING* machineName,
    PSECPKG_PRIMARY_CRED primaryCredentials,
    PSECPKG_SUPPLEMENTAL_CRED_ARRAY* supplementalCredentials)
{
    if (subStatus) *subStatus = STATUS_LOGON_FAILURE;
    if (profileBuffer) *profileBuffer = nullptr;
    if (profileBufferLength) *profileBufferLength = 0;
    if (tokenInformationType) *tokenInformationType = LsaTokenInformationNull;
    if (tokenInformation) *tokenInformation = nullptr;
    if (accountName) *accountName = nullptr;
    if (authenticatingAuthority) *authenticatingAuthority = nullptr;
    if (machineName) *machineName = nullptr;
    if (primaryCredentials) std::memset(primaryCredentials, 0, sizeof(SECPKG_PRIMARY_CRED));
    if (supplementalCredentials) *supplementalCredentials = nullptr;

    // 1. Validate submit buffer pointer and size
    if (!protocolSubmitBuffer) {
        if (subStatus) *subStatus = STATUS_INVALID_PARAMETER;
        return STATUS_INVALID_PARAMETER;
    }

    if (submitBufferLength < sizeof(MOBILE_UNLOCK_LSA_LOGON_BUFFER)) {
        if (subStatus) *subStatus = STATUS_BUFFER_TOO_SMALL;
        return STATUS_BUFFER_TOO_SMALL;
    }

    const auto* pBuf = static_cast<const MOBILE_UNLOCK_LSA_LOGON_BUFFER*>(protocolSubmitBuffer);

    // 2. Validate magic, version, and reserved fields
    if (pBuf->Magic != LSA_SUBMIT_BUFFER_MAGIC ||
        pBuf->Version != LSA_SUBMIT_BUFFER_VERSION ||
        pBuf->Reserved != 0) {
        if (subStatus) *subStatus = STATUS_INVALID_PARAMETER;
        return STATUS_INVALID_PARAMETER;
    }

    // 3. Deserialize and validate canonical signed message
    auto parseRes = Protocol::DeserializeSignedMessage(
        pBuf->CanonicalMessage, LSA_CANONICAL_MESSAGE_SIZE);
    if (!parseRes.has_value()) {
        if (subStatus) *subStatus = STATUS_INVALID_PARAMETER;
        return STATUS_INVALID_PARAMETER;
    }

    const auto& msg = parseRes.value;

    // Validate protocol version in signed message
    if (msg.ProtocolVersion != 0x0100) {
        if (subStatus) *subStatus = STATUS_INVALID_PARAMETER;
        return STATUS_INVALID_PARAMETER;
    }

    // Validate DeviceId in CanonicalMessage matches buffer DeviceId
    if (std::memcmp(msg.DeviceIdentity, pBuf->DeviceId, LSA_DEVICE_ID_SIZE) != 0) {
        if (subStatus) *subStatus = STATUS_LOGON_FAILURE;
        return STATUS_LOGON_FAILURE;
    }

    // Validate Operation opcode is AUTH_RESPONSE
    if (msg.Operation != static_cast<uint16_t>(Protocol::MessageType::AUTH_RESPONSE)) {
        if (subStatus) *subStatus = STATUS_LOGON_FAILURE;
        return STATUS_LOGON_FAILURE;
    }

    // 4. Resolve DeviceIdentity in DeviceRegistry
    //    DeviceId is std::array<uint8_t,16> — copy raw bytes from buffer
    Pairing::DeviceId devId;
    std::memcpy(devId.data(), pBuf->DeviceId, LSA_DEVICE_ID_SIZE);
    std::string devIdStr = Pairing::DeviceIdToString(devId);
    if (devIdStr.empty()) {
        if (subStatus) *subStatus = STATUS_INVALID_PARAMETER;
        return STATUS_INVALID_PARAMETER;
    }
    Pairing::DeviceRecord deviceRecord{};
    LONG regRes = Pairing::ReadDeviceRecord(devIdStr, deviceRecord);
    if (regRes != ERROR_SUCCESS) {
        if (subStatus) *subStatus = STATUS_NO_SUCH_USER;
        return STATUS_NO_SUCH_USER;
    }

    // Check device pair status (must be ACTIVE)
    if (deviceRecord.pairStatus != Pairing::kStatusActive) {
        if (subStatus) *subStatus = STATUS_ACCOUNT_RESTRICTION;
        return STATUS_ACCOUNT_RESTRICTION;
    }

    if (deviceRecord.publicKey.empty()) {
        if (subStatus) *subStatus = STATUS_LOGON_FAILURE;
        return STATUS_LOGON_FAILURE;
    }

    // 5. Cryptographic signature verification (local CNG ECDSA P-256)
    bool sigValid = Crypto::CryptoManager::VerifyCanonicalSignedMessage(
        deviceRecord.publicKey,
        msg,
        pBuf->Signature,
        LSA_SIGNATURE_SIZE);

    if (!sigValid) {
        if (subStatus) *subStatus = STATUS_LOGON_FAILURE;
        return STATUS_LOGON_FAILURE;
    }

    // 6. Account SID mapping resolution
    std::wstring targetUserName;
    if (!deviceRecord.accountSid.empty()) {
        // Resolve Account SID to username
        PSID pSid = nullptr;
        // MinGW's ConvertStringSidToSidA requires non-const LPSTR
        std::string sidCopy = deviceRecord.accountSid;
        if (ConvertStringSidToSidA(&sidCopy[0], &pSid)) {
            WCHAR nameBuf[256] = {0};
            DWORD cchName = 256;
            WCHAR domainBuf[256] = {0};
            DWORD cchDomain = 256;
            SID_NAME_USE use;

            if (LookupAccountSidW(nullptr, pSid, nameBuf, &cchName, domainBuf, &cchDomain, &use)) {
                targetUserName = nameBuf;
            }
            LocalFree(pSid);
        }
    }

    // Fallback: if SID lookup not available in test environment, use device name or fallback
    if (targetUserName.empty()) {
        if (!deviceRecord.deviceName.empty()) {
            targetUserName = std::wstring(deviceRecord.deviceName.begin(), deviceRecord.deviceName.end());
        } else {
            targetUserName = L"MobileUnlockUser";
        }
    }

    // 7. Allocate LSA output structures
    if (accountName) {
        *accountName = CreateUnicodeStringOnLsaHeap(targetUserName);
        if (!*accountName) {
            if (subStatus) *subStatus = STATUS_INSUFFICIENT_RESOURCES;
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    if (authenticatingAuthority) {
        *authenticatingAuthority = CreateUnicodeStringOnLsaHeap(AUTH_AUTHORITY_W);
        if (!*authenticatingAuthority) {
            if (accountName && *accountName) {
                FreeHeap(*accountName);
                *accountName = nullptr;
            }
            if (subStatus) *subStatus = STATUS_INSUFFICIENT_RESOURCES;
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    if (tokenInformationType) {
        *tokenInformationType = LsaTokenInformationNull; // Laboratory mode for Phase 8
    }

    if (subStatus) {
        *subStatus = STATUS_SUCCESS;
    }

    return STATUS_SUCCESS;
}

// ============================================================
// LsaApLogonTerminated
// ============================================================

VOID LsaPackage::LogonTerminated(PLUID /*logonId*/) {
    // No session state cleanup required in Phase 8
}

} // namespace MobileUnlock::Lsa
