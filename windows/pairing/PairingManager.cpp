#include "PairingManager.h"
#include <map>
#include <vector>
#include <cstring>
#include <cstdio>
#include <sstream>
#include <sddl.h>

namespace MobileUnlock::Pairing {

static inline void SafeZeroMem(void* ptr, size_t len) {
    if (!ptr || len == 0) return;
    volatile char* p = static_cast<volatile char*>(ptr);
    while (len--) {
        *p++ = 0;
    }
}

// ---------------------------------------------------------------------------
// Simple JSON helpers (no external lib)
// ---------------------------------------------------------------------------
static std::string JsonGetString(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return "";
    pos += search.size();
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == ':')) ++pos;
    if (pos >= json.size() || json[pos] != '"') return "";
    ++pos;
    std::string val;
    while (pos < json.size() && json[pos] != '"') {
        val += json[pos++];
    }
    return val;
}

static std::vector<uint8_t> HexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    if (hex.size() % 2 != 0) return bytes;
    for (size_t i = 0; i < hex.size(); i += 2) {
        unsigned int byte = 0;
        if (std::sscanf(hex.c_str() + i, "%02x", &byte) != 1) return bytes;
        bytes.push_back(static_cast<uint8_t>(byte));
    }
    return bytes;
}

// ---------------------------------------------------------------------------
// Payload parse/build
// ---------------------------------------------------------------------------
PairRequestPayload ParsePairRequest(const std::vector<uint8_t>& payloadBytes) {
    PairRequestPayload req;
    if (payloadBytes.empty()) return req;

    std::string json(payloadBytes.begin(), payloadBytes.end());
    req.deviceId   = JsonGetString(json, "deviceId");
    req.deviceName = JsonGetString(json, "deviceName");
    std::string pkHex = JsonGetString(json, "publicKey");
    req.publicKey  = HexToBytes(pkHex);

    // Validate: deviceId must be a 36-char UUID string, deviceName must be non-empty
    if (req.deviceId.size() == 36 && !req.deviceName.empty()) {
        req.valid = true;
    }
    return req;
}

std::vector<uint8_t> BuildPairResponse(const std::string& serverHostname) {
    // Sends sasRequired=true so the phone knows to show SAS PIN input
    std::string json = "{\"sasRequired\":true,\"serverName\":\"" + serverHostname + "\"}";
    return std::vector<uint8_t>(json.begin(), json.end());
}

std::vector<uint8_t> BuildPairComplete(const std::string& deviceIdStr) {
    std::string json = "{\"status\":\"PAIRED\",\"deviceId\":\"" + deviceIdStr + "\"}";
    return std::vector<uint8_t>(json.begin(), json.end());
}

std::vector<uint8_t> BuildErrorPayload(uint32_t errorCode, const std::string& message) {
    char buf[512];
    std::snprintf(buf, sizeof(buf), "{\"errorCode\":%u,\"message\":\"%s\"}", errorCode, message.c_str());
    std::string json(buf);
    return std::vector<uint8_t>(json.begin(), json.end());
}

PairConfirmPayload ParsePairConfirm(const std::vector<uint8_t>& payloadBytes) {
    PairConfirmPayload conf;
    if (payloadBytes.empty()) return conf;
    std::string json(payloadBytes.begin(), payloadBytes.end());
    conf.deviceId = JsonGetString(json, "deviceId");
    conf.sasPin   = JsonGetString(json, "sasPin"); // validated, never logged
    if (conf.deviceId.size() == 36 && conf.sasPin.size() == static_cast<size_t>(SAS_PIN_LENGTH)) {
        conf.valid = true;
    }
    return conf;
}

std::vector<uint8_t> BuildUnpairResponse(bool success, const std::string& deviceIdStr) {
    std::string statusStr = success ? "UNPAIRED" : "ERROR";
    std::string json = "{\"status\":\"" + statusStr + "\",\"deviceId\":\"" + deviceIdStr + "\"}";
    return std::vector<uint8_t>(json.begin(), json.end());
}

// ---------------------------------------------------------------------------
// PairingManager implementation
// ---------------------------------------------------------------------------
PairingManager::PairingManager() {
    InitializeCriticalSection(&m_cs);
}

PairingManager::~PairingManager() {
    EnterCriticalSection(&m_cs);
    // Securely clear all SAS PINs from memory
    for (auto& kv : m_sessions) {
        SafeZeroMem(const_cast<char*>(kv.second.sasPin.data()), kv.second.sasPin.size());
    }
    m_sessions.clear();
    LeaveCriticalSection(&m_cs);
    DeleteCriticalSection(&m_cs);
}

bool PairingManager::IsRateLimited(const std::string& deviceIdStr) const {
    auto it = m_rateLimitMap.find(deviceIdStr);
    if (it == m_rateLimitMap.end()) return false;

    int count = it->second.first;
    FILETIME windowStart = it->second.second;
    FILETIME now;
    GetSystemTimeAsFileTime(&now);
    uint64_t nowU64 = (static_cast<uint64_t>(now.dwHighDateTime) << 32) | now.dwLowDateTime;
    uint64_t winU64 = (static_cast<uint64_t>(windowStart.dwHighDateTime) << 32) | windowStart.dwLowDateTime;

    // Rate limit window: 60 seconds = 600,000,000 100-ns units
    if (nowU64 - winU64 > 600000000ULL) return false; // Window expired
    return count >= 5; // 5 attempts per minute per device
}

void PairingManager::RecordFailedAttempt(const std::string& deviceIdStr) {
    auto it = m_rateLimitMap.find(deviceIdStr);
    if (it == m_rateLimitMap.end()) {
        FILETIME now;
        GetSystemTimeAsFileTime(&now);
        m_rateLimitMap[deviceIdStr] = std::make_pair(1, now);
    } else {
        it->second.first++;
    }
}

void PairingManager::ClearFailedAttempts(const std::string& deviceIdStr) {
    m_rateLimitMap.erase(deviceIdStr);
}

void PairingManager::ClearSession(uint64_t clientId) {
    auto it = m_sessions.find(clientId);
    if (it != m_sessions.end()) {
        // Securely zero the SAS PIN before erasing
        SafeZeroMem(const_cast<char*>(it->second.sasPin.data()), it->second.sasPin.size());
        m_sessions.erase(it);
    }
}

std::vector<uint8_t> PairingManager::HandlePairRequest(
    uint64_t clientId, const std::string& clientIp,
    const std::vector<uint8_t>& payloadBytes,
    Protocol::MessageType& outResponseType)
{
    EnterCriticalSection(&m_cs);

    // Cancel any existing session for this client (duplicate protection)
    ClearSession(clientId);

    auto req = ParsePairRequest(payloadBytes);
    if (!req.valid) {
        LeaveCriticalSection(&m_cs);
        outResponseType = Protocol::MessageType::PROTO_ERROR;
        return BuildErrorPayload(static_cast<uint32_t>(Protocol::ErrorCode::MALFORMED_HEADER),
                                 "Invalid PAIR_REQUEST payload");
    }

    // Rate limit check per DeviceID
    if (IsRateLimited(req.deviceId)) {
        LeaveCriticalSection(&m_cs);
        outResponseType = Protocol::MessageType::PROTO_ERROR;
        return BuildErrorPayload(static_cast<uint32_t>(Protocol::ErrorCode::RATE_LIMITED),
                                 "Pairing rate limit exceeded");
    }

    // Check if device already exists and is ACTIVE — prevent duplicate pairing
    if (IsDeviceActive(req.deviceId)) {
        // Device already paired and active; require explicit unpair first
        LeaveCriticalSection(&m_cs);
        outResponseType = Protocol::MessageType::PROTO_ERROR;
        return BuildErrorPayload(static_cast<uint32_t>(Protocol::ErrorCode::UNAUTHORIZED),
                                 "Device already paired. Unpair first.");
    }

    // Check account device limit
    std::string accountSid = ResolveCurrentAccountSid();
    if (!accountSid.empty()) {
        int activeCount = CountActiveDevicesForAccount(accountSid);
        if (activeCount >= kMaxDevicesPerAccount) {
            LeaveCriticalSection(&m_cs);
            outResponseType = Protocol::MessageType::PROTO_ERROR;
            return BuildErrorPayload(static_cast<uint32_t>(Protocol::ErrorCode::UNAUTHORIZED),
                                     "Maximum paired devices reached");
        }
    }

    // Generate SAS PIN
    std::string sasPin = GenerateSasPin();
    if (sasPin.empty()) {
        LeaveCriticalSection(&m_cs);
        outResponseType = Protocol::MessageType::PROTO_ERROR;
        return BuildErrorPayload(static_cast<uint32_t>(Protocol::ErrorCode::INTERNAL_ERROR),
                                 "SAS generation failed");
    }

    // Create session
    PairingSession session{};
    DeviceIdFromString(req.deviceId, session.deviceId);
    session.deviceName    = req.deviceName;
    session.clientIp      = clientIp;
    session.sasPin        = sasPin;
    session.sasAttempts   = 0;
    session.state         = PairingState::WAITING_FOR_SAS;
    session.sessionClientId = clientId;
    session.clientPublicKey = req.publicKey;
    GetSystemTimeAsFileTime(&session.sasGeneratedAt);

    m_sessions[clientId] = session;

    // Copy pin for callback before it can be cleared
    std::string pinCopy = sasPin;
    std::string nameCopy = req.deviceName;

    LeaveCriticalSection(&m_cs);

    // Display SAS PIN to user (callback — called outside lock to avoid deadlock)
    if (m_onSasDisplay) {
        m_onSasDisplay(pinCopy, nameCopy);
    }
    // Securely zero pin copy after callback
    SafeZeroMem(const_cast<char*>(pinCopy.data()), pinCopy.size());

    // Resolve PC hostname for PAIR_RESPONSE
    char hostname[256] = "PC";
    DWORD hostLen = sizeof(hostname);
    GetComputerNameA(hostname, &hostLen);

    outResponseType = Protocol::MessageType::PAIR_RESPONSE;
    return BuildPairResponse(std::string(hostname));
}

std::vector<uint8_t> PairingManager::HandlePairConfirm(
    uint64_t clientId,
    const std::vector<uint8_t>& payloadBytes,
    Protocol::MessageType& outResponseType)
{
    EnterCriticalSection(&m_cs);

    auto it = m_sessions.find(clientId);
    if (it == m_sessions.end() || it->second.state != PairingState::WAITING_FOR_SAS) {
        LeaveCriticalSection(&m_cs);
        outResponseType = Protocol::MessageType::PROTO_ERROR;
        return BuildErrorPayload(static_cast<uint32_t>(Protocol::ErrorCode::UNAUTHORIZED),
                                 "No active pairing session");
    }

    PairingSession& session = it->second;
    auto conf = ParsePairConfirm(payloadBytes);

    if (!conf.valid) {
        session.sasAttempts++;
        RecordFailedAttempt(DeviceIdToString(session.deviceId));
        if (session.sasAttempts >= SAS_MAX_ATTEMPTS) {
            session.state = PairingState::FAILED;
        }
        LeaveCriticalSection(&m_cs);
        if (m_onFailure) m_onFailure("Invalid PAIR_CONFIRM payload");
        outResponseType = Protocol::MessageType::PROTO_ERROR;
        return BuildErrorPayload(static_cast<uint32_t>(Protocol::ErrorCode::MALFORMED_HEADER),
                                 "Invalid PAIR_CONFIRM payload");
    }

    // Validate SAS PIN (constant-time, checks expiry and attempt count)
    bool pinOk = ValidateSasPin(conf.sasPin, session.sasPin, session.sasGeneratedAt, session.sasAttempts);
    // Immediately zero the submitted PIN copy — never retain in memory
    SafeZeroMem(const_cast<char*>(conf.sasPin.data()), conf.sasPin.size());

    if (!pinOk) {
        session.sasAttempts++;
        RecordFailedAttempt(DeviceIdToString(session.deviceId));

        bool expired = SasPinExpired(session.sasGeneratedAt);
        bool maxAttempts = session.sasAttempts >= SAS_MAX_ATTEMPTS;

        if (expired || maxAttempts) {
            session.state = expired ? PairingState::EXPIRED : PairingState::FAILED;
            std::string reason = expired ? "SAS PIN expired" : "Maximum SAS attempts exceeded";
            SafeZeroMem(const_cast<char*>(session.sasPin.data()), session.sasPin.size());
            ClearSession(clientId);
            LeaveCriticalSection(&m_cs);
            if (m_onFailure) m_onFailure(reason);
            outResponseType = Protocol::MessageType::PROTO_ERROR;
            return BuildErrorPayload(static_cast<uint32_t>(Protocol::ErrorCode::UNAUTHORIZED), reason);
        }

        LeaveCriticalSection(&m_cs);
        outResponseType = Protocol::MessageType::PROTO_ERROR;
        return BuildErrorPayload(static_cast<uint32_t>(Protocol::ErrorCode::UNAUTHORIZED),
                                 "Incorrect SAS PIN");
    }

    // SAS verified — write device to registry
    session.state = PairingState::SAS_VERIFIED;
    std::string accountSid = ResolveCurrentAccountSid();
    std::string deviceIdStr = DeviceIdToString(session.deviceId);

    DeviceRecord record{};
    record.deviceId    = session.deviceId;
    record.deviceName  = session.deviceName;
    record.accountSid  = accountSid;
    record.publicKey   = session.clientPublicKey;
    record.pairStatus  = kStatusActive;
    GetSystemTimeAsFileTime(&record.pairedTime);
    record.lastSeen    = record.pairedTime;

    LONG regErr = WriteDeviceRecord(record);

    // Immediately zero SAS PIN from session memory
    SafeZeroMem(const_cast<char*>(session.sasPin.data()), session.sasPin.size());
    ClearFailedAttempts(deviceIdStr);

    std::string clientIp = session.clientIp;
    std::string deviceName = session.deviceName;
    DeviceId deviceId = session.deviceId;

    if (regErr == ERROR_SUCCESS) {
        session.state = PairingState::PAIRED;
        ClearSession(clientId);
        LeaveCriticalSection(&m_cs);

        if (m_onSuccess) m_onSuccess(deviceId, deviceName, clientIp);

        outResponseType = Protocol::MessageType::PAIR_COMPLETE;
        return BuildPairComplete(deviceIdStr);
    } else {
        ClearSession(clientId);
        LeaveCriticalSection(&m_cs);
        if (m_onFailure) m_onFailure("Registry write failed");
        outResponseType = Protocol::MessageType::PROTO_ERROR;
        return BuildErrorPayload(static_cast<uint32_t>(Protocol::ErrorCode::INTERNAL_ERROR),
                                 "Registry write failed");
    }
}

std::vector<uint8_t> PairingManager::HandleUnpairRequest(
    uint64_t /*clientId*/,
    const std::vector<uint8_t>& payloadBytes,
    Protocol::MessageType& outResponseType)
{
    std::string json(payloadBytes.begin(), payloadBytes.end());
    std::string deviceIdStr = JsonGetString(json, "deviceId");

    if (deviceIdStr.size() != 36) {
        outResponseType = Protocol::MessageType::PROTO_ERROR;
        return BuildErrorPayload(static_cast<uint32_t>(Protocol::ErrorCode::MALFORMED_HEADER),
                                 "Invalid deviceId in UNPAIR_REQUEST");
    }

    LONG err = DeleteDeviceRecord(deviceIdStr);
    bool success = (err == ERROR_SUCCESS || err == ERROR_FILE_NOT_FOUND);

    outResponseType = Protocol::MessageType::UNPAIR_RESPONSE;
    return BuildUnpairResponse(success, deviceIdStr);
}

bool PairingManager::HasActivePairingSession(uint64_t clientId) const {
    EnterCriticalSection(const_cast<CRITICAL_SECTION*>(&m_cs));
    bool has = m_sessions.count(clientId) > 0;
    LeaveCriticalSection(const_cast<CRITICAL_SECTION*>(&m_cs));
    return has;
}

void PairingManager::CancelPairingSession(uint64_t clientId) {
    EnterCriticalSection(&m_cs);
    auto it = m_sessions.find(clientId);
    if (it != m_sessions.end()) {
        it->second.state = PairingState::CANCELLED;
        SafeZeroMem(const_cast<char*>(it->second.sasPin.data()), it->second.sasPin.size());
    }
    ClearSession(clientId);
    LeaveCriticalSection(&m_cs);
    if (m_onFailure) m_onFailure("Pairing cancelled");
}

void PairingManager::ExpireStaleSessions() {
    EnterCriticalSection(&m_cs);
    std::vector<uint64_t> toExpire;
    for (auto& kv : m_sessions) {
        if (SasPinExpired(kv.second.sasGeneratedAt)) {
            SafeZeroMem(const_cast<char*>(kv.second.sasPin.data()), kv.second.sasPin.size());
            kv.second.state = PairingState::EXPIRED;
            toExpire.push_back(kv.first);
        }
    }
    for (auto id : toExpire) {
        m_sessions.erase(id);
    }
    LeaveCriticalSection(&m_cs);
}

PairingState PairingManager::GetSessionState(uint64_t clientId) const {
    EnterCriticalSection(const_cast<CRITICAL_SECTION*>(&m_cs));
    auto it = m_sessions.find(clientId);
    PairingState state = (it != m_sessions.end()) ? it->second.state : PairingState::UNPAIRED;
    LeaveCriticalSection(const_cast<CRITICAL_SECTION*>(&m_cs));
    return state;
}

std::string PairingManager::ResolveCurrentAccountSid() {
    // Get the first active interactive session token and resolve the account SID
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return "";
    }

    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &dwSize);
    if (dwSize == 0) {
        CloseHandle(hToken);
        return "";
    }

    std::vector<BYTE> buf(dwSize);
    if (!GetTokenInformation(hToken, TokenUser, buf.data(), dwSize, &dwSize)) {
        CloseHandle(hToken);
        return "";
    }
    CloseHandle(hToken);

    auto* pUser = reinterpret_cast<TOKEN_USER*>(buf.data());

    typedef BOOL (WINAPI *FnConvertSidToStringSidA)(PSID, LPSTR*);
    HMODULE hAdvApi = LoadLibraryA("advapi32.dll");
    if (!hAdvApi) return "";

    auto pfnConvertSid = reinterpret_cast<FnConvertSidToStringSidA>(GetProcAddress(hAdvApi, "ConvertSidToStringSidA"));
    if (!pfnConvertSid) {
        FreeLibrary(hAdvApi);
        return "";
    }

    LPSTR sidStr = nullptr;
    if (!pfnConvertSid(pUser->User.Sid, &sidStr)) {
        FreeLibrary(hAdvApi);
        return "";
    }

    std::string result(sidStr);
    LocalFree(sidStr);
    FreeLibrary(hAdvApi);
    return result;
}

} // namespace MobileUnlock::Pairing
