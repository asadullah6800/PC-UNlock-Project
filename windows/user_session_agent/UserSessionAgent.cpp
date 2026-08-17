#include "UserSessionAgent.h"
#include <iostream>
#include <string>
#include <sstream>

#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "user32.lib")

namespace MobileUnlock::Agent {

static BOOL WINAPI DefaultLockWorkStation() {
    typedef BOOL (WINAPI *pfnLockWS)();
    static pfnLockWS fnLockWS = nullptr;
    if (!fnLockWS) {
        HMODULE hUser32 = GetModuleHandleW(L"user32.dll");
        if (!hUser32) hUser32 = LoadLibraryW(L"user32.dll");
        if (hUser32) {
            fnLockWS = (pfnLockWS)GetProcAddress(hUser32, "LockWorkStation");
        }
    }
    if (fnLockWS) {
        return fnLockWS();
    }
    return FALSE;
}

UserSessionAgent::UserSessionAgent()
    : m_isRunning(false),
      m_ipcClient(new IPC::NamedPipeClient(std::wstring(Constants::SECURE_IPC_PIPE_NAME))),
      m_lockWorkStationFn(DefaultLockWorkStation)
{}

UserSessionAgent::~UserSessionAgent() {
    Stop();
}

void UserSessionAgent::SetLockFunctionForTesting(pfnLockWorkStation lockFn) {
    m_lockWorkStationFn = lockFn ? lockFn : DefaultLockWorkStation;
}

SessionInfo UserSessionAgent::DiscoverCurrentSession() {
    SessionInfo info;
    info.SessionId = WTSGetActiveConsoleSessionId();

    if (info.SessionId == 0xFFFFFFFF) {
        return info;
    }

    LPWSTR pBuffer = nullptr;
    DWORD bytesReturned = 0;

    if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, info.SessionId, WTSUserName, &pBuffer, &bytesReturned) && pBuffer) {
        info.UserName = pBuffer;
        WTSFreeMemory(pBuffer);
        pBuffer = nullptr;
    }

    if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, info.SessionId, WTSDomainName, &pBuffer, &bytesReturned) && pBuffer) {
        info.DomainName = pBuffer;
        WTSFreeMemory(pBuffer);
        pBuffer = nullptr;
    }

    WTS_CONNECTSTATE_CLASS* pState = nullptr;
    if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, info.SessionId, WTSConnectState, reinterpret_cast<LPWSTR*>(&pState), &bytesReturned) && pState) {
        info.ConnectState = *pState;
        info.IsActiveInteractive = (info.ConnectState == WTSActive);
        WTSFreeMemory(pState);
    }

    return info;
}

bool UserSessionAgent::ConnectToService() {
    return m_ipcClient->Connect(5000);
}

bool UserSessionAgent::ReportSessionState(Protocol::PcState state) {
    if (!m_ipcClient || !m_ipcClient->IsConnected()) {
        if (!ConnectToService()) {
            return false;
        }
    }

    Protocol::FrameHeader header;
    header.MessageType    = static_cast<uint16_t>(Protocol::MessageType::STATUS_RESPONSE);
    header.MessageID      = 1;
    header.SequenceNumber = 1;
    
    std::string payload = "{\"state\":" + std::to_string(static_cast<uint32_t>(state)) + "}";
    header.PayloadLength  = static_cast<uint32_t>(payload.size());

    auto buf = Protocol::SerializeFrameHeader(header);
    buf.insert(buf.end(), payload.begin(), payload.end());
    return m_ipcClient->SendMessageToServer(buf);
}

bool UserSessionAgent::ProcessLockCommand(const Protocol::FrameHeader& header,
                                          const std::vector<uint8_t>& /*payload*/,
                                          Protocol::FrameHeader& outHeader,
                                          std::vector<uint8_t>& outPayload) {
    outHeader.Magic          = Protocol::PROTOCOL_MAGIC;
    outHeader.MajorVersion   = Protocol::PROTOCOL_MAJOR_VERSION;
    outHeader.MinorVersion   = Protocol::PROTOCOL_MINOR_VERSION;
    outHeader.MessageType    = static_cast<uint16_t>(Protocol::MessageType::LOCK_RESPONSE);
    outHeader.Reserved       = 0;
    outHeader.MessageID      = header.MessageID;
    outHeader.SequenceNumber = header.SequenceNumber + 1;

    // Call LockWorkStation() in interactive desktop context
    BOOL lockSuccess = m_lockWorkStationFn ? m_lockWorkStationFn() : FALSE;

    if (lockSuccess) {
        std::string json = "{\"status\":\"SUCCESS\"}";
        outPayload.assign(json.begin(), json.end());
        outHeader.PayloadLength = static_cast<uint32_t>(outPayload.size());
        return true;
    } else {
        std::string json = "{\"status\":\"FAILURE\",\"reason\":\"LOCK_FAILED\"}";
        outPayload.assign(json.begin(), json.end());
        outHeader.PayloadLength = static_cast<uint32_t>(outPayload.size());
        return false;
    }
}

int UserSessionAgent::Run() {
    m_isRunning.store(true);
    m_currentSession = DiscoverCurrentSession();

    std::wcout << L"UserSessionAgent starting in Session ID: " << m_currentSession.SessionId
               << L" | User: " << m_currentSession.DomainName << L"\\" << m_currentSession.UserName
               << L" | Active: " << (m_currentSession.IsActiveInteractive ? L"YES" : L"NO") << std::endl;

    if (ConnectToService()) {
        std::wcout << L"UserSessionAgent connected to MobileUnlockService." << std::endl;
        ReportSessionState(Protocol::PcState::ONLINE);
    } else {
        std::wcout << L"UserSessionAgent waiting for MobileUnlockService IPC connection..." << std::endl;
    }

    while (m_isRunning.load()) {
        if (!m_ipcClient->IsConnected()) {
            if (ConnectToService()) {
                std::wcout << L"UserSessionAgent reconnected to MobileUnlockService." << std::endl;
                ReportSessionState(Protocol::PcState::ONLINE);
            } else {
                Sleep(2000);
                continue;
            }
        }

        // Read command from MobileUnlockService with 1000ms timeout
        IPC::ReadResult readRes = m_ipcClient->ReadMessageFromServer(1000);
        if (readRes.valid && !readRes.data.empty()) {
            auto parseRes = Protocol::DeserializeFrameHeader(readRes.data.data(), readRes.data.size());
            if (parseRes.has_value()) {
                const auto& hdr = parseRes.value;
                std::vector<uint8_t> payload;
                if (readRes.data.size() > Protocol::FRAME_HEADER_SIZE) {
                    payload.assign(readRes.data.begin() + Protocol::FRAME_HEADER_SIZE, readRes.data.end());
                }

                if (hdr.MessageType == static_cast<uint16_t>(Protocol::MessageType::LOCK_REQUEST)) {
                    std::wcout << L"UserSessionAgent received LOCK_REQUEST command from service." << std::endl;
                    Protocol::FrameHeader respHeader;
                    std::vector<uint8_t> respPayload;
                    ProcessLockCommand(hdr, payload, respHeader, respPayload);

                    // Send LOCK_RESPONSE back to service
                    std::vector<uint8_t> respMsg = Protocol::SerializeFrameHeader(respHeader);
                    respMsg.insert(respMsg.end(), respPayload.begin(), respPayload.end());
                    m_ipcClient->SendMessageToServer(respMsg);

                    std::wcout << L"UserSessionAgent dispatched LockWorkStation() and returned LOCK_RESPONSE." << std::endl;
                } else if (hdr.MessageType == static_cast<uint16_t>(Protocol::MessageType::PING)) {
                    Protocol::FrameHeader pongHdr;
                    pongHdr.MessageType = static_cast<uint16_t>(Protocol::MessageType::PONG);
                    pongHdr.MessageID = hdr.MessageID;
                    pongHdr.SequenceNumber = hdr.SequenceNumber + 1;
                    pongHdr.PayloadLength = 0;
                    auto pongBuf = Protocol::SerializeFrameHeader(pongHdr);
                    m_ipcClient->SendMessageToServer(pongBuf);
                }
            }
        }

        // Check session state changes
        auto latestSession = DiscoverCurrentSession();
        if (latestSession.ConnectState != m_currentSession.ConnectState) {
            m_currentSession = latestSession;
        }
    }

    if (m_ipcClient && m_ipcClient->IsConnected()) {
        m_ipcClient->Disconnect();
    }

    std::wcout << L"UserSessionAgent stopped." << std::endl;
    return 0;
}

} // namespace MobileUnlock::Agent
