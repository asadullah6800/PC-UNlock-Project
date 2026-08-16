#include "UserSessionAgent.h"
#include <iostream>
#include <string>

#pragma comment(lib, "wtsapi32.lib")

namespace MobileUnlock::Agent {

UserSessionAgent::UserSessionAgent()
    : m_isRunning(false),
      m_ipcClient(new IPC::NamedPipeClient(std::wstring(Constants::SECURE_IPC_PIPE_NAME)))
{}

UserSessionAgent::~UserSessionAgent() {
    Stop();
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

bool UserSessionAgent::ReportSessionState(Protocol::PcState /*state*/) {
    if (!m_ipcClient || !m_ipcClient->IsConnected()) {
        if (!ConnectToService()) {
            return false;
        }
    }

    Protocol::FrameHeader header;
    header.MessageType    = static_cast<uint16_t>(Protocol::MessageType::STATUS_RESPONSE);
    header.MessageID      = 1;
    header.SequenceNumber = 1;
    header.PayloadLength  = 0;

    auto buf = Protocol::SerializeFrameHeader(header);
    return m_ipcClient->SendMessageToServer(buf);
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
        Sleep(5000);
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
