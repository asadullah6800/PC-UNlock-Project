#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#if defined(__GNUC__) && !defined(_WTS_VIRTUAL_CLASS_DEFINED)
typedef enum _WTS_VIRTUAL_CLASS {
    WTSVirtualClientData,
    WTSVirtualFileHandle
} WTS_VIRTUAL_CLASS;
#define _WTS_VIRTUAL_CLASS_DEFINED

extern "C" DWORD WINAPI WTSGetActiveConsoleSessionId(void);
#endif
#include <wtsapi32.h>
#include <string>
#include <memory>
#include <atomic>
#include "../ipc/SecureIPC.h"
#include "../../shared/protocol/ProtocolTypes.h"
#include "../../shared/constants/BleConstants.h"

namespace MobileUnlock::Agent {

struct SessionInfo {
    DWORD SessionId;
    std::wstring UserName;
    std::wstring DomainName;
    WTS_CONNECTSTATE_CLASS ConnectState;
    bool IsActiveInteractive;

    SessionInfo()
        : SessionId(0xFFFFFFFF),
          ConnectState(WTSDisconnected),
          IsActiveInteractive(false) {}
};

class UserSessionAgent {
public:
    UserSessionAgent();
    ~UserSessionAgent();

    int Run();
    static SessionInfo DiscoverCurrentSession();
    bool ConnectToService();
    bool ReportSessionState(Protocol::PcState state);
    void Stop() { m_isRunning.store(false); }

private:
    std::atomic<bool> m_isRunning;
    SessionInfo m_currentSession;
    std::unique_ptr<IPC::NamedPipeClient> m_ipcClient;
};

} // namespace MobileUnlock::Agent
