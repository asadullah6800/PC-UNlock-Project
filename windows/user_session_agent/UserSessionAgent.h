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
#include <vector>
#include <memory>
#include <atomic>
#include <functional>
#include "../ipc/SecureIPC.h"
#include "../../shared/protocol/ProtocolTypes.h"
#include "../../shared/constants/BleConstants.h"

namespace MobileUnlock::Agent {

typedef BOOL (WINAPI *pfnLockWorkStation)();

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

    /**
     * Processes an incoming LOCK_REQUEST (0x0030) from MobileUnlockService.
     * Calls LockWorkStation() and returns a LOCK_RESPONSE (0x0031) frame.
     *
     * @param header Input FrameHeader.
     * @param payload Input payload bytes.
     * @param outHeader Output FrameHeader for LOCK_RESPONSE.
     * @param outPayload Output payload bytes for LOCK_RESPONSE.
     * @return true if lock was initiated successfully, false otherwise.
     */
    bool ProcessLockCommand(const Protocol::FrameHeader& header,
                            const std::vector<uint8_t>& payload,
                            Protocol::FrameHeader& outHeader,
                            std::vector<uint8_t>& outPayload);

    // Testing hook: inject mock LockWorkStation implementation
    void SetLockFunctionForTesting(pfnLockWorkStation lockFn);

private:
    std::atomic<bool> m_isRunning;
    SessionInfo m_currentSession;
    std::unique_ptr<IPC::NamedPipeClient> m_ipcClient;
    pfnLockWorkStation m_lockWorkStationFn;
};

} // namespace MobileUnlock::Agent
