#pragma once

#include <windows.h>
#include <memory>
#include <atomic>
#include <string>
#include "../configuration/ConfigurationManager.h"
#include "../logging/SecurityAuditLogger.h"
#include "../diagnostics/DiagnosticManager.h"
#include "../ipc/SecureIPC.h"
#include "../network/NetworkEngine.h"
#include "../network/MdnsResponder.h"
#include "../../shared/protocol/ProtocolTypes.h"

namespace MobileUnlock::Service {

class MobileUnlockService {
public:
    static MobileUnlockService& GetInstance();

    int Run(int argc, wchar_t* argv[]);

    static void WINAPI ServiceMain(DWORD argc, LPWSTR* argv);
    static DWORD WINAPI ServiceHandlerEx(DWORD control, DWORD eventType, LPVOID eventData, LPVOID context);

    bool StartServiceComponents();
    void StopServiceComponents();

    Protocol::PcState GetCurrentState() const { return m_currentState.load(); }
    void SetState(Protocol::PcState state);

private:
    MobileUnlockService();
    ~MobileUnlockService();

    MobileUnlockService(const MobileUnlockService&) = delete;
    MobileUnlockService& operator=(const MobileUnlockService&) = delete;

    void ReportServiceStatus(DWORD currentState, DWORD exitCode, DWORD waitHint);
    void HandleIpcMessage(const std::vector<uint8_t>& message);
    void HandleNetworkFrame(uint64_t clientId, const Protocol::FrameHeader& header, const std::vector<uint8_t>& payload);

    SERVICE_STATUS_HANDLE m_statusHandle;
    SERVICE_STATUS        m_serviceStatus;
    std::atomic<Protocol::PcState> m_currentState;
    std::atomic<bool>     m_isRunning;

    Configuration::ConfigurationManager m_configManager;
    Diagnostics::DiagnosticManager m_diagnosticManager;
    std::unique_ptr<IPC::NamedPipeServer> m_ipcServer;
    std::unique_ptr<Network::NetworkEngine> m_networkEngine;
    std::unique_ptr<Network::MdnsResponder> m_mdnsResponder;

    std::atomic<uint64_t> m_pendingLockClientId{0};
    std::atomic<uint32_t> m_pendingLockMessageId{0};
};

} // namespace MobileUnlock::Service
