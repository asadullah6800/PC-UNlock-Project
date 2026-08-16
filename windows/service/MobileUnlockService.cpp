#include "MobileUnlockService.h"
#include "../logging/SecurityAuditLogger.h"
#include <iostream>
#include <string>

namespace MobileUnlock::Service {

constexpr wchar_t SERVICE_NAME[] = L"MobileUnlockService";

MobileUnlockService& MobileUnlockService::GetInstance() {
    static MobileUnlockService instance;
    return instance;
}

MobileUnlockService::MobileUnlockService()
    : m_statusHandle(0),
      m_serviceStatus(),
      m_currentState(Protocol::PcState::OFFLINE),
      m_isRunning(false)
{
    std::memset(&m_serviceStatus, 0, sizeof(m_serviceStatus));
}

MobileUnlockService::~MobileUnlockService() {
    StopServiceComponents();
}

int MobileUnlockService::Run(int argc, wchar_t* argv[]) {
    if (argc > 1) {
        std::wstring arg1(argv[1]);
        if (arg1 == L"-console" || arg1 == L"--console") {
            std::wcout << L"Starting MobileUnlockService in Console Mode..." << std::endl;
            if (StartServiceComponents()) {
                std::wcout << L"Service running. Press ENTER to exit." << std::endl;
                std::cin.get();
                StopServiceComponents();
            }
            return 0;
        }
    }

    SERVICE_TABLE_ENTRYW serviceTable[] = {
        { const_cast<LPWSTR>(SERVICE_NAME), ServiceMain },
        { nullptr, nullptr }
    };

    if (!StartServiceCtrlDispatcherW(serviceTable)) {
        DWORD err = GetLastError();
        if (err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            std::wcout << L"Run with -console to start in interactive mode." << std::endl;
        }
        return static_cast<int>(err);
    }
    return 0;
}

void WINAPI MobileUnlockService::ServiceMain(DWORD /*argc*/, LPWSTR* /*argv*/) {
    auto& service = GetInstance();

    service.m_statusHandle = RegisterServiceCtrlHandlerExW(
        SERVICE_NAME,
        ServiceHandlerEx,
        &service
    );

    if (!service.m_statusHandle) {
        Logging::SecurityAuditLogger::GetInstance().LogSecurityEvent(
            Logging::EventId::SERVICE_FAULT,
            Logging::LogLevel::Error,
            L"Failed to register service control handler."
        );
        return;
    }

    service.ReportServiceStatus(SERVICE_START_PENDING, NO_ERROR, 3000);

    if (service.StartServiceComponents()) {
        service.ReportServiceStatus(SERVICE_RUNNING, NO_ERROR, 0);
    } else {
        service.ReportServiceStatus(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, 0);
    }
}

DWORD WINAPI MobileUnlockService::ServiceHandlerEx(DWORD control, DWORD /*eventType*/, LPVOID /*eventData*/, LPVOID context) {
    auto* service = static_cast<MobileUnlockService*>(context);
    if (!service) return ERROR_CALL_NOT_IMPLEMENTED;

    switch (control) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        service->ReportServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 5000);
        service->StopServiceComponents();
        service->ReportServiceStatus(SERVICE_STOPPED, NO_ERROR, 0);
        return NO_ERROR;

    case SERVICE_CONTROL_INTERROGATE:
        return NO_ERROR;

    default:
        return NO_ERROR;
    }
}

void MobileUnlockService::ReportServiceStatus(DWORD currentState, DWORD exitCode, DWORD waitHint) {
    static DWORD checkPoint = 1;

    m_serviceStatus.dwServiceType      = SERVICE_WIN32_OWN_PROCESS;
    m_serviceStatus.dwCurrentState     = currentState;
    m_serviceStatus.dwControlsAccepted = (currentState == SERVICE_RUNNING) ? (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN) : 0;
    m_serviceStatus.dwWin32ExitCode    = exitCode;
    m_serviceStatus.dwCheckPoint       = (currentState == SERVICE_RUNNING || currentState == SERVICE_STOPPED) ? 0 : checkPoint++;
    m_serviceStatus.dwWaitHint         = waitHint;

    if (m_statusHandle) {
        SetServiceStatus(m_statusHandle, &m_serviceStatus);
    }
}

bool MobileUnlockService::StartServiceComponents() {
    if (m_isRunning.load()) return true;

    if (!m_configManager.LoadConfiguration()) {
        Logging::SecurityAuditLogger::GetInstance().LogSecurityEvent(
            Logging::EventId::SERVICE_FAULT,
            Logging::LogLevel::Error,
            L"Configuration validation failed."
        );
        return false;
    }

    const auto& config = m_configManager.GetConfig();

    m_ipcServer = std::unique_ptr<IPC::NamedPipeServer>(
        new IPC::NamedPipeServer(config.ServicePipeName)
    );

    if (!m_ipcServer->Start([this](const std::vector<uint8_t>& msg) { HandleIpcMessage(msg); })) {
        Logging::SecurityAuditLogger::GetInstance().LogSecurityEvent(
            Logging::EventId::SERVICE_FAULT,
            Logging::LogLevel::Error,
            L"Failed to start Secure IPC Server."
        );
        return false;
    }

    m_diagnosticManager.SetServiceStatus(Diagnostics::ComponentStatus::OK, L"Service started successfully");
    m_diagnosticManager.SetIpcStatus(Diagnostics::ComponentStatus::OK, L"IPC Server active");
    SetState(Protocol::PcState::ONLINE);

    Logging::SecurityAuditLogger::GetInstance().LogSecurityEvent(
        Logging::EventId::SERVICE_FAULT,
        Logging::LogLevel::Info,
        L"MobileUnlockService started successfully under NetworkService identity."
    );

    m_isRunning.store(true);
    return true;
}

void MobileUnlockService::StopServiceComponents() {
    if (!m_isRunning.load()) return;

    if (m_ipcServer) {
        m_ipcServer->Stop();
        m_ipcServer.reset();
    }

    SetState(Protocol::PcState::OFFLINE);
    m_diagnosticManager.SetServiceStatus(Diagnostics::ComponentStatus::UNINITIALIZED, L"Service stopped");
    m_isRunning.store(false);

    Logging::SecurityAuditLogger::GetInstance().LogSecurityEvent(
        Logging::EventId::SERVICE_FAULT,
        Logging::LogLevel::Info,
        L"MobileUnlockService components stopped safely."
    );
}

void MobileUnlockService::SetState(Protocol::PcState state) {
    m_currentState.store(state);
}

void MobileUnlockService::HandleIpcMessage(const std::vector<uint8_t>& message) {
    m_diagnosticManager.IncrementProcessedMessages();

    auto headerResult = Protocol::DeserializeFrameHeader(message.data(), message.size());
    if (!headerResult.has_value()) {
        Logging::SecurityAuditLogger::GetInstance().LogSecurityEvent(
            Logging::EventId::SERVICE_FAULT,
            Logging::LogLevel::Warning,
            L"Received malformed IPC frame header."
        );
        return;
    }

    auto header = headerResult.value;
    if (header.MessageType == static_cast<uint16_t>(Protocol::MessageType::PING)) {
        Protocol::FrameHeader pongHeader;
        pongHeader.MessageType    = static_cast<uint16_t>(Protocol::MessageType::PONG);
        pongHeader.MessageID      = header.MessageID;
        pongHeader.SequenceNumber = header.SequenceNumber + 1;
        pongHeader.PayloadLength  = 0;

        auto responseBuf = Protocol::SerializeFrameHeader(pongHeader);
        m_ipcServer->SendMessageToClient(responseBuf);
    }
}

} // namespace MobileUnlock::Service
