#include "MobileUnlockService.h"
#include "../logging/SecurityAuditLogger.h"
#include "../authentication/AuthenticationManager.h"
#include "../pairing/PairingManager.h"
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
                std::wcout << L"Service running on Port " << m_configManager.GetConfig().WifiPort
                           << L" with mDNS on Port " << m_configManager.GetConfig().MdnsPort
                           << L". Press ENTER to exit." << std::endl;
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

    // 1. Start Secure IPC Server
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

    // 2. Start NetworkEngine (TCP / TLS 1.3 server)
    m_networkEngine = std::unique_ptr<Network::NetworkEngine>(
        new Network::NetworkEngine(config.WifiPort)
    );

    if (!m_networkEngine->Start([this](uint64_t clientId, const Protocol::FrameHeader& header, const std::vector<uint8_t>& payload) {
        HandleNetworkFrame(clientId, header, payload);
    })) {
        Logging::SecurityAuditLogger::GetInstance().LogSecurityEvent(
            Logging::EventId::SERVICE_FAULT,
            Logging::LogLevel::Error,
            L"Failed to start NetworkEngine TCP/TLS Server."
        );
        return false;
    }

    // 3. Start mDNS Responder
    m_mdnsResponder = std::unique_ptr<Network::MdnsResponder>(
        new Network::MdnsResponder(config.MdnsPort, config.WifiPort)
    );

    if (!m_mdnsResponder->Start(Protocol::PcState::ONLINE)) {
        Logging::SecurityAuditLogger::GetInstance().LogSecurityEvent(
            Logging::EventId::SERVICE_FAULT,
            Logging::LogLevel::Warning,
            L"Failed to start mDNS Responder (UDP port may be occupied)."
        );
    }

    m_diagnosticManager.SetServiceStatus(Diagnostics::ComponentStatus::OK, L"Service, TCP/TLS Server, and mDNS active");
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

    if (m_mdnsResponder) {
        m_mdnsResponder->Stop();
        m_mdnsResponder.reset();
    }

    if (m_networkEngine) {
        m_networkEngine->Stop();
        m_networkEngine.reset();
    }

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
    if (m_mdnsResponder) {
        m_mdnsResponder->SetState(state);
    }
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
    std::vector<uint8_t> payload;
    if (message.size() > Protocol::FRAME_HEADER_SIZE) {
        payload.assign(message.begin() + Protocol::FRAME_HEADER_SIZE, message.end());
    }

    if (header.MessageType == static_cast<uint16_t>(Protocol::MessageType::PING)) {
        Protocol::FrameHeader pongHeader;
        pongHeader.Magic          = Protocol::PROTOCOL_MAGIC;
        pongHeader.MajorVersion   = Protocol::PROTOCOL_MAJOR_VERSION;
        pongHeader.MinorVersion   = Protocol::PROTOCOL_MINOR_VERSION;
        pongHeader.MessageType    = static_cast<uint16_t>(Protocol::MessageType::PONG);
        pongHeader.Reserved       = 0;
        pongHeader.MessageID      = header.MessageID;
        pongHeader.SequenceNumber = header.SequenceNumber + 1;
        pongHeader.PayloadLength  = 0;

        auto responseBuf = Protocol::SerializeFrameHeader(pongHeader);
        m_ipcServer->SendMessageToClient(responseBuf);
        return;
    }

    if (header.MessageType == static_cast<uint16_t>(Protocol::MessageType::LOCK_RESPONSE)) {
        uint64_t client = m_pendingLockClientId.exchange(0);
        uint32_t msgId = m_pendingLockMessageId.load();

        if (client != 0 && m_networkEngine) {
            Protocol::FrameHeader netHeader;
            netHeader.Magic          = Protocol::PROTOCOL_MAGIC;
            netHeader.MajorVersion   = Protocol::PROTOCOL_MAJOR_VERSION;
            netHeader.MinorVersion   = Protocol::PROTOCOL_MINOR_VERSION;
            netHeader.MessageType    = static_cast<uint16_t>(Protocol::MessageType::LOCK_RESPONSE);
            netHeader.Reserved       = 0;
            netHeader.MessageID      = msgId;
            netHeader.SequenceNumber = 2;
            netHeader.PayloadLength  = static_cast<uint32_t>(payload.size());

            m_networkEngine->SendFrame(client, netHeader, payload);
        }

        SetState(Protocol::PcState::LOCKED);
        Logging::SecurityAuditLogger::GetInstance().LogSecurityEvent(
            Logging::EventId::LOCK_EXECUTED,
            Logging::LogLevel::Info,
            L"Workstation successfully locked via UserSessionAgent remote lock."
        );
        return;
    }

    if (header.MessageType == static_cast<uint16_t>(Protocol::MessageType::STATUS_RESPONSE)) {
        // Agent reporting status
        return;
    }
}

void MobileUnlockService::HandleNetworkFrame(uint64_t clientId, const Protocol::FrameHeader& header, const std::vector<uint8_t>& payload) {
    m_diagnosticManager.IncrementProcessedMessages();

    if (header.MessageType == static_cast<uint16_t>(Protocol::MessageType::PING)) {
        Protocol::FrameHeader pongHeader;
        pongHeader.Magic          = Protocol::PROTOCOL_MAGIC;
        pongHeader.MajorVersion   = Protocol::PROTOCOL_MAJOR_VERSION;
        pongHeader.MinorVersion   = Protocol::PROTOCOL_MINOR_VERSION;
        pongHeader.MessageType    = static_cast<uint16_t>(Protocol::MessageType::PONG);
        pongHeader.Reserved       = 0;
        pongHeader.MessageID      = header.MessageID;
        pongHeader.SequenceNumber = header.SequenceNumber + 1;
        pongHeader.PayloadLength  = 0;

        m_networkEngine->SendFrame(clientId, pongHeader, {});
        return;
    }

    if (header.MessageType == static_cast<uint16_t>(Protocol::MessageType::AUTH_REQUEST)) {
        Pairing::DeviceId deviceId;
        if (payload.size() >= 16) {
            std::memcpy(deviceId.data(), payload.data(), 16);
        } else {
            std::string payloadStr(payload.begin(), payload.end());
            size_t pos = payloadStr.find("\"deviceId\":\"");
            if (pos != std::string::npos) {
                std::string devStr = payloadStr.substr(pos + 12, 36);
                Pairing::DeviceIdFromString(devStr, deviceId);
            }
        }

        std::vector<uint8_t> challengePayload;
        Protocol::FrameHeader outHeader;
        Auth::AuthenticationManager::Instance().HandleAuthRequest(deviceId, header, challengePayload, outHeader);
        m_networkEngine->SendFrame(clientId, outHeader, challengePayload);
        return;
    }

    if (header.MessageType == static_cast<uint16_t>(Protocol::MessageType::AUTH_RESPONSE)) {
        std::vector<uint8_t> outcomePayload;
        Protocol::FrameHeader outHeader;
        Auth::AuthenticationManager::Instance().HandleAuthResponse(header, payload, outcomePayload, outHeader);
        m_networkEngine->SendFrame(clientId, outHeader, outcomePayload);
        return;
    }

    if (header.MessageType == static_cast<uint16_t>(Protocol::MessageType::LOCK_REQUEST)) {
        Pairing::DeviceId deviceId;
        bool hasDeviceId = false;

        // Try extracting deviceId from canonical 88B message if present
        if (payload.size() >= Protocol::CANONICAL_SIGNED_MESSAGE_SIZE) {
            auto parseMsg = Protocol::DeserializeSignedMessage(payload.data(), Protocol::CANONICAL_SIGNED_MESSAGE_SIZE);
            if (parseMsg.has_value()) {
                std::memcpy(deviceId.data(), parseMsg.value.DeviceIdentity, 16);
                hasDeviceId = true;
            }
        }

        if (!hasDeviceId && payload.size() >= 16) {
            std::memcpy(deviceId.data(), payload.data(), 16);
            hasDeviceId = true;
        }

        if (!hasDeviceId) {
            std::string payloadStr(payload.begin(), payload.end());
            size_t pos = payloadStr.find("\"deviceId\":\"");
            if (pos != std::string::npos) {
                std::string devStr = payloadStr.substr(pos + 12, 36);
                hasDeviceId = Pairing::DeviceIdFromString(devStr, deviceId);
            }
        }

        // Validate device in DeviceRegistry if deviceId is provided
        std::string devIdStr = hasDeviceId ? Pairing::DeviceIdToString(deviceId) : "";
        if (hasDeviceId && !Pairing::IsDeviceActive(devIdStr)) {
            Protocol::FrameHeader failHdr;
            failHdr.Magic          = Protocol::PROTOCOL_MAGIC;
            failHdr.MajorVersion   = Protocol::PROTOCOL_MAJOR_VERSION;
            failHdr.MinorVersion   = Protocol::PROTOCOL_MINOR_VERSION;
            failHdr.MessageType    = static_cast<uint16_t>(Protocol::MessageType::LOCK_RESPONSE);
            failHdr.Reserved       = 0;
            failHdr.MessageID      = header.MessageID;
            failHdr.SequenceNumber = header.SequenceNumber + 1;

            std::string err = "{\"status\":\"FAILURE\",\"reason\":\"DEVICE_UNAUTHORIZED\"}";
            std::vector<uint8_t> errPayload(err.begin(), err.end());
            failHdr.PayloadLength = static_cast<uint32_t>(errPayload.size());

            m_networkEngine->SendFrame(clientId, failHdr, errPayload);
            return;
        }

        // Check if UserSessionAgent is connected
        if (!m_ipcServer || !m_ipcServer->IsConnected()) {
            Protocol::FrameHeader failHdr;
            failHdr.Magic          = Protocol::PROTOCOL_MAGIC;
            failHdr.MajorVersion   = Protocol::PROTOCOL_MAJOR_VERSION;
            failHdr.MinorVersion   = Protocol::PROTOCOL_MINOR_VERSION;
            failHdr.MessageType    = static_cast<uint16_t>(Protocol::MessageType::LOCK_RESPONSE);
            failHdr.Reserved       = 0;
            failHdr.MessageID      = header.MessageID;
            failHdr.SequenceNumber = header.SequenceNumber + 1;

            std::string err = "{\"status\":\"FAILURE\",\"reason\":\"AGENT_UNAVAILABLE\"}";
            std::vector<uint8_t> errPayload(err.begin(), err.end());
            failHdr.PayloadLength = static_cast<uint32_t>(errPayload.size());

            m_networkEngine->SendFrame(clientId, failHdr, errPayload);
            return;
        }

        // Save pending lock client ID
        m_pendingLockClientId.store(clientId);
        m_pendingLockMessageId.store(header.MessageID);

        // Dispatch LOCK_REQUEST to UserSessionAgent via Secure IPC
        Protocol::FrameHeader ipcReq;
        ipcReq.Magic          = Protocol::PROTOCOL_MAGIC;
        ipcReq.MajorVersion   = Protocol::PROTOCOL_MAJOR_VERSION;
        ipcReq.MinorVersion   = Protocol::PROTOCOL_MINOR_VERSION;
        ipcReq.MessageType    = static_cast<uint16_t>(Protocol::MessageType::LOCK_REQUEST);
        ipcReq.Reserved       = 0;
        ipcReq.MessageID      = header.MessageID;
        ipcReq.SequenceNumber = 1;
        ipcReq.PayloadLength  = static_cast<uint32_t>(payload.size());

        auto ipcBuf = Protocol::SerializeFrameHeader(ipcReq);
        ipcBuf.insert(ipcBuf.end(), payload.begin(), payload.end());
        m_ipcServer->SendMessageToClient(ipcBuf);
    }
}

} // namespace MobileUnlock::Service
