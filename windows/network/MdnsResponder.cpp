#include "MdnsResponder.h"
#include <iostream>
#include <sstream>
#include <cstring>

namespace MobileUnlock::Network {

MdnsResponder::MdnsResponder(uint16_t udpPort, uint16_t tcpServicePort)
    : m_udpPort(udpPort),
      m_tcpPort(tcpServicePort)
{
    char computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computerName);
    if (GetComputerNameA(computerName, &size)) {
        m_hostName = std::string(computerName);
    } else {
        m_hostName = "Windows-PC";
    }

    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
}

MdnsResponder::~MdnsResponder() {
    Stop();
    WSACleanup();
}

void MdnsResponder::SetState(Protocol::PcState state) {
    m_state.store(state);
}

std::vector<uint8_t> MdnsResponder::BuildDiscoveryResponsePayload(const DiscoveryAnnouncement& ann) {
    // Format: JSON payload containing hostname, port, state, serviceType
    // Example: {"host":"DESKTOP-123","port":8443,"state":2,"service":"_mobileunlock._tcp.local."}
    std::ostringstream oss;
    oss << "{\"host\":\"" << ann.HostName << "\","
        << "\"port\":" << ann.Port << ","
        << "\"state\":" << static_cast<uint32_t>(ann.State) << ","
        << "\"service\":\"" << ann.ServiceType << "\"}";

    std::string str = oss.str();
    return std::vector<uint8_t>(str.begin(), str.end());
}

bool MdnsResponder::ParseDiscoveryResponsePayload(const uint8_t* data, size_t len, DiscoveryAnnouncement& outAnn) {
    if (data == nullptr || len == 0 || len > Protocol::MAX_PAYLOAD_SIZE) return false;
    std::string str(reinterpret_cast<const char*>(data), len);

    // Simple robust JSON extractor without external heavy dependencies
    auto extractString = [&](const std::string& key) -> std::string {
        std::string pattern = "\"" + key + "\":\"";
        size_t pos = str.find(pattern);
        if (pos == std::string::npos) return "";
        size_t start = pos + pattern.length();
        size_t end = str.find("\"", start);
        if (end == std::string::npos) return "";
        return str.substr(start, end - start);
    };

    auto extractInt = [&](const std::string& key) -> int {
        std::string pattern = "\"" + key + "\":";
        size_t pos = str.find(pattern);
        if (pos == std::string::npos) return -1;
        size_t start = pos + pattern.length();
        size_t end = str.find_first_of(",}", start);
        if (end == std::string::npos) return -1;
        std::string valStr = str.substr(start, end - start);
        try {
            return std::stoi(valStr);
        } catch (...) {
            return -1;
        }
    };

    std::string host = extractString("host");
    std::string service = extractString("service");
    int port = extractInt("port");
    int state = extractInt("state");

    if (host.empty() || port <= 0 || port > 65535 || service.empty() || state < 0) {
        return false;
    }

    outAnn.HostName = host;
    outAnn.Port = static_cast<uint16_t>(port);
    outAnn.ServiceType = service;
    outAnn.State = static_cast<Protocol::PcState>(state);
    return true;
}

bool MdnsResponder::Start(Protocol::PcState initialState) {
    if (m_isRunning.load()) return false;
    m_state.store(initialState);

    m_udpSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (m_udpSocket == INVALID_SOCKET) {
        return false;
    }

    BOOL opt = TRUE;
    setsockopt(m_udpSocket, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));
    setsockopt(m_udpSocket, SOL_SOCKET, SO_BROADCAST, reinterpret_cast<const char*>(&opt), sizeof(opt));

    // Set receive timeout
    DWORD timeout = 2000;
    setsockopt(m_udpSocket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));

    sockaddr_in bindAddr{};
    bindAddr.sin_family = AF_INET;
    bindAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    bindAddr.sin_port = htons(m_udpPort);

    if (bind(m_udpSocket, reinterpret_cast<sockaddr*>(&bindAddr), sizeof(bindAddr)) == SOCKET_ERROR) {
        closesocket(m_udpSocket);
        m_udpSocket = INVALID_SOCKET;
        return false;
    }

    m_isRunning.store(true);
    m_hListenerThread = CreateThread(nullptr, 0, ListenerThreadProc, this, 0, nullptr);
    return (m_hListenerThread != nullptr);
}

void MdnsResponder::Stop() {
    if (!m_isRunning.load()) return;
    m_isRunning.store(false);

    if (m_udpSocket != INVALID_SOCKET) {
        closesocket(m_udpSocket);
        m_udpSocket = INVALID_SOCKET;
    }

    if (m_hListenerThread) {
        WaitForSingleObject(m_hListenerThread, 1000);
        CloseHandle(m_hListenerThread);
        m_hListenerThread = nullptr;
    }
}

DWORD WINAPI MdnsResponder::ListenerThreadProc(LPVOID lpParam) {
    auto* responder = static_cast<MdnsResponder*>(lpParam);
    if (responder) responder->ListenerLoop();
    return 0;
}

void MdnsResponder::ListenerLoop() {
    std::vector<uint8_t> buffer(2048);

    while (m_isRunning.load()) {
        sockaddr_in clientAddr{};
        int clientAddrLen = sizeof(clientAddr);

        int bytesRead = recvfrom(
            m_udpSocket,
            reinterpret_cast<char*>(buffer.data()),
            static_cast<int>(buffer.size()),
            0,
            reinterpret_cast<sockaddr*>(&clientAddr),
            &clientAddrLen
        );

        if (bytesRead <= 0) {
            if (!m_isRunning.load()) break;
            Sleep(50);
            continue;
        }

        // Validate incoming discovery request (either 24B FrameHeader with DISCOVER opcode or text query)
        bool isValidQuery = false;
        if (bytesRead >= static_cast<int>(Protocol::FRAME_HEADER_SIZE)) {
            auto headerResult = Protocol::DeserializeFrameHeader(buffer.data(), bytesRead);
            if (headerResult.has_value() && headerResult.value.MessageType == static_cast<uint16_t>(Protocol::MessageType::DISCOVER)) {
                isValidQuery = true;
            }
        } else {
            std::string queryStr(reinterpret_cast<char*>(buffer.data()), bytesRead);
            if (queryStr.find("_mobileunlock._tcp") != std::string::npos || queryStr.find("DISCOVER") != std::string::npos) {
                isValidQuery = true;
            }
        }

        if (isValidQuery) {
            DiscoveryAnnouncement ann;
            ann.HostName = m_hostName;
            ann.Port = m_tcpPort;
            ann.State = m_state.load();
            ann.ServiceType = Constants::MDNS_SERVICE_TYPE;

            auto payload = BuildDiscoveryResponsePayload(ann);

            Protocol::FrameHeader respHeader;
            respHeader.Magic = Protocol::PROTOCOL_MAGIC;
            respHeader.MajorVersion = Protocol::PROTOCOL_MAJOR_VERSION;
            respHeader.MinorVersion = Protocol::PROTOCOL_MINOR_VERSION;
            respHeader.MessageType = static_cast<uint16_t>(Protocol::MessageType::DISCOVERY_RESPONSE);
            respHeader.MessageID = 1;
            respHeader.PayloadLength = static_cast<uint32_t>(payload.size());
            respHeader.SequenceNumber = 1;

            auto respFrame = Protocol::SerializeFrameHeader(respHeader);
            respFrame.insert(respFrame.end(), payload.begin(), payload.end());

            sendto(
                m_udpSocket,
                reinterpret_cast<const char*>(respFrame.data()),
                static_cast<int>(respFrame.size()),
                0,
                reinterpret_cast<sockaddr*>(&clientAddr),
                clientAddrLen
            );
        }
    }
}

} // namespace MobileUnlock::Network
