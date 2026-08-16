#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <string>
#include <vector>
#include <atomic>
#include "../../shared/protocol/ProtocolTypes.h"
#include "../../shared/constants/BleConstants.h"

namespace MobileUnlock::Network {

struct DiscoveryAnnouncement {
    std::string HostName;
    uint16_t Port{Constants::DEFAULT_WIFI_PORT};
    Protocol::PcState State{Protocol::PcState::ONLINE};
    std::string ServiceType{Constants::MDNS_SERVICE_TYPE};
};

class MdnsResponder {
public:
    explicit MdnsResponder(uint16_t udpPort = Constants::DEFAULT_MDNS_PORT, uint16_t tcpServicePort = Constants::DEFAULT_WIFI_PORT);
    ~MdnsResponder();

    MdnsResponder(const MdnsResponder&) = delete;
    MdnsResponder& operator=(const MdnsResponder&) = delete;

    bool Start(Protocol::PcState initialState = Protocol::PcState::ONLINE);
    void Stop();
    void SetState(Protocol::PcState state);

    bool IsRunning() const noexcept { return m_isRunning.load(); }
    uint16_t GetUdpPort() const noexcept { return m_udpPort; }

    // Helper static methods for parsing and constructing discovery payloads
    static std::vector<uint8_t> BuildDiscoveryResponsePayload(const DiscoveryAnnouncement& ann);
    static bool ParseDiscoveryResponsePayload(const uint8_t* data, size_t len, DiscoveryAnnouncement& outAnn);

private:
    void ListenerLoop();
    static DWORD WINAPI ListenerThreadProc(LPVOID lpParam);

    uint16_t m_udpPort;
    uint16_t m_tcpPort;
    SOCKET m_udpSocket{INVALID_SOCKET};
    std::atomic<bool> m_isRunning{false};
    std::atomic<Protocol::PcState> m_state{Protocol::PcState::ONLINE};
    std::string m_hostName;
    HANDLE m_hListenerThread{nullptr};
};

} // namespace MobileUnlock::Network
