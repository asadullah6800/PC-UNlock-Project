#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <functional>
#include <atomic>
#include <mutex>
#include "TlsContext.h"
#include "../../shared/protocol/ProtocolTypes.h"

namespace MobileUnlock::Network {

enum class ConnectionState {
    DISCONNECTED,
    TCP_CONNECTING,
    TLS_HANDSHAKE,
    ACTIVE_SESSION,
    RECONNECTING,
    ERROR_STATE
};

struct ClientSession {
    uint64_t ClientId{0};
    SOCKET Socket{INVALID_SOCKET};
    std::string ClientIp;
    uint16_t ClientPort{0};
    ConnectionState State{ConnectionState::DISCONNECTED};
    DWORD ConnectTimestampMs{0};
    DWORD LastActiveTimestampMs{0};
    std::unique_ptr<TlsContext> Tls;
    std::vector<uint8_t> ReceiveBuffer;
};

using FrameReceivedCallback = std::function<void(uint64_t clientId, const Protocol::FrameHeader& header, const std::vector<uint8_t>& payload)>;

class NetworkEngine {
public:
    explicit NetworkEngine(uint16_t port = 8443);
    ~NetworkEngine();

    NetworkEngine(const NetworkEngine&) = delete;
    NetworkEngine& operator=(const NetworkEngine&) = delete;

    // Start TCP & TLS 1.3 server
    bool Start(FrameReceivedCallback callback);

    // Stop server and cleanly disconnect all clients
    void Stop();

    // Send protocol frame to specific connected client
    bool SendFrame(uint64_t clientId, const Protocol::FrameHeader& header, const std::vector<uint8_t>& payload);

    // Broadcast frame to all active sessions
    void BroadcastFrame(const Protocol::FrameHeader& header, const std::vector<uint8_t>& payload);

    // Rate limiting check: returns true if IP allowed, false if rate limited
    bool CheckRateLimit(const std::string& ip);

    // Query active client count
    size_t GetActiveClientCount() const;

    bool IsRunning() const noexcept { return m_isRunning.load(); }
    uint16_t GetPort() const noexcept { return m_port; }

private:
    void ServerAcceptLoop();
    void ClientWorkerLoop(uint64_t clientId);
    void CleanupStaleSessions();

    static DWORD WINAPI AcceptThreadProc(LPVOID lpParam);
    static DWORD WINAPI ClientThreadProc(LPVOID lpParam);
    static DWORD WINAPI MaintenanceThreadProc(LPVOID lpParam);

    uint16_t m_port;
    SOCKET m_listenSocket{INVALID_SOCKET};
    std::atomic<bool> m_isRunning{false};
    std::atomic<uint64_t> m_nextClientId{1};

    FrameReceivedCallback m_callback;

    mutable CRITICAL_SECTION m_clientsLock;
    std::unordered_map<uint64_t, std::shared_ptr<ClientSession>> m_clients;

    mutable CRITICAL_SECTION m_rateLimitLock;
    struct RateLimitEntry {
        DWORD FirstAttemptMs{0};
        uint32_t AttemptCount{0};
        DWORD BlockedUntilMs{0};
    };
    std::unordered_map<std::string, RateLimitEntry> m_rateLimits;

    HANDLE m_hAcceptThread{nullptr};
    HANDLE m_hMaintenanceThread{nullptr};
};

} // namespace MobileUnlock::Network
