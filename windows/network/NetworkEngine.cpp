#include "NetworkEngine.h"
#include "../logging/SecurityAuditLogger.h"
#include <iostream>
#include <vector>
#include <cstring>

namespace MobileUnlock::Network {

struct ClientThreadArg {
    NetworkEngine* Engine;
    uint64_t ClientId;
};

NetworkEngine::NetworkEngine(uint16_t port)
    : m_port(port)
{
    InitializeCriticalSection(&m_clientsLock);
    InitializeCriticalSection(&m_rateLimitLock);

    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
}

NetworkEngine::~NetworkEngine() {
    Stop();
    WSACleanup();
    DeleteCriticalSection(&m_clientsLock);
    DeleteCriticalSection(&m_rateLimitLock);
}

bool NetworkEngine::CheckRateLimit(const std::string& ip) {
    EnterCriticalSection(&m_rateLimitLock);
    DWORD now = GetTickCount();

    auto it = m_rateLimits.find(ip);
    if (it == m_rateLimits.end()) {
        RateLimitEntry entry;
        entry.FirstAttemptMs = now;
        entry.AttemptCount = 1;
        entry.BlockedUntilMs = 0;
        m_rateLimits[ip] = entry;
        LeaveCriticalSection(&m_rateLimitLock);
        return true;
    }

    auto& entry = it->second;
    if (entry.BlockedUntilMs > now) {
        LeaveCriticalSection(&m_rateLimitLock);
        return false; // Currently blocked
    }

    if ((now - entry.FirstAttemptMs) > 60000) {
        // Reset 1-minute window
        entry.FirstAttemptMs = now;
        entry.AttemptCount = 1;
        entry.BlockedUntilMs = 0;
        LeaveCriticalSection(&m_rateLimitLock);
        return true;
    }

    entry.AttemptCount++;
    if (entry.AttemptCount > 5) {
        // Rate limit exceeded: block for 15 minutes (900,000 ms)
        entry.BlockedUntilMs = now + 900000;
        LeaveCriticalSection(&m_rateLimitLock);
        return false;
    }

    LeaveCriticalSection(&m_rateLimitLock);
    return true;
}

bool NetworkEngine::Start(FrameReceivedCallback callback) {
    if (m_isRunning.load()) return false;

    m_callback = std::move(callback);

    m_listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_listenSocket == INVALID_SOCKET) {
        return false;
    }

    // Set SO_REUSEADDR
    BOOL opt = TRUE;
    setsockopt(m_listenSocket, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serverAddr.sin_port = htons(m_port);

    if (bind(m_listenSocket, reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr)) == SOCKET_ERROR) {
        closesocket(m_listenSocket);
        m_listenSocket = INVALID_SOCKET;
        return false;
    }

    if (listen(m_listenSocket, SOMAXCONN) == SOCKET_ERROR) {
        closesocket(m_listenSocket);
        m_listenSocket = INVALID_SOCKET;
        return false;
    }

    m_isRunning.store(true);

    m_hAcceptThread = CreateThread(nullptr, 0, AcceptThreadProc, this, 0, nullptr);
    m_hMaintenanceThread = CreateThread(nullptr, 0, MaintenanceThreadProc, this, 0, nullptr);

    return (m_hAcceptThread != nullptr);
}

void NetworkEngine::Stop() {
    if (!m_isRunning.load()) return;
    m_isRunning.store(false);

    if (m_listenSocket != INVALID_SOCKET) {
        closesocket(m_listenSocket);
        m_listenSocket = INVALID_SOCKET;
    }

    // Disconnect and close all active client sockets
    EnterCriticalSection(&m_clientsLock);
    for (auto& pair : m_clients) {
        if (pair.second && pair.second->Socket != INVALID_SOCKET) {
            shutdown(pair.second->Socket, SD_BOTH);
            closesocket(pair.second->Socket);
            pair.second->Socket = INVALID_SOCKET;
            pair.second->State = ConnectionState::DISCONNECTED;
        }
    }
    m_clients.clear();
    LeaveCriticalSection(&m_clientsLock);

    if (m_hAcceptThread) {
        WaitForSingleObject(m_hAcceptThread, 1000);
        CloseHandle(m_hAcceptThread);
        m_hAcceptThread = nullptr;
    }

    if (m_hMaintenanceThread) {
        WaitForSingleObject(m_hMaintenanceThread, 1000);
        CloseHandle(m_hMaintenanceThread);
        m_hMaintenanceThread = nullptr;
    }
}

DWORD WINAPI NetworkEngine::AcceptThreadProc(LPVOID lpParam) {
    auto* engine = static_cast<NetworkEngine*>(lpParam);
    if (engine) engine->ServerAcceptLoop();
    return 0;
}

DWORD WINAPI NetworkEngine::MaintenanceThreadProc(LPVOID lpParam) {
    auto* engine = static_cast<NetworkEngine*>(lpParam);
    while (engine && engine->m_isRunning.load()) {
        Sleep(5000);
        engine->CleanupStaleSessions();
    }
    return 0;
}

void NetworkEngine::ServerAcceptLoop() {
    while (m_isRunning.load()) {
        sockaddr_in clientAddr{};
        int clientAddrLen = sizeof(clientAddr);

        SOCKET clientSock = accept(m_listenSocket, reinterpret_cast<sockaddr*>(&clientAddr), &clientAddrLen);
        if (clientSock == INVALID_SOCKET) {
            if (!m_isRunning.load()) break;
            Sleep(50);
            continue;
        }

        const char* ipStr = inet_ntoa(clientAddr.sin_addr);
        std::string clientIp = (ipStr != nullptr) ? ipStr : "127.0.0.1";
        uint16_t clientPort = ntohs(clientAddr.sin_port);

        if (!CheckRateLimit(clientIp)) {
            Logging::SecurityAuditLogger::GetInstance().LogSecurityEvent(
                Logging::EventId::SERVICE_FAULT,
                Logging::LogLevel::Warning,
                L"Rate limit exceeded for client IP: " + std::wstring(clientIp.begin(), clientIp.end())
            );
            closesocket(clientSock);
            continue;
        }

        // Set socket send/recv timeouts (5 seconds)
        DWORD timeout = 5000;
        setsockopt(clientSock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
        setsockopt(clientSock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));

        uint64_t clientId = m_nextClientId++;
        auto session = std::make_shared<ClientSession>();
        session->ClientId = clientId;
        session->Socket = clientSock;
        session->ClientIp = clientIp;
        session->ClientPort = clientPort;
        session->State = ConnectionState::TCP_CONNECTING;
        session->ConnectTimestampMs = GetTickCount();
        session->LastActiveTimestampMs = GetTickCount();
        session->Tls = std::make_unique<TlsContext>();

        EnterCriticalSection(&m_clientsLock);
        m_clients[clientId] = session;
        LeaveCriticalSection(&m_clientsLock);

        auto* arg = new ClientThreadArg{this, clientId};
        HANDLE hClientThread = CreateThread(nullptr, 0, ClientThreadProc, arg, 0, nullptr);
        if (hClientThread) {
            CloseHandle(hClientThread); // detached worker thread
        } else {
            delete arg;
            closesocket(clientSock);
        }
    }
}

DWORD WINAPI NetworkEngine::ClientThreadProc(LPVOID lpParam) {
    auto* arg = static_cast<ClientThreadArg*>(lpParam);
    if (arg && arg->Engine) {
        arg->Engine->ClientWorkerLoop(arg->ClientId);
    }
    delete arg;
    return 0;
}

void NetworkEngine::ClientWorkerLoop(uint64_t clientId) {
    std::shared_ptr<ClientSession> session;
    {
        EnterCriticalSection(&m_clientsLock);
        auto it = m_clients.find(clientId);
        if (it != m_clients.end()) session = it->second;
        LeaveCriticalSection(&m_clientsLock);
    }
    if (!session) return;

    std::vector<uint8_t> rawBuffer(4096);
    session->State = ConnectionState::TCP_CONNECTING;

    while (m_isRunning.load() && session->Socket != INVALID_SOCKET) {
        int bytesRead = recv(session->Socket, reinterpret_cast<char*>(rawBuffer.data()), static_cast<int>(rawBuffer.size()), 0);
        if (bytesRead <= 0) {
            int err = WSAGetLastError();
            if (err == WSAETIMEDOUT) {
                // Inactivity check: 30 seconds
                if ((GetTickCount() - session->LastActiveTimestampMs) > 30000) {
                    break;
                }
                continue;
            }
            break; // Socket closed or error
        }

        session->LastActiveTimestampMs = GetTickCount();

        // Check if incoming data starts with TLS Handshake Record (0x16) or direct FrameHeader magic (0x4D)
        if (session->State == ConnectionState::TCP_CONNECTING) {
            if (rawBuffer[0] == 0x16) {
                session->State = ConnectionState::TLS_HANDSHAKE;
            } else if (rawBuffer[0] == 0x4D) {
                session->State = ConnectionState::ACTIVE_SESSION;
            }
        }

        if (session->State == ConnectionState::TLS_HANDSHAKE) {
            std::vector<uint8_t> outTls;
            size_t consumed = 0;
            TlsStatus status = session->Tls->AcceptHandshake(rawBuffer.data(), bytesRead, outTls, consumed);

            if (!outTls.empty()) {
                send(session->Socket, reinterpret_cast<const char*>(outTls.data()), static_cast<int>(outTls.size()), 0);
            }

            if (status == TlsStatus::SUCCESS) {
                session->State = ConnectionState::ACTIVE_SESSION;
            } else if (status == TlsStatus::CONTINUE_NEEDED) {
                // Handshake continuing
            } else if (status == TlsStatus::INCOMPLETE_DATA) {
                // Wait for more TLS records
            } else {
                // Handshake error / protocol version rejected
                break;
            }
            continue;
        }

        if (session->State == ConnectionState::ACTIVE_SESSION) {
            if (session->Tls && session->Tls->IsHandshakeComplete()) {
                std::vector<uint8_t> plainData;
                size_t consumed = 0;
                TlsStatus decStatus = session->Tls->DecryptPayload(rawBuffer.data(), bytesRead, plainData, consumed);
                if (decStatus == TlsStatus::SUCCESS && !plainData.empty()) {
                    session->ReceiveBuffer.insert(session->ReceiveBuffer.end(), plainData.begin(), plainData.end());
                }
            } else {
                session->ReceiveBuffer.insert(session->ReceiveBuffer.end(), rawBuffer.begin(), rawBuffer.begin() + bytesRead);
            }

            const uint8_t* frameBytes = session->ReceiveBuffer.data();
            size_t frameLen = session->ReceiveBuffer.size();

            while (frameLen >= Protocol::FRAME_HEADER_SIZE) {
                auto headerResult = Protocol::DeserializeFrameHeader(frameBytes, frameLen);
                if (!headerResult.has_value()) {
                    // Malformed header magic/version or opcode — drop socket immediately
                    session->Socket = INVALID_SOCKET;
                    break;
                }

                auto header = headerResult.value;
                if (header.PayloadLength > Protocol::MAX_PAYLOAD_SIZE) {
                    // Exceeds 4096B limit — defense mechanism
                    session->Socket = INVALID_SOCKET;
                    break;
                }

                size_t totalMessageLen = Protocol::FRAME_HEADER_SIZE + header.PayloadLength;
                if (frameLen < totalMessageLen) {
                    // Need more bytes for full payload
                    break;
                }

                std::vector<uint8_t> payload(frameBytes + Protocol::FRAME_HEADER_SIZE, frameBytes + totalMessageLen);
                if (m_callback) {
                    m_callback(clientId, header, payload);
                }

                session->ReceiveBuffer.erase(session->ReceiveBuffer.begin(), session->ReceiveBuffer.begin() + totalMessageLen);
                frameBytes = session->ReceiveBuffer.data();
                frameLen = session->ReceiveBuffer.size();
            }

            if (session->Socket == INVALID_SOCKET) {
                break;
            }
        }
    }

    // Cleanup client session
    session->State = ConnectionState::DISCONNECTED;
    if (session->Socket != INVALID_SOCKET) {
        closesocket(session->Socket);
        session->Socket = INVALID_SOCKET;
    }

    EnterCriticalSection(&m_clientsLock);
    m_clients.erase(clientId);
    LeaveCriticalSection(&m_clientsLock);
}

bool NetworkEngine::SendFrame(uint64_t clientId, const Protocol::FrameHeader& header, const std::vector<uint8_t>& payload) {
    std::shared_ptr<ClientSession> session;
    {
        EnterCriticalSection(&m_clientsLock);
        auto it = m_clients.find(clientId);
        if (it != m_clients.end()) session = it->second;
        LeaveCriticalSection(&m_clientsLock);
    }

    if (!session || session->Socket == INVALID_SOCKET) return false;

    auto headerBytes = Protocol::SerializeFrameHeader(header);
    std::vector<uint8_t> fullFrame = headerBytes;
    if (!payload.empty()) {
        fullFrame.insert(fullFrame.end(), payload.begin(), payload.end());
    }

    if (session->Tls && session->Tls->IsHandshakeComplete()) {
        std::vector<uint8_t> encrypted;
        if (session->Tls->EncryptPayload(fullFrame.data(), fullFrame.size(), encrypted) == TlsStatus::SUCCESS) {
            int sent = send(session->Socket, reinterpret_cast<const char*>(encrypted.data()), static_cast<int>(encrypted.size()), 0);
            return (sent == static_cast<int>(encrypted.size()));
        }
        return false;
    }

    int sent = send(session->Socket, reinterpret_cast<const char*>(fullFrame.data()), static_cast<int>(fullFrame.size()), 0);
    return (sent == static_cast<int>(fullFrame.size()));
}

void NetworkEngine::BroadcastFrame(const Protocol::FrameHeader& header, const std::vector<uint8_t>& payload) {
    EnterCriticalSection(&m_clientsLock);
    std::vector<uint64_t> clientIds;
    for (const auto& pair : m_clients) {
        if (pair.second && pair.second->State == ConnectionState::ACTIVE_SESSION) {
            clientIds.push_back(pair.first);
        }
    }
    LeaveCriticalSection(&m_clientsLock);

    for (uint64_t cid : clientIds) {
        SendFrame(cid, header, payload);
    }
}

void NetworkEngine::CleanupStaleSessions() {
    DWORD now = GetTickCount();
    std::vector<SOCKET> staleSockets;

    EnterCriticalSection(&m_clientsLock);
    for (auto it = m_clients.begin(); it != m_clients.end();) {
        if (it->second && (now - it->second->LastActiveTimestampMs) > 30000) {
            if (it->second->Socket != INVALID_SOCKET) {
                staleSockets.push_back(it->second->Socket);
                it->second->Socket = INVALID_SOCKET;
            }
            it = m_clients.erase(it);
        } else {
            ++it;
        }
    }
    LeaveCriticalSection(&m_clientsLock);

    for (SOCKET s : staleSockets) {
        closesocket(s);
    }
}

size_t NetworkEngine::GetActiveClientCount() const {
    EnterCriticalSection(&m_clientsLock);
    size_t count = m_clients.size();
    LeaveCriticalSection(&m_clientsLock);
    return count;
}

} // namespace MobileUnlock::Network
