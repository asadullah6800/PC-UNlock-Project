#include "SecureIPC.h"
#include <iostream>
#include <chrono>

namespace MobileUnlock::IPC {

// NamedPipeServer Implementation

NamedPipeServer::NamedPipeServer(std::wstring pipeName)
    : m_pipeName(std::move(pipeName)),
      m_hPipe(INVALID_HANDLE_VALUE),
      m_isRunning(false),
      m_isConnected(false)
{}

NamedPipeServer::~NamedPipeServer() {
    Stop();
}

PSECURITY_ATTRIBUTES NamedPipeServer::CreatePipeSecurityAttributes() {
    LPCWSTR sddl = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;NS)(A;;GA;;;IU)(A;;GA;;;AU)";
    PSECURITY_DESCRIPTOR pSd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &pSd, nullptr)) {
        return nullptr;
    }

    PSECURITY_ATTRIBUTES pSa = static_cast<PSECURITY_ATTRIBUTES>(LocalAlloc(LPTR, sizeof(SECURITY_ATTRIBUTES)));
    if (!pSa) {
        LocalFree(pSd);
        return nullptr;
    }

    pSa->nLength = sizeof(SECURITY_ATTRIBUTES);
    pSa->lpSecurityDescriptor = pSd;
    pSa->bInheritHandle = FALSE;
    return pSa;
}

void NamedPipeServer::FreePipeSecurityAttributes(PSECURITY_ATTRIBUTES pSa) {
    if (pSa) {
        if (pSa->lpSecurityDescriptor) {
            LocalFree(pSa->lpSecurityDescriptor);
        }
        LocalFree(pSa);
    }
}

bool NamedPipeServer::Start(MessageHandler handler) {
    if (m_isRunning.load()) return false;
    m_handler = std::move(handler);
    m_isRunning.store(true);
    m_hWorkerThread = CreateThread(
        nullptr,
        0,
        WorkerThreadProc,
        this,
        0,
        nullptr
    );
    return (m_hWorkerThread != nullptr);
}

DWORD WINAPI NamedPipeServer::WorkerThreadProc(LPVOID lpParam) {
    auto* server = static_cast<NamedPipeServer*>(lpParam);
    if (server) {
        server->ServerWorkerThread();
    }
    return 0;
}

void NamedPipeServer::Stop() {
    m_isRunning.store(false);
    m_isConnected.store(false);

    if (m_hPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(m_hPipe);
        m_hPipe = INVALID_HANDLE_VALUE;
    }

    if (m_hWorkerThread != nullptr) {
        CancelSynchronousIo(m_hWorkerThread);
        WaitForSingleObject(m_hWorkerThread, 1000);
        CloseHandle(m_hWorkerThread);
        m_hWorkerThread = nullptr;
    }
}

void NamedPipeServer::ServerWorkerThread() {
    while (m_isRunning.load()) {
        PSECURITY_ATTRIBUTES pSa = CreatePipeSecurityAttributes();

        m_hPipe = CreateNamedPipeW(
            m_pipeName.c_str(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            4096,
            4096,
            5000,
            pSa
        );

        FreePipeSecurityAttributes(pSa);

        if (m_hPipe == INVALID_HANDLE_VALUE) {
            Sleep(100);
            continue;
        }

        BOOL connected = ConnectNamedPipe(m_hPipe, nullptr) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

        if (connected && m_isRunning.load()) {
            m_isConnected.store(true);
            std::vector<uint8_t> buffer(4096);
            DWORD bytesRead = 0;

            while (m_isRunning.load() && m_isConnected.load()) {
                DWORD bytesAvail = 0;
                if (!PeekNamedPipe(m_hPipe, nullptr, 0, nullptr, &bytesAvail, nullptr)) {
                    m_isConnected.store(false);
                    break;
                }
                if (bytesAvail == 0) {
                    Sleep(10);
                    continue;
                }

                BOOL success = ReadFile(m_hPipe, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead, nullptr);
                if (success && bytesRead > 0) {
                    std::vector<uint8_t> message(buffer.begin(), buffer.begin() + bytesRead);
                    if (m_handler) {
                        m_handler(message);
                    }
                } else {
                    m_isConnected.store(false);
                }
            }
            DisconnectNamedPipe(m_hPipe);
        }

        CloseHandle(m_hPipe);
        m_hPipe = INVALID_HANDLE_VALUE;
        m_isConnected.store(false);
    }
}

bool NamedPipeServer::SendMessageToClient(const std::vector<uint8_t>& message) {
    if (!m_isConnected.load() || m_hPipe == INVALID_HANDLE_VALUE || message.empty()) {
        return false;
    }
    DWORD bytesWritten = 0;
    BOOL success = WriteFile(m_hPipe, message.data(), static_cast<DWORD>(message.size()), &bytesWritten, nullptr);
    return success && (bytesWritten == static_cast<DWORD>(message.size()));
}

// NamedPipeClient Implementation

NamedPipeClient::NamedPipeClient(std::wstring pipeName)
    : m_pipeName(std::move(pipeName)),
      m_hPipe(INVALID_HANDLE_VALUE)
{}

NamedPipeClient::~NamedPipeClient() {
    Disconnect();
}

bool NamedPipeClient::Connect(DWORD timeoutMs) {
    if (m_hPipe != INVALID_HANDLE_VALUE) return true;

    DWORD startTime = GetTickCount();
    while ((GetTickCount() - startTime) < timeoutMs) {
        m_hPipe = CreateFileW(
            m_pipeName.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr
        );

        if (m_hPipe != INVALID_HANDLE_VALUE) {
            break;
        }

        DWORD err = GetLastError();
        if (err == ERROR_PIPE_BUSY) {
            WaitNamedPipeW(m_pipeName.c_str(), 1000);
        } else {
            Sleep(50);
        }
    }

    if (m_hPipe == INVALID_HANDLE_VALUE) return false;

    DWORD dwMode = PIPE_READMODE_MESSAGE;
    if (!SetNamedPipeHandleState(m_hPipe, &dwMode, nullptr, nullptr)) {
        CloseHandle(m_hPipe);
        m_hPipe = INVALID_HANDLE_VALUE;
        return false;
    }

    return true;
}

void NamedPipeClient::Disconnect() {
    if (m_hPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(m_hPipe);
        m_hPipe = INVALID_HANDLE_VALUE;
    }
}

bool NamedPipeClient::SendMessageToServer(const std::vector<uint8_t>& message) {
    if (m_hPipe == INVALID_HANDLE_VALUE || message.empty()) return false;
    DWORD bytesWritten = 0;
    BOOL success = WriteFile(m_hPipe, message.data(), static_cast<DWORD>(message.size()), &bytesWritten, nullptr);
    return success && (bytesWritten == static_cast<DWORD>(message.size()));
}

ReadResult NamedPipeClient::ReadMessageFromServer(DWORD timeoutMs) {
    if (m_hPipe == INVALID_HANDLE_VALUE) return ReadResult();

    DWORD startTime = GetTickCount();
    DWORD bytesAvail = 0;
    while (true) {
        if (PeekNamedPipe(m_hPipe, nullptr, 0, nullptr, &bytesAvail, nullptr) && bytesAvail > 0) {
            break;
        }
        if ((GetTickCount() - startTime) >= timeoutMs) {
            return ReadResult();
        }
        Sleep(10);
    }

    std::vector<uint8_t> buffer(bytesAvail > 0 ? bytesAvail : 4096);
    DWORD bytesRead = 0;
    BOOL success = ReadFile(m_hPipe, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead, nullptr);

    if (success && bytesRead > 0) {
        buffer.resize(bytesRead);
        return ReadResult(buffer);
    }
    return ReadResult();
}

} // namespace MobileUnlock::IPC
