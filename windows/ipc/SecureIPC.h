#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <sddl.h>

#ifndef SDDL_REVISION_1
#define SDDL_REVISION_1 1
#endif

#if defined(__GNUC__)
extern "C" {
WINADVAPI BOOL WINAPI ConvertStringSecurityDescriptorToSecurityDescriptorW(
    LPCWSTR StringSecurityDescriptor,
    DWORD StringSDRevision,
    PSECURITY_DESCRIPTOR *SecurityDescriptor,
    PULONG SecurityDescriptorSize
);
WINBASEAPI BOOL WINAPI CancelSynchronousIo(HANDLE hThread);
}
#endif

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <atomic>
#include "../../shared/protocol/ProtocolTypes.h"

namespace MobileUnlock::IPC {

using MessageHandler = std::function<void(const std::vector<uint8_t>& message)>;

struct ReadResult {
    bool valid;
    std::vector<uint8_t> data;
    ReadResult() : valid(false) {}
    ReadResult(std::vector<uint8_t> d) : valid(true), data(std::move(d)) {}
};

class NamedPipeServer {
public:
    explicit NamedPipeServer(std::wstring pipeName);
    ~NamedPipeServer();

    NamedPipeServer(const NamedPipeServer&) = delete;
    NamedPipeServer& operator=(const NamedPipeServer&) = delete;

    bool Start(MessageHandler handler);
    void Stop();
    bool SendMessageToClient(const std::vector<uint8_t>& message);

    bool IsConnected() const { return m_isConnected.load(); }

private:
    void ServerWorkerThread();
    static DWORD WINAPI WorkerThreadProc(LPVOID lpParam);
    PSECURITY_ATTRIBUTES CreatePipeSecurityAttributes();
    void FreePipeSecurityAttributes(PSECURITY_ATTRIBUTES pSa);

    std::wstring m_pipeName;
    HANDLE m_hPipe;
    std::atomic<bool> m_isRunning;
    std::atomic<bool> m_isConnected;
    MessageHandler m_handler;
    HANDLE m_hWorkerThread{nullptr};
};

class NamedPipeClient {
public:
    explicit NamedPipeClient(std::wstring pipeName);
    ~NamedPipeClient();

    bool Connect(DWORD timeoutMs = 5000);
    void Disconnect();
    bool SendMessageToServer(const std::vector<uint8_t>& message);
    ReadResult ReadMessageFromServer(DWORD timeoutMs = 5000);

    bool IsConnected() const { return m_hPipe != INVALID_HANDLE_VALUE; }

private:
    std::wstring m_pipeName;
    HANDLE m_hPipe;
};

} // namespace MobileUnlock::IPC
