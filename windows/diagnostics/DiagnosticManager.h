#pragma once

#include <string>
#include <atomic>
#include <chrono>

namespace MobileUnlock::Diagnostics {

enum class ComponentStatus {
    OK,
    WARNING,
    ERROR_STATE,
    UNINITIALIZED
};

struct DiagnosticReport {
    ComponentStatus ServiceStatus{ComponentStatus::UNINITIALIZED};
    ComponentStatus IpcStatus{ComponentStatus::UNINITIALIZED};
    ComponentStatus SessionAgentStatus{ComponentStatus::UNINITIALIZED};
    uint64_t ActiveConnections{0};
    uint64_t TotalMessagesProcessed{0};
    uint64_t UpTimeSeconds{0};
    std::wstring StatusDetails;
};

class DiagnosticManager {
public:
    DiagnosticManager();
    ~DiagnosticManager() = default;

    void SetServiceStatus(ComponentStatus status, std::wstring details = L"");
    void SetIpcStatus(ComponentStatus status, std::wstring details = L"");
    void SetSessionAgentStatus(ComponentStatus status, std::wstring details = L"");

    void IncrementProcessedMessages() { m_totalMessagesProcessed++; }
    void SetActiveConnections(uint64_t count) { m_activeConnections = count; }

    DiagnosticReport GenerateReport() const;

private:
    std::atomic<ComponentStatus> m_serviceStatus;
    std::atomic<ComponentStatus> m_ipcStatus;
    std::atomic<ComponentStatus> m_sessionAgentStatus;
    std::atomic<uint64_t> m_activeConnections;
    std::atomic<uint64_t> m_totalMessagesProcessed;

    std::wstring m_serviceDetails;
    std::wstring m_ipcDetails;
    std::wstring m_sessionAgentDetails;
    std::chrono::steady_clock::time_point m_startTime;
};

} // namespace MobileUnlock::Diagnostics
