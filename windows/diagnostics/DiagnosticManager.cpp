#include "DiagnosticManager.h"

namespace MobileUnlock::Diagnostics {

DiagnosticManager::DiagnosticManager()
    : m_serviceStatus(ComponentStatus::UNINITIALIZED),
      m_ipcStatus(ComponentStatus::UNINITIALIZED),
      m_sessionAgentStatus(ComponentStatus::UNINITIALIZED),
      m_activeConnections(0),
      m_totalMessagesProcessed(0),
      m_startTime(std::chrono::steady_clock::now()) {}

void DiagnosticManager::SetServiceStatus(ComponentStatus status, std::wstring details) {
    m_serviceStatus.store(status);
    m_serviceDetails = std::move(details);
}

void DiagnosticManager::SetIpcStatus(ComponentStatus status, std::wstring details) {
    m_ipcStatus.store(status);
    m_ipcDetails = std::move(details);
}

void DiagnosticManager::SetSessionAgentStatus(ComponentStatus status, std::wstring details) {
    m_sessionAgentStatus.store(status);
    m_sessionAgentDetails = std::move(details);
}

DiagnosticReport DiagnosticManager::GenerateReport() const {
    DiagnosticReport report;
    report.ServiceStatus = m_serviceStatus.load();
    report.IpcStatus = m_ipcStatus.load();
    report.SessionAgentStatus = m_sessionAgentStatus.load();
    report.ActiveConnections = m_activeConnections.load();
    report.TotalMessagesProcessed = m_totalMessagesProcessed.load();

    auto now = std::chrono::steady_clock::now();
    report.UpTimeSeconds = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(now - m_startTime).count()
    );
    report.StatusDetails = L"Service: " + m_serviceDetails + L" | IPC: " + m_ipcDetails + L" | Agent: " + m_sessionAgentDetails;
    return report;
}

} // namespace MobileUnlock::Diagnostics
