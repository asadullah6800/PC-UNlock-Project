#pragma once

#include <string>
#include <windows.h>

namespace MobileUnlock::Logging {

enum class EventId : DWORD {
    PAIRING_SUCCESS  = 1001,
    UNPAIR_SUCCESS   = 1002,
    AUTH_SUCCESS     = 2001,
    AUTH_FAILURE     = 2002,
    AUTH_REPLAY      = 2003,
    LOCK_EXECUTED    = 3001,
    SERVICE_FAULT    = 4001
};

enum class LogLevel {
    Info,
    Warning,
    Error
};

class SecurityAuditLogger {
public:
    static SecurityAuditLogger& GetInstance();

    // Writes structured security event to Windows Event Log
    void LogSecurityEvent(EventId eventId, LogLevel level, const std::wstring& message, const std::wstring& deviceId = L"");

    // General diagnostic logging
    void LogDiagnostic(LogLevel level, const std::wstring& message);

private:
    SecurityAuditLogger();
    ~SecurityAuditLogger();

    SecurityAuditLogger(const SecurityAuditLogger&) = delete;
    SecurityAuditLogger& operator=(const SecurityAuditLogger&) = delete;

    HANDLE m_hEventLog{nullptr};
};

} // namespace MobileUnlock::Logging
