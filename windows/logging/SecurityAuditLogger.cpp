#include "SecurityAuditLogger.h"
#include <iostream>
#include <sstream>

namespace MobileUnlock::Logging {

const wchar_t* SOURCE_NAME = L"MobileFingerprintUnlock";

SecurityAuditLogger& SecurityAuditLogger::GetInstance() {
    static SecurityAuditLogger instance;
    return instance;
}

SecurityAuditLogger::SecurityAuditLogger() {
    m_hEventLog = RegisterEventSourceW(nullptr, SOURCE_NAME);
}

SecurityAuditLogger::~SecurityAuditLogger() {
    if (m_hEventLog != nullptr) {
        DeregisterEventSource(m_hEventLog);
        m_hEventLog = nullptr;
    }
}

void SecurityAuditLogger::LogSecurityEvent(EventId eventId, LogLevel level, const std::wstring& message, const std::wstring& deviceId) {
    std::wostringstream oss;
    oss << L"[MobileUnlockAudit] EventID: " << static_cast<DWORD>(eventId) << L" | Msg: " << message;
    if (!deviceId.empty()) {
        oss << L" | DeviceID: " << deviceId;
    }
    std::wstring formattedMsg = oss.str();

    // Write to console for development / service testing
    std::wcout << formattedMsg << std::endl;

    if (m_hEventLog == nullptr) {
        return;
    }

    WORD wType = EVENTLOG_INFORMATION_TYPE;
    switch (level) {
    case LogLevel::Info:    wType = EVENTLOG_INFORMATION_TYPE; break;
    case LogLevel::Warning: wType = EVENTLOG_WARNING_TYPE; break;
    case LogLevel::Error:   wType = EVENTLOG_ERROR_TYPE; break;
    }

    LPCWSTR strings[1] = { formattedMsg.c_str() };
    ReportEventW(
        m_hEventLog,
        wType,
        0,
        static_cast<DWORD>(eventId),
        nullptr,
        1,
        0,
        strings,
        nullptr
    );
}

void SecurityAuditLogger::LogDiagnostic(LogLevel level, const std::wstring& message) {
    LogSecurityEvent(EventId::SERVICE_FAULT, level, message);
}

} // namespace MobileUnlock::Logging
