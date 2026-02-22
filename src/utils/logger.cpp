#include "src/utils/logger.h"
#include "src/utils/string_utils.h"
#include <string>
#include <fstream>
#include <iostream>
#include <sstream>
#include <ctime>
#include <iomanip>
#include <chrono>
#include <shlobj.h>
#include <windows.h> // For OutputDebugStringW

namespace NetSentinel {
namespace {
bool SafeLocalTime(std::tm& out, const std::time_t& in) {
    std::tm* tmp = std::localtime(&in);
    if (!tmp) {
        return false;
    }
    out = *tmp;
    return true;
}
} // namespace

Logger& Logger::Instance() {
    static Logger instance;
    return instance;
}

bool Logger::Initialize(const std::wstring& logDirectory) {
    logDir_ = logDirectory;
    
    // Create directory tree if needed (CreateDirectoryW can't create parents).
    const int shRes = SHCreateDirectoryExW(nullptr, logDir_.c_str(), nullptr);
    if (shRes != ERROR_SUCCESS && shRes != ERROR_ALREADY_EXISTS) {
        return false;
    }
    
    // Set restrictive permissions (user only)
    // Simplified - in production, set ACLs here
    
    currentLogFile_ = GetLogFilePath();

    file_.open(Utils::WideToUTF8(currentLogFile_), std::ios::app);
    if (!file_.is_open()) return false;
    
    Info(L"Logger initialized: " + currentLogFile_);
    return true;
}

void Logger::Shutdown() {
    if (file_.is_open()) {
        file_.close();
    }
}

void Logger::Log(LogLevel level, const std::wstring& message) {
    if (level < minLevel_) return;

    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::tm localTime{};
    if (!SafeLocalTime(localTime, time)) {
        return;
    }

    std::wostringstream oss;
    oss << std::put_time(&localTime, L"%Y-%m-%d %H:%M:%S");
    oss << L" [" << LevelToString(level) << L"] " << message;

    if (file_.is_open()) {
        file_ << oss.str() << std::endl;
        file_.flush();
    }

    // Only pipe WARNING and above to Electron frontend stdout
    // INFO/DEBUG go to log file only to avoid flooding the monitor UI
    if (level >= LogLevel::WARNING) {
        std::string narrow = Utils::WideToUTF8(oss.str());
        std::cout << narrow << "\n" << std::flush;
    }

    // Also OutputDebugString for debugging
    OutputDebugStringW((oss.str() + L"\n").c_str());
}

std::wstring Logger::GetLogFilePath() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::tm localTime{};
    if (!SafeLocalTime(localTime, time)) {
        return logDir_ + L"\\NetSentinel.log";
    }
    
    std::wostringstream oss;
    oss << logDir_ << L"\\NetSentinel_";
    oss << std::put_time(&localTime, L"%Y%m%d") << L".log";
    return oss.str();
}

std::wstring Logger::LevelToString(LogLevel level) {
    switch (level) {
        case LogLevel::DEBUG: return L"DEBUG";
        case LogLevel::INFO: return L"INFO";
        case LogLevel::WARNING: return L"WARN";
        case LogLevel::ERR: return L"ERROR";
        case LogLevel::CRITICAL: return L"CRIT";
        default: return L"UNKNOWN";
    }
}

} // namespace NetSentinel
