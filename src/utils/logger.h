// logger.h
#pragma once
#include <string>
#include <fstream>

namespace NetSentinel {

enum class LogLevel {
    DEBUG = 0,
    INFO = 1,
    WARNING = 2,
    ERR = 3,
    CRITICAL = 4
};

class Logger {
public:
    static Logger& Instance();
    
    bool Initialize(const std::wstring& logDirectory);
    void Shutdown();
    
    void Log(LogLevel level, const std::wstring& message);
    void Debug(const std::wstring& msg) { Log(LogLevel::DEBUG, msg); }
    void Info(const std::wstring& msg) { Log(LogLevel::INFO, msg); }
    void Warning(const std::wstring& msg) { Log(LogLevel::WARNING, msg); }
    void Error(const std::wstring& msg) { Log(LogLevel::ERR, msg); }
    void Critical(const std::wstring& msg) { Log(LogLevel::CRITICAL, msg); }
    
    void SetLevel(LogLevel level) { minLevel_ = level; }
    
private:
    Logger() = default;
    ~Logger() { Shutdown(); }
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
    
    std::wstring GetLogFilePath();
    std::wstring LevelToString(LogLevel level);
    
    std::wstring logDir_;
    std::wstring currentLogFile_;
    LogLevel minLevel_ = LogLevel::INFO;
    std::wofstream file_;
};

} 
// namespace Net Sentinel
