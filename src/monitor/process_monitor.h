#pragma once
// process_monitor.h — uses Windows native HANDLE threads (no std::thread / pthread needed)
#include <windows.h>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <functional>
#include <atomic>

namespace NetSentinel {

enum class ProcessThreatType {
    SUSPICIOUS_PARENT,   // Browser/WhatsApp spawning cmd/powershell
    SUSPICIOUS_PATH,     // Process running from Downloads/Temp/AppData
    MASQUERADE,          // System process name but wrong path
    MEMORY_INJECTION,    // Process has RWX unbacked memory pages (Reflective DLL / Hollowed)
};

struct ProcessThreat {
    ProcessThreatType type;
    DWORD             pid;
    DWORD             parentPid;
    std::wstring      processName;
    std::wstring      processPath;
    std::wstring      parentName;
    std::wstring      detailMessage;
};

using ProcessThreatCallback = std::function<void(const ProcessThreat&)>;

class ProcessMonitor {
public:
    ProcessMonitor();
    ~ProcessMonitor();

    void Start(ProcessThreatCallback callback);
    void Stop();

    // Now public for EventSink access
    void CheckProcess(DWORD pid, DWORD parentPid,
                      const std::wstring& name, const std::wstring& path);
    std::wstring GetProcessPath(DWORD pid);
    std::wstring GetProcessName(DWORD pid);
    bool         ScanProcessMemoryForInjection(DWORD pid);
    bool         InjectProtectiveDLL(DWORD pid);

private:
    void MonitorLoop();
    void ScanProcesses(); // Initial snapshot scan

    bool         IsFromSuspiciousPath(const std::wstring& path);
    bool         IsMasquerading(const std::wstring& name, const std::wstring& path);

    std::atomic<bool>         m_running{ false };
    HANDLE                    m_thread{ nullptr };  // Windows HANDLE instead of std::thread
    ProcessThreatCallback     m_callback;
    std::unordered_set<DWORD> m_alertedPids;

    static const std::unordered_set<std::wstring>& GetSuspiciousParents();
    static const std::unordered_set<std::wstring>& GetShellProcesses();
    static const std::unordered_set<std::wstring>& GetSystemProcessNames();
    static const std::unordered_set<std::wstring>& GetTrustedDevProcessPrefixes();
    static bool IsTrustedDevProcess(const std::wstring& nameLower);

    // Thread entry point
    static DWORD WINAPI MonitorThreadProc(LPVOID param);
};

} // namespace NetSentinel
