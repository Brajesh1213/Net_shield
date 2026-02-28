// registry_monitor.h — Monitor Windows registry for persistence mechanisms
// Detects: Run/RunOnce key modifications, service installations, scheduled tasks
#pragma once

#include <windows.h>
#include <string>
#include <functional>
#include <atomic>
#include <vector>

namespace Asthak {

enum class RegistryThreatType {
    AUTORUN_ADDED,      // New entry in Run/RunOnce keys
    SERVICE_INSTALLED,  // New service registered
    WINLOGON_MODIFIED,  // Shell/Userinit modified (hijack)
    IMAGE_HIJACK,       // Image File Execution Options (debugger redirect)
    COM_HIJACK,         // InprocServer32 modification
};

struct RegistryThreat {
    RegistryThreatType type;
    std::wstring       keyPath;
    std::wstring       valueName;
    std::wstring       valueData;
    std::wstring       detail;
};

using RegistryThreatCallback = std::function<void(const RegistryThreat&)>;

class RegistryMonitor {
public:
    RegistryMonitor();
    ~RegistryMonitor();

    void Start(RegistryThreatCallback callback);
    void Stop();

private:
    void MonitorKey(HKEY hRoot, const std::wstring& subKey, const std::wstring& label);
    void CheckAutorunEntries(HKEY hRoot, const std::wstring& subKey, const std::wstring& label);
    
    static DWORD WINAPI MonitorThreadProc(LPVOID param);

    struct MonitorArgs {
        RegistryMonitor* self;
        HKEY hRoot;
        std::wstring subKey;
        std::wstring label;
    };

    std::atomic<bool>         m_running{false};
    RegistryThreatCallback    m_callback;
    std::vector<HANDLE>       m_threads;
    std::vector<HANDLE>       m_events;  // For cleanup
};

} // namespace Asthak
