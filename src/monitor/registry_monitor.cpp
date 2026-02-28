// registry_monitor.cpp — Monitor Windows registry for persistence mechanisms
// Uses RegNotifyChangeKeyValue for async notification when autorun keys change.
// This catches:
//   1. Malware adding Run/RunOnce entries for persistence
//   2. Service installation (new service = potential backdoor)
//   3. Winlogon Shell/Userinit hijacking
//   4. Image File Execution Options (IFEO) debugger injection
//
// Malwarebytes uses similar registry monitoring for their real-time protection.

#include "monitor/registry_monitor.h"
#include "utils/logger.h"
#include <sstream>
#include <algorithm>
#include <cwctype>

namespace Asthak {

namespace {
template<typename T>
std::wstring ToWStr(T v) { std::wostringstream o; o << v; return o.str(); }
}

// ── Registry keys to monitor ────────────────────────────────────────────────
struct WatchedKey {
    HKEY         hRoot;
    const wchar_t* subKey;
    const wchar_t* label;
};

static const WatchedKey kWatchedKeys[] = {
    // Current user autorun
    { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", L"HKCU\\Run" },
    { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", L"HKCU\\RunOnce" },
    
    // Machine-wide autorun (requires admin to write, but we can monitor)
    { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", L"HKLM\\Run" },
    { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", L"HKLM\\RunOnce" },
    
    // Winlogon hijacking
    { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Winlogon" },
    
    // Image File Execution Options (debugger injection)
    { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", L"IFEO" },
    
    // Services (new service = potential backdoor)
    { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services", L"Services" },
};


RegistryMonitor::RegistryMonitor() = default;

RegistryMonitor::~RegistryMonitor() {
    Stop();
}

DWORD WINAPI RegistryMonitor::MonitorThreadProc(LPVOID param) {
    auto* args = static_cast<MonitorArgs*>(param);
    args->self->MonitorKey(args->hRoot, args->subKey, args->label);
    delete args;
    return 0;
}

void RegistryMonitor::Start(RegistryThreatCallback callback) {
    if (m_running.load()) return;
    
    m_callback = callback;
    m_running  = true;
    
    for (const auto& wk : kWatchedKeys) {
        auto* args = new MonitorArgs{ this, wk.hRoot, wk.subKey, wk.label };
        HANDLE h = CreateThread(nullptr, 0, MonitorThreadProc, args, 0, nullptr);
        if (h) m_threads.push_back(h);
    }
    
    Logger::Instance().Info(L"[RegMonitor] Watching " + ToWStr(sizeof(kWatchedKeys)/sizeof(kWatchedKeys[0])) + L" registry keys for persistence");
}

void RegistryMonitor::Stop() {
    m_running = false;
    
    // Signal all events to unblock RegNotifyChangeKeyValue
    for (auto h : m_events) {
        if (h) SetEvent(h);
    }
    
    for (auto h : m_threads) {
        if (h) {
            WaitForSingleObject(h, 3000);
            CloseHandle(h);
        }
    }
    for (auto h : m_events) {
        if (h) CloseHandle(h);
    }
    m_threads.clear();
    m_events.clear();
}


// ═══════════════════════════════════════════════════════════════════════════
// MONITOR KEY (blocking loop per key)
// ═══════════════════════════════════════════════════════════════════════════

void RegistryMonitor::MonitorKey(HKEY hRoot, const std::wstring& subKey, const std::wstring& label) {
    HKEY hKey = nullptr;
    LONG result = RegOpenKeyExW(hRoot, subKey.c_str(), 0,
                                 KEY_NOTIFY | KEY_READ, &hKey);
    if (result != ERROR_SUCCESS) {
        // Key might not exist (e.g., RunOnce) — not an error
        return;
    }
    
    HANDLE hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!hEvent) {
        RegCloseKey(hKey);
        return;
    }
    
    // Store event handle for cleanup
    {
        m_events.push_back(hEvent);
    }
    
    // Initial scan to establish baseline
    CheckAutorunEntries(hRoot, subKey, label);
    
    while (m_running.load()) {
        // Wait for changes (subtree = TRUE to catch subkey changes)
        result = RegNotifyChangeKeyValue(hKey, TRUE,
            REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_NAME,
            hEvent, TRUE);
        
        if (result != ERROR_SUCCESS) break;
        
        // Wait for notification or stop signal
        DWORD waited = WaitForSingleObject(hEvent, INFINITE);
        if (!m_running.load()) break;
        if (waited != WAIT_OBJECT_0) break;
        
        ResetEvent(hEvent);
        
        // Registry changed — check what was added
        Logger::Instance().Info(L"[RegMonitor] Change detected in " + label);
        CheckAutorunEntries(hRoot, subKey, label);
    }
    
    RegCloseKey(hKey);
}


// ═══════════════════════════════════════════════════════════════════════════
// CHECK AUTORUN ENTRIES
// ═══════════════════════════════════════════════════════════════════════════

void RegistryMonitor::CheckAutorunEntries(HKEY hRoot, const std::wstring& subKey, const std::wstring& label) {
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(hRoot, subKey.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) return;
    
    DWORD index = 0;
    WCHAR valueName[512] = {};
    DWORD valueNameLen = 512;
    BYTE  valueData[2048] = {};
    DWORD valueDataLen = 2048;
    DWORD valueType = 0;
    
    while (RegEnumValueW(hKey, index, valueName, &valueNameLen, nullptr,
                          &valueType, valueData, &valueDataLen) == ERROR_SUCCESS) {
        
        std::wstring name(valueName);
        std::wstring data;
        if (valueType == REG_SZ || valueType == REG_EXPAND_SZ) {
            data = std::wstring(reinterpret_cast<WCHAR*>(valueData));
        }
        
        // Check for suspicious patterns
        std::wstring lowerData = data;
        std::transform(lowerData.begin(), lowerData.end(), lowerData.begin(), ::towlower);
        
        bool suspicious = false;
        std::wstring reason;
        
        // Suspicious: running from temp/downloads/appdata
        if (lowerData.find(L"\\temp\\") != std::wstring::npos ||
            lowerData.find(L"\\downloads\\") != std::wstring::npos ||
            lowerData.find(L"\\appdata\\local\\temp") != std::wstring::npos) {
            suspicious = true;
            reason = L"Autorun from suspicious path";
        }
        
        // Suspicious: powershell/cmd with encoded commands
        if (lowerData.find(L"powershell") != std::wstring::npos &&
            (lowerData.find(L"-enc") != std::wstring::npos ||
             lowerData.find(L"-w hidden") != std::wstring::npos ||
             lowerData.find(L"bypass") != std::wstring::npos)) {
            suspicious = true;
            reason = L"Obfuscated PowerShell in autorun";
        }
        
        // Suspicious: mshta/wscript/cscript in autorun
        if (lowerData.find(L"mshta") != std::wstring::npos ||
            lowerData.find(L"wscript") != std::wstring::npos ||
            lowerData.find(L"cscript") != std::wstring::npos) {
            suspicious = true;
            reason = L"Script host in autorun (LOLBaS)";
        }
        
        // Suspicious: rundll32 from unusual path
        if (lowerData.find(L"rundll32") != std::wstring::npos &&
            lowerData.find(L"\\windows\\system32") == std::wstring::npos) {
            suspicious = true;
            reason = L"rundll32 from non-system path";
        }
        
        // IFEO debugger injection
        if (label == L"IFEO" && name == L"Debugger") {
            suspicious = true;
            reason = L"Image File Execution Options debugger redirect";
        }
        
        // Winlogon shell hijack
        if (label == L"Winlogon" && 
            (name == L"Shell" || name == L"Userinit") &&
            lowerData.find(L"explorer.exe") == std::wstring::npos) {
            suspicious = true;
            reason = L"Winlogon shell/userinit hijack";
        }
        
        if (suspicious && m_callback) {
            RegistryThreat threat;
            threat.type      = RegistryThreatType::AUTORUN_ADDED;
            threat.keyPath   = label;
            threat.valueName = name;
            threat.valueData = data;
            threat.detail    = reason + L" | Key: " + label + L" | Value: " + name + L" | Data: " + data;
            
            if (label == L"Winlogon") threat.type = RegistryThreatType::WINLOGON_MODIFIED;
            if (label == L"IFEO")     threat.type = RegistryThreatType::IMAGE_HIJACK;
            if (label == L"Services") threat.type = RegistryThreatType::SERVICE_INSTALLED;
            
            m_callback(threat);
        }
        
        // Reset for next iteration
        index++;
        valueNameLen = 512;
        valueDataLen = 2048;
        ZeroMemory(valueName, sizeof(valueName));
        ZeroMemory(valueData, sizeof(valueData));
    }
    
    RegCloseKey(hKey);
}

} // namespace Asthak
