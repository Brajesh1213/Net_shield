// ransomware_guard.h — Ransomware detection and rollback via VSS
// Detects mass file encryption and provides recovery via Volume Shadow Copy
#pragma once

#include <windows.h>
#include <string>
#include <functional>
#include <atomic>
#include <unordered_map>
#include <mutex>
#include <fstream>
#include <vector>

namespace Asthak {

struct RansomwareAlert {
    DWORD        pid;
    std::wstring processName;
    std::wstring detail;
    uint32_t     filesAffected;
    double       avgEntropy;
};

using RansomwareCallback = std::function<void(const RansomwareAlert&)>;

class RansomwareGuard {
public:
    static RansomwareGuard& Instance();

    bool Initialize();
    void Start(RansomwareCallback callback);
    void Stop();

    // Called by FileMonitor when a file is modified
    void OnFileModified(const std::wstring& filePath, DWORD pid, const std::wstring& processName);

    // VSS snapshot management
    bool CreateSnapshot();
    bool RestoreFromSnapshot(const std::wstring& targetPath);
    void RollbackProcess(DWORD pid);  // Restore all files encrypted by a PID

    // Stats
    uint64_t GetEventsProcessed() const { return m_eventsProcessed.load(); }
    uint64_t GetAlertsRaised()    const { return m_alertsRaised.load(); }

private:
    RansomwareGuard() = default;

    // Per-process file modification tracking
    struct ProcessActivity {
        uint32_t filesModified{0};
        uint32_t filesRenamed{0};
        double   totalEntropyDelta{0.0};
        DWORD    firstSeenTick{0};
        std::vector<std::wstring> recentFiles;
    };

    double ComputeFileEntropy(const std::wstring& filePath);
    bool IsRansomwarePattern(const ProcessActivity& activity);

    std::unordered_map<DWORD, ProcessActivity> m_processActivity;
    std::mutex          m_mutex;
    RansomwareCallback  m_callback;
    std::atomic<bool>   m_running{false};
    std::atomic<uint64_t> m_eventsProcessed{0};
    std::atomic<uint64_t> m_alertsRaised{0};
    HANDLE              m_cleanupThread{nullptr};
    
    static DWORD WINAPI CleanupThreadProc(LPVOID param);
};

} // namespace Asthak
