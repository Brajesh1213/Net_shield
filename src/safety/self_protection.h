// self_protection.h — User-mode tamper resistance for Asthak
// Prevents attackers from simply killing the Asthak process.
// Uses DACL manipulation + watchdog thread.
#pragma once

#include <windows.h>
#include <atomic>

namespace Asthak {

class SelfProtection {
public:
    static SelfProtection& Instance();

    // Apply process-level protections
    bool Enable();
    void Disable();

    // Check if a debugger is attached (anti-analysis)
    bool IsDebuggerDetected() const;

private:
    SelfProtection() = default;

    // Set restrictive DACL on our own process to deny PROCESS_TERMINATE
    bool SetProcessDacl();

    // Start a watchdog that monitors if protection is tampered with
    bool StartWatchdog();
    void StopWatchdog();

    static DWORD WINAPI WatchdogThreadProc(LPVOID param);

    std::atomic<bool> m_enabled{false};
    std::atomic<bool> m_watchdogRunning{false};
    HANDLE            m_watchdogThread{nullptr};
};

} // namespace Asthak
