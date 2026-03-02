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
    // Restore original DACL (called on clean shutdown so the engine CAN be stopped)
    void RestoreProcessDacl();

    // Start a watchdog that monitors if protection is tampered with
    bool StartWatchdog();
    void StopWatchdog();

    static DWORD WINAPI WatchdogThreadProc(LPVOID param);

    std::atomic<bool> m_enabled{false};
    std::atomic<bool> m_watchdogRunning{false};
    HANDLE            m_watchdogThread{nullptr};
    // Saved original security descriptor — restored on Disable() so clean shutdown works
    PSECURITY_DESCRIPTOR m_originalSD{nullptr};
    PACL                 m_originalDacl{nullptr}; // pointer into m_originalSD, do NOT free separately
};

} // namespace Asthak
