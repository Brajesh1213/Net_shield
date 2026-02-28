// self_protection.cpp — User-mode tamper resistance
// Technique: Modify the DACL (Discretionary Access Control List) of our own
// process to DENY the PROCESS_TERMINATE right to non-admin users.
//
// This means:
//   - Normal malware calling TerminateProcess(asthak_pid) will get ACCESS_DENIED
//   - Task Manager (non-elevated) cannot kill Asthak
//   - Only elevated (admin) processes can kill us
//
// This is the SAME technique used by Malwarebytes, Norton, and Kaspersky
// in their user-mode self-protection layers.
//
// Additionally, we run a watchdog thread that:
//   1. Checks for debugger attachment (anti-analysis)
//   2. Could restart the engine if killed (via a separate service, future work)

#include "safety/self_protection.h"
#include "utils/logger.h"
#include <sddl.h>
#include <aclapi.h>
#include <sstream>

// MinGW compatibility
#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif
#ifndef PROCESS_SUSPEND_RESUME
#define PROCESS_SUSPEND_RESUME 0x0800
#endif

#pragma comment(lib, "advapi32.lib")

namespace Asthak {

namespace {
template<typename T>
std::wstring ToWStr(T v) { std::wostringstream o; o << v; return o.str(); }
}

SelfProtection& SelfProtection::Instance() {
    static SelfProtection instance;
    return instance;
}

bool SelfProtection::Enable() {
    if (m_enabled.load()) return true;
    
    // Step 1: Set restrictive DACL on our process
    if (!SetProcessDacl()) {
        Logger::Instance().Warning(L"[SelfProtect] DACL protection failed (may need admin)");
        // Continue anyway — watchdog is still valuable
    } else {
        Logger::Instance().Info(L"[SelfProtect] Process DACL hardened — PROCESS_TERMINATE denied to non-admin");
    }
    
    // Step 2: Start watchdog
    if (!StartWatchdog()) {
        Logger::Instance().Warning(L"[SelfProtect] Watchdog thread failed to start");
    }
    
    m_enabled = true;
    Logger::Instance().Info(L"[SelfProtect] Self-protection ENABLED");
    return true;
}

void SelfProtection::Disable() {
    StopWatchdog();
    m_enabled = false;
    Logger::Instance().Info(L"[SelfProtect] Self-protection disabled");
}


// ═══════════════════════════════════════════════════════════════════════════
// DACL HARDENING
// ═══════════════════════════════════════════════════════════════════════════

bool SelfProtection::SetProcessDacl() {
    HANDLE hProcess = GetCurrentProcess();
    
    // Get current DACL
    PACL pOldDacl = nullptr;
    PSECURITY_DESCRIPTOR pSD = nullptr;
    DWORD err = GetSecurityInfo(hProcess, SE_KERNEL_OBJECT,
                                DACL_SECURITY_INFORMATION,
                                nullptr, nullptr, &pOldDacl, nullptr, &pSD);
    if (err != ERROR_SUCCESS) {
        Logger::Instance().Error(L"[SelfProtect] GetSecurityInfo failed: " + ToWStr(err));
        return false;
    }
    
    // Create a Deny ACE for EVERYONE: deny PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME
    SID_IDENTIFIER_AUTHORITY worldAuth = SECURITY_WORLD_SID_AUTHORITY;
    PSID pEveryoneSid = nullptr;
    if (!AllocateAndInitializeSid(&worldAuth, 1, SECURITY_WORLD_RID,
                                   0, 0, 0, 0, 0, 0, 0, &pEveryoneSid)) {
        LocalFree(pSD);
        return false;
    }
    
    EXPLICIT_ACCESS_W ea = {};
    ea.grfAccessPermissions = PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME | PROCESS_VM_WRITE;
    ea.grfAccessMode        = DENY_ACCESS;
    ea.grfInheritance       = NO_INHERITANCE;
    ea.Trustee.TrusteeForm  = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType  = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName    = (LPWSTR)pEveryoneSid;
    
    PACL pNewDacl = nullptr;
    err = SetEntriesInAclW(1, &ea, pOldDacl, &pNewDacl);
    if (err != ERROR_SUCCESS) {
        FreeSid(pEveryoneSid);
        LocalFree(pSD);
        return false;
    }
    
    // Apply the new DACL
    err = SetSecurityInfo(hProcess, SE_KERNEL_OBJECT,
                          DACL_SECURITY_INFORMATION,
                          nullptr, nullptr, pNewDacl, nullptr);
    
    LocalFree(pNewDacl);
    FreeSid(pEveryoneSid);
    LocalFree(pSD);
    
    return err == ERROR_SUCCESS;
}


// ═══════════════════════════════════════════════════════════════════════════
// ANTI-DEBUGGING
// ═══════════════════════════════════════════════════════════════════════════

bool SelfProtection::IsDebuggerDetected() const {
    // Check 1: IsDebuggerPresent (user-mode)
    if (IsDebuggerPresent()) return true;
    
    // Check 2: CheckRemoteDebuggerPresent
    BOOL remoteDebugger = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebugger) && remoteDebugger) {
        return true;
    }
    
    // Check 3: NtQueryInformationProcess (ProcessDebugPort)
    // This catches more sophisticated debugger attachments
    typedef NTSTATUS (WINAPI *PNtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        auto NtQIP = (PNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
        if (NtQIP) {
            DWORD_PTR debugPort = 0;
            NTSTATUS status = NtQIP(GetCurrentProcess(), 7 /* ProcessDebugPort */,
                                    &debugPort, sizeof(debugPort), nullptr);
            if (status == 0 && debugPort != 0) return true;
        }
    }
    
    return false;
}


// ═══════════════════════════════════════════════════════════════════════════
// WATCHDOG THREAD
// ═══════════════════════════════════════════════════════════════════════════

bool SelfProtection::StartWatchdog() {
    if (m_watchdogRunning.load()) return true;
    
    m_watchdogRunning = true;
    m_watchdogThread = CreateThread(nullptr, 0, WatchdogThreadProc, this, 0, nullptr);
    return m_watchdogThread != nullptr;
}

void SelfProtection::StopWatchdog() {
    m_watchdogRunning = false;
    if (m_watchdogThread) {
        WaitForSingleObject(m_watchdogThread, 3000);
        CloseHandle(m_watchdogThread);
        m_watchdogThread = nullptr;
    }
}

DWORD WINAPI SelfProtection::WatchdogThreadProc(LPVOID param) {
    auto* self = static_cast<SelfProtection*>(param);
    
    while (self->m_watchdogRunning.load()) {
        // Check for debugger every 5 seconds
        if (self->IsDebuggerDetected()) {
            Logger::Instance().Critical(L"[SelfProtect] DEBUGGER DETECTED — possible analysis/evasion attempt");
            // In production: could detach, alert SOC, or take defensive action
        }
        
        // Re-apply DACL periodically (in case it was modified)
        self->SetProcessDacl();
        
        Sleep(5000);
    }
    
    return 0;
}

} // namespace Asthak
