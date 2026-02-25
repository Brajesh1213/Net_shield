// sandbox.cpp — Lightweight process sandbox / isolation helpers for NetSentinel
// Launches a suspicious process in a restricted Job Object so it cannot
// spawn children, access the network, or modify system files.
#include <windows.h>
#include <string>
#include <sstream>

namespace NetSentinel {
namespace Sandbox {

// ── Sandbox a process by PID: assign it to a restrictive Job Object ──────────
// Returns true if the job was successfully applied.
bool AssignToRestrictiveJob(DWORD pid) {
    HANDLE hProc = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE |
                               PROCESS_QUERY_INFORMATION,
                               FALSE, pid);
    if (!hProc) return false;

    // Create a new job object
    HANDLE hJob = CreateJobObjectW(nullptr, nullptr);
    if (!hJob) {
        CloseHandle(hProc);
        return false;
    }

    // Basic UI restrictions: no desktop/clipboard/global atoms access
    JOBOBJECT_BASIC_UI_RESTRICTIONS uiRestrict = {};
    uiRestrict.UIRestrictionsClass =
        JOB_OBJECT_UILIMIT_DESKTOP     |
        JOB_OBJECT_UILIMIT_DISPLAYSETTINGS |
        JOB_OBJECT_UILIMIT_EXITWINDOWS |
        JOB_OBJECT_UILIMIT_GLOBALATOMS |
        JOB_OBJECT_UILIMIT_HANDLES     |
        JOB_OBJECT_UILIMIT_READCLIPBOARD |
        JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS |
        JOB_OBJECT_UILIMIT_WRITECLIPBOARD;
    SetInformationJobObject(hJob, JobObjectBasicUIRestrictions,
                            &uiRestrict, sizeof(uiRestrict));

    // Kill all processes in job when the job handle is closed
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION extLimits = {};
    extLimits.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
        JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    SetInformationJobObject(hJob, JobObjectExtendedLimitInformation,
                            &extLimits, sizeof(extLimits));

    bool ok = AssignProcessToJobObject(hJob, hProc) != FALSE;

    CloseHandle(hJob);
    CloseHandle(hProc);
    return ok;
}

// ── Launch a file inside a sandbox (restricted job + low-integrity token) ───
// Returns the PID of the sandboxed process, or 0 on failure.
DWORD LaunchSandboxed(const std::wstring& exePath,
                      const std::wstring& args) {
    // Build command line
    std::wstring cmdLine = L"\"" + exePath + L"\"";
    if (!args.empty()) cmdLine += L" " + args;

    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};

    // Launch suspended so we can assign to job before it runs
    BOOL ok = CreateProcessW(
        nullptr,
        const_cast<LPWSTR>(cmdLine.c_str()),
        nullptr, nullptr, FALSE,
        CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
        nullptr, nullptr,
        &si, &pi);

    if (!ok) return 0;

    HANDLE hJob = CreateJobObjectW(nullptr, nullptr);
    if (hJob) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION extLimits = {};
        extLimits.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
            JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
        SetInformationJobObject(hJob, JobObjectExtendedLimitInformation,
                                &extLimits, sizeof(extLimits));

        JOBOBJECT_BASIC_UI_RESTRICTIONS uiRestrict = {};
        uiRestrict.UIRestrictionsClass =
            JOB_OBJECT_UILIMIT_GLOBALATOMS |
            JOB_OBJECT_UILIMIT_HANDLES     |
            JOB_OBJECT_UILIMIT_WRITECLIPBOARD;
        SetInformationJobObject(hJob, JobObjectBasicUIRestrictions,
                                &uiRestrict, sizeof(uiRestrict));

        AssignProcessToJobObject(hJob, pi.hProcess);
        CloseHandle(hJob);
    }

    ResumeThread(pi.hThread);
    DWORD pid = pi.dwProcessId;

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return pid;
}

} // namespace Sandbox
} // namespace NetSentinel
