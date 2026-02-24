// process_monitor.cpp — MinGW 6.3 compatible, Windows native threads
#include "monitor/process_monitor.h"
#include "utils/logger.h"
#include <tlhelp32.h>
#include <psapi.h>
#include <algorithm>
#include <sstream>

#pragma comment(lib, "psapi.lib")

namespace NetSentinel {

// ── MinGW 6.3: std::to_wstring is broken, use wostringstream ─────────────────
namespace {
template<typename T>
std::wstring ToWStr(T v) { std::wostringstream o; o << v; return o.str(); }
}

const std::unordered_set<std::wstring>& ProcessMonitor::GetSuspiciousParents() {
    static const std::unordered_set<std::wstring> p = {
        L"chrome.exe",   L"firefox.exe",  L"msedge.exe",
        L"opera.exe",    L"brave.exe",    L"iexplore.exe",
        L"whatsapp.exe", L"telegram.exe", L"discord.exe",
        L"slack.exe",    L"teams.exe",    L"zoom.exe",
        L"skype.exe",    L"signal.exe",
        L"outlook.exe",  L"thunderbird.exe",
        L"winword.exe",  L"excel.exe",    L"powerpnt.exe",
        L"acrord32.exe", L"foxit.exe",
        L"7zfm.exe",     L"winrar.exe",   L"7z.exe",
    };
    return p;
}

const std::unordered_set<std::wstring>& ProcessMonitor::GetShellProcesses() {
    static const std::unordered_set<std::wstring> s = {
        L"cmd.exe",       L"powershell.exe", L"pwsh.exe",
        L"wscript.exe",   L"cscript.exe",    L"mshta.exe",
        L"regsvr32.exe",  L"rundll32.exe",   L"certutil.exe",
        L"bitsadmin.exe", L"msiexec.exe",
    };
    return s;
}

const std::unordered_set<std::wstring>& ProcessMonitor::GetSystemProcessNames() {
    // Processes that MUST live in specific OS directories.
    // explorer.exe is intentionally excluded here because its
    // expected path (C:\Windows\) is handled separately in IsMasquerading().
    static const std::unordered_set<std::wstring> s = {
        L"svchost.exe",  L"lsass.exe",    L"csrss.exe",
        L"winlogon.exe", L"services.exe", L"smss.exe",
        L"spoolsv.exe",  L"conhost.exe",  L"dllhost.exe",
        L"taskhost.exe", L"taskhostw.exe",
    };
    return s;
}

// ── Trusted developer / IDE processes — never flag these ─────────────────────
const std::unordered_set<std::wstring>& ProcessMonitor::GetTrustedDevProcessPrefixes() {
    // Compared as lowercase prefix/substring matches in IsTrustedDevProcess().
    static const std::unordered_set<std::wstring> t = {
        // VS Code / VS language servers
        L"language_server_windows",
        L"language_server_",
        L"vscode",
        L"code.exe",
        L"code - insiders.exe",
        L"microsoft.visualstudio",
        // JetBrains IDEs
        L"idea64.exe", L"clion64.exe", L"pycharm64.exe",
        L"webstorm64.exe", L"rider64.exe",
        // Compilers / build tools
        L"cl.exe", L"link.exe", L"msbuild.exe",
        L"cmake.exe", L"ninja.exe",
        L"gcc.exe", L"g++.exe", L"mingw32-make.exe",
        L"clang.exe", L"clang++.exe",
        // Package managers
        L"npm.exe", L"node.exe", L"yarn.exe",
        L"pip.exe", L"python.exe", L"python3.exe",
        // Git
        L"git.exe",
        // Electron-based apps (the app itself)
        L"electron.exe",
    };
    return t;
}

bool ProcessMonitor::IsTrustedDevProcess(const std::wstring& nameLower) {
    // Exact match first
    if (GetTrustedDevProcessPrefixes().count(nameLower)) return true;
    // Prefix / substring match for language_server_*.exe variants
    for (const auto& prefix : GetTrustedDevProcessPrefixes()) {
        if (nameLower.size() >= prefix.size() &&
            nameLower.compare(0, prefix.size(), prefix) == 0) {
            return true;
        }
    }
    return false;
}

ProcessMonitor::ProcessMonitor()  = default;
ProcessMonitor::~ProcessMonitor() { Stop(); }

// ── Static Windows thread entry point ────────────────────────────────────────
DWORD WINAPI ProcessMonitor::MonitorThreadProc(LPVOID param) {
    static_cast<ProcessMonitor*>(param)->MonitorLoop();
    return 0;
}

void ProcessMonitor::Start(ProcessThreatCallback callback) {
    m_callback = callback;
    m_running  = true;
    m_thread   = CreateThread(nullptr, 0, MonitorThreadProc, this, 0, nullptr);
    Logger::Instance().Info(L"[ProcessMonitor] Watching for child-process exploits & masquerading");
}

void ProcessMonitor::Stop() {
    m_running = false;
    if (m_thread) {
        WaitForSingleObject(m_thread, 4000);
        CloseHandle(m_thread);
        m_thread = nullptr;
    }
}

void ProcessMonitor::MonitorLoop() {
    while (m_running) {
        ScanProcesses();
        Sleep(3000);
    }
}

void ProcessMonitor::ScanProcesses() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    if (!Process32FirstW(snap, &pe)) { CloseHandle(snap); return; }

    do {
        DWORD pid    = pe.th32ProcessID;
        DWORD parent = pe.th32ParentProcessID;
        if (pid <= 4 || m_alertedPids.count(pid)) continue;

        std::wstring name = pe.szExeFile;
        std::wstring lower = name;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

        std::wstring path = GetProcessPath(pid);
        CheckProcess(pid, parent, lower, path);

    } while (Process32NextW(snap, &pe));

    CloseHandle(snap);
}

void ProcessMonitor::CheckProcess(DWORD pid, DWORD parentPid,
                                  const std::wstring& name, const std::wstring& path) {
    // ── 0. Skip trusted developer / IDE processes entirely ───────────────────
    //    These tools (language servers, compilers, node.exe, etc.) make many
    //    connections by design and will never be masquerading system processes.
    if (IsTrustedDevProcess(name)) return;

    // ── 1. Shell spawned by suspicious parent (e.g. WhatsApp → cmd.exe) ─────
    if (GetShellProcesses().count(name)) {
        std::wstring parentName = GetProcessName(parentPid);
        std::wstring parentLower = parentName;
        std::transform(parentLower.begin(), parentLower.end(),
                       parentLower.begin(), ::towlower);

        if (GetSuspiciousParents().count(parentLower)) {
            ProcessThreat t;
            t.type          = ProcessThreatType::SUSPICIOUS_PARENT;
            t.pid           = pid;
            t.parentPid     = parentPid;
            t.processName   = name;
            t.processPath   = path;
            t.parentName    = parentName;
            t.detailMessage = L"EXPLOIT DETECTED: " + parentName +
                              L" (PID:" + ToWStr(parentPid) + L") spawned " +
                              name + L" (PID:" + ToWStr(pid) + L"). "
                              L"Classic exploit pattern — e.g. WhatsApp image payload or Office macro.";
            m_alertedPids.insert(pid);
            if (m_callback) m_callback(t);
            return;
        }
    }

    // ── 2. Process running from suspicious path (polymorphic malware) ─────────
    if (!path.empty() && IsFromSuspiciousPath(path)) {
        ProcessThreat t;
        t.type          = ProcessThreatType::SUSPICIOUS_PATH;
        t.pid           = pid;
        t.parentPid     = parentPid;
        t.processName   = name;
        t.processPath   = path;
        t.detailMessage = L"SUSPICIOUS PATH: '" + name +
                          L"' (PID:" + ToWStr(pid) + L") running from: " + path +
                          L" — legitimate software never runs from Temp/Downloads.";
        m_alertedPids.insert(pid);
        if (m_callback) m_callback(t);
        return;
    }

    // ── 3. Masquerade: system process name but wrong directory ───────────────
    if (GetSystemProcessNames().count(name) && IsMasquerading(name, path)) {
        // Build readable "expected location" string for the alert message
        std::wstring expectedLoc = L"System32 or SysWOW64";
        ProcessThreat t;
        t.type          = ProcessThreatType::MASQUERADE;
        t.pid           = pid;
        t.parentPid     = parentPid;
        t.processName   = name;
        t.processPath   = path;
        t.detailMessage = L"MASQUERADE ATTACK: '" + name +
                          L"' (PID:" + ToWStr(pid) + L") in unexpected path: " +
                          path + L" — real " + name +
                          L" should be in " + expectedLoc + L".";
        m_alertedPids.insert(pid);
        if (m_callback) m_callback(t);
    }

    // ── 4. explorer.exe masquerade (special case: lives in C:\Windows\) ─────
    //    explorer.exe is NOT in System32; check it separately.
    if (name == L"explorer.exe" && !path.empty()) {
        std::wstring lp = path;
        std::transform(lp.begin(), lp.end(), lp.begin(), ::towlower);
        wchar_t winDir[MAX_PATH] = {};
        bool isMasq = true;
        if (GetWindowsDirectoryW(winDir, MAX_PATH)) {
            std::wstring winLow = winDir;
            std::transform(winLow.begin(), winLow.end(), winLow.begin(), ::towlower);
            // Exact expected path: C:\windows\explorer.exe
            std::wstring expected = winLow + L"\\explorer.exe";
            isMasq = (lp != expected);
        } else {
            // Fallback: allow C:\windows\ root
            isMasq = (lp.find(L"\\windows\\explorer.exe") == std::wstring::npos);
        }
        if (isMasq && !m_alertedPids.count(pid)) {
            ProcessThreat t;
            t.type          = ProcessThreatType::MASQUERADE;
            t.pid           = pid;
            t.parentPid     = parentPid;
            t.processName   = name;
            t.processPath   = path;
            t.detailMessage = L"MASQUERADE ATTACK: 'explorer.exe' (PID:" +
                              ToWStr(pid) + L") in unexpected path: " + path +
                              L" — real explorer.exe must be at C:\\Windows\\explorer.exe";
            m_alertedPids.insert(pid);
            if (m_callback) m_callback(t);
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

std::wstring ProcessMonitor::GetProcessPath(DWORD pid) {
    // Use PROCESS_QUERY_INFORMATION | PROCESS_VM_READ for GetModuleFileNameExW
    // (MinGW 6.3 compatible — QueryFullProcessImageNameW requires Vista+ headers)
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) return L"";

    wchar_t path[MAX_PATH] = {};
    // GetModuleFileNameExW is in psapi.h, available in MinGW 6.3
    GetModuleFileNameExW(h, nullptr, path, MAX_PATH);
    CloseHandle(h);
    return std::wstring(path);
}

std::wstring ProcessMonitor::GetProcessName(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return L"";

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    std::wstring result;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == pid) { result = pe.szExeFile; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return result;
}

bool ProcessMonitor::IsFromSuspiciousPath(const std::wstring& path) {
    std::wstring lp = path;
    std::transform(lp.begin(), lp.end(), lp.begin(), ::towlower);

    const wchar_t* suspiciousDirs[] = {
        L"\\downloads\\", L"\\temp\\", L"\\tmp\\",
        L"\\appdata\\local\\temp\\", L"\\users\\public\\",
        L"\\recycle", L"\\programdata\\"
    };
    for (auto& dir : suspiciousDirs) {
        if (lp.find(dir) != std::wstring::npos) return true;
    }
    return false;
}

bool ProcessMonitor::IsMasquerading(const std::wstring& /*name*/, const std::wstring& path) {
    // Used only for processes in GetSystemProcessNames() (i.e., NOT explorer.exe).
    // Those processes must reside in System32 or SysWOW64.
    if (path.empty()) return false;
    std::wstring lp = path;
    std::transform(lp.begin(), lp.end(), lp.begin(), ::towlower);
    return lp.find(L"\\system32\\") == std::wstring::npos &&
           lp.find(L"\\syswow64\\") == std::wstring::npos;
}

} // namespace NetSentinel
