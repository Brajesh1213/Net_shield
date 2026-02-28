// process_monitor.cpp — MinGW 6.3 compatible, Windows native threads
#include "monitor/process_monitor.h"
#include "utils/logger.h"
#include <tlhelp32.h>
#include <psapi.h>
#include <algorithm>
#include <sstream>
#include <vector>
#include <wbemidl.h>
#include "network/packet_capture.h"

#ifdef USE_YARA
#include <yara.h>

namespace {985
    
    int ProcessYaraScanCallback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data) {
        if (message == CALLBACK_MSG_RULE_MATCHING) {
            bool* matched = (bool*)user_data;
            *matched = true;
        }
        return CALLBACK_CONTINUE;
    }
}
#endif

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "wbemuuid.lib")

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

class EventSink : public IWbemObjectSink {
    LONG m_lRef;
    ProcessMonitor* monitor;
public:
    EventSink(ProcessMonitor* pm) : m_lRef(1), monitor(pm) {}
    ~EventSink() {}

    virtual ULONG STDMETHODCALLTYPE AddRef() { return InterlockedIncrement(&m_lRef); }
    virtual ULONG STDMETHODCALLTYPE Release() {
        LONG lRef = InterlockedDecrement(&m_lRef);
        if (lRef == 0) delete this;
        return lRef;
    }
    virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) {
        if (riid == IID_IUnknown || riid == IID_IWbemObjectSink) {
            *ppv = (IWbemObjectSink*) this;
            AddRef();
            return WBEM_S_NO_ERROR;
        }
        return E_NOINTERFACE;
    }

    virtual HRESULT STDMETHODCALLTYPE Indicate(LONG lObjectCount, IWbemClassObject **apObjArray) {
        for (long i = 0; i < lObjectCount; i++) {
            IWbemClassObject* pObj = apObjArray[i];
            VARIANT varTarget;
            VariantInit(&varTarget);
            if (SUCCEEDED(pObj->Get(L"TargetInstance", 0, &varTarget, NULL, NULL)) && varTarget.vt == VT_UNKNOWN) {
                IWbemClassObject* pProc = NULL;
                if (SUCCEEDED(varTarget.punkVal->QueryInterface(IID_IWbemClassObject, (void**)&pProc))) {
                    VARIANT varName, varPid, varParent, varPath;
                    VariantInit(&varName); VariantInit(&varPid); VariantInit(&varParent); VariantInit(&varPath);
                    
                    pProc->Get(L"Name", 0, &varName, NULL, NULL);
                    pProc->Get(L"ProcessId", 0, &varPid, NULL, NULL);
                    pProc->Get(L"ParentProcessId", 0, &varParent, NULL, NULL);
                    pProc->Get(L"ExecutablePath", 0, &varPath, NULL, NULL);
                    
                    if (varPid.vt == VT_I4 && varName.vt == VT_BSTR) {
                        DWORD pid = varPid.lVal;
                        DWORD parentPid = (varParent.vt == VT_I4) ? varParent.lVal : 0;
                        std::wstring name = varName.bstrVal;
                        std::wstring path = (varPath.vt == VT_BSTR && varPath.bstrVal) ? varPath.bstrVal : L"";
                        
                        std::wstring lower = name;
                        std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
                        
                        monitor->CheckProcess(pid, parentPid, lower, path);
                    }
                    
                    VariantClear(&varName);
                    VariantClear(&varPid);
                    VariantClear(&varParent);
                    VariantClear(&varPath);
                    pProc->Release();
                }
            }
            VariantClear(&varTarget);
        }
        return WBEM_S_NO_ERROR;
    }

    virtual HRESULT STDMETHODCALLTYPE SetStatus(LONG lFlags, HRESULT hResult, BSTR strParam, IWbemClassObject *pObjParam) {
        return WBEM_S_NO_ERROR;
    }
};

void ProcessMonitor::MonitorLoop() {
    HRESULT hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) return;

    hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);

    IWbemLocator* pLoc = NULL;
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hres)) { CoUninitialize(); return; }

    IWbemServices* pSvc = NULL;
    BSTR resource = SysAllocString(L"ROOT\\CIMV2");
    hres = pLoc->ConnectServer(resource, NULL, NULL, 0, 0, 0, 0, &pSvc);
    SysFreeString(resource);
    if (FAILED(hres)) { pLoc->Release(); CoUninitialize(); return; }

    hres = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

    IUnsecuredApartment* pUnsecApp = NULL;
    hres = CoCreateInstance(CLSID_UnsecuredApartment, NULL, CLSCTX_LOCAL_SERVER,
        IID_IUnsecuredApartment, (void**)&pUnsecApp);
    if (FAILED(hres)) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return;
    }

    EventSink* pSink = new EventSink(this);

    IUnknown* pStubUnk = NULL; 
    pUnsecApp->CreateObjectStub(pSink, &pStubUnk);

    IWbemObjectSink* pStubSink = NULL;
    pStubUnk->QueryInterface(IID_IWbemObjectSink, (void**)&pStubSink);

    BSTR lang = SysAllocString(L"WQL");
    BSTR query = SysAllocString(L"SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'");
    hres = pSvc->ExecNotificationQueryAsync(lang, query, WBEM_FLAG_SEND_STATUS, NULL, pStubSink);
    SysFreeString(lang);
    SysFreeString(query);

    // Initial snapshot scan
    ScanProcesses();

    while (m_running) {
        Sleep(500); // Wait idly while WMI callbacks fire the event sink in real time
    }

    pSvc->CancelAsyncCall(pStubSink);
    pStubSink->Release();
    pStubUnk->Release();
    pSink->Release();
    pUnsecApp->Release();
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
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

    // ── 5. Scan memory for reflective DLL injection ──────────────────────────
    if (!m_alertedPids.count(pid)) {
        if (ScanProcessMemoryForInjection(pid)) {
            ProcessThreat t;
            t.type          = ProcessThreatType::MEMORY_INJECTION;
            t.pid           = pid;
            t.parentPid     = parentPid;
            t.processName   = name;
            t.processPath   = path;
            t.detailMessage = L"MEMORY INJECTION ATTACK: '" + name +
                              L"' (PID:" + ToWStr(pid) + L") has unbacked executable memory. " +
                              L"This strongly indicates reflective DLL injection or process hollowing.";
            m_alertedPids.insert(pid);
            if (m_callback) m_callback(t);
        }
    }

    // ── 6. EDR Proactive Defense: Inject Our Protective DLL ──────────────────
    // If it's a new process and seems okay, we still inject our hook DLL.
    // This hooks CreateRemoteThread, blocking this process if it later turns malicious.
    if (!m_alertedPids.count(pid)) {
        // Run injection asynchronously to not block the ETW monitoring loop
        struct InjectParam { ProcessMonitor* pm; DWORD pid; std::wstring name; ProcessThreatCallback cb; };
        InjectParam* p = new InjectParam{this, pid, name, m_callback};
        
        HANDLE hThread = CreateThread(NULL, 0, [](LPVOID param) -> DWORD {
            InjectParam* p = (InjectParam*)param;
            if (p->pm->InjectProtectiveDLL(p->pid)) {
                if (p->cb) {
                    ProcessThreat t;
                    t.type = ProcessThreatType::MEMORY_INJECTION; // Reuse memory injection struct safely
                    t.pid = p->pid;
                    t.processName = p->name;
                    t.detailMessage = L"EDR HOOK INJECTED: Protective Ring successfully initialized in '" + p->name + L"' (PID:" + std::to_wstring(p->pid) + L") to prevent zero-day exploits.";
                    // We don't want to technically 'alert' it as a block, but rather as proactive intel
                    p->cb(t);
                }
            }
            delete p;
            return 0;
        }, p, 0, NULL);
        if (hThread) CloseHandle(hThread);
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

bool ProcessMonitor::ScanProcessMemoryForInjection(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return false;

    MEMORY_BASIC_INFORMATION mbi;
    uint8_t* pAddress = nullptr;

    while (VirtualQueryEx(hProcess, pAddress, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        // Look for memory pages that are committed, and have RWX or RX permissions
        if (mbi.State == MEM_COMMIT && 
            (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_READ)) {
            
            // Private memory (not MEM_IMAGE) executing code is deeply suspicious
            if (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED) {
                wchar_t mappedFileName[MAX_PATH] = {};
                DWORD len = GetMappedFileNameW(hProcess, mbi.BaseAddress, mappedFileName, MAX_PATH);
                // If there's no physical file backing this executable memory block
                if (len == 0) {
                    
                    // 1. FAST PATH: Check for MZ Header (Classic Reflective DLL / Hollowing)
                    char buffer[2] = {0};
                    SIZE_T bytesRead = 0;
                    if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer, 2, &bytesRead) && bytesRead == 2) {
                        if (buffer[0] == 'M' && buffer[1] == 'Z') {
                            CloseHandle(hProcess);
                            return true; // Unbacked MZ executable
                        }
                    }

                    // 2. DEEP PATH: Malware might wipe the 'MZ' header or just inject raw shellcode
                    // We only scan small to medium blocks (e.g. up to 10MB) to avoid CPU spikes.
                    if (mbi.RegionSize > 0 && mbi.RegionSize < (10 * 1024 * 1024)) {
                        std::vector<uint8_t> memBuffer(mbi.RegionSize);
                        if (ReadProcessMemory(hProcess, mbi.BaseAddress, memBuffer.data(), mbi.RegionSize, &bytesRead)) {
                            
#ifdef USE_YARA
                            void* yRules = PacketCapture::Instance().GetYaraRules();
                            if (yRules) {
                                bool matched = false;
                                yr_rules_scan_mem(
                                    static_cast<YR_RULES*>(yRules),
                                    memBuffer.data(),
                                    memBuffer.size(),
                                    0,
                                    ProcessYaraScanCallback,
                                    &matched,
                                    0
                                );
                                if (matched) {
                                    CloseHandle(hProcess);
                                    return true;
                                }
                            }
#endif
                            // Basic Heuristic: If we find NOP sleds (0x90 0x90 0x90) or common Reverse Shell hex patterns
                            size_t nopSledSize = 0;
                            for (size_t i = 0; i < bytesRead; i++) {
                                if (memBuffer[i] == 0x90) { // NOP instruction
                                    nopSledSize++;
                                    if (nopSledSize > 40) { // Found a large NOP sled (classic buffer overflow / shellcode)
                                        CloseHandle(hProcess);
                                        return true;
                                    }
                                } else {
                                    nopSledSize = 0;
                                }
                            }
                        }
                    }
                }
            }
        }
        
        pAddress = static_cast<uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
    }
    
    CloseHandle(hProcess);
    return false;
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

bool ProcessMonitor::InjectProtectiveDLL(DWORD pid) {
    // 1. Get path to our DLL (must be compiled and placed next to NetSentinel.exe)
    wchar_t exePath[MAX_PATH] = {};
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    std::wstring dllPath = std::wstring(exePath);
    size_t lastSlash = dllPath.find_last_of(L"\\/");
    if (lastSlash != std::wstring::npos) {
        dllPath = dllPath.substr(0, lastSlash + 1) + L"NetSentinel_Hook.dll";
    }

    // 2. Open Target Process
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
                                  PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, 
                                  FALSE, pid);
    if (!hProcess) return false;

    // 3. Allocate memory in target process for the DLL path string
    size_t pathSize = (dllPath.length() + 1) * sizeof(wchar_t);
    LPVOID pRemoteBuf = VirtualAllocEx(hProcess, NULL, pathSize, MEM_COMMIT, PAGE_READWRITE);
    if (!pRemoteBuf) {
        CloseHandle(hProcess);
        return false;
    }

    // 4. Write the DLL path into the target process
    if (!WriteProcessMemory(hProcess, pRemoteBuf, dllPath.c_str(), pathSize, NULL)) {
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // 5. Get memory address of LoadLibraryW in Kernel32.dll (it's the same in all processes)
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    LPVOID pLoadLibrary = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryW");
    if (!pLoadLibrary) {
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // 6. Force the target process to create a thread that runs LoadLibraryW(our_dll_path)
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, 
                                        (LPTHREAD_START_ROUTINE)pLoadLibrary, 
                                        pRemoteBuf, 0, NULL);
    if (!hThread) {
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Give it a moment to load and then clean up our memory footprints
    WaitForSingleObject(hThread, 2000);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    
    return true;
}

} // namespace NetSentinel
