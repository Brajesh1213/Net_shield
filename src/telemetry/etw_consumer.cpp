// etw_consumer.cpp — ETW (Event Tracing for Windows) telemetry consumer
// Provides deep kernel/user-mode visibility without requiring a kernel driver.
//
// This is the single biggest detection uplift for Asthak — it lets us see:
//   1. Every DNS query any process makes (detect C2 domains, DGA, tunneling)
//   2. PowerShell script blocks BEFORE execution (decode -enc payloads)
//   3. Process creation with FULL command lines (detect LOLBaS chains)
//   4. DLL/Image loads (detect side-loading, reflective injection)
//
// Architecture:
//   - We create a real-time ETW trace session
//   - Enable multiple providers on that session
//   - A dedicated thread calls ProcessTrace() (blocking) to receive events
//   - The static callback dispatches to our parser methods
//   - Parsed events are emitted via the user-supplied callback
//
// Compatible with MinGW 6.3+ (no std::thread, uses Windows HANDLE threads)

#include "telemetry/etw_consumer.h"
#include "utils/logger.h"
#include <evntrace.h>
#include <algorithm>
#include <sstream>
#include <cwctype>
#include <vector>

// Link required Windows libraries
#pragma comment(lib, "advapi32.lib")  // ETW APIs
#pragma comment(lib, "tdh.lib")       // Trace Data Helper

namespace Asthak {

// Static instance pointer for the C-style callback
EtwConsumer* EtwConsumer::s_instance = nullptr;

// ── Well-known provider GUIDs ───────────────────────────────────────────────

// Microsoft-Windows-DNS-Client
// {1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}
static const GUID DNS_CLIENT_GUID = 
    {0x1C95126E, 0x7EEA, 0x49A9, {0xA3, 0xFE, 0xA3, 0x78, 0xB0, 0x3D, 0xDB, 0x4D}};

// Microsoft-Windows-PowerShell
// {A0C1853B-5C40-4B15-8766-3CF1C58F985A}
static const GUID POWERSHELL_GUID = 
    {0xA0C1853B, 0x5C40, 0x4B15, {0x87, 0x66, 0x3C, 0xF1, 0xC5, 0x8F, 0x98, 0x5A}};

// Microsoft-Windows-Kernel-Process
// {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
static const GUID KERNEL_PROCESS_GUID = 
    {0x22FB2CD6, 0x0E7B, 0x422B, {0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16}};

// Session name — must be unique system-wide
static const WCHAR SESSION_NAME[] = L"AsthakEtwSession";

// ── MinGW-safe wstring helper ───────────────────────────────────────────────
namespace {
template<typename T>
std::wstring ToWStr(T v) { std::wostringstream o; o << v; return o.str(); }

// Safe property extraction from EVENT_RECORD
std::wstring GetStringProperty(PEVENT_RECORD pEvent, DWORD propertyIndex) {
    DWORD bufSize = 0;
    PROPERTY_DATA_DESCRIPTOR pdd = {};
    pdd.PropertyName = propertyIndex;
    pdd.ArrayIndex   = ULONG_MAX;

    // First call to get size — may fail, which is OK
    TdhGetProperty(pEvent, 0, nullptr, 1, &pdd, 0, nullptr);
    
    if (bufSize == 0 || bufSize > 65536) return L"";
    
    std::vector<BYTE> buffer(bufSize);
    DWORD status = TdhGetProperty(pEvent, 0, nullptr, 1, &pdd, bufSize, buffer.data());
    if (status != ERROR_SUCCESS) return L"";
    
    return std::wstring(reinterpret_cast<WCHAR*>(buffer.data()));
}

// Lowercase helper
std::wstring ToLower(const std::wstring& s) {
    std::wstring r = s;
    std::transform(r.begin(), r.end(), r.begin(), ::towlower);
    return r;
}

} // anonymous namespace


// ═══════════════════════════════════════════════════════════════════════════
// CONSTRUCTOR / DESTRUCTOR
// ═══════════════════════════════════════════════════════════════════════════

EtwConsumer::EtwConsumer() {
    s_instance = this;
}

EtwConsumer::~EtwConsumer() {
    Stop();
    if (s_instance == this) s_instance = nullptr;
}


// ═══════════════════════════════════════════════════════════════════════════
// START / STOP
// ═══════════════════════════════════════════════════════════════════════════

bool EtwConsumer::Start(EtwEventCallback callback) {
    if (m_running.load()) return true;
    
    m_callback = callback;
    
    if (!StartTraceSession()) {
        Logger::Instance().Error(L"[ETW] Failed to start trace session");
        return false;
    }
    
    m_running = true;
    
    // Launch the blocking ProcessTrace on a separate thread
    m_thread = CreateThread(nullptr, 0, TraceThreadProc, this, 0, nullptr);
    if (!m_thread) {
        Logger::Instance().Error(L"[ETW] Failed to create trace thread");
        StopTraceSession();
        m_running = false;
        return false;
    }
    
    Logger::Instance().Info(L"[ETW] Consumer started — listening for DNS, PowerShell, Process, Image events");
    return true;
}

void EtwConsumer::Stop() {
    if (!m_running.load()) return;
    
    m_running = false;
    StopTraceSession();
    
    if (m_thread) {
        WaitForSingleObject(m_thread, 5000);
        CloseHandle(m_thread);
        m_thread = nullptr;
    }
    
    Logger::Instance().Info(L"[ETW] Consumer stopped. Total events: " + ToWStr(m_totalEvents.load()));
}


// ═══════════════════════════════════════════════════════════════════════════
// ETW SESSION MANAGEMENT
// ═══════════════════════════════════════════════════════════════════════════

bool EtwConsumer::StartTraceSession() {
    // Stop any previous session with same name
    {
        ULONG bufSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(SESSION_NAME) + 256;
        std::vector<BYTE> buf(bufSize, 0);
        auto* props = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(buf.data());
        props->Wnode.BufferSize = bufSize;
        // Try to stop leftover sessions (ignore errors)
        ControlTraceW(0, SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);
    }
    
    // Prepare session properties
    ULONG bufSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(SESSION_NAME) + 256;
    ZeroMemory(&m_sessionProps, sizeof(m_sessionProps));
    m_sessionProps.props.Wnode.BufferSize = bufSize;
    m_sessionProps.props.Wnode.Flags      = WNODE_FLAG_TRACED_GUID;
    m_sessionProps.props.Wnode.ClientContext = 1; // QPC timestamps
    m_sessionProps.props.LogFileMode      = EVENT_TRACE_REAL_TIME_MODE;
    m_sessionProps.props.MaximumBuffers   = 64;
    m_sessionProps.props.BufferSize       = 64;   // 64 KB per buffer
    m_sessionProps.props.LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    ULONG status = StartTraceW(&m_sessionHandle, SESSION_NAME, &m_sessionProps.props);
    if (status != ERROR_SUCCESS) {
        Logger::Instance().Error(L"[ETW] StartTrace failed: " + ToWStr(status));
        return false;
    }

    // ── Enable providers on our session ─────────────────────────────────────

    // 1. DNS Client — level Informational (4), keyword all
    status = EnableTraceEx2(m_sessionHandle, &DNS_CLIENT_GUID,
                            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                            TRACE_LEVEL_INFORMATION, 0, 0, 0, nullptr);
    if (status != ERROR_SUCCESS) {
        Logger::Instance().Warning(L"[ETW] DNS provider enable failed: " + ToWStr(status));
    }

    // 2. PowerShell — level Verbose (5), keyword 0x1 (script block logging)
    status = EnableTraceEx2(m_sessionHandle, &POWERSHELL_GUID,
                            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                            TRACE_LEVEL_VERBOSE, 0x1, 0, 0, nullptr);
    if (status != ERROR_SUCCESS) {
        Logger::Instance().Warning(L"[ETW] PowerShell provider enable failed: " + ToWStr(status));
    }

    // 3. Kernel-Process — level Info (4), keyword 0x10 (Process + Image)
    status = EnableTraceEx2(m_sessionHandle, &KERNEL_PROCESS_GUID,
                            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                            TRACE_LEVEL_INFORMATION, 0x10 | 0x20, 0, 0, nullptr);
    if (status != ERROR_SUCCESS) {
        Logger::Instance().Warning(L"[ETW] Kernel-Process provider enable failed: " + ToWStr(status));
    }

    // ── Open the trace for consumption ──────────────────────────────────────
    EVENT_TRACE_LOGFILEW traceLog = {};
    traceLog.LoggerName           = const_cast<LPWSTR>(SESSION_NAME);
    traceLog.ProcessTraceMode     = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;
    traceLog.EventRecordCallback  = EventRecordCallback;

    m_traceHandle = OpenTraceW(&traceLog);
    if (m_traceHandle == INVALID_PROCESSTRACE_HANDLE) {
        Logger::Instance().Error(L"[ETW] OpenTrace failed");
        StopTraceSession();
        return false;
    }

    return true;
}

void EtwConsumer::StopTraceSession() {
    if (m_traceHandle != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(m_traceHandle);
        m_traceHandle = INVALID_PROCESSTRACE_HANDLE;
    }
    
    if (m_sessionHandle != 0) {
        ULONG bufSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(SESSION_NAME) + 256;
        std::vector<BYTE> buf(bufSize, 0);
        auto* props = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(buf.data());
        props->Wnode.BufferSize = bufSize;
        ControlTraceW(m_sessionHandle, nullptr, props, EVENT_TRACE_CONTROL_STOP);
        m_sessionHandle = 0;
    }
}


// ═══════════════════════════════════════════════════════════════════════════
// TRACE THREAD (blocking ProcessTrace)
// ═══════════════════════════════════════════════════════════════════════════

DWORD WINAPI EtwConsumer::TraceThreadProc(LPVOID param) {
    auto* self = static_cast<EtwConsumer*>(param);
    
    // ProcessTrace blocks until the session is stopped
    TRACEHANDLE handles[] = { self->m_traceHandle };
    ULONG status = ProcessTrace(handles, 1, nullptr, nullptr);
    
    if (status != ERROR_SUCCESS && status != ERROR_CANCELLED) {
        Logger::Instance().Error(L"[ETW] ProcessTrace exited with: " + ToWStr(status));
    }
    
    return 0;
}


// ═══════════════════════════════════════════════════════════════════════════
// EVENT DISPATCH (static → instance)
// ═══════════════════════════════════════════════════════════════════════════

void WINAPI EtwConsumer::EventRecordCallback(PEVENT_RECORD pEvent) {
    if (!s_instance || !s_instance->m_running.load()) return;
    
    const GUID& providerId = pEvent->EventHeader.ProviderId;
    
    if (IsEqualGUID(providerId, DNS_CLIENT_GUID)) {
        s_instance->OnDnsEvent(pEvent);
    }
    else if (IsEqualGUID(providerId, POWERSHELL_GUID)) {
        s_instance->OnPowerShellEvent(pEvent);
    }
    else if (IsEqualGUID(providerId, KERNEL_PROCESS_GUID)) {
        USHORT eventId = pEvent->EventHeader.EventDescriptor.Id;
        if (eventId == 1 || eventId == 2) {
            // Process Start (1) / Process Stop (2)
            s_instance->OnKernelProcessEvent(pEvent);
        }
        else if (eventId == 5) {
            // Image Load
            s_instance->OnImageLoadEvent(pEvent);
        }
    }
    
    s_instance->m_totalEvents.fetch_add(1);
}


// ═══════════════════════════════════════════════════════════════════════════
// EVENT PARSERS
// ═══════════════════════════════════════════════════════════════════════════

void EtwConsumer::OnDnsEvent(PEVENT_RECORD pEvent) {
    // DNS Client Event ID 3006 = Query Completed (has both domain and result)
    if (pEvent->EventHeader.EventDescriptor.Id != 3006) return;
    
    // Extract domain name from the event's UserData
    if (!pEvent->UserData || pEvent->UserDataLength < 4) return;
    
    // The DNS client event stores the query name as a wide string at the start
    const WCHAR* domain = reinterpret_cast<const WCHAR*>(pEvent->UserData);
    if (!domain || domain[0] == L'\0') return;
    
    // Safety: ensure null-terminated within bounds
    std::wstring domainStr;
    size_t maxChars = pEvent->UserDataLength / sizeof(WCHAR);
    for (size_t i = 0; i < maxChars && domain[i] != L'\0'; ++i) {
        domainStr += domain[i];
    }
    
    if (domainStr.empty()) return;
    
    DWORD pid = pEvent->EventHeader.ProcessId;
    
    // Basic deduplication: don't fire same domain+pid repeatedly
    {
        std::lock_guard<std::mutex> lock(m_dnsCacheMutex);
        auto key = ToLower(domainStr);
        auto it = m_recentDns.find(key);
        if (it != m_recentDns.end() && it->second == pid) return;
        m_recentDns[key] = pid;
        
        // Evict cache if too large
        if (m_recentDns.size() > 10000) m_recentDns.clear();
    }
    
    EtwEvent evt;
    evt.type        = EtwEventType::DNS_QUERY;
    evt.pid         = pid;
    evt.detail      = domainStr;
    evt.timestamp   = pEvent->EventHeader.TimeStamp;
    
    m_dnsEvents.fetch_add(1);
    EmitEvent(std::move(evt));
}

void EtwConsumer::OnPowerShellEvent(PEVENT_RECORD pEvent) {
    // Event ID 4104 = Script Block Logging (the decoded script)
    if (pEvent->EventHeader.EventDescriptor.Id != 4104) return;
    
    if (!pEvent->UserData || pEvent->UserDataLength < 4) return;
    
    // Script block text is in UserData — extract as string
    // The PowerShell ETW format has multiple fields; the script body is
    // typically the third field. We use TDH to parse properly.
    DWORD bufferSize = 0;
    DWORD status = TdhGetEventInformation(pEvent, 0, nullptr, nullptr, &bufferSize);
    if (status != ERROR_INSUFFICIENT_BUFFER || bufferSize == 0) return;
    
    std::vector<BYTE> buffer(bufferSize);
    auto* info = reinterpret_cast<PTRACE_EVENT_INFO>(buffer.data());
    status = TdhGetEventInformation(pEvent, 0, nullptr, info, &bufferSize);
    if (status != ERROR_SUCCESS) return;
    
    // Look for the "ScriptBlockText" property
    std::wstring scriptText;
    for (DWORD i = 0; i < info->TopLevelPropertyCount; ++i) {
        auto& propInfo = info->EventPropertyInfoArray[i];
        LPCWSTR propName = reinterpret_cast<LPCWSTR>(
            reinterpret_cast<const BYTE*>(info) + propInfo.NameOffset);
        
        if (_wcsicmp(propName, L"ScriptBlockText") == 0) {
            PROPERTY_DATA_DESCRIPTOR pdd = {};
            pdd.PropertyName = (ULONGLONG)propName;
            pdd.ArrayIndex   = ULONG_MAX;
            
            DWORD propSize = 0;
            TdhGetPropertySize(pEvent, 0, nullptr, 1, &pdd, &propSize);
            if (propSize > 0 && propSize < 1048576) { // Max 1 MB
                std::vector<BYTE> propBuf(propSize);
                if (TdhGetProperty(pEvent, 0, nullptr, 1, &pdd, propSize, propBuf.data()) == ERROR_SUCCESS) {
                    scriptText = std::wstring(reinterpret_cast<WCHAR*>(propBuf.data()));
                }
            }
            break;
        }
    }
    
    if (scriptText.empty()) return;
    
    // Truncate very long scripts for the event
    if (scriptText.size() > 2048) {
        scriptText = scriptText.substr(0, 2048) + L"... [TRUNCATED]";
    }
    
    EtwEvent evt;
    evt.type        = EtwEventType::POWERSHELL_SCRIPT;
    evt.pid         = pEvent->EventHeader.ProcessId;
    evt.detail      = std::move(scriptText);
    evt.timestamp   = pEvent->EventHeader.TimeStamp;
    
    m_psEvents.fetch_add(1);
    EmitEvent(std::move(evt));
}

void EtwConsumer::OnKernelProcessEvent(PEVENT_RECORD pEvent) {
    USHORT eventId = pEvent->EventHeader.EventDescriptor.Id;
    
    // Parse event info via TDH
    DWORD bufferSize = 0;
    DWORD status = TdhGetEventInformation(pEvent, 0, nullptr, nullptr, &bufferSize);
    if (status != ERROR_INSUFFICIENT_BUFFER || bufferSize == 0) return;
    
    std::vector<BYTE> buffer(bufferSize);
    auto* info = reinterpret_cast<PTRACE_EVENT_INFO>(buffer.data());
    status = TdhGetEventInformation(pEvent, 0, nullptr, info, &bufferSize);
    if (status != ERROR_SUCCESS) return;
    
    std::wstring imageName;
    std::wstring commandLine;
    DWORD parentPid = 0;
    
    for (DWORD i = 0; i < info->TopLevelPropertyCount; ++i) {
        auto& propInfo = info->EventPropertyInfoArray[i];
        LPCWSTR propName = reinterpret_cast<LPCWSTR>(
            reinterpret_cast<const BYTE*>(info) + propInfo.NameOffset);
        
        PROPERTY_DATA_DESCRIPTOR pdd = {};
        pdd.PropertyName = (ULONGLONG)propName;
        pdd.ArrayIndex   = ULONG_MAX;
        
        DWORD propSize = 0;
        TdhGetPropertySize(pEvent, 0, nullptr, 1, &pdd, &propSize);
        if (propSize == 0 || propSize > 65536) continue;
        
        std::vector<BYTE> propBuf(propSize);
        if (TdhGetProperty(pEvent, 0, nullptr, 1, &pdd, propSize, propBuf.data()) != ERROR_SUCCESS) continue;
        
        if (_wcsicmp(propName, L"ImageName") == 0) {
            imageName = std::wstring(reinterpret_cast<WCHAR*>(propBuf.data()));
        }
        else if (_wcsicmp(propName, L"CommandLine") == 0) {
            commandLine = std::wstring(reinterpret_cast<WCHAR*>(propBuf.data()));
        }
        else if (_wcsicmp(propName, L"ParentProcessID") == 0 && propSize >= 4) {
            parentPid = *reinterpret_cast<DWORD*>(propBuf.data());
        }
    }
    
    EtwEvent evt;
    evt.type        = (eventId == 1) ? EtwEventType::PROCESS_CREATE : EtwEventType::PROCESS_EXIT;
    evt.pid         = pEvent->EventHeader.ProcessId;
    evt.processName = imageName;
    evt.detail      = commandLine;
    evt.extra       = ToWStr(parentPid);
    evt.timestamp   = pEvent->EventHeader.TimeStamp;
    
    m_procEvents.fetch_add(1);
    EmitEvent(std::move(evt));
}

void EtwConsumer::OnImageLoadEvent(PEVENT_RECORD pEvent) {
    // Parse image name from TDH
    DWORD bufferSize = 0;
    DWORD status = TdhGetEventInformation(pEvent, 0, nullptr, nullptr, &bufferSize);
    if (status != ERROR_INSUFFICIENT_BUFFER || bufferSize == 0) return;
    
    std::vector<BYTE> buffer(bufferSize);
    auto* info = reinterpret_cast<PTRACE_EVENT_INFO>(buffer.data());
    status = TdhGetEventInformation(pEvent, 0, nullptr, info, &bufferSize);
    if (status != ERROR_SUCCESS) return;
    
    std::wstring imagePath;
    
    for (DWORD i = 0; i < info->TopLevelPropertyCount; ++i) {
        auto& propInfo = info->EventPropertyInfoArray[i];
        LPCWSTR propName = reinterpret_cast<LPCWSTR>(
            reinterpret_cast<const BYTE*>(info) + propInfo.NameOffset);
        
        if (_wcsicmp(propName, L"ImageName") == 0 || _wcsicmp(propName, L"FileName") == 0) {
            PROPERTY_DATA_DESCRIPTOR pdd = {};
            pdd.PropertyName = (ULONGLONG)propName;
            pdd.ArrayIndex   = ULONG_MAX;
            
            DWORD propSize = 0;
            TdhGetPropertySize(pEvent, 0, nullptr, 1, &pdd, &propSize);
            if (propSize > 0 && propSize < 65536) {
                std::vector<BYTE> propBuf(propSize);
                if (TdhGetProperty(pEvent, 0, nullptr, 1, &pdd, propSize, propBuf.data()) == ERROR_SUCCESS) {
                    imagePath = std::wstring(reinterpret_cast<WCHAR*>(propBuf.data()));
                }
            }
            break;
        }
    }
    
    if (imagePath.empty()) return;
    
    EtwEvent evt;
    evt.type        = EtwEventType::IMAGE_LOAD;
    evt.pid         = pEvent->EventHeader.ProcessId;
    evt.detail      = imagePath;
    evt.timestamp   = pEvent->EventHeader.TimeStamp;
    
    m_imageEvents.fetch_add(1);
    EmitEvent(std::move(evt));
}


// ═══════════════════════════════════════════════════════════════════════════
// EMIT (feeds events to the engine)
// ═══════════════════════════════════════════════════════════════════════════

void EtwConsumer::EmitEvent(EtwEvent&& evt) {
    if (m_callback) {
        m_callback(evt);
    }
}

} // namespace Asthak
