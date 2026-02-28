// etw_consumer.h — ETW (Event Tracing for Windows) telemetry consumer
// Consumes kernel and user-mode events for deep visibility:
//   - DNS queries  (Microsoft-Windows-DNS-Client)
//   - PowerShell   (Microsoft-Windows-PowerShell)
//   - Process create/exit  (Microsoft-Windows-Kernel-Process)
//   - Image/DLL loads      (Microsoft-Windows-Kernel-Process)
//   - Registry changes     (via SecurityAuditing)
#pragma once

#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <string>

// MinGW may not define this constant
#ifndef INVALID_PROCESSTRACE_HANDLE
#define INVALID_PROCESSTRACE_HANDLE ((TRACEHANDLE)INVALID_HANDLE_VALUE)
#endif
#include <functional>
#include <atomic>
#include <vector>
#include <unordered_map>
#include <mutex>

namespace Asthak {

// ── Event types surfaced to the engine ──────────────────────────────────────
enum class EtwEventType {
    DNS_QUERY,             // Process resolved a domain name
    POWERSHELL_SCRIPT,     // PowerShell script block executed
    PROCESS_CREATE,        // New process started (with full command line)
    PROCESS_EXIT,          // Process terminated
    IMAGE_LOAD,            // DLL/EXE loaded into a process
    REGISTRY_PERSIST,      // Autorun registry key modified
};

struct EtwEvent {
    EtwEventType type;
    DWORD        pid;
    std::wstring processName;
    std::wstring detail;        // domain / script block / command line / dll path / reg key
    std::wstring extra;         // resolved IP / parent PID / etc.
    LARGE_INTEGER timestamp;
};

using EtwEventCallback = std::function<void(const EtwEvent&)>;

// ── Main ETW Consumer class ─────────────────────────────────────────────────
class EtwConsumer {
public:
    EtwConsumer();
    ~EtwConsumer();

    // Start consuming events in a background thread
    bool Start(EtwEventCallback callback);
    void Stop();
    bool IsRunning() const { return m_running.load(); }

    // Stats
    uint64_t GetTotalEventsProcessed() const { return m_totalEvents.load(); }
    uint64_t GetDnsEventsCount()       const { return m_dnsEvents.load(); }
    uint64_t GetPsEventsCount()        const { return m_psEvents.load(); }
    uint64_t GetProcEventsCount()      const { return m_procEvents.load(); }
    uint64_t GetImageEventsCount()     const { return m_imageEvents.load(); }

private:
    // ETW session management
    bool StartTraceSession();
    void StopTraceSession();

    // Process incoming ETW records
    static void WINAPI EventRecordCallback(PEVENT_RECORD pEvent);

    // Thread proc for ProcessTrace (blocking call)
    static DWORD WINAPI TraceThreadProc(LPVOID param);

    // Parse specific event types
    void OnDnsEvent(PEVENT_RECORD pEvent);
    void OnPowerShellEvent(PEVENT_RECORD pEvent);
    void OnKernelProcessEvent(PEVENT_RECORD pEvent);
    void OnImageLoadEvent(PEVENT_RECORD pEvent);

    // Internal emit helper
    void EmitEvent(EtwEvent&& evt);

    // Session properties
    struct SessionProps {
        EVENT_TRACE_PROPERTIES props;
        WCHAR                  loggerName[256];
    };

    std::atomic<bool>   m_running{false};
    EtwEventCallback    m_callback;
    TRACEHANDLE         m_sessionHandle{INVALID_PROCESSTRACE_HANDLE};
    TRACEHANDLE         m_traceHandle{INVALID_PROCESSTRACE_HANDLE};
    HANDLE              m_thread{nullptr};
    SessionProps        m_sessionProps{};

    // Stats counters
    std::atomic<uint64_t> m_totalEvents{0};
    std::atomic<uint64_t> m_dnsEvents{0};
    std::atomic<uint64_t> m_psEvents{0};
    std::atomic<uint64_t> m_procEvents{0};
    std::atomic<uint64_t> m_imageEvents{0};

    // DNS cache for dedup
    std::mutex                              m_dnsCacheMutex;
    std::unordered_map<std::wstring, DWORD> m_recentDns; // domain -> last PID

    // Singleton-ish context for static callback
    static EtwConsumer* s_instance;
};

} // namespace Asthak
