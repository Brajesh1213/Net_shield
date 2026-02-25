// connection_monitor.h
#pragma once
#include "netsentinel_common.h"
#include <string>
#include <vector>
#include <functional>
#include <atomic>
#include <windows.h>

namespace NetSentinel {

using ConnectionCallback = std::function<void(const Connection&)>;

class ConnectionMonitor {
public:
    static ConnectionMonitor& Instance();

    // Start monitoring all active connections
    void Start(ConnectionCallback callback);

    // Stop monitoring
    void Stop();

    // Check if monitoring is active
    bool IsRunning() const { return m_running.load(); }

private:
    ConnectionMonitor() = default;
    ~ConnectionMonitor() { Stop(); }
    ConnectionMonitor(const ConnectionMonitor&) = delete;
    ConnectionMonitor& operator=(const ConnectionMonitor&) = delete;

    void MonitorLoop();

    std::atomic<bool>   m_running{ false };
    HANDLE              m_thread{ nullptr };
    ConnectionCallback  m_callback;

    static DWORD WINAPI MonitorThreadProc(LPVOID param);
};

} // namespace NetSentinel
