// connection_monitor.cpp
#include "connection_monitor.h"
#include "../network/tcp_table.h"
#include "../network/udp_table.h"
#include <algorithm>

namespace Asthak {

ConnectionMonitor& ConnectionMonitor::Instance() {
    static ConnectionMonitor instance;
    return instance;
}

void ConnectionMonitor::Start(ConnectionCallback callback) {
    if (m_running.load()) return;
    m_callback = std::move(callback);
    m_running = true;
    m_thread = CreateThread(nullptr, 0, MonitorThreadProc, this, 0, nullptr);
}

void ConnectionMonitor::Stop() {
    if (!m_running.load()) return;
    m_running = false;
    if (m_thread) {
        WaitForSingleObject(m_thread, 5000);
        CloseHandle(m_thread);
        m_thread = nullptr;
    }
}

void ConnectionMonitor::MonitorLoop() {
    TcpTable tcpTable;
    UdpTable udpTable;
    tcpTable.SetEstablishedOnly(false);
    tcpTable.SetIncludeLoopback(true);
    udpTable.SetIncludeLoopback(true);

    while (m_running.load()) {
        auto tcpConns = tcpTable.GetAllConnections();
        auto udpConns = udpTable.GetAllConnections();

        for (auto& conn : tcpConns) {
            if (m_callback) m_callback(conn);
        }
        for (auto& conn : udpConns) {
            if (m_callback) m_callback(conn);
        }

        Sleep(2000);
    }
}

DWORD WINAPI ConnectionMonitor::MonitorThreadProc(LPVOID param) {
    auto* self = static_cast<ConnectionMonitor*>(param);
    self->MonitorLoop();
    return 0;
}

} // namespace Asthak
