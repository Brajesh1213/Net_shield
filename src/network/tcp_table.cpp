// tcp_table.cpp
#include "tcp_table.h"
#include "src/utils/string_utils.h"
#include "src/core/process_cache.h"
#include <iphlpapi.h>
#include <ws2tcpip.h>

#pragma comment(lib, "iphlpapi.lib")

namespace Asthak {

TcpTable::TcpTable() = default;
TcpTable::~TcpTable() = default;

std::vector<Connection> TcpTable::GetAllConnections() {
    std::vector<Connection> result;
    
    auto ipv4 = GetIPv4Table();
    auto ipv6 = GetIPv6Table();
    
    result.reserve(ipv4.size() + ipv6.size());
    result.insert(result.end(), std::make_move_iterator(ipv4.begin()), 
                               std::make_move_iterator(ipv4.end()));
    result.insert(result.end(), std::make_move_iterator(ipv6.begin()), 
                               std::make_move_iterator(ipv6.end()));
    
    return result;
}

std::vector<Connection> TcpTable::GetIPv4Connections() {
    return GetIPv4Table();
}

std::vector<Connection> TcpTable::GetIPv6Connections() {
    return GetIPv6Table();
}

std::vector<Connection> TcpTable::GetIPv4Table() {
    std::vector<Connection> connections;
    
    DWORD size = 0;
    DWORD result = GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, 
                                      TCP_TABLE_OWNER_PID_ALL, 0);
    if (result != ERROR_INSUFFICIENT_BUFFER) {
        return connections;
    }
    
    std::vector<BYTE> buffer(size);
    auto* table = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());
    
    if (GetExtendedTcpTable(table, &size, FALSE, AF_INET, 
                           TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
        return connections;
    }
    
    connections.reserve(table->dwNumEntries);
    
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& row = table->table[i];
        
        // Filter by state
        if (establishedOnly_ && row.dwState != MIB_TCP_STATE_ESTAB) {
            continue;
        }
        
        // Filter loopback
        if (!includeLoopback_ && Utils::IsLoopbackIPv4(row.dwRemoteAddr)) {
            continue;
        }
        
        // Filter multicast
        if (Utils::IsMulticastIPv4(row.dwRemoteAddr)) {
            continue;
        }
        
        Connection conn;
        conn.pid = row.dwOwningPid;
        conn.protocol = Protocol::TCP;
        // TCP table entries do not provide reliable directionality metadata.
        conn.direction = Direction::BOTH;
        
        // Use cache for process info
        auto procInfo = ProcessCache::Instance().GetProcessInfo(row.dwOwningPid);
        conn.processName = procInfo.name;
        conn.processPath = procInfo.path;
        
        // IP addresses
        conn.localIp = Utils::IPv4ToString(row.dwLocalAddr);
        conn.remoteIp = Utils::IPv4ToString(row.dwRemoteAddr);
        conn.localPort = ntohs(static_cast<u_short>(row.dwLocalPort));
        conn.remotePort = ntohs(static_cast<u_short>(row.dwRemotePort));
        
        // Check if private IP
        if (Utils::IsPrivateIPv4(row.dwRemoteAddr)) {
            conn.countryCode = L"PRIVATE";
        }
        
        conn.timestamp = std::chrono::steady_clock::now();
        
        connections.push_back(std::move(conn));
    }
    
    return connections;
}

std::vector<Connection> TcpTable::GetIPv6Table() {
    std::vector<Connection> connections;
    
    DWORD size = 0;
    DWORD result = GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET6, 
                                      TCP_TABLE_OWNER_PID_ALL, 0);
    if (result != ERROR_INSUFFICIENT_BUFFER) {
        return connections;
    }
    
    std::vector<BYTE> buffer(size);
    auto* table = reinterpret_cast<PMIB_TCP6TABLE_OWNER_PID>(buffer.data());
    
    if (GetExtendedTcpTable(table, &size, FALSE, AF_INET6, 
                           TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
        return connections;
    }
    
    connections.reserve(table->dwNumEntries);
    
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& row = table->table[i];
        
        if (establishedOnly_ && row.dwState != MIB_TCP_STATE_ESTAB) {
            continue;
        }
        
        // Check loopback (::1)
        bool isLoopback = true;
        for (int j = 0; j < 16; ++j) {
            if (row.ucRemoteAddr[j] != static_cast<UCHAR>((j == 15) ? 1 : 0)) {
                isLoopback = false;
                break;
            }
        }
        if (!includeLoopback_ && isLoopback) continue;
        
        Connection conn;
        conn.pid = row.dwOwningPid;
        conn.protocol = Protocol::TCP;
        // TCP table entries do not provide reliable directionality metadata.
        conn.direction = Direction::BOTH;
        
        auto procInfo = ProcessCache::Instance().GetProcessInfo(row.dwOwningPid);
        conn.processName = procInfo.name;
        conn.processPath = procInfo.path;
        
        conn.localIp = Utils::IPv6ToString(row.ucLocalAddr);
        conn.remoteIp = Utils::IPv6ToString(row.ucRemoteAddr);
        conn.localPort = ntohs(static_cast<u_short>(row.dwLocalPort));
        conn.remotePort = ntohs(static_cast<u_short>(row.dwRemotePort));
        
        conn.timestamp = std::chrono::steady_clock::now();
        
        connections.push_back(std::move(conn));
    }
    
    return connections;
}

} // namespace Asthak
