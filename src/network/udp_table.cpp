// udp_table.cpp
#include "udp_table.h"
#include "src/utils/string_utils.h"
#include "src/core/process_cache.h"
#include "src/utils/logger.h"
#include <iphlpapi.h>
#include <ws2tcpip.h>

// Modern MSYS2/MinGW headers (GCC 15+) already define all UDP table
// structs and enums in iprtrmib.h — no manual definitions needed.

// Dynamic loading for GetExtendedUdpTable
namespace {
    typedef DWORD (WINAPI *PFN_GetExtendedUdpTable)(
        PVOID pUdpTable,
        PDWORD pdwSize,
        BOOL bOrder,
        ULONG ulAf,
        UDP_TABLE_CLASS TableClass,
        ULONG Reserved
    );
    
    PFN_GetExtendedUdpTable g_pfnGetExtendedUdpTable = nullptr;
    HMODULE g_hIphlpapi = nullptr;
    bool g_udpTableLoaded = false;
    
    bool LoadUdpTableFunction() {
        if (g_udpTableLoaded) {
            return g_pfnGetExtendedUdpTable != nullptr;
        }
        
        g_hIphlpapi = LoadLibraryW(L"iphlpapi.dll");
        if (!g_hIphlpapi) {
            NetSentinel::Logger::Instance().Error(L"UdpTable: Failed to load iphlpapi.dll");
            g_udpTableLoaded = true;
            return false;
        }
        
        g_pfnGetExtendedUdpTable = (PFN_GetExtendedUdpTable)
            GetProcAddress(g_hIphlpapi, "GetExtendedUdpTable");
            
        if (!g_pfnGetExtendedUdpTable) {
             NetSentinel::Logger::Instance().Error(L"UdpTable: GetExtendedUdpTable function not found in iphlpapi.dll");
        } else {
             NetSentinel::Logger::Instance().Info(L"UdpTable: Successfully loaded GetExtendedUdpTable");
        }
        
        g_udpTableLoaded = true;
        return g_pfnGetExtendedUdpTable != nullptr;
    }
}

#pragma comment(lib, "iphlpapi.lib")

namespace NetSentinel {

UdpTable::UdpTable() = default;
UdpTable::~UdpTable() = default;

std::vector<Connection> UdpTable::GetAllConnections() {
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

std::vector<Connection> UdpTable::GetIPv4Connections() {
    return GetIPv4Table();
}

std::vector<Connection> UdpTable::GetIPv6Connections() {
    return GetIPv6Table();
}

std::vector<Connection> UdpTable::GetIPv4Table() {
    std::vector<Connection> connections;
    
    // Load function dynamically
    if (!LoadUdpTableFunction()) {
        // Function not available - return empty (UDP monitoring disabled)
        return connections;
    }
    
    DWORD size = 0;
    DWORD result = g_pfnGetExtendedUdpTable(nullptr, &size, FALSE, AF_INET, 
                                          UDP_TABLE_OWNER_PID, 0);
    if (result != ERROR_INSUFFICIENT_BUFFER) {
        return connections;
    }
    
    std::vector<BYTE> buffer(size);
    auto* table = reinterpret_cast<PMIB_UDPTABLE_OWNER_PID>(buffer.data());
    
    if (g_pfnGetExtendedUdpTable(table, &size, FALSE, AF_INET, 
                                 UDP_TABLE_OWNER_PID, 0) != NO_ERROR) {
        return connections;
    }
    
    connections.reserve(table->dwNumEntries);
    
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& row = table->table[i];
        
        // Filter loopback
        if (!includeLoopback_ && Utils::IsLoopbackIPv4(row.dwLocalAddr)) {
            continue;
        }
        
        // Filter multicast
        if (Utils::IsMulticastIPv4(row.dwLocalAddr)) {
            continue;
        }
        
        Connection conn;
        conn.pid = row.dwOwningPid;
        conn.protocol = Protocol::UDP;
        conn.direction = Direction::OUTBOUND; // UDP is typically outbound
        
        // Use cache for process info
        auto procInfo = ProcessCache::Instance().GetProcessInfo(row.dwOwningPid);
        conn.processName = procInfo.name;
        conn.processPath = procInfo.path;
        
        // IP addresses
        conn.localIp = Utils::IPv4ToString(row.dwLocalAddr);
        conn.remoteIp = L"*"; // UDP doesn't have remote IP in table
        conn.localPort = ntohs(static_cast<u_short>(row.dwLocalPort));
        conn.remotePort = 0; // UDP table doesn't provide remote port
        
        // Check if private IP
        if (Utils::IsPrivateIPv4(row.dwLocalAddr)) {
            conn.countryCode = L"PRIVATE";
        }
        
        conn.timestamp = std::chrono::steady_clock::now();
        
        connections.push_back(std::move(conn));
    }
    
    return connections;
}

std::vector<Connection> UdpTable::GetIPv6Table() {
    std::vector<Connection> connections;
    
    // Load function dynamically
    if (!LoadUdpTableFunction()) {
        // Function not available - return empty (UDP monitoring disabled)
        return connections;
    }
    
    DWORD size = 0;
    DWORD result = g_pfnGetExtendedUdpTable(nullptr, &size, FALSE, AF_INET6, 
                                          UDP_TABLE_OWNER_PID, 0);
    if (result != ERROR_INSUFFICIENT_BUFFER) {
        return connections;
    }
    
    std::vector<BYTE> buffer(size);
    auto* table = reinterpret_cast<PMIB_UDP6TABLE_OWNER_PID>(buffer.data());
    
    if (g_pfnGetExtendedUdpTable(table, &size, FALSE, AF_INET6, 
                                 UDP_TABLE_OWNER_PID, 0) != NO_ERROR) {
        return connections;
    }
    
    connections.reserve(table->dwNumEntries);
    
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& row = table->table[i];
        
        // Check loopback (::1)
        bool isLoopback = true;
        for (int j = 0; j < 16; ++j) {
            if (row.ucLocalAddr[j] != static_cast<UCHAR>((j == 15) ? 1 : 0)) {
                isLoopback = false;
                break;
            }
        }
        if (!includeLoopback_ && isLoopback) continue;
        
        Connection conn;
        conn.pid = row.dwOwningPid;
        conn.protocol = Protocol::UDP;
        conn.direction = Direction::OUTBOUND;
        
        auto procInfo = ProcessCache::Instance().GetProcessInfo(row.dwOwningPid);
        conn.processName = procInfo.name;
        conn.processPath = procInfo.path;
        
        conn.localIp = Utils::IPv6ToString(row.ucLocalAddr);
        conn.remoteIp = L"*"; // UDP doesn't have remote IP in table
        conn.localPort = ntohs(static_cast<u_short>(row.dwLocalPort));
        conn.remotePort = 0;
        
        conn.timestamp = std::chrono::steady_clock::now();
        
        connections.push_back(std::move(conn));
    }
    
    return connections;
}

} // namespace NetSentinel
