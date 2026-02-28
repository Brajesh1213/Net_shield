// udp_table.h
#pragma once
#include "asthak_common.h"
#include <vector>

namespace Asthak {

class UdpTable {
public:
    UdpTable();
    ~UdpTable();
    
    // Disable copy
    UdpTable(const UdpTable&) = delete;
    UdpTable& operator=(const UdpTable&) = delete;
    
    // Get all UDP connections (IPv4 and IPv6)
    std::vector<Connection> GetAllConnections();
    
    // Get only IPv4
    std::vector<Connection> GetIPv4Connections();
    
    // Get only IPv6
    std::vector<Connection> GetIPv6Connections();
    
    // Set loopback inclusion (default false)
    void SetIncludeLoopback(bool include) { includeLoopback_ = include; }
    
private:
    std::vector<Connection> GetIPv4Table();
    std::vector<Connection> GetIPv6Table();
    
    bool includeLoopback_ = false;
};

} // namespace Asthak
