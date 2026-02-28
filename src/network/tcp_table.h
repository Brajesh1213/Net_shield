// tcp_table.h
#pragma once
#include "asthak_common.h"
#include <vector>
#include <memory>

namespace Asthak {

class TcpTable {
public:
    TcpTable();
    ~TcpTable();
    
    // Disable copy
    TcpTable(const TcpTable&) = delete;
    TcpTable& operator=(const TcpTable&) = delete;
    
    // Get all connections (IPv4 and IPv6)
    std::vector<Connection> GetAllConnections();
    
    // Get only IPv4
    std::vector<Connection> GetIPv4Connections();
    
    // Get only IPv6
    std::vector<Connection> GetIPv6Connections();
    
    // Set filter for established connections only (default true)
    void SetEstablishedOnly(bool establishedOnly) { establishedOnly_ = establishedOnly; }
    
    // Set loopback inclusion (default false)
    void SetIncludeLoopback(bool include) { includeLoopback_ = include; }
    
private:
    std::vector<Connection> GetIPv4Table();
    std::vector<Connection> GetIPv6Table();
    
    bool establishedOnly_ = true;
    bool includeLoopback_ = false;
};

} // namespace Asthak