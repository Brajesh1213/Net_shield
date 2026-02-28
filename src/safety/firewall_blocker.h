// firewall_blocker.h
#pragma once
#include "asthak_common.h"
#include <string>

namespace Asthak {

class FirewallBlocker {
public:
    static FirewallBlocker& Instance();
    
    // Block a connection by IP and port
    bool BlockIP(const std::wstring& ip, uint16_t port, Protocol protocol, const std::wstring& reason);
    
    // Block a connection by process path
    bool BlockProcess(const std::wstring& processPath, const std::wstring& reason);
    
    // Block a specific IP:port:protocol combination
    bool BlockConnection(const Connection& conn, const std::wstring& reason);
    
    // Unblock an IP
    bool UnblockIP(const std::wstring& ip);
    
    // Unblock a process
    bool UnblockProcess(const std::wstring& processPath);
    
    // Check if IP is blocked
    bool IsIPBlocked(const std::wstring& ip);
    
    // Initialize firewall COM interface
    bool Initialize();
    
    // Cleanup
    void Shutdown();
    
private:
    FirewallBlocker() = default;
    ~FirewallBlocker();
    FirewallBlocker(const FirewallBlocker&) = delete;
    FirewallBlocker& operator=(const FirewallBlocker&) = delete;
    
    void* firewallPolicy_ = nullptr; // INetFwPolicy2 COM interface
    void* firewallRules_ = nullptr;   // INetFwRules COM interface
    bool initialized_ = false;
    
    std::wstring GenerateRuleName(const std::wstring& ip, uint16_t port, Protocol protocol);
    std::wstring GenerateProcessRuleName(const std::wstring& processPath);
};

} // namespace Asthak
