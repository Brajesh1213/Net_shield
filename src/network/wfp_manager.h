// wfp_manager.h — Windows Filtering Platform (WFP) manager
#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <cstdint>

namespace Asthak {

struct WfpRule {
    std::wstring   remoteIp;
    uint16_t       remotePort;
    uint8_t        protocol;     // IPPROTO_TCP = 6, IPPROTO_UDP = 17
    std::wstring   ruleName;
    UINT64         filterId;
};

class WfpManager {
public:
    static WfpManager& Instance();

    // Open/close a WFP engine session
    bool Open();
    void Close();

    // Block outbound traffic to a remote IP:port
    bool BlockRemoteIpPort(const std::wstring& remoteIp,
                           uint16_t             remotePort,
                           uint8_t              protocol,
                           const std::wstring&  ruleName);

    // Remove a previously added block rule by filter ID
    bool RemoveRule(UINT64 filterId);

    // Remove all rules added in this session
    void RemoveAllRules();

    bool IsOpen() const { return m_engineHandle != nullptr; }

private:
    WfpManager()  = default;
    ~WfpManager() { Close(); }
    WfpManager(const WfpManager&) = delete;
    WfpManager& operator=(const WfpManager&) = delete;

    HANDLE              m_engineHandle{ nullptr };
    std::vector<WfpRule> m_rules;
};

} // namespace Asthak
