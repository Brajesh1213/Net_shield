// wfp_manager.cpp — Windows Filtering Platform (WFP) manager implementation
// NOTE: Requires linking with fwpuclnt.lib (-lfwpuclnt)
#include "wfp_manager.h"

// WFP headers – must come AFTER windows.h
#include <fwpmu.h>
#include <initguid.h>
#include <guiddef.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>

#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Ws2_32.lib")

namespace Asthak {

WfpManager& WfpManager::Instance() {
    static WfpManager instance;
    return instance;
}

bool WfpManager::Open() {
    if (m_engineHandle) return true;

    FWPM_SESSION0 session = {};
    session.flags = FWPM_SESSION_FLAG_DYNAMIC; // rules auto-removed on close

    DWORD result = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_DEFAULT,
                                   nullptr, &session, &m_engineHandle);
    if (result != ERROR_SUCCESS) {
        m_engineHandle = nullptr;
        return false;
    }
    return true;
}

void WfpManager::Close() {
    if (!m_engineHandle) return;
    RemoveAllRules();
    FwpmEngineClose0(m_engineHandle);
    m_engineHandle = nullptr;
}

bool WfpManager::BlockRemoteIpPort(const std::wstring& remoteIp,
                                    uint16_t            remotePort,
                                    uint8_t             protocol,
                                    const std::wstring& ruleName) {
    if (!m_engineHandle) return false;

    // Parse the remote IP address
    FWP_BYTE_ARRAY16 ipAddr = {};
    SOCKADDR_STORAGE sa = {};
    int saLen = sizeof(sa);
    if (WSAStringToAddressW(const_cast<LPWSTR>(remoteIp.c_str()),
                            AF_INET, nullptr,
                            reinterpret_cast<LPSOCKADDR>(&sa), &saLen) != 0) {
        return false; // Only IPv4 for now
    }
    UINT32 ipv4Addr = reinterpret_cast<SOCKADDR_IN*>(&sa)->sin_addr.s_addr;

    // Build conditions: remote IP + remote port + protocol
    FWPM_FILTER_CONDITION0 conds[3] = {};

    // Condition 0: remote IP
    conds[0].fieldKey           = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    conds[0].matchType          = FWP_MATCH_EQUAL;
    conds[0].conditionValue.type      = FWP_UINT32;
    conds[0].conditionValue.uint32    = ntohl(ipv4Addr);

    // Condition 1: remote port
    conds[1].fieldKey           = FWPM_CONDITION_IP_REMOTE_PORT;
    conds[1].matchType          = FWP_MATCH_EQUAL;
    conds[1].conditionValue.type      = FWP_UINT16;
    conds[1].conditionValue.uint16    = remotePort;

    // Condition 2: protocol
    conds[2].fieldKey           = FWPM_CONDITION_IP_PROTOCOL;
    conds[2].matchType          = FWP_MATCH_EQUAL;
    conds[2].conditionValue.type      = FWP_UINT8;
    conds[2].conditionValue.uint8     = protocol;

    // Build filter
    FWPM_FILTER0 filter = {};
    filter.displayData.name        = const_cast<PWSTR>(ruleName.c_str());
    filter.displayData.description = L"Asthak WFP block rule";
    filter.layerKey                = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.action.type             = FWP_ACTION_BLOCK;
    filter.numFilterConditions     = 3;
    filter.filterCondition         = conds;
    filter.weight.type             = FWP_EMPTY; // auto-weight

    UINT64 filterId = 0;
    DWORD result = FwpmFilterAdd0(m_engineHandle, &filter, nullptr, &filterId);
    if (result != ERROR_SUCCESS) return false;

    WfpRule rule;
    rule.remoteIp   = remoteIp;
    rule.remotePort = remotePort;
    rule.protocol   = protocol;
    rule.ruleName   = ruleName;
    rule.filterId   = filterId;
    m_rules.push_back(rule);
    return true;
}

bool WfpManager::RemoveRule(UINT64 filterId) {
    if (!m_engineHandle) return false;
    DWORD result = FwpmFilterDeleteById0(m_engineHandle, filterId);
    if (result != ERROR_SUCCESS) return false;

    m_rules.erase(std::remove_if(m_rules.begin(), m_rules.end(),
        [filterId](const WfpRule& r){ return r.filterId == filterId; }),
        m_rules.end());
    return true;
}

void WfpManager::RemoveAllRules() {
    if (!m_engineHandle) return;
    for (auto& rule : m_rules) {
        FwpmFilterDeleteById0(m_engineHandle, rule.filterId);
    }
    m_rules.clear();
}

} // namespace Asthak
