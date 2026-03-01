// wfp_manager.cpp — Windows Filtering Platform (WFP) manager implementation
//
// MinGW's <fwpmu.h> often lacks the FWPM_CONDITION_* GUIDs and
// FWPM_SESSION_FLAG_DYNAMIC / FWPM_LAYER_* constants.
// We define them manually here — these are stable, documented Windows constants.

#include "network/wfp_manager.h"
#include "utils/logger.h"
#include <algorithm>
#include <sstream>
#include <ws2tcpip.h>

// ── Manual MinGW WFP compatibility defines ───────────────────────────────────
// These are normally from <fwpmu.h> / <fwpmtypes.h> but may be missing in MinGW.

#ifndef FWPM_SESSION_FLAG_DYNAMIC
#define FWPM_SESSION_FLAG_DYNAMIC 0x00000001
#endif

// FWPM_LAYER_ALE_AUTH_CONNECT_V4 GUID
#ifndef FWPM_LAYER_ALE_AUTH_CONNECT_V4
static const GUID FWPM_LAYER_ALE_AUTH_CONNECT_V4 = {
    0xc38d57d1, 0x05a7, 0x4c33,
    { 0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82 }
};
#endif

// FWPM_CONDITION_IP_REMOTE_ADDRESS GUID
#ifndef FWPM_CONDITION_IP_REMOTE_ADDRESS
static const GUID FWPM_CONDITION_IP_REMOTE_ADDRESS = {
    0xb235ae9a, 0x1d64, 0x49b8,
    { 0xa4, 0x4c, 0xb7, 0xe0, 0x98, 0x15, 0x8c, 0x61 }
};
#endif

// FWPM_CONDITION_IP_REMOTE_PORT GUID
#ifndef FWPM_CONDITION_IP_REMOTE_PORT
static const GUID FWPM_CONDITION_IP_REMOTE_PORT = {
    0xc35a604d, 0xd22b, 0x4e1a,
    { 0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b }
};
#endif

// FWPM_CONDITION_IP_PROTOCOL GUID
#ifndef FWPM_CONDITION_IP_PROTOCOL
static const GUID FWPM_CONDITION_IP_PROTOCOL = {
    0x3971ef2b, 0x623e, 0x4f9a,
    { 0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7 }
};
#endif

// Now include WFP API AFTER our manual defines
#include <fwpmu.h>
#include <initguid.h>

#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Ws2_32.lib")
// ─────────────────────────────────────────────────────────────────────────────

namespace Asthak {

namespace {
template<typename T>
std::wstring ToWStr(T v) { std::wostringstream o; o << v; return o.str(); }
} // anonymous namespace

WfpManager& WfpManager::Instance() {
    static WfpManager instance;
    return instance;
}

bool WfpManager::Open() {
    if (m_engineHandle) return true;

    FWPM_SESSION0 session = {};
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    DWORD res = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_DEFAULT,
                                nullptr, &session, &m_engineHandle);
    if (res != ERROR_SUCCESS) {
        m_engineHandle = nullptr;
        Logger::Instance().Warning(L"[WfpManager] FwpmEngineOpen0 failed: " + ToWStr(res));
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

    // Parse IPv4 address
    SOCKADDR_STORAGE sa = {};
    int saLen = sizeof(sa);
    if (WSAStringToAddressW(const_cast<LPWSTR>(remoteIp.c_str()),
                            AF_INET, nullptr,
                            reinterpret_cast<LPSOCKADDR>(&sa), &saLen) != 0) {
        return false;
    }
    UINT32 ipv4Addr = reinterpret_cast<SOCKADDR_IN*>(&sa)->sin_addr.s_addr;

    // Build 3 filter conditions
    FWPM_FILTER_CONDITION0 conds[3] = {};

    conds[0].fieldKey              = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    conds[0].matchType             = FWP_MATCH_EQUAL;
    conds[0].conditionValue.type   = FWP_UINT32;
    conds[0].conditionValue.uint32 = ntohl(ipv4Addr);

    conds[1].fieldKey              = FWPM_CONDITION_IP_REMOTE_PORT;
    conds[1].matchType             = FWP_MATCH_EQUAL;
    conds[1].conditionValue.type   = FWP_UINT16;
    conds[1].conditionValue.uint16 = remotePort;

    conds[2].fieldKey             = FWPM_CONDITION_IP_PROTOCOL;
    conds[2].matchType            = FWP_MATCH_EQUAL;
    conds[2].conditionValue.type  = FWP_UINT8;
    conds[2].conditionValue.uint8 = protocol;

    // Build the filter
    static wchar_t descBuf[] = L"Asthak WFP block rule";
    FWPM_FILTER0 filter = {};
    filter.displayData.name        = const_cast<PWSTR>(ruleName.c_str());
    filter.displayData.description = descBuf;
    filter.layerKey                = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.action.type             = FWP_ACTION_BLOCK;
    filter.numFilterConditions     = 3;
    filter.filterCondition         = conds;
    filter.weight.type             = FWP_EMPTY;

    UINT64 filterId = 0;
    DWORD res = FwpmFilterAdd0(m_engineHandle, &filter, nullptr, &filterId);
    if (res != ERROR_SUCCESS) {
        Logger::Instance().Warning(L"[WfpManager] FwpmFilterAdd0 failed: " + ToWStr(res));
        return false;
    }

    WfpRule rule;
    rule.remoteIp   = remoteIp;
    rule.remotePort = remotePort;
    rule.protocol   = protocol;
    rule.ruleName   = ruleName;
    rule.filterId   = filterId;
    m_rules.push_back(rule);
    Logger::Instance().Info(L"[WfpManager] Blocked " + remoteIp + L":" + ToWStr(remotePort));
    return true;
}

bool WfpManager::RemoveRule(UINT64 filterId) {
    if (!m_engineHandle) return false;

    DWORD res = FwpmFilterDeleteById0(m_engineHandle, filterId);
    if (res != ERROR_SUCCESS) return false;

    m_rules.erase(
        std::remove_if(m_rules.begin(), m_rules.end(),
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
