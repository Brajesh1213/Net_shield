#pragma once
#include "netsentinel_common.h"
#include <string>
#include <unordered_set>
#include <unordered_map>
#include <chrono>

namespace NetSentinel {

struct ThreatCacheEntry {
    std::wstring result;
    std::chrono::steady_clock::time_point timestamp;
};

class ThreatIntel {
public:
    static ThreatIntel& Instance();
    
    // Check if IP/domain is known malicious
    std::wstring CheckIP(const std::wstring& ip);
    std::wstring CheckDomain(const std::wstring& domain);
    
    // Load threat feeds
    bool LoadFeeds();
    
    // Set API keys for threat intelligence services
    void SetAbuseIPDBKey(const std::wstring& apiKey);
    void SetVirusTotalKey(const std::wstring& apiKey);
    
private:
    ThreatIntel();
    ~ThreatIntel();
    ThreatIntel(const ThreatIntel&) = delete;
    ThreatIntel& operator=(const ThreatIntel&) = delete;
    
    void LoadStaticFeeds();
    std::wstring CheckAbuseIPDB(const std::wstring& ip);
    std::wstring CheckVirusTotal(const std::wstring& ip);
    std::wstring CheckVirusTotalDomain(const std::wstring& domain);
    
    std::unordered_set<std::wstring> knownBadIPs_;
    std::unordered_set<std::wstring> knownBadDomains_;
    std::unordered_map<std::wstring, ThreatCacheEntry> ipCache_;
    std::wstring abuseIPDBKey_;
    std::wstring virusTotalKey_;
};

} // namespace NetSentinel