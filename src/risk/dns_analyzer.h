// dns_analyzer.h — DNS threat intelligence & DGA detection
// Analyzes DNS queries from ETW for C2 domains, DGA patterns, tunneling
#pragma once

#include <string>
#include <unordered_set>
#include <unordered_map>
#include <mutex>
#include <cstdint>

namespace Asthak {

enum class DnsVerdict {
    CLEAN,
    KNOWN_C2,         // Known command & control domain
    DGA_DETECTED,     // Domain Generation Algorithm pattern
    DNS_TUNNELING,    // Likely DNS tunneling (exfiltration)
    SUSPICIOUS_TLD,   // Uncommon/dangerous TLD
    NEWLY_REGISTERED, // Domain less than 30 days old (heuristic)
};

struct DnsAnalysisResult {
    DnsVerdict    verdict;
    std::wstring  domain;
    std::wstring  reason;
    double        dgaScore; // 0.0-1.0 probability of being DGA
};

class DnsAnalyzer {
public:
    static DnsAnalyzer& Instance();

    bool Initialize();
    DnsAnalysisResult AnalyzeDomain(const std::wstring& domain);

    // Load custom blocklist
    bool LoadBlocklist(const std::wstring& path);
    void AddToBlocklist(const std::wstring& domain);

private:
    DnsAnalyzer() = default;

    double ComputeDGAScore(const std::wstring& domain);
    double ComputeEntropyStr(const std::wstring& str);
    bool IsKnownC2(const std::wstring& domain);
    bool IsSuspiciousTLD(const std::wstring& domain);
    std::wstring ExtractRegisteredDomain(const std::wstring& domain);

    std::unordered_set<std::wstring> m_blocklist;     // Known C2 domains
    std::unordered_set<std::wstring> m_whitelist;      // Known-safe domains
    std::mutex m_mutex;
    bool m_initialized{false};
};

} // namespace Asthak
