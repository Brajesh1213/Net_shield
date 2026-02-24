#include "threat_intel.h"
#include "src/utils/logger.h"
#include "src/utils/string_utils.h"
#include <unordered_set>
#include <unordered_map>
#include <sstream>
#include <chrono>

// WinHTTP for API calls (optional - can be disabled if not available)
#ifdef HAVE_WINHTTP
    #include <winhttp.h>
    #pragma comment(lib, "winhttp.lib")
#endif

namespace NetSentinel {

ThreatIntel& ThreatIntel::Instance() {
    static ThreatIntel instance;
    return instance;
}

ThreatIntel::ThreatIntel() {
    // Load static threat feeds
    LoadStaticFeeds();
}

ThreatIntel::~ThreatIntel() {
    // Cleanup
}

void ThreatIntel::LoadStaticFeeds() {
    // Known malicious IPs from various threat feeds
    // In production, load from files or APIs
    knownBadIPs_ = {
        // Add real known-bad public IPs here (never use RFC1918 private ranges!)
        // Example: L"185.220.101.1",  // Known Tor exit node
    };
    
    // Known malicious domains
    knownBadDomains_ = {
        L"malicious.example.com",
        // Add more known bad domains here
    };
}

std::wstring ThreatIntel::CheckIP(const std::wstring& ip) {
    // Check cache first
    auto cacheIt = ipCache_.find(ip);
    if (cacheIt != ipCache_.end()) {
        auto age = std::chrono::steady_clock::now() - cacheIt->second.timestamp;
        if (age < std::chrono::hours(24)) {
            return cacheIt->second.result;
        }
        // Cache expired, remove
        ipCache_.erase(cacheIt);
    }
    
    // Check static feeds
    if (knownBadIPs_.find(ip) != knownBadIPs_.end()) {
        std::wstring result = L"Known malicious IP (static feed)";
        ipCache_[ip] = {result, std::chrono::steady_clock::now()};
        return result;
    }
    
    // Check AbuseIPDB (if API key configured)
    std::wstring abuseResult = CheckAbuseIPDB(ip);
    if (!abuseResult.empty()) {
        ipCache_[ip] = {abuseResult, std::chrono::steady_clock::now()};
        return abuseResult;
    }
    
    // Check VirusTotal (if API key configured)
    std::wstring vtResult = CheckVirusTotal(ip);
    if (!vtResult.empty()) {
        ipCache_[ip] = {vtResult, std::chrono::steady_clock::now()};
        return vtResult;
    }
    
    // No threat found
    ipCache_[ip] = {L"", std::chrono::steady_clock::now()};
    return L"";
}

std::wstring ThreatIntel::CheckDomain(const std::wstring& domain) {
    // Check static feeds
    if (knownBadDomains_.find(domain) != knownBadDomains_.end()) {
        return L"Known malicious domain";
    }
    
    // Check VirusTotal for domain
    return CheckVirusTotalDomain(domain);
}

std::wstring ThreatIntel::CheckAbuseIPDB(const std::wstring& ip) {
    // AbuseIPDB API check
    // Requires API key in environment variable or config
    // For now, return empty (implement when API key available)
    
#ifdef HAVE_WINHTTP
    if (abuseIPDBKey_.empty()) {
        return L"";
    }
    
    // Example implementation:
    // HINTERNET hSession = WinHttpOpen(L"NetSentinel/1.0", ...);
    // HINTERNET hConnect = WinHttpConnect(hSession, L"api.abuseipdb.com", ...);
    // HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", 
    //     (L"/api/v2/check?ipAddress=" + ip).c_str(), ...);
    // WinHttpAddRequestHeaders(hRequest, (L"Key: " + abuseIPDBKey_).c_str(), ...);
    // WinHttpSendRequest(...);
    // Parse JSON response for abuseConfidenceScore
    
    // TODO: Implement when API key is configured
#endif
    
    return L"";
}

std::wstring ThreatIntel::CheckVirusTotal(const std::wstring& ip) {
    // VirusTotal API check
    // Requires API key
    // Similar to AbuseIPDB implementation
    
    return L"";
}

std::wstring ThreatIntel::CheckVirusTotalDomain(const std::wstring& domain) {
    // VirusTotal domain check
    return L"";
}

bool ThreatIntel::LoadFeeds() {
    // Load threat intelligence feeds from files or APIs
    LoadStaticFeeds();
    
    // In production:
    // - Load from AbuseIPDB API
    // - Load from VirusTotal API
    // - Load from AlienVault OTX
    // - Load from local threat feed files
    
    Logger::Instance().Info(L"ThreatIntel: Loaded threat feeds");
    return true;
}

void ThreatIntel::SetAbuseIPDBKey(const std::wstring& apiKey) {
    abuseIPDBKey_ = apiKey;
}

void ThreatIntel::SetVirusTotalKey(const std::wstring& apiKey) {
    virusTotalKey_ = apiKey;
}

} // namespace NetSentinel