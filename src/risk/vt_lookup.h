// vt_lookup.h — VirusTotal API cloud hash lookup
// Checks file hashes against VirusTotal's database of 2B+ samples
#pragma once

#include <windows.h>
#include <string>
#include <functional>
#include <atomic>
#include <unordered_map>
#include <mutex>

namespace Asthak {

struct VtResult {
    bool        found;           // Hash was found in VT database
    bool        malicious;       // Flagged as malware by VT
    int         positives;       // Number of engines that flagged it
    int         total;           // Total number of engines
    std::wstring malwareFamily;  // E.g., "Trojan.GenericKD", "Emotet"
    std::wstring permalink;      // Link to VT report
    std::wstring detail;
};

using VtResultCallback = std::function<void(const std::wstring& hash, const VtResult&)>;

class VtLookup {
public:
    static VtLookup& Instance();

    // Set API key (free tier = 4 req/min, premium = 1000 req/min)
    void SetApiKey(const std::wstring& apiKey);

    // Initialize (loads API key from config file if not set)
    bool Initialize();

    // Lookup a SHA-256 hash against VirusTotal
    VtResult LookupHash(const std::wstring& sha256Hash);

    // Async lookup with callback
    void LookupHashAsync(const std::wstring& sha256Hash, VtResultCallback callback);

    // Check if we have an API key configured
    bool HasApiKey()      const { return !m_apiKey.empty(); }
    bool IsInitialized()  const { return m_initialized; }

    // Rate limiting
    bool CanMakeRequest() const;

    // Stats
    uint64_t GetLookupsPerformed() const { return m_lookups.load(); }
    uint64_t GetMalwareFound()     const { return m_malwareFound.load(); }

private:
    VtLookup() = default;

    // HTTP GET using WinINet
    std::string HttpGet(const std::wstring& url);

    // Parse VT JSON response
    VtResult ParseResponse(const std::string& json);

    std::wstring m_apiKey;
    std::mutex   m_mutex;

    // Cache to avoid redundant lookups
    std::unordered_map<std::wstring, VtResult> m_cache;
    std::mutex m_cacheMutex;

    // Rate limiting (free tier: 4 requests per minute)
    DWORD m_lastRequestTick{0};
    int   m_requestsThisMinute{0};
    DWORD m_minuteStartTick{0};

    std::atomic<uint64_t> m_lookups{0};
    std::atomic<uint64_t> m_malwareFound{0};
    bool m_initialized{false};
};

} // namespace Asthak
