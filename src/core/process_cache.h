// process_cache.h
#pragma once
#include <windows.h>
#include <string>
#include <unordered_map>
#include <chrono>

namespace NetSentinel {

struct ProcessInfo {
    std::wstring name;
    std::wstring path;
    std::chrono::steady_clock::time_point lastAccess;
};

class ProcessCache {
public:
    static ProcessCache& Instance();
    
    // Get process info (cached or fresh)
    ProcessInfo GetProcessInfo(uint32_t pid);
    
    // Manually invalidate cache entry
    void Invalidate(uint32_t pid);
    
    // Clear entire cache
    void Clear();
    
    // Set cache TTL (default 30 seconds)
    void SetTTL(std::chrono::seconds ttl) { ttl_ = ttl; }
    
private:
    ProcessCache() = default;
    ~ProcessCache() = default;
    ProcessCache(const ProcessCache&) = delete;
    ProcessCache& operator=(const ProcessCache&) = delete;
    
    std::wstring GetProcessNameInternal(uint32_t pid, std::wstring& fullPath);
    void CleanupExpired();
    
    std::unordered_map<uint32_t, ProcessInfo> cache_;
    std::chrono::seconds ttl_{30};
};

} // namespace NetSentinel
