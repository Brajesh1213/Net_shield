// process_cache.cpp
#include "process_cache.h"
#include <psapi.h>
#include <tlhelp32.h>  // For CreateToolhelp32Snapshot (fallback)
#include <algorithm>
#include <vector>


#pragma comment(lib, "psapi.lib")

namespace NetSentinel {

ProcessCache& ProcessCache::Instance() {    
    static ProcessCache instance;
    return instance;
}

ProcessInfo ProcessCache::GetProcessInfo(uint32_t pid) {
    // Special system PIDs
    if (pid == 0) return {L"System Idle", L"", std::chrono::steady_clock::now()};
    if (pid == 4) return {L"System", L"\\SystemRoot\\System32\\ntoskrnl.exe", 
                          std::chrono::steady_clock::now()};
    
    auto now = std::chrono::steady_clock::now();

    // Check cache
    auto it = cache_.find(pid);
    if (it != cache_.end()) {
        // Check if expired
        if (now - it->second.lastAccess < ttl_) {
            it->second.lastAccess = now; // Update LRU
            return it->second;
        }
        // Expired, will refresh
        cache_.erase(it);
    }
    
    // Not in cache or expired - fetch fresh
    std::wstring fullPath;
    std::wstring name = GetProcessNameInternal(pid, fullPath);
    
    ProcessInfo info{name, fullPath, now};
    
    cache_[pid] = info;

    // Cleanup if cache too large (simple LRU eviction)
    if (cache_.size() > 1000) {
        CleanupExpired();
    }
    
    return info;
}

void ProcessCache::Invalidate(uint32_t pid) {
    cache_.erase(pid);
}

void ProcessCache::Clear() {
    cache_.clear();
}

std::wstring ProcessCache::GetProcessNameInternal(uint32_t pid, std::wstring& fullPath) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        // Try with less permissions
        hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hProcess) {
            return L"unknown";
        }
    }
    
    // RAII handle wrapper
    struct HandleGuard {
        HANDLE h;
        HandleGuard(HANDLE handle) : h(handle) {}
        ~HandleGuard() { if (h) CloseHandle(h); }
    } guard(hProcess);
    
    WCHAR path[MAX_PATH] = {0};
    DWORD size = MAX_PATH;
    
    // Try GetModuleFileNameEx first (widely available across MinGW variants)
    if (GetModuleFileNameExW(hProcess, nullptr, path, size)) {
        fullPath = path;
        
        // Extract filename
        const WCHAR* lastSlash = wcsrchr(path, L'\\');
        if (lastSlash) {
            return lastSlash + 1;
        }
        return path;
    }

    // Fallback to base module name when full path is unavailable.
    if (GetModuleBaseNameW(hProcess, nullptr, path, size)) {
        return path;
    }
    
    return L"unknown";
}

void ProcessCache::CleanupExpired() {
    auto now = std::chrono::steady_clock::now();
    
    // Remove entries older than 2x TTL
    for (auto it = cache_.begin(); it != cache_.end(); ) {
        if (now - it->second.lastAccess > ttl_ * 2) {
            it = cache_.erase(it);
        } else {
            ++it;
        }
    }
    
    // If still too large, remove oldest 20%
    if (cache_.size() > 1000) {
        std::vector<std::pair<uint32_t, std::chrono::steady_clock::time_point>> entries;
        for (std::unordered_map<uint32_t, ProcessInfo>::const_iterator it = cache_.begin();
             it != cache_.end(); ++it) {
            entries.emplace_back(it->first, it->second.lastAccess);
        }
        
        std::sort(entries.begin(), entries.end(),
            [](const auto& a, const auto& b) { return a.second < b.second; });
        
        size_t toRemove = entries.size() / 5; // Remove 20%
        for (size_t i = 0; i < toRemove; ++i) {
            cache_.erase(entries[i].first);
        }
    }
}

} // namespace NetSentinel
