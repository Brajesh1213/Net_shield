// hash_scanner.h — SHA-256 hash-based threat detection
// Computes file hashes and checks against known malware hash databases.
// This is a core technique used by ALL commercial EDR products.
#pragma once

#include <windows.h>
#include <string>
#include <unordered_set>
#include <unordered_map>
#include <mutex>
#include <atomic>

namespace Asthak {

enum class HashVerdict {
    CLEAN,          // Hash not found in any blocklist
    KNOWN_MALWARE,  // Hash matches known malware
    SUSPICIOUS,     // Hash has low reputation
    UNKNOWN,        // Hash not in any database (first-seen)
    ERROR_HASHING,  // Could not compute hash
};

struct HashResult {
    HashVerdict   verdict;
    std::wstring  sha256;
    std::wstring  malwareFamily;   // e.g. "Emotet", "Cobalt Strike Beacon"
    std::wstring  source;          // e.g. "local_blocklist", "cloud_lookup"
};

class HashScanner {
public:
    static HashScanner& Instance();

    // Initialize with local blocklist file path
    bool Initialize(const std::wstring& blocklist_path = L"");
    
    // Compute SHA-256 hash of a file
    std::wstring ComputeSHA256(const std::wstring& filePath);
    
    // Check a file against the blocklist
    HashResult ScanFile(const std::wstring& filePath);
    
    // Check a hash directly
    HashResult CheckHash(const std::wstring& sha256);
    
    // Add a hash to the local blocklist at runtime
    void AddToBlocklist(const std::wstring& sha256, const std::wstring& family);
    
    // Load hashes from a text file (one hash per line, optionally hash,family)
    bool LoadBlocklistFile(const std::wstring& path);
    
    // Stats
    uint64_t GetFilesScanned()      const { return m_filesScanned.load(); }
    uint64_t GetMalwareDetected()   const { return m_malwareFound.load(); }
    uint64_t GetBlocklistSize()     const;

private:
    HashScanner() = default;
    
    // Known malware hashes: sha256 → malware family name
    std::unordered_map<std::wstring, std::wstring> m_blocklist;
    mutable std::mutex m_mutex;
    
    // Cache: recently scanned files (path → sha256) to avoid re-hashing
    std::unordered_map<std::wstring, std::wstring> m_hashCache;
    
    std::atomic<uint64_t> m_filesScanned{0};
    std::atomic<uint64_t> m_malwareFound{0};
    bool m_initialized{false};
    
    // Built-in well-known malware hashes (hardcoded as a baseline)
    void LoadBuiltinHashes();
};

} // namespace Asthak
