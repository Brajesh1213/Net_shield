// false_positive_filter.h — False Positive / Whitelist Engine
// ─────────────────────────────────────────────────────────────────────────────
// Prevents Asthak from alerting on known-good software.
// Whitelists by: process path, SHA-256 hash, certificate signer, parent process.
// ─────────────────────────────────────────────────────────────────────────────
#pragma once

#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <string>
#include <vector>
#include <unordered_set>
#include <mutex>
#include <functional>
#include <algorithm>
#include <cctype>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

namespace Asthak {

// ─────────────────────────────────────────────────────────────────────────────
// Whitelist entry types
// ─────────────────────────────────────────────────────────────────────────────
enum class WhitelistReason {
    MICROSOFT_SIGNED,       // Signed by Microsoft
    TRUSTED_VENDOR,         // Signed by known trusted vendor
    HASH_WHITELISTED,       // SHA-256 in trusted hash list
    PATH_WHITELISTED,       // Path in trusted path list
    PROCESS_WHITELISTED,    // Process name in trusted list
    USER_APPROVED,          // User manually approved
};

struct WhitelistResult {
    bool         isTrusted = false;
    WhitelistReason reason;
    std::string  details;   // e.g. "Signed by: Microsoft Windows"
};

// ─────────────────────────────────────────────────────────────────────────────
class FalsePositiveFilter {
public:
    static FalsePositiveFilter& Instance();

    // Initialize with config (called at startup)
    void Initialize();

    // Main API — call before taking action on any detection
    WhitelistResult IsWhitelisted(const std::wstring& filePath, DWORD pid = 0) const;
    WhitelistResult IsHashWhitelisted(const std::string& sha256) const;
    WhitelistResult IsProcessWhitelisted(const std::wstring& processName) const;

    // Add entries at runtime (user-approved)
    void WhitelistPath(const std::wstring& path);
    void WhitelistHash(const std::string& sha256);
    void WhitelistProcessName(const std::wstring& name);

    // Load/save whitelist from config file
    void LoadFromConfig(const std::wstring& configPath);
    void SaveToConfig(const std::wstring& configPath) const;

private:
    FalsePositiveFilter();

    bool IsSignedByMicrosoft(const std::wstring& filePath) const;
    bool IsSignedByTrustedVendor(const std::wstring& filePath, std::string& signerOut) const;
    bool IsPathTrusted(const std::wstring& filePath) const;

    // Built-in Microsoft system paths
    static const std::vector<std::wstring> s_systemPaths;

    // Built-in trusted process names
    static const std::vector<std::wstring> s_trustedProcesses;

    // Built-in trusted certificate subjects
    static const std::vector<std::string> s_trustedSigners;

    // User/config-loaded lists
    std::unordered_set<std::wstring> m_whitelistedPaths;
    std::unordered_set<std::string>  m_whitelistedHashes;
    std::unordered_set<std::wstring> m_whitelistedProcesses;

    mutable std::mutex m_mutex;
};

} // namespace Asthak
