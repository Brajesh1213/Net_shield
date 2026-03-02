// yara_scanner.h — Built-in YARA-compatible rule engine
// ─────────────────────────────────────────────────────────────────────────────
// Implements YARA-style pattern matching in pure C++ with NO external library
// dependency.  Rules are defined as structs with string/hex/regex patterns and
// a condition.  All 8 industry-standard rules from the docs are pre-loaded.
//
// Scan targets:
//   • File content (read from disk into memory)
//   • Process memory regions (ReadProcessMemory over all committed pages)
//   • Raw byte buffers (network packet payloads)
//   • Wide-string script blocks (PowerShell ScriptBlock ETW events)
// ─────────────────────────────────────────────────────────────────────────────
#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <functional>
#include <atomic>
#include <unordered_set>
#include <unordered_map>
#include <mutex>

namespace Asthak {

// ── Severity ──────────────────────────────────────────────────────────────────
enum class YaraRuleSeverity { LOW, MEDIUM, HIGH, CRITICAL };

// ── A single YARA-style string pattern ───────────────────────────────────────
enum class YaraPatternType { PLAIN_ASCII, PLAIN_WIDE, HEX_BYTES, REGEX_ASCII };

struct YaraPattern {
    std::string       id;         // $s1, $hex1, ...
    YaraPatternType   type;
    std::string       value;      // ASCII/hex/regex pattern
    bool              nocase;     // case-insensitive match
    bool              wide;       // UTF-16 expansion
};

// ── Condition type ────────────────────────────────────────────────────────────
enum class YaraCondition {
    ANY_OF_STRINGS,   // any of ($*)
    ALL_OF_STRINGS,   // all of ($*)
    N_OF_STRINGS,     // N of ($*)
};

// ── A complete YARA rule ──────────────────────────────────────────────────────
struct YaraRule {
    std::string         name;
    std::string         description;
    std::string         malwareFamily;   // tag for ResponseEngine
    YaraRuleSeverity    severity;
    YaraCondition       condition;
    int                 conditionN{1};   // used when condition == N_OF_STRINGS
    std::vector<YaraPattern> patterns;
};

// ── Result of scanning one buffer/file/process ───────────────────────────────
struct YaraMatch {
    std::string  ruleName;
    std::string  malwareFamily;
    std::string  description;
    YaraRuleSeverity severity;
    size_t       matchOffset{0};
    std::string  matchedPattern;
};

using YaraMatchCallback = std::function<void(const YaraMatch&, DWORD pid)>;

// ─────────────────────────────────────────────────────────────────────────────
// YaraScanner — singleton, thread-safe
// ─────────────────────────────────────────────────────────────────────────────
class YaraScanner {
public:
    static YaraScanner& Instance();

    // Initialize — loads built-in rules + any extra .yar files from rulesDir
    bool Initialize(const std::wstring& rulesDir = L"");

    // Register a callback for every match
    void SetCallback(YaraMatchCallback cb) { m_callback = cb; }

    // ── Scan overloads ──────────────────────────────────────────────────────

    // Scan a raw byte buffer (e.g. network packet)
    std::vector<YaraMatch> ScanBuffer(const uint8_t* data, size_t size,
                                       DWORD pid = 0);

    // Scan a wide-string (PowerShell ScriptBlock)
    std::vector<YaraMatch> ScanWString(const std::wstring& script, DWORD pid = 0);

    // Scan a file on disk (reads up to 4 MB)
    std::vector<YaraMatch> ScanFile(const std::wstring& filePath, DWORD pid = 0);

    // Scan all committed memory pages of a live process
    std::vector<YaraMatch> ScanProcess(DWORD pid);

    // Stats
    uint64_t ScansTotal()   const { return m_scansTotal.load(); }
    uint64_t MatchesTotal() const { return m_matches.load(); }
    size_t   RuleCount()    const { return m_rules.size(); }
    bool     IsReady()      const { return m_ready; }

private:
    YaraScanner() = default;

    // Load the 8 hard-coded built-in rules
    void LoadBuiltinRules();

    // Core matching engine
    std::vector<YaraMatch> MatchRules(const uint8_t* data, size_t size,
                                       DWORD pid = 0);

    // Per-pattern matching helpers
    bool MatchPattern(const YaraPattern& p,
                      const uint8_t* data, size_t size,
                      size_t& outOffset, std::string& outSnippet) const;

    bool MatchPlainAscii(const std::string& needle, bool nocase,
                          const uint8_t* data, size_t size,
                          size_t& outOffset) const;

    bool MatchHexBytes(const std::string& hexPattern,
                        const uint8_t* data, size_t size,
                        size_t& outOffset) const;

    // Parse a hex pattern like "4D 5A 90 ?? 03" into bytes + mask
    bool ParseHexPattern(const std::string& hex,
                          std::vector<uint8_t>& bytes,
                          std::vector<bool>&    mask) const;  // true = must match

    std::vector<YaraRule>   m_rules;
    YaraMatchCallback       m_callback;
    mutable std::mutex      m_mutex;
    bool                    m_ready{false};
    std::atomic<uint64_t>   m_scansTotal{0};
    std::atomic<uint64_t>   m_matches{0};

    // Deduplicate: don't fire same rule for same PID twice in 60s
    struct MatchKey { std::string rule; DWORD pid; };
    struct MatchKeyHash {
        size_t operator()(const std::pair<std::string,DWORD>& k) const {
            return std::hash<std::string>()(k.first) ^ (k.second * 2654435761UL);
        }
    };
    std::unordered_map<std::string, DWORD> m_recentMatches;
    std::mutex m_dedupeM;
};

} // namespace Asthak
