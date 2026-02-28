// config.h — Application configuration for Asthak
#pragma once
#include <string>
#include <cstdint>
#include <vector>

namespace Asthak {

// All tunable runtime parameters in one place
struct Config {
    // ── Polling ────────────────────────────────────────────────────────────
    uint32_t pollingIntervalMs    = 2000;   // Main loop poll cadence
    uint32_t heartbeatIntervalSec = 30;     // Heartbeat log period

    // ── Risk thresholds ────────────────────────────────────────────────────
    uint32_t beaconWindowSec      = 300;    // Sliding window for beacon detection
    uint32_t beaconMinHits        = 5;      // Min identical-interval hits to flag C2
    uint32_t highPortalConns      = 20;     // Connections/window before flagging scanner

    // ── Quarantine ─────────────────────────────────────────────────────────
    bool     quarantineEnabled    = true;
    std::wstring quarantineVaultDir; // Set at runtime from %APPDATA%

    // ── Logging ────────────────────────────────────────────────────────────
    bool     logToFile            = true;
    bool     logToEventLog        = true;
    std::wstring logDirectory;           // Set at runtime from %LOCALAPPDATA%

    // ── Protection mode ────────────────────────────────────────────────────
    bool     activeBlocking       = true;  // false = monitor-only
    bool     includeLoopback      = true;  // Monitor 127.x traffic

    // ── Threat feeds ───────────────────────────────────────────────────────
    bool     loadBuiltinFeeds     = true;
    std::vector<std::wstring> extraFeedPaths; // Paths to additional blocklist files

    // ── Notification ───────────────────────────────────────────────────────
    bool     desktopNotifications = true;
};

// Singleton accessor — call Config::Instance() everywhere
class AppConfig {
public:
    static AppConfig& Instance();

    const Config& Get() const { return m_cfg; }
    Config&       Get()       { return m_cfg; }

    // Load from an INI-style file (key=value, # comments)
    bool LoadFromFile(const std::wstring& path);

    // Save current config back to file
    bool SaveToFile(const std::wstring& path) const;

    // Reset to compiled-in defaults
    void ResetDefaults();

private:
    AppConfig()  = default;
    ~AppConfig() = default;
    AppConfig(const AppConfig&) = delete;
    AppConfig& operator=(const AppConfig&) = delete;

    Config m_cfg;
};

} // namespace Asthak
