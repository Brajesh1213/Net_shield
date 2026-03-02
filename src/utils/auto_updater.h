// auto_updater.h — Asthak EDR Auto-Updater
// ─────────────────────────────────────────────────────────────────────────────
// Checks for new YARA rule sets and app versions from the update server.
// Rule updates are applied without restart. App updates prompt the user.
// ─────────────────────────────────────────────────────────────────────────────
#pragma once

#include <windows.h>
#include <string>
#include <functional>
#include <thread>
#include <atomic>

namespace Asthak {

// ─────────────────────────────────────────────────────────────────────────────
struct UpdateInfo {
    std::string currentVersion;      // e.g. "1.0.0"
    std::string latestVersion;       // e.g. "1.1.0"
    std::string latestRulesVersion;  // e.g. "2026.03.01"
    std::string changelog;
    std::string downloadUrl;
    std::string rulesUrl;
    bool        appUpdateAvailable  = false;
    bool        rulesUpdateAvailable = false;
};

// ─────────────────────────────────────────────────────────────────────────────
class AutoUpdater {
public:
    static AutoUpdater& Instance();

    // Initialize — starts background check thread
    void Initialize(const std::string& currentVersion,
                    const std::string& updateServerUrl,
                    int checkIntervalHours = 24);

    // Callbacks
    using AppUpdateCallback   = std::function<void(const UpdateInfo&)>;
    using RulesUpdateCallback = std::function<void(const std::string& newRulesContent)>;

    void SetAppUpdateCallback(AppUpdateCallback cb)   { m_appCb   = cb; }
    void SetRulesUpdateCallback(RulesUpdateCallback cb){ m_rulesCb = cb; }

    // Manual check (blocking)
    UpdateInfo CheckNow();

    // Download and apply rules update (non-blocking)
    void ApplyRulesUpdate(const std::string& rulesUrl);

    void Shutdown();

    const std::string& GetCurrentVersion() const { return m_currentVersion; }
    const std::string& GetCurrentRulesVersion() const { return m_rulesVersion; }

private:
    AutoUpdater() = default;
    ~AutoUpdater() { Shutdown(); }

    void BackgroundThread();
    std::string HttpGet(const std::string& url);
    bool        VersionIsNewer(const std::string& latest, const std::string& current);
    std::string ParseJsonField(const std::string& json, const std::string& key);
    std::string LoadRulesVersion();

    std::string         m_currentVersion;
    std::string         m_rulesVersion;
    std::string         m_updateServer;
    int                 m_intervalHours = 24;
    std::atomic<bool>   m_running{false};
    std::thread         m_thread;
    AppUpdateCallback   m_appCb;
    RulesUpdateCallback m_rulesCb;

    mutable CRITICAL_SECTION m_cs;
};

} // namespace Asthak
