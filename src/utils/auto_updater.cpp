// auto_updater.cpp — Auto-updater implementation
// Uses WinInet to poll update server for new app/rules versions.
// ─────────────────────────────────────────────────────────────────────────────
#include "utils/auto_updater.h"
#include "utils/logger.h"
#include <wininet.h>
#include <fstream>
#include <sstream>
#include <filesystem>

#pragma comment(lib, "wininet.lib")

namespace Asthak {

static const std::string APP_VERSION_URL  = "/api/version?app=asthak-edr&channel=stable";
static const std::string RULES_VERSION_URL = "/api/rules/version";
static const std::string RULES_DOWNLOAD_URL = "/api/rules/latest.yar";

// ─────────────────────────────────────────────────────────────────────────────
AutoUpdater& AutoUpdater::Instance() {
    static AutoUpdater s;
    return s;
}

// ─────────────────────────────────────────────────────────────────────────────
void AutoUpdater::Initialize(const std::string& currentVersion,
                              const std::string& updateServerUrl,
                              int checkIntervalHours) {
    m_currentVersion = currentVersion;
    m_updateServer   = updateServerUrl;
    m_intervalHours  = checkIntervalHours;
    m_rulesVersion   = LoadRulesVersion();

    InitializeCriticalSection(&m_cs);

    Logger::Instance().Info(L"[Updater] Initialized. App: " +
        std::wstring(m_currentVersion.begin(), m_currentVersion.end()) +
        L" | Rules: " +
        std::wstring(m_rulesVersion.begin(), m_rulesVersion.end()) +
        L" | Server: " +
        std::wstring(m_updateServer.begin(), m_updateServer.end()));

    // Start background update check thread
    m_running = true;
    m_thread  = std::thread(&AutoUpdater::BackgroundThread, this);
}

// ─────────────────────────────────────────────────────────────────────────────
void AutoUpdater::Shutdown() {
    m_running = false;
    if (m_thread.joinable()) m_thread.join();
    DeleteCriticalSection(&m_cs);
}

// ─────────────────────────────────────────────────────────────────────────────
// Background thread — checks every N hours
// ─────────────────────────────────────────────────────────────────────────────
void AutoUpdater::BackgroundThread() {
    // Wait 10 minutes before first check (let the app settle)
    for (int i = 0; i < 60 && m_running; ++i) {
        Sleep(10000); // 10 seconds × 60 = 10 minutes
    }

    while (m_running) {
        try {
            Logger::Instance().Info(L"[Updater] Checking for updates...");
            auto info = CheckNow();

            if (info.rulesUpdateAvailable) {
                Logger::Instance().Info(L"[Updater] Rules update available: " +
                    std::wstring(info.latestRulesVersion.begin(), info.latestRulesVersion.end()));
                ApplyRulesUpdate(info.rulesUrl);
            }

            if (info.appUpdateAvailable && m_appCb) {
                Logger::Instance().Info(L"[Updater] App update available: " +
                    std::wstring(info.latestVersion.begin(), info.latestVersion.end()));
                m_appCb(info);
            }

            if (!info.appUpdateAvailable && !info.rulesUpdateAvailable) {
                Logger::Instance().Info(L"[Updater] Everything is up to date.");
            }
        } catch (...) {
            Logger::Instance().Warning(L"[Updater] Update check failed (network unavailable?)");
        }

        // Sleep for configured interval
        int sleepMs = m_intervalHours * 3600 * 1000;
        int elapsed = 0;
        const int SLICE = 30000; // 30s sleep slices for responsive shutdown
        while (m_running && elapsed < sleepMs) {
            Sleep(SLICE);
            elapsed += SLICE;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CheckNow — synchronously checks server and returns UpdateInfo
// ─────────────────────────────────────────────────────────────────────────────
UpdateInfo AutoUpdater::CheckNow() {
    UpdateInfo info;
    info.currentVersion  = m_currentVersion;

    // Check app version
    std::string appResp  = HttpGet(m_updateServer + APP_VERSION_URL);
    info.latestVersion   = ParseJsonField(appResp, "version");
    info.changelog       = ParseJsonField(appResp, "changelog");
    info.downloadUrl     = ParseJsonField(appResp, "download_url");
    info.appUpdateAvailable = !info.latestVersion.empty() &&
                              VersionIsNewer(info.latestVersion, m_currentVersion);

    // Check rules version
    std::string rulesResp       = HttpGet(m_updateServer + RULES_VERSION_URL);
    info.latestRulesVersion     = ParseJsonField(rulesResp, "version");
    info.rulesUrl               = m_updateServer + RULES_DOWNLOAD_URL;
    info.rulesUpdateAvailable   = !info.latestRulesVersion.empty() &&
                                  VersionIsNewer(info.latestRulesVersion, m_rulesVersion);

    return info;
}

// ─────────────────────────────────────────────────────────────────────────────
// ApplyRulesUpdate — downloads new rules and notifies callback
// ─────────────────────────────────────────────────────────────────────────────
void AutoUpdater::ApplyRulesUpdate(const std::string& rulesUrl) {
    std::string rulesContent = HttpGet(rulesUrl);
    if (rulesContent.empty()) {
        Logger::Instance().Warning(L"[Updater] Rules download failed or empty.");
        return;
    }

    // Save to disk
    std::filesystem::path rulesPath = std::filesystem::path("rules") / "latest.yar";
    try {
        std::filesystem::create_directories(rulesPath.parent_path());
        std::ofstream f(rulesPath, std::ios::binary);
        f << rulesContent;
        f.close();
        Logger::Instance().Info(L"[Updater] Rules saved to: " +
            std::wstring(rulesPath.wstring()));
    } catch (...) {
        Logger::Instance().Warning(L"[Updater] Failed to save rules to disk.");
    }

    // Notify callback (YaraScanner can reload hot)
    if (m_rulesCb) {
        m_rulesCb(rulesContent);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HttpGet — simple WinInet GET request
// ─────────────────────────────────────────────────────────────────────────────
std::string AutoUpdater::HttpGet(const std::string& url) {
    std::string result;

    // Parse URL
    std::string host, path;
    bool https = (url.substr(0, 8) == "https://");
    std::string rest = url.substr(https ? 8 : 7);
    size_t slash = rest.find('/');
    if (slash != std::string::npos) {
        host = rest.substr(0, slash);
        path = rest.substr(slash);
    } else {
        host = rest;
        path = "/";
    }

    HINTERNET hInet = InternetOpenA("AsthakEDR-Updater/1.0",
        INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
    if (!hInet) return result;

    HINTERNET hConn = InternetConnectA(hInet, host.c_str(),
        https ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT,
        nullptr, nullptr,
        INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConn) { InternetCloseHandle(hInet); return result; }

    DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE;
    if (https) flags |= INTERNET_FLAG_SECURE;

    HINTERNET hReq = HttpOpenRequestA(hConn, "GET", path.c_str(),
        nullptr, nullptr, nullptr, flags, 0);
    if (!hReq) { InternetCloseHandle(hConn); InternetCloseHandle(hInet); return result; }

    if (HttpSendRequestA(hReq, nullptr, 0, nullptr, 0)) {
        char buf[4096];
        DWORD read = 0;
        while (InternetReadFile(hReq, buf, sizeof(buf) - 1, &read) && read > 0) {
            buf[read] = '\0';
            result += buf;
            read = 0;
        }
    }

    InternetCloseHandle(hReq);
    InternetCloseHandle(hConn);
    InternetCloseHandle(hInet);
    return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// VersionIsNewer — compares semantic versions "1.2.3"
// ─────────────────────────────────────────────────────────────────────────────
bool AutoUpdater::VersionIsNewer(const std::string& latest, const std::string& current) {
    auto parse = [](const std::string& v) -> std::tuple<int,int,int> {
        int a=0, b=0, c=0;
        std::istringstream ss(v);
        char dot;
        ss >> a >> dot >> b >> dot >> c;
        return {a, b, c};
    };
    return parse(latest) > parse(current);
}

// ─────────────────────────────────────────────────────────────────────────────
// ParseJsonField — minimal JSON field extractor (no external deps)
// ─────────────────────────────────────────────────────────────────────────────
std::string AutoUpdater::ParseJsonField(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return "";

    pos = json.find(':', pos);
    if (pos == std::string::npos) return "";
    pos = json.find('"', pos);
    if (pos == std::string::npos) return "";
    ++pos;

    size_t end = json.find('"', pos);
    if (end == std::string::npos) return "";

    return json.substr(pos, end - pos);
}

// ─────────────────────────────────────────────────────────────────────────────
// LoadRulesVersion — reads version from rules/latest.yar header comment
// ─────────────────────────────────────────────────────────────────────────────
std::string AutoUpdater::LoadRulesVersion() {
    std::ifstream f("rules/latest.yar");
    if (!f) return "2026.03.01-builtin";  // Default: built-in rules date

    std::string line;
    while (std::getline(f, line)) {
        // Look for: // RULES_VERSION: 2026.03.01
        if (line.find("RULES_VERSION:") != std::string::npos) {
            size_t colon = line.find(':');
            if (colon != std::string::npos) {
                std::string ver = line.substr(colon + 1);
                // Trim whitespace
                ver.erase(0, ver.find_first_not_of(" \t"));
                ver.erase(ver.find_last_not_of(" \t\r\n") + 1);
                return ver;
            }
        }
        if (f.tellg() > 512) break; // Only check first 512 bytes
    }
    return "2026.03.01-builtin";
}

} // namespace Asthak
