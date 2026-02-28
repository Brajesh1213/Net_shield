// config.cpp — Application configuration implementation
#include "config.h"
#include <windows.h>
#include <shlobj.h>
#include <fstream>
#include <sstream>
#include <algorithm>

namespace Asthak {

AppConfig& AppConfig::Instance() {
    static AppConfig instance;
    return instance;
}

void AppConfig::ResetDefaults() {
    m_cfg = Config{};
}

// ── Simple INI parser (key=value, lines starting with '#' are comments) ───────
bool AppConfig::LoadFromFile(const std::wstring& path) {
    std::wifstream file(path);
    if (!file.is_open()) return false;

    std::wstring line;
    while (std::getline(file, line)) {
        // Trim leading whitespace
        size_t start = line.find_first_not_of(L" \t\r\n");
        if (start == std::wstring::npos) continue;
        line = line.substr(start);

        // Skip comments and empty lines
        if (line.empty() || line[0] == L'#' || line[0] == L';') continue;

        size_t eq = line.find(L'=');
        if (eq == std::wstring::npos) continue;

        std::wstring key = line.substr(0, eq);
        std::wstring val = line.substr(eq + 1);

        // Trim trailing whitespace / CR
        auto trimRight = [](std::wstring& s) {
            while (!s.empty() && (s.back() == L' ' || s.back() == L'\t' ||
                                  s.back() == L'\r' || s.back() == L'\n'))
                s.pop_back();
        };
        trimRight(key);
        trimRight(val);

        // Map keys to config fields
        if      (key == L"pollingIntervalMs")    m_cfg.pollingIntervalMs    = static_cast<uint32_t>(_wtoi(val.c_str()));
        else if (key == L"heartbeatIntervalSec") m_cfg.heartbeatIntervalSec = static_cast<uint32_t>(_wtoi(val.c_str()));
        else if (key == L"beaconWindowSec")      m_cfg.beaconWindowSec      = static_cast<uint32_t>(_wtoi(val.c_str()));
        else if (key == L"beaconMinHits")        m_cfg.beaconMinHits        = static_cast<uint32_t>(_wtoi(val.c_str()));
        else if (key == L"highPortalConns")      m_cfg.highPortalConns      = static_cast<uint32_t>(_wtoi(val.c_str()));
        else if (key == L"quarantineEnabled")    m_cfg.quarantineEnabled    = (val == L"true" || val == L"1");
        else if (key == L"quarantineVaultDir")   m_cfg.quarantineVaultDir   = val;
        else if (key == L"logToFile")            m_cfg.logToFile            = (val == L"true" || val == L"1");
        else if (key == L"logToEventLog")        m_cfg.logToEventLog        = (val == L"true" || val == L"1");
        else if (key == L"logDirectory")         m_cfg.logDirectory         = val;
        else if (key == L"activeBlocking")       m_cfg.activeBlocking       = (val == L"true" || val == L"1");
        else if (key == L"includeLoopback")      m_cfg.includeLoopback      = (val == L"true" || val == L"1");
        else if (key == L"loadBuiltinFeeds")     m_cfg.loadBuiltinFeeds     = (val == L"true" || val == L"1");
        else if (key == L"desktopNotifications") m_cfg.desktopNotifications = (val == L"true" || val == L"1");
        else if (key == L"extraFeedPath")        m_cfg.extraFeedPaths.push_back(val);
    }
    return true;
}

bool AppConfig::SaveToFile(const std::wstring& path) const {
    std::wofstream file(path, std::ios::trunc);
    if (!file.is_open()) return false;

    auto boolStr = [](bool b) -> const wchar_t* { return b ? L"true" : L"false"; };

    file << L"# Asthak Configuration\n";
    file << L"pollingIntervalMs="    << m_cfg.pollingIntervalMs    << L"\n";
    file << L"heartbeatIntervalSec=" << m_cfg.heartbeatIntervalSec << L"\n";
    file << L"beaconWindowSec="      << m_cfg.beaconWindowSec      << L"\n";
    file << L"beaconMinHits="        << m_cfg.beaconMinHits        << L"\n";
    file << L"highPortalConns="      << m_cfg.highPortalConns      << L"\n";
    file << L"quarantineEnabled="    << boolStr(m_cfg.quarantineEnabled)    << L"\n";
    file << L"quarantineVaultDir="   << m_cfg.quarantineVaultDir   << L"\n";
    file << L"logToFile="            << boolStr(m_cfg.logToFile)            << L"\n";
    file << L"logToEventLog="        << boolStr(m_cfg.logToEventLog)        << L"\n";
    file << L"logDirectory="         << m_cfg.logDirectory         << L"\n";
    file << L"activeBlocking="       << boolStr(m_cfg.activeBlocking)       << L"\n";
    file << L"includeLoopback="      << boolStr(m_cfg.includeLoopback)      << L"\n";
    file << L"loadBuiltinFeeds="     << boolStr(m_cfg.loadBuiltinFeeds)     << L"\n";
    file << L"desktopNotifications=" << boolStr(m_cfg.desktopNotifications) << L"\n";
    for (const auto& fp : m_cfg.extraFeedPaths) {
        file << L"extraFeedPath=" << fp << L"\n";
    }
    return true;
}

} // namespace Asthak
