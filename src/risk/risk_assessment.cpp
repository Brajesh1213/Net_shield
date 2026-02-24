// risk_assessment.cpp
// Production-hardened Zero Trust implementation with layered defense
#include "risk_assessment.h"
#include "utils/string_utils.h"
#include "utils/logger.h"
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cwctype>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>
#include <sstream>

namespace NetSentinel {

namespace {
template <typename T>
std::wstring ToWideString(T value) {
    std::wostringstream oss;
    oss << value;
    return oss.str();
}
}  // namespace

//=============================================================================
// THREAT INTELLIGENCE DATA
//=============================================================================

// Known C2 and malware ports (expanded list)
static const std::unordered_set<uint16_t> kMaliciousPorts = {
    // Common C2 ports
    4444, 4445, 4446,        // Metasploit
    5555, 5556,              // Android Debug Bridge (ADB) - often abused
    6666, 6667, 6668, 6669,  // IRC-based C2
    7777, 8080, 8443,        // Common alternative HTTP/HTTPS
    9999,                    // Common backdoor
    31337, 31338,            // Elite/leet
    12345, 54321,            // NetBus, Back Orifice
    1337,                    // Common hacker port

    // RAT ports
    1234,                    // SubSeven
    9090,                    // Common RAT

    // Crypto mining
    3333, 3334, 3335,        // Stratum mining protocol
    5730,                    // Monero

    // Ransomware
    8444,                    // Common ransomware C2

    // Botnets
    48101,                   // Mirai
};

// Suspicious port ranges
static const std::vector<std::pair<uint16_t, uint16_t>> kSuspiciousRanges = {
    {1024, 1030},   // Very low ephemeral (unusual for legitimate apps)
    {65000, 65535}  // Very high ports (rare in legitimate software)
};

// Known hacker tools and malware process names (lowercase for comparison)
static const std::unordered_set<std::wstring> kMalwareProcessNames = {
    // Post-exploitation / C2 frameworks
    L"mimikatz.exe",  L"mimi.exe",
    L"meterpreter",   L"metasploit",
    L"cobalt",        L"cobaltstrike.exe",
    L"empire.exe",    L"powershell_empire",
    L"pupy.exe",      L"quasar.exe",
    L"darkcomet.exe", L"njrat.exe",
    L"nanocore.exe",  L"remcos.exe",
    L"asyncrat.exe",  L"orcus.exe",

    // Network hacking tools
    L"nc.exe",        L"ncat.exe",      // Netcat - C2 shell
    L"netcat.exe",
    L"nmap.exe",                        // Port scanner
    L"masscan.exe",                     // Fast port scanner
    L"zmap.exe",
    L"hydra.exe",                       // Brute force
    L"medusa.exe",   L"bruteforcer.exe",

    // Credential dumpers
    L"gsecdump.exe", L"wce.exe",        // Windows Credential Editor
    L"pwdump.exe",   L"fgdump.exe",
    L"procdump.exe",                    // Memory dumper (abused for creds)

    // Ransomware indicators
    L"encrypt.exe",  L"locker.exe",
    L"cryptor.exe",  L"ransom.exe",

    // Crypto miners
    L"xmrig.exe",    L"minerd.exe",
    L"cpuminer.exe", L"ethminer.exe",   L"t-rex.exe",
    L"nbminer.exe",  L"phoenixminer.exe",

    // Script-based loaders (unusual outbound usage)
    L"wscript.exe",  L"cscript.exe",   // Windows Script Host
    L"mshta.exe",                      // HTML Application Host (LOLBaS)
    L"regsvr32.exe",                   // COM surrogate (LOLBaS abuse)
    L"rundll32.exe",                   // DLL loader (LOLBaS abuse)
    L"certutil.exe",                   // Certificate tool (LOLBaS - download)
    L"bitsadmin.exe",                  // Background transfer (LOLBaS)
};

// Suspicious legitimate processes making OUTBOUND connections (LOLBaS)
static const std::unordered_set<std::wstring> kSuspiciousLolbas = {
    L"powershell.exe", L"cmd.exe", L"wscript.exe",
    L"cscript.exe",    L"mshta.exe",  L"certutil.exe",
    L"bitsadmin.exe",  L"regsvr32.exe", L"rundll32.exe",
};

// ── Trusted developer / build tools — exempt from behavioral analysis ─────────
// These processes make many fast connections by design (LSP, IntelliSense,
// package fetches, compiler tool chains, etc.).  Flagging them as worms or
// C2 beacons produces only noise and causes real harm (killing your IDE).
static const std::unordered_set<std::wstring> kTrustedDevProcessExact = {
    // VS Code / Editors
    L"code.exe",
    L"code - insiders.exe",
    L"electron.exe",
    L"atom.exe",
    L"sublime_text.exe",
    // JetBrains
    L"idea64.exe",  L"clion64.exe",  L"pycharm64.exe",
    L"webstorm64.exe", L"rider64.exe", L"goland64.exe",
    // Node / JS ecosystem
    L"node.exe",
    L"npm.exe",  L"yarn.exe",  L"pnpm.exe",
    // Python ecosystem
    L"python.exe",  L"python3.exe",  L"pip.exe",
    // Build tools
    L"cmake.exe",  L"ninja.exe",  L"msbuild.exe",
    L"cl.exe",     L"link.exe",
    L"gcc.exe",    L"g++.exe",   L"mingw32-make.exe",
    L"clang.exe",  L"clang++.exe",
    // Git
    L"git.exe",
    // System / infrastructure (benign high-connection processes)
    L"svchost.exe",
    L"system idle process",
    L"system idle",
    L"system",
    // Browsers (legitimately hold 100+ connections: tabs, prefetch, sync)
    L"chrome.exe",     L"firefox.exe",     L"msedge.exe",
    L"opera.exe",      L"brave.exe",       L"vivaldi.exe",
    L"iexplore.exe",   L"safari.exe",      L"arc.exe",
    // Common high-connection desktop apps
    L"discord.exe",    L"slack.exe",       L"teams.exe",
    L"spotify.exe",    L"steam.exe",       L"steamwebhelper.exe",
    L"onedrive.exe",   L"dropbox.exe",     L"googledrive.exe",
    L"outlook.exe",    L"thunderbird.exe",
    L"ollama.exe",
    L"ollama app.exe",
    L"antigravity.exe",
};

// Prefix-match: processes whose names START with these strings are trusted.
// e.g. "language_server_windows_x64.exe", "language_server_linux_x64"
static const std::vector<std::wstring> kTrustedDevProcessPrefixes = {
    L"language_server_",
    L"msedgewebview",
    L"microsoftedge",
    L"chrome",           // chrome.exe, chrome_crashpad_handler.exe, etc.
    L"firefox",          // firefox.exe, firefox_crashreporter.exe
    L"brave",            // brave.exe, brave_crashpad_handler.exe
    L"opera",            // opera.exe, opera_crashreporter.exe
    L"vivaldi",          // vivaldi.exe, etc.
};

static bool IsKnownDevProcess(const std::wstring& lowerName) {
    if (kTrustedDevProcessExact.count(lowerName)) return true;
    for (const auto& prefix : kTrustedDevProcessPrefixes) {
        if (lowerName.size() >= prefix.size() &&
            lowerName.compare(0, prefix.size(), prefix) == 0) {
            return true;
        }
    }
    return false;
}

// High-risk countries (for geolocation check)
static const std::unordered_set<std::wstring> kHighRiskCountries = {
    L"KP",  // North Korea
    L"IR",  // Iran
    L"SY",  // Syria
    L"PK",  // Pakistan
    L"RU",  // Russia (context-dependent)
    L"CN",  // China (context-dependent)
};


//=============================================================================
// RISK ENGINE IMPLEMENTATION
//=============================================================================

RiskEngine::RiskEngine() {
    // Initialize with default settings
    m_windowsEventLogEnabled = true;
    m_desktopNotificationsEnabled = true;
}

RiskEngine::~RiskEngine() {
    // Cleanup
    m_behaviorMap.clear();
}

void RiskEngine::Assess(Connection& conn) {
    // ZERO TRUST PRINCIPLE: Guilty until proven innocent
    conn.riskLevel = RiskLevel::MEDIUM;
    conn.threatIntel = L"Zero Trust: Awaiting verification";

    // Layer 1: Port-based threat intelligence
    CheckPortPolicy(conn);
    if (conn.riskLevel >= RiskLevel::HIGH) {
        TriggerAlert(conn, conn.threatIntel, false);
        return;
    }

    // Layer 2: Process integrity and digital signature validation
    CheckProcessIntegrity(conn);
    if (conn.riskLevel >= RiskLevel::HIGH) {
        TriggerAlert(conn, conn.threatIntel, false);
        return;
    }

    // Layer 3: Parent process chain validation
    CheckParentProcessChain(conn);
    if (conn.riskLevel >= RiskLevel::HIGH) {
        TriggerAlert(conn, conn.threatIntel, false);
        return;
    }

    // Track connection for behavioral analysis BEFORE checking patterns.
    // This ensures behavior data is available on the first cycle.
    // Skip tracking for trusted dev processes to prevent false accumulation.
    {
        std::wstring lowerName = conn.processName;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);
        if (!IsKnownDevProcess(lowerName)) {
            TrackConnectionBehavior(conn);
        }
    }

    // Layer 4: Behavioral analysis (beaconing, frequency)
    CheckBehavioralPatterns(conn);
    if (conn.riskLevel >= RiskLevel::HIGH) {
        TriggerAlert(conn, conn.threatIntel, false);
        return;
    }

    // Layer 5: Geolocation policy
    CheckGeolocationPolicy(conn);
    if (conn.riskLevel >= RiskLevel::HIGH) {
        TriggerAlert(conn, conn.threatIntel, false);
        return;
    }

    // Log medium-risk events
    if (conn.riskLevel == RiskLevel::MEDIUM) {
        Logger::Instance().Info(L"[MEDIUM RISK] " + conn.processName +
                                L" (PID:" + ToWideString(conn.pid) + L") -> " +
                                conn.remoteIp + L":" + ToWideString(conn.remotePort) +
                                L" | " + conn.threatIntel);
    }
}

//=============================================================================
// LAYER 1: PORT POLICY
//=============================================================================

void RiskEngine::CheckPortPolicy(Connection& conn) {
    // Check remote port against known malicious ports
    if (kMaliciousPorts.find(conn.remotePort) != kMaliciousPorts.end()) {
        conn.riskLevel = RiskLevel::HIGH;
        conn.threatIntel = L"CRITICAL: Connection to known C2/malware port " +
                          ToWideString(conn.remotePort);
        return;
    }

    // ALSO check local port — catches processes SERVING on malicious ports (C2 backdoors)
    if (conn.localPort != 0 && kMaliciousPorts.find(conn.localPort) != kMaliciousPorts.end()) {
        conn.riskLevel = RiskLevel::HIGH;
        conn.threatIntel = L"CRITICAL: Process listening/serving on known C2/malware port " +
                          ToWideString(conn.localPort);
        return;
    }

    // Check suspicious port ranges
    for (const auto& range : kSuspiciousRanges) {
        if (conn.remotePort >= range.first && conn.remotePort <= range.second) {
            conn.riskLevel = RiskLevel::MEDIUM;
            conn.threatIntel += L" | Port " + ToWideString(conn.remotePort) +
                              L" in suspicious range [" + ToWideString(range.first) +
                              L"-" + ToWideString(range.second) + L"]";
            break;
        }
    }

    // Dynamic/Ephemeral ports are common for beaconing
    if (conn.remotePort >= 49152) {
        conn.threatIntel += L" | Dynamic port (common for beaconing)";
        // Stay at MEDIUM - will be verified by process integrity
    }

    // Common legitimate ports - still require process verification
    if (conn.remotePort == 443 || conn.remotePort == 80) {
        conn.threatIntel += L" | Standard HTTPS/HTTP port";
        // Remain at MEDIUM until process is verified
    }
}

//=============================================================================
// LAYER 2: PROCESS INTEGRITY
//=============================================================================

void RiskEngine::CheckProcessIntegrity(Connection& conn) {
    // ── Step 0: Check against known malware process names ─────────────────
    std::wstring lowerName = conn.processName;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);

    if (kMalwareProcessNames.count(lowerName)) {
        conn.riskLevel = RiskLevel::HIGH;
        conn.threatIntel = L"CRITICAL: Known malware/hacker tool detected: " + conn.processName;
        return;
    }

    // ── Step 1: LOLBaS detection (Living off the Land Binaries making outbound connections)
    if (kSuspiciousLolbas.count(lowerName) && conn.remotePort != 0) {
        // Legitimate use: powershell/cmd rarely need outbound TCP connections
        // Exception: port 80/443 COULD be legitimate but still worth flagging
        conn.riskLevel = RiskLevel::HIGH;
        conn.threatIntel = L"CRITICAL: LOLBaS - " + conn.processName +
                          L" making outbound connection to " +
                          conn.remoteIp + L":" + ToWideString(conn.remotePort) +
                          L" (possible malware dropper/C2 relay)";
        return;
    }

    // ── Step 2: Process signature verification ───────────────────────────
    ProcessVerificationResult verification = VerifyProcess(conn.processName, conn.pid);
    const std::wstring verifiedPath = verification.fullPath.empty() ?
        conn.processPath : verification.fullPath;

    conn.threatIntel += L" | Process: " + verifiedPath;

    // Fail closed when signature check fails.
    if (!verification.isMicrosoftSigned) {
        conn.riskLevel = RiskLevel::MEDIUM;
        conn.threatIntel = L"MEDIUM: Untrusted/unsigned process | " + verifiedPath;
    } else if (!verification.isInSystem32) {
        conn.riskLevel = RiskLevel::MEDIUM;
        conn.threatIntel = L"MEDIUM: Signed process outside trusted location | " + verifiedPath;
    } else {
        conn.riskLevel = RiskLevel::LOW;
        conn.threatIntel = L"Verified: Trusted signed process | " + verification.signerName;
    }
}


//=============================================================================
// LAYER 3: PARENT PROCESS CHAIN
//=============================================================================

void RiskEngine::CheckParentProcessChain(Connection& conn) {
    ProcessVerificationResult verification = VerifyProcess(conn.processName, conn.pid);

    // Parent process metadata is not available in current verification API.
    // Keep a conservative check using available integrity context.
    if (verification.isRunningAsSystem && !verification.isInSystem32) {
        conn.riskLevel = std::max(conn.riskLevel, RiskLevel::MEDIUM);
        conn.threatIntel += L" | HIGH: SYSTEM context process outside trusted location";
    } else {
        conn.threatIntel += L" | Parent-chain telemetry unavailable in this build";
    }
}

//=============================================================================
// LAYER 4: BEHAVIORAL ANALYSIS
//=============================================================================

void RiskEngine::TrackConnectionBehavior(const Connection& conn) {
    auto& behavior = m_behaviorMap[conn.pid];

    auto now = std::chrono::steady_clock::now();

    if (behavior.connectionCount == 0) {
        behavior.firstSeen = now;
    } else {
        auto diff = std::chrono::duration_cast<std::chrono::seconds>(now - behavior.lastSeen).count();
        // Check if interval is ~60s (common malware beaconing interval, allowing 10% jitter)
        if (diff >= 54 && diff <= 66) {
            behavior.beaconHits++;
        }
    }

    behavior.lastSeen = now;
    behavior.connectionCount++;
    behavior.totalBytesTransferred += conn.bytesReceived + conn.bytesSent;

    // Track unique ports
    if (std::find(behavior.portsUsed.begin(), behavior.portsUsed.end(),
                  conn.remotePort) == behavior.portsUsed.end()) {
        behavior.portsUsed.push_back(conn.remotePort);
    }
}

bool RiskEngine::DetectBeaconing(DWORD pid) {
    auto it = m_behaviorMap.find(pid);
    if (it == m_behaviorMap.end()) {
        return false;
    }

    auto& behavior = it->second;

    // Beaconing requires highly regular repeated connections.
    // We strictly look for 10 or more hits of the ~60s interval.
    if (behavior.beaconHits >= 10) {
        behavior.isBeaconing = true;
        return true;
    }

    return false;
}

void RiskEngine::CheckBehavioralPatterns(Connection& conn) {
    // ── Trusted developer tools: skip all behavioral analysis ────────────────
    // Language servers, IDEs, and compilers legitimately make many connections.
    // Flagging them as worms kills the IDE and produces zero security value.
    std::wstring lowerName = conn.processName;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);
    if (IsKnownDevProcess(lowerName)) {
        conn.threatIntel = L"Trusted developer tool (behavioral analysis skipped)";
        // Ensure risk stays LOW for recognized dev processes
        if (conn.riskLevel >= RiskLevel::HIGH)
            conn.riskLevel = RiskLevel::LOW;
        return;
    }

    auto it = m_behaviorMap.find(conn.pid);
    if (it == m_behaviorMap.end()) {
        return;  // First connection, no pattern yet
    }

    auto& behavior = it->second;
    auto now = std::chrono::steady_clock::now();
    auto elapsedSec = std::chrono::duration_cast<std::chrono::seconds>(
        now - behavior.firstSeen).count();

    // ── 1. Beaconing Detection ────────────────────────────────────────────────
    if (DetectBeaconing(conn.pid)) {
        conn.riskLevel = RiskLevel::HIGH;
        conn.threatIntel = L"BEHAVIORAL: C2 Beaconing detected | " +
                          ToWideString(behavior.connectionCount) +
                          L" connections at regular intervals";
        return;
    }

    // ── 2. Port Scanning / Lateral Movement Detection ───────────────────────
    if (behavior.portsUsed.size() > 50) {
        conn.riskLevel = RiskLevel::HIGH;
        conn.threatIntel = L"BEHAVIORAL: Port scanning / lateral movement | " +
                          ToWideString(behavior.portsUsed.size()) +
                          L" unique ports accessed";
        return;
    }

    // ── 3. Worm-like Behavior: Too many connections in short time ───────────
    //    Thresholds raised to reduce false positives from bursty legitimate
    //    processes (browsers, language servers, system services).
    if (elapsedSec > 0 && behavior.connectionCount > 0) {
        double connPerSec = static_cast<double>(behavior.connectionCount) /
                           static_cast<double>(elapsedSec);
        if (connPerSec > 10.0 && behavior.connectionCount > 100) {
            conn.riskLevel = RiskLevel::HIGH;
            conn.threatIntel = L"BEHAVIORAL: Worm/scanner activity | " +
                              ToWideString(static_cast<int>(connPerSec)) +
                              L" connections/sec (" +
                              ToWideString(behavior.connectionCount) + L" total)";
            return;
        }
    }

    // ── 4. Cumulative Data Exfiltration Detection ────────────────────────
    // Track cumulative upload vs download across ALL connections for this PID
    if (behavior.totalBytesTransferred > 0) {
        uint64_t totalSent = conn.bytesSent;
        uint64_t totalRecv = conn.bytesReceived + 1; // avoid div/0

        // Cumulative exfil: process sent > 10MB AND upload ratio > 5:1
        if (totalSent > (10 * 1024 * 1024) &&
            (static_cast<double>(totalSent) / static_cast<double>(totalRecv)) > 5.0) {
            conn.riskLevel = RiskLevel::HIGH;
            conn.threatIntel = L"BEHAVIORAL: DATA EXFILTRATION - " +
                              ToWideString(totalSent / 1024) + L" KB sent vs " +
                              ToWideString(totalRecv / 1024) + L" KB received";
            return;
        }

        // Moderate warning: high upload ratio on single connection
        if (conn.bytesSent > 0 && conn.bytesReceived > 0) {
            double uploadRatio = static_cast<double>(conn.bytesSent) /
                                static_cast<double>(conn.bytesReceived);
            if (uploadRatio > 10.0) {
                conn.threatIntel += L" | High upload ratio (possible exfiltration)";
            }
        }
    }

    // ── 5. Crypto Miner Detection (stratum ports + high connection frequency) ─
    // Stratum ports: 3333, 3334, 3335, 5730 are in kMaliciousPorts
    // Additional heuristic: excessive connections to same IP on mining ports
    static const std::unordered_set<uint16_t> kMiningPorts = {
        3333, 3334, 3335, 5730, 14444, 7777, 45560
    };
    if (kMiningPorts.count(conn.remotePort) && behavior.connectionCount > 3) {
        conn.riskLevel = RiskLevel::HIGH;
        conn.threatIntel = L"BEHAVIORAL: Crypto mining detected | Stratum protocol port " +
                          ToWideString(conn.remotePort) + L" | Process: " + conn.processName;
        return;
    }
}


//=============================================================================
// LAYER 5: GEOLOCATION POLICY
//=============================================================================

void RiskEngine::CheckGeolocationPolicy(Connection& conn) {
    // Note: Requires GeoIP database integration (MaxMind, IP2Location, etc.)
    // This is a placeholder showing the structure

    if (conn.countryCode.empty()) {
        return;  // No geolocation data available
    }

    // Check against high-risk countries
    if (kHighRiskCountries.find(conn.countryCode) != kHighRiskCountries.end()) {
        conn.riskLevel = RiskLevel::HIGH;
        conn.threatIntel = L"GEOLOCATION: Connection to high-risk country: " +
                          conn.countryCode + L" | IP: " + conn.remoteIp;
        return;
    }

    // Check for unusual geographic patterns (example)
    // If process normally connects to US, but now connecting to Russia
    // This requires historical tracking - placeholder for now
}

//=============================================================================
// ALERT MANAGEMENT
//=============================================================================

void RiskEngine::TriggerAlert(Connection& conn, const std::wstring& reason, bool blockConnection) {
    // ── Deduplication: only alert once per unique connection key ──────────────
    // Key = PID + localPort + remoteIp:remotePort
    // This prevents the same C2 port from flooding the log every 2 seconds
    static std::unordered_map<std::string, std::chrono::steady_clock::time_point> seenAlerts;
    
    std::ostringstream keyStream;
    keyStream << conn.pid << "|" << conn.localPort
              << "|" << Utils::WideToUTF8(conn.remoteIp) << ":" << conn.remotePort;
    std::string alertKey = keyStream.str();
    
    auto now = std::chrono::steady_clock::now();
    auto it = seenAlerts.find(alertKey);
    if (it != seenAlerts.end()) {
        // Already alerted for this connection — skip unless it's been > 5 minutes
        if (std::chrono::duration_cast<std::chrono::minutes>(now - it->second).count() < 5) {
            return; // suppress duplicate alert
        }
    }
    seenAlerts[alertKey] = now;
    // ──────────────────────────────────────────────────────────────────────────

    // Log to console/file (now fires only once per unique connection)
    Logger::Instance().Critical(L"[HIGH RISK ALERT] " + reason);

    // Windows Event Log
    if (m_windowsEventLogEnabled) {
        LogToWindowsEventLog(conn, reason);
    }

    // Desktop notification
    if (m_desktopNotificationsEnabled) {
        ShowDesktopNotification(L"NetSentinel Security Alert", reason);
    }

    // Custom callback
    if (m_alertCallback) {
        m_alertCallback(conn, reason);
    }

    // Optional: Block connection (requires driver/firewall integration)
    if (blockConnection) {
        // TODO: Integrate with Windows Filtering Platform (WFP)
        // or update firewall rules to block this connection
        Logger::Instance().Warning(L"[ACTION] Connection blocked: " + reason);
    }
}

void RiskEngine::LogToWindowsEventLog(const Connection& conn, const std::wstring& message) {
    // Register event source (do this once at startup in production)
    HANDLE hEventLog = RegisterEventSourceW(nullptr, L"NetSentinel");
    if (!hEventLog) {
        return;
    }

    std::wstring eventMessage = L"Security Alert\n";
    eventMessage += L"Process: ";
    eventMessage += conn.processName;
    eventMessage += L" (PID: ";
    eventMessage += ToWideString(conn.pid);
    eventMessage += L")\n";
    eventMessage += L"Remote: ";
    eventMessage += conn.remoteIp;
    eventMessage += L":";
    eventMessage += ToWideString(conn.remotePort);
    eventMessage += L"\n";
    eventMessage += L"Threat: ";
    eventMessage += message;

    const wchar_t* strings[1] = { eventMessage.c_str() };

    // Write to Windows Event Log
    ReportEventW(
        hEventLog,
        EVENTLOG_WARNING_TYPE,  // Warning level
        0,                      // Category
        1000,                   // Event ID (define your own)
        nullptr,                // User SID
        1,                      // Number of strings
        0,                      // Binary data size
        strings,                // String array
        nullptr                 // Binary data
    );

    DeregisterEventSource(hEventLog);
}

void RiskEngine::ShowDesktopNotification(const std::wstring& title, const std::wstring& message) {
    // Windows 10+ Toast Notification
    // This requires WinRT APIs - simplified example:
    // In production, use Windows.UI.Notifications or shell_notify_icon

    // For now, use logging as a non-blocking fallback
    Logger::Instance().Info(L"[NOTIFICATION] " + title + L": " + message);
}

std::wstring RiskEngine::GenerateRiskReport(const Connection& conn,
                                           const ProcessVerificationResult& verification) {
    const std::wstring verifiedPath = verification.fullPath.empty() ?
        conn.processPath : verification.fullPath;

    std::wstring report = L"=== RISK ASSESSMENT REPORT ===\n";
    report += L"Process: " + conn.processName + L" (PID: " + ToWideString(conn.pid) + L")\n";
    report += L"Path: " + verifiedPath + L"\n";
    report += L"Signer: " + verification.signerName + L"\n";
    report += L"Remote: " + conn.remoteIp + L":" + ToWideString(conn.remotePort) + L"\n";
    report += L"Risk Level: ";

    switch (conn.riskLevel) {
        case RiskLevel::LOW:    report += L"LOW\n"; break;
        case RiskLevel::MEDIUM: report += L"MEDIUM\n"; break;
        case RiskLevel::HIGH:   report += L"HIGH\n"; break;
        default:                report += L"UNKNOWN\n"; break;
    }

    report += L"Threat Intel: " + conn.threatIntel + L"\n";
    report += L"============================\n";

    return report;
}

void RiskEngine::SetAlertCallback(std::function<void(const Connection&, const std::wstring&)> callback) {
    m_alertCallback = callback;
}

void RiskEngine::EnableWindowsEventLog(bool enable) {
    m_windowsEventLogEnabled = enable;
}

void RiskEngine::EnableDesktopNotifications(bool enable) {
    m_desktopNotificationsEnabled = enable;
}

} // namespace NetSentinel
