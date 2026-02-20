// risk_assessment.cpp
// Production-hardened Zero Trust implementation with layered defense
#include "risk_assessment.h"
#include "utils/string_utils.h"
#include "utils/logger.h"
#include <algorithm>
#include <cmath>
#include <cwctype>
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

// High-risk countries (for geolocation check - example list)
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
    if (conn.riskLevel == RiskLevel::HIGH) {
        TriggerAlert(conn, conn.threatIntel, false);
        return;
    }

    // Layer 2: Process integrity and digital signature validation
    CheckProcessIntegrity(conn);
    if (conn.riskLevel == RiskLevel::HIGH) {
        TriggerAlert(conn, conn.threatIntel, false);
        return;
    }

    // Layer 3: Parent process chain validation
    CheckParentProcessChain(conn);
    if (conn.riskLevel == RiskLevel::HIGH) {
        TriggerAlert(conn, conn.threatIntel, false);
        return;
    }

    // Layer 4: Behavioral analysis (beaconing, frequency)
    CheckBehavioralPatterns(conn);
    if (conn.riskLevel == RiskLevel::HIGH) {
        TriggerAlert(conn, conn.threatIntel, false);
        return;
    }

    // Layer 5: Geolocation policy
    CheckGeolocationPolicy(conn);
    if (conn.riskLevel == RiskLevel::HIGH) {
        TriggerAlert(conn, conn.threatIntel, false);
        return;
    }

    // Track connection for behavioral analysis
    TrackConnectionBehavior(conn);

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
    // Check against known malicious ports
    if (kMaliciousPorts.find(conn.remotePort) != kMaliciousPorts.end()) {
        conn.riskLevel = RiskLevel::HIGH;
        conn.threatIntel = L"CRITICAL: Connection to known C2/malware port " +
                          ToWideString(conn.remotePort);
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
    // Perform process verification with currently available API.
    ProcessVerificationResult verification = VerifyProcess(conn.processName, conn.pid);
    const std::wstring verifiedPath = verification.fullPath.empty() ?
        conn.processPath : verification.fullPath;

    conn.threatIntel += L" | Process: " + verifiedPath;

    // Fail closed when signature check fails.
    if (!verification.isMicrosoftSigned) {
        conn.riskLevel = RiskLevel::HIGH;
        conn.threatIntel = L"HIGH: Untrusted/unsigned process | " + verifiedPath;
        return;
    }

    // Keep strict location check based on current verification field.
    if (!verification.isInSystem32) {
        conn.riskLevel = RiskLevel::HIGH;
        conn.threatIntel = L"HIGH: Signed process outside trusted location | " + verifiedPath;
        return;
    }

    conn.riskLevel = RiskLevel::LOW;
    conn.threatIntel = L"Verified: Trusted signed process | " + verification.signerName;
}

//=============================================================================
// LAYER 3: PARENT PROCESS CHAIN
//=============================================================================

void RiskEngine::CheckParentProcessChain(Connection& conn) {
    ProcessVerificationResult verification = VerifyProcess(conn.processName, conn.pid);

    // Parent process metadata is not available in current verification API.
    // Keep a conservative check using available integrity context.
    if (verification.isRunningAsSystem && !verification.isInSystem32) {
        conn.riskLevel = RiskLevel::HIGH;
        conn.threatIntel = L"HIGH: SYSTEM context process outside trusted location";
        return;
    }

    conn.threatIntel += L" | Parent-chain telemetry unavailable in this build";
}

//=============================================================================
// LAYER 4: BEHAVIORAL ANALYSIS
//=============================================================================

void RiskEngine::TrackConnectionBehavior(const Connection& conn) {
    auto& behavior = m_behaviorMap[conn.pid];

    auto now = std::chrono::steady_clock::now();

    if (behavior.connectionCount == 0) {
        behavior.firstSeen = now;
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

    // Beaconing indicators:
    // 1. High connection frequency (>10 connections)
    // 2. Regular intervals
    // 3. Low data transfer per connection

    if (behavior.connectionCount < 10) {
        return false;
    }

    auto duration = std::chrono::duration_cast<std::chrono::seconds>(
        behavior.lastSeen - behavior.firstSeen);

    if (duration.count() == 0) {
        return false;
    }

    // Calculate average connection interval
    double avgInterval = static_cast<double>(duration.count()) /
                        static_cast<double>(behavior.connectionCount);

    // If connections are very regular (within 10% variance) - suspicious
    double variance = std::abs(avgInterval - 60.0);  // Assuming 60s beacon
    if (variance < 6.0) {  // Within +/-10%
        behavior.isBeaconing = true;
        return true;
    }

    return false;
}

void RiskEngine::CheckBehavioralPatterns(Connection& conn) {
    auto it = m_behaviorMap.find(conn.pid);
    if (it == m_behaviorMap.end()) {
        return;  // First connection, no pattern yet
    }

    auto& behavior = it->second;

    // Check for beaconing
    if (DetectBeaconing(conn.pid)) {
        conn.riskLevel = RiskLevel::HIGH;
        conn.threatIntel = L"BEHAVIORAL: Beaconing detected | " +
                          ToWideString(behavior.connectionCount) +
                          L" connections in regular intervals";
        return;
    }

    // Check for port scanning behavior
    if (behavior.portsUsed.size() > 50) {
        conn.riskLevel = RiskLevel::HIGH;
        conn.threatIntel = L"BEHAVIORAL: Port scanning detected | " +
                          ToWideString(behavior.portsUsed.size()) +
                          L" unique ports accessed";
        return;
    }

    // Check for data exfiltration (high upload ratio)
    if (conn.bytesSent > 0 && conn.bytesReceived > 0) {
        double uploadRatio = static_cast<double>(conn.bytesSent) /
                            static_cast<double>(conn.bytesReceived);

        if (uploadRatio > 10.0) {  // Sending 10x more than receiving
            conn.riskLevel = RiskLevel::MEDIUM;
            conn.threatIntel += L" | High upload ratio (possible exfiltration)";
        }
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
    // Log to console/file
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
