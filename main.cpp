// SPDX-License-Identifier: MIT
// Copyright 2026 Brajesh
// NetSentinel v0.3 - Production Backend

#include <windows.h>
#include <shlobj.h>
#include <iostream>
#include <iomanip>
#include <atomic>
#include <csignal>
#include <chrono>
#include <unordered_set>
#include <ctime>
#include <clocale>
#include <locale>

#include "include/netsentinel_common.h"
#include "src/network/tcp_table.h"
#include "src/network/udp_table.h"
#include "src/network/packet_capture.h"
#include "src/risk/risk_assessment.h"
#include "src/risk/threat_intel.h"
#include "src/safety/kill_switch.h"
#include "src/safety/firewall_blocker.h"
#include "src/utils/logger.h"
#include "src/core/process_cache.h"

using namespace NetSentinel;
using namespace std::chrono;

namespace {
bool SafeLocalTime(std::tm& out, const std::time_t& in) {
    std::tm* tmp = std::localtime(&in);
    if (!tmp) {
        return false;
    }
    out = *tmp;
    return true;
}
} // namespace

// Configuration
constexpr DWORD kPollingIntervalMs = 2000;
constexpr size_t kMaxConnectionsPerPoll = 1000;

// Global state
std::atomic<bool> g_running{true};
std::atomic<bool> g_paused{false};

// Console handler
BOOL WINAPI ConsoleHandler(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_CLOSE_EVENT || 
        signal == CTRL_BREAK_EVENT) {
        std::wcout << L"\n🛑 Shutdown signal received...\n";
        g_running = false;
        return TRUE;
    }
    return FALSE;
}

// Format risk level with emoji
std::wstring FormatRisk(RiskLevel level) {
    switch (level) {
        case RiskLevel::CRITICAL: return L"🔴 CRITICAL";
        case RiskLevel::HIGH:     return L"🟠 HIGH    ";
        case RiskLevel::MEDIUM:   return L"🟡 MEDIUM  ";
        case RiskLevel::LOW:      return L"🟢 LOW     ";
        default:                  return L"⚪ UNKNOWN ";
    }
}

// Initialize secure logging
bool InitializeLogger() {
    WCHAR path[MAX_PATH];
    if (SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, path) != S_OK) {
        return false;
    }
    
    std::wstring logDir = std::wstring(path) + L"\\NetSentinel\\Logs";
    return Logger::Instance().Initialize(logDir);
}

// Print banner
void PrintBanner() {
    std::wcout << L"\n";
    std::wcout << L"NetSentinel v" << VERSION_MAJOR << L"." << VERSION_MINOR << L"." << VERSION_PATCH << L"\n";
    std::wcout << L"Network Security Monitor & Protection\n";
    
    // Check if running as admin earlier for the banner? No, we can just print generic info here.
    // But let's be optimistic.
    std::wcout << L"Status: ACTIVE (Protection available if running as Admin)\n";
    std::wcout << L"\n";
}

// Print table header
void PrintHeader() {
    std::wcout << L"TIME     | PROCESS          | PID    | REMOTE ADDRESS        | PORT  | RISK      | INFO\n";
    std::wcout << L"─────────┼──────────────────┼────────┼───────────────────────┼───────┼───────────┼──────────────────\n";
}

// Print connection row
void PrintConnection(const Connection& conn) {
    auto now = system_clock::now();
    auto time = system_clock::to_time_t(now);
    std::tm localTime{};
    if (!SafeLocalTime(localTime, time)) {
        return;
    }
    
    std::wcout << std::put_time(&localTime, L"%H:%M:%S") << L" | ";
    std::wcout << std::left << std::setw(16) << conn.processName.substr(0, 16) << L" | ";
    std::wcout << std::right << std::setw(6) << conn.pid << L" | ";
    std::wcout << std::left << std::setw(21) << conn.remoteIp << L" | ";
    std::wcout << std::right << std::setw(5) << conn.remotePort << L" | ";
    std::wcout << FormatRisk(conn.riskLevel) << L" | ";
    
    if (!conn.threatIntel.empty()) {
        std::wcout << conn.threatIntel.substr(0, 20);
    }
    std::wcout << L"\n";
}

int main() {
    
    // Configure locale so wide console output renders correctly on Windows.
    std::setlocale(LC_ALL, ".UTF-8");
    try {
        std::locale::global(std::locale(""));
        std::wcout.imbue(std::locale());
        std::wcerr.imbue(std::locale());
    } catch (...) {
        // Keep running even if locale setup fails.
    }

    // Set console mode
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);
    
    // Kill switch check
    if (KillSwitch::IsDisabled()) {
        std::wcout << L"🛑 NetSentinel is DISABLED via kill switch\n";
        std::wcout << L"   Run: reg delete HKCU\\Software\\CyberGuardian\\NetSentinel /v DisableMonitoring\n";
        return 0;
    }
    
    // Initialize logging
    if (!InitializeLogger()) {
        std::wcerr << L"⚠️  Warning: Failed to initialize logger (continuing)\n";
    }
    
    Logger::Instance().Info(L"NetSentinel starting...");
    
    // Print banner
    PrintBanner();
    
    // Check for admin rights (recommended but not required for monitoring)
    BOOL isAdmin = FALSE;
    PSID administratorsGroup = nullptr;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                                  &administratorsGroup)) {
        CheckTokenMembership(nullptr, administratorsGroup, &isAdmin);
        FreeSid(administratorsGroup);
    }
    
    if (!isAdmin) {
        std::wcout << L"⚠️  Warning: Running without administrator rights\n";
        std::wcout << L"    Some processes may show as 'unknown'\n\n";
        Logger::Instance().Warning(L"Running without admin rights");
    }
    
    // Initialize components
    TcpTable tcpTable;
    UdpTable udpTable;
    RiskEngine riskEngine;
    ThreatIntel& threatIntel = ThreatIntel::Instance();
    FirewallBlocker& firewallBlocker = FirewallBlocker::Instance();
    PacketCapture& packetCapture = PacketCapture::Instance();
    
    tcpTable.SetEstablishedOnly(false);
    // Test mode: allow loopback so offline/local tests can prove detection.
    const wchar_t* testMode = _wgetenv(L"NETSENTINEL_TEST_MODE");
    const bool isTestMode = (testMode && *testMode);

    tcpTable.SetIncludeLoopback(isTestMode);
    udpTable.SetIncludeLoopback(isTestMode);
    
    // Initialize threat intelligence
    threatIntel.LoadFeeds();
    
    // Initialize firewall blocker (requires admin)
    // Initialize firewall blocker (requires admin)
    if (isAdmin) {
        if (!firewallBlocker.Initialize()) {
            std::wcout << L"⚠️  Warning: Failed to initialize firewall blocker\n";
            Logger::Instance().Warning(L"Firewall blocker initialization failed");
        } else {
            std::wcout << L"✅ Firewall blocker initialized (ACTIVE PROTECTION ENABLED)\n";
        }
    } else {
        std::wcout << L"⚠️  Warning: Firewall blocking requires administrator rights\n";
        std::wcout << L"    NetSentinel will operate in MONITOR ONLY mode\n";
    }
    
    // Initialize packet capture (optional, requires WinPcap/Npcap)
    if (packetCapture.Initialize()) {
        packetCapture.StartCapture();
        std::wcout << L"✅ Packet capture initialized\n";
    }
    
    PrintHeader();
    
    // Stats
    uint64_t totalConnections = 0;
    uint64_t criticalRiskCount = 0;
    uint64_t highRiskCount = 0;
    uint64_t mediumRiskCount = 0;
    auto startTime = steady_clock::now();
    
    // Main loop
    while (g_running) {
        // Check kill switch dynamically
        if (KillSwitch::IsDisabled()) {
            std::wcout << L"\n🛑 Kill switch activated - stopping\n";
            Logger::Instance().Info(L"Kill switch activated");
            break;
        }
        
        if (g_paused) {
            Sleep(100);
            continue;
        }
        
        auto pollStart = steady_clock::now();
        
        try {
            // Get TCP connections (IPv4 + IPv6)
            auto tcpConnections = tcpTable.GetAllConnections();
            
            // Get UDP connections (IPv4 + IPv6)
            auto udpConnections = udpTable.GetAllConnections();
            
            // Combine TCP and UDP
            std::vector<Connection> allConnections;
            allConnections.reserve(tcpConnections.size() + udpConnections.size());
            allConnections.insert(allConnections.end(), 
                                 std::make_move_iterator(tcpConnections.begin()),
                                 std::make_move_iterator(tcpConnections.end()));
            allConnections.insert(allConnections.end(),
                                 std::make_move_iterator(udpConnections.begin()),
                                 std::make_move_iterator(udpConnections.end()));
            
            // Deduplicate using connection key
            std::unordered_set<std::wstring> seen;
            std::vector<Connection> uniqueConnections;
            uniqueConnections.reserve(allConnections.size());
            
            for (auto& conn : allConnections) {
                if (seen.insert(conn.GetKey()).second) { // New connection
                    uniqueConnections.push_back(std::move(conn));
                }
            }
            
            // Assess risk and display
            for (auto& conn : uniqueConnections) {
                // Check threat intelligence first
                if (!conn.remoteIp.empty() && conn.remoteIp != L"*") {
                    std::wstring threatInfo = threatIntel.CheckIP(conn.remoteIp);
                    if (!threatInfo.empty()) {
                        conn.threatIntel += L" | " + threatInfo;
                        if (conn.riskLevel < RiskLevel::HIGH) {
                            conn.riskLevel = RiskLevel::HIGH;
                        }
                    }
                }
                
                // Assess risk
                riskEngine.Assess(conn);
                
                // Payload inspection (if packet capture available)
                // Note: This requires actual packet capture implementation
                // For now, this is a placeholder showing the structure
                
                // Only display MEDIUM and above in normal mode (reduce noise)
                if (conn.riskLevel >= RiskLevel::MEDIUM) {
                    PrintConnection(conn);
                }
                
                // Block HIGH/CRITICAL connections
                if (conn.riskLevel >= RiskLevel::HIGH && isAdmin) {
                    std::wostringstream alert;
                    alert << L"HIGH RISK: " << conn.processName << L" (PID " << conn.pid 
                          << L") connecting to " << conn.remoteIp << L":" << conn.remotePort;
                    if (!conn.threatIntel.empty()) {
                        alert << L" - " << conn.threatIntel;
                    }
                    Logger::Instance().Warning(alert.str());
                    
                    // Attempt to block connection
                    if (firewallBlocker.BlockConnection(conn, conn.threatIntel)) {
                        std::wcout << L"🛑 BLOCKED: " << conn.processName 
                                  << L" -> " << conn.remoteIp << L":" << conn.remotePort << L"\n";
                        Logger::Instance().Critical(L"Connection BLOCKED: " + alert.str());
                    }
                } else if (conn.riskLevel >= RiskLevel::HIGH) {
                    // Log but don't block (no admin rights)
                    std::wostringstream alert;
                    alert << L"HIGH RISK: " << conn.processName << L" (PID " << conn.pid 
                          << L") connecting to " << conn.remoteIp << L":" << conn.remotePort;
                    if (!conn.threatIntel.empty()) {
                        alert << L" - " << conn.threatIntel;
                    }
                    Logger::Instance().Warning(alert.str());
                }

                if (conn.riskLevel == RiskLevel::CRITICAL) criticalRiskCount++;
                if (conn.riskLevel == RiskLevel::HIGH) highRiskCount++;
                if (conn.riskLevel == RiskLevel::MEDIUM) mediumRiskCount++;
                
                totalConnections++;
            }
            
            // Periodic stats every 30 seconds
            static auto lastStats = steady_clock::now();
            if (duration_cast<seconds>(steady_clock::now() - lastStats).count() >= 30) {
                std::wostringstream stats;
                stats << L"Stats: " << totalConnections << L" connections scanned, "
                      << criticalRiskCount << L" critical, "
                      << highRiskCount << L" high risk, "
                      << mediumRiskCount << L" medium risk";
                Logger::Instance().Info(stats.str());
                lastStats = steady_clock::now();
            }
            
        } catch (const std::exception& e) {
            std::string narrowWhat(e.what());
            std::wstring wideWhat(narrowWhat.begin(), narrowWhat.end());
            Logger::Instance().Error(L"Exception in main loop: " + wideWhat);
        }
        
        // Precise sleep to maintain interval
        auto elapsed = duration_cast<milliseconds>(steady_clock::now() - pollStart);
        auto sleepTime = milliseconds(kPollingIntervalMs) - elapsed;
        
        if (sleepTime > milliseconds(0)) {
            Sleep(static_cast<DWORD>(sleepTime.count()));
        }
    }
    
    // Cleanup
    auto runtime = duration_cast<seconds>(steady_clock::now() - startTime);
    std::wostringstream shutdownMsg;
    shutdownMsg << L"NetSentinel shutting down. Runtime: " << runtime.count() << L"s, "
                << L"Total connections: " << totalConnections;
    Logger::Instance().Info(shutdownMsg.str());
    
    // Cleanup
    packetCapture.Shutdown();
    firewallBlocker.Shutdown();
    Logger::Instance().Shutdown();
    ProcessCache::Instance().Clear();
    
    std::wcout << L"\n✅ Monitoring stopped cleanly\n";
    return 0;
}
