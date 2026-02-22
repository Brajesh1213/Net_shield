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
#include <sstream>

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
// Helper: convert wstring to UTF-8 string for piped stdout
std::string WStr(const std::wstring& w) {
    if (w.empty()) return {};
    int sz = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(sz, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), &s[0], sz, nullptr, nullptr);
    return s;
}

BOOL WINAPI ConsoleHandler(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_CLOSE_EVENT || 
        signal == CTRL_BREAK_EVENT) {
        std::cout << "\nShutdown signal received...\n" << std::flush;
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
    std::cout << "\n";
    std::cout << "NetSentinel v" << VERSION_MAJOR << "." << VERSION_MINOR << "." << VERSION_PATCH << "\n";
    std::cout << "Network Security Monitor & Protection\n";
    std::cout << "Status: ACTIVE (Protection available if running as Admin)\n";
    std::cout << "\n" << std::flush;
}

// Print table header
void PrintHeader() {
    std::cout << "TIME     | PROCESS          | PID    | REMOTE ADDRESS        | PORT  | RISK      | INFO\n";
    std::cout << "---------+------------------+--------+-----------------------+-------+-----------+------------------\n" << std::flush;
}

// Print connection row
void PrintConnection(const Connection& conn) {
    auto now = system_clock::now();
    auto time = system_clock::to_time_t(now);
    std::tm localTime{};
    if (!SafeLocalTime(localTime, time)) {
        return;
    }
    
    std::cout << std::put_time(&localTime, "%H:%M:%S") << " | ";
    std::cout << std::left << std::setw(16) << WStr(conn.processName).substr(0, 16) << " | ";
    std::cout << std::right << std::setw(6) << conn.pid << " | ";
    std::cout << std::left << std::setw(21) << WStr(conn.remoteIp) << " | ";
    std::cout << std::right << std::setw(5) << conn.remotePort << " | ";
    std::cout << WStr(FormatRisk(conn.riskLevel)) << " | ";
    
    if (!conn.threatIntel.empty()) {
        std::cout << WStr(conn.threatIntel);
    }
    std::cout << "\n" << std::flush;
}

int main() {
    // Force UTF-8 byte stream on stdout/stderr so Node.js pipe can read it
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);
    // Disable sync with C stdio for faster pipe flushing
    std::ios::sync_with_stdio(false);
    std::cout.setf(std::ios::unitbuf); // auto-flush every write
    
    // Kill switch check
    if (KillSwitch::IsDisabled()) {
        std::cout << "[WARN] NetSentinel is DISABLED via kill switch\n" << std::flush;
        return 0;
    }
    
    // Initialize logging
    if (!InitializeLogger()) {
        std::cout << "[WARN] Failed to initialize logger (continuing)\n" << std::flush;
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
        std::cout << "[WARN] Running without administrator rights. Some processes may show as unknown.\n" << std::flush;
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
    // Always monitor loopback traffic (localhost/127.0.0.1) so simulated attacks on the same machine are always shown
    tcpTable.SetIncludeLoopback(true);
    udpTable.SetIncludeLoopback(true);
    
    // Initialize threat intelligence
    threatIntel.LoadFeeds();
    
    // Initialize firewall blocker (requires admin)
    // Initialize firewall blocker (requires admin)
    if (isAdmin) {
        if (!firewallBlocker.Initialize()) {
            std::cout << "[WARN] Failed to initialize firewall blocker\n" << std::flush;
            Logger::Instance().Warning(L"Firewall blocker initialization failed");
        } else {
            std::cout << "[OK] Firewall blocker initialized (ACTIVE PROTECTION ENABLED)\n" << std::flush;
        }
    } else {
        std::cout << "[WARN] Firewall blocking requires administrator rights. Running in MONITOR ONLY mode.\n" << std::flush;
    }
    
    // Initialize packet capture (optional, requires WinPcap/Npcap)
    if (packetCapture.Initialize()) {
        packetCapture.StartCapture();
        std::cout << "[OK] Packet capture initialized\n" << std::flush;
    }
    
    PrintHeader();
    
    // Stats
    uint64_t totalConnections = 0;
    uint64_t criticalRiskCount = 0;
    uint64_t highRiskCount = 0;
    uint64_t mediumRiskCount = 0;
    auto startTime = steady_clock::now();
    
    // Deduplication: track HIGH-risk connections already alerted this session
    // Key = processName + localPort + remoteIp + remotePort
    // Cleared when the connection disappears (not seen in a scan cycle)
    std::unordered_set<std::string> alertedConnections;
    std::unordered_set<std::string> currentCycleHighKeys;
    
    // Main loop
    while (g_running) {
        // Check kill switch dynamically
        if (KillSwitch::IsDisabled()) {
            std::cout << "\n[STOP] Kill switch activated - stopping\n" << std::flush;
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
                
                // Only display HIGH/CRITICAL connections in the Electron monitor
                // MEDIUM/LOW go silently to the log file only
                if (conn.riskLevel >= RiskLevel::HIGH) {
                    // Build a stable key for this specific high-risk alert
                    std::ostringstream keyStream;
                    keyStream << WStr(conn.processName) << "|" << conn.pid
                              << "|" << conn.localPort
                              << "|" << WStr(conn.remoteIp) << ":" << conn.remotePort;
                    std::string alertKey = keyStream.str();
                    currentCycleHighKeys.insert(alertKey);

                    if (alertedConnections.find(alertKey) == alertedConnections.end()) {
                        // NEW alert — show it and mark as seen
                        alertedConnections.insert(alertKey);
                        PrintConnection(conn);
                        
                        // Try to block: first WFP firewall (admin), then TerminateProcess (same-user)
                        bool blocked = false;
                        
                        if (isAdmin) {
                            blocked = firewallBlocker.BlockConnection(conn, conn.threatIntel);
                        }
                        
                        if (!blocked && conn.pid > 4) {
                            // Fallback: terminate the malicious process directly
                            // Works without admin if the process runs as the same user
                            HANDLE hProc = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION,
                                                       FALSE, static_cast<DWORD>(conn.pid));
                            if (hProc != nullptr) {
                                if (TerminateProcess(hProc, 1)) {
                                    blocked = true;
                                    std::wostringstream pidStream;
                                    pidStream << conn.pid;
                                    Logger::Instance().Critical(
                                        L"Process TERMINATED: " + conn.processName +
                                        L" (PID " + pidStream.str() + L") - " +
                                        conn.threatIntel);
                                }
                                CloseHandle(hProc);
                            }
                        }
                        
                        if (blocked) {
                            std::cout << "[BLOCKED] " << WStr(conn.processName)
                                      << " (PID " << conn.pid << ")"
                                      << " -> " << WStr(conn.remoteIp) << ":" << conn.remotePort
                                      << " | " << WStr(conn.threatIntel) << "\n" << std::flush;
                        }
                    }
                    // else: already alerted this session, skip silently
                }

                if (conn.riskLevel == RiskLevel::CRITICAL) criticalRiskCount++;
                if (conn.riskLevel == RiskLevel::HIGH) highRiskCount++;
                if (conn.riskLevel == RiskLevel::MEDIUM) mediumRiskCount++;
                
                totalConnections++;
            }
            
            // Remove stale alert keys: connections no longer present are cleared
            // so if the process restarts on the same port, it alerts again
            std::unordered_set<std::string> staleKeys;
            for (const auto& key : alertedConnections) {
                if (currentCycleHighKeys.find(key) == currentCycleHighKeys.end()) {
                    staleKeys.insert(key);
                }
            }
            for (const auto& key : staleKeys) {
                alertedConnections.erase(key);
            }
            currentCycleHighKeys.clear();
            

            // Heartbeat every 30 seconds to show system is alive
            static auto lastStats = steady_clock::now();
            if (duration_cast<seconds>(steady_clock::now() - lastStats).count() >= 30) {
                std::ostringstream stats;
                stats << "[HEARTBEAT] Scanned " << totalConnections
                      << " connections | HIGH: " << highRiskCount
                      << " | CRITICAL: " << criticalRiskCount;
                std::cout << stats.str() << "\n" << std::flush;
                std::wostringstream wstats;
                wstats << L"Stats: " << totalConnections << L" scanned, "
                       << criticalRiskCount << L" critical, "
                       << highRiskCount << L" high risk";
                Logger::Instance().Info(wstats.str());
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

        // Extremely important when piping to a Node.js/Electron child process!
        std::wcout.flush();
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
    
    std::cout << "\n[OK] Monitoring stopped cleanly\n" << std::flush;
    return 0;
}
