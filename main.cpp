#include <windows.h>
#include <shlobj.h>
#include <iostream>
#include <iomanip>
#include <atomic>
#include <csignal>
#include <chrono>
#include <unordered_set>
#include <vector>
#include <algorithm>
#include <ctime>
#include <clocale>
#include <locale>
#include <sstream>

#include "include/asthak_common.h"
#include "src/network/tcp_table.h"
#include "src/network/udp_table.h"
#include "src/network/packet_capture.h"
#include "src/risk/risk_assessment.h"
#include "src/risk/threat_intel.h"
#include "src/risk/hash_scanner.h"
#include "src/risk/pe_analyzer.h"
#include "src/risk/dns_analyzer.h"
#include "src/risk/vt_lookup.h"
#include "src/safety/kill_switch.h"
#include "src/safety/firewall_blocker.h"
#include "src/safety/self_protection.h"
#include "src/safety/ransomware_guard.h"
#include "src/safety/response_engine.h"
#include "src/safety/amsi_scanner.h"
#include "src/risk/yara_scanner.h"
#include "src/telemetry/etw_consumer.h"
#include "src/utils/logger.h"
#include "src/utils/auto_updater.h"
#include "src/utils/false_positive_filter.h"
#include "src/core/process_cache.h"
#include "src/monitor/file_monitor.h"
#include "src/monitor/process_monitor.h"
#include "src/monitor/registry_monitor.h"


using namespace Asthak;
using namespace std::chrono;

namespace {
bool SafeLocalTime(std::tm& out, const std::time_t& in) {
    return localtime_s(&out, &in) == 0;
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
    
    std::wstring logDir = std::wstring(path) + L"\\Asthak\\Logs";
    return Logger::Instance().Initialize(logDir);
}

// Print banner
void PrintBanner() {
    std::cout << "\n";
    std::cout << "Asthak v" << VERSION_MAJOR << "." << VERSION_MINOR << "." << VERSION_PATCH << "\n";
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
        std::cout << "[WARN] Asthak is DISABLED via kill switch\n" << std::flush;
        return 0;
    }
    
    // Initialize logging
    if (!InitializeLogger()) {
        std::cout << "[WARN] Failed to initialize logger (continuing)\n" << std::flush;
    }
    
    Logger::Instance().Info(L"Asthak starting...");
    
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
    
    // ── Initialize Hash Scanner ──────────────────────────────────────────────
    HashScanner& hashScanner = HashScanner::Instance();
    hashScanner.Initialize();
    std::cout << "[OK] Hash scanner initialized (" << hashScanner.GetBlocklistSize() << " known hashes)\n" << std::flush;
    
    // ── Initialize VirusTotal Cloud Lookup ───────────────────────────────────
    VtLookup& vtLookup = VtLookup::Instance();
    vtLookup.Initialize();
    if (vtLookup.HasApiKey()) {
        std::cout << "[OK] VirusTotal cloud lookup active (2B+ hash database)\n" << std::flush;
    } else {
        std::cout << "[INFO] VirusTotal: No API key. Place key in %LOCALAPPDATA%\\Asthak\\vt_apikey.txt\n" << std::flush;
    }
    
    // ── Initialize PE Analyzer ───────────────────────────────────────────────
    PeAnalyzer& peAnalyzer = PeAnalyzer::Instance();
    std::cout << "[OK] PE static analyzer ready (entropy + import + packer detection)\n" << std::flush;
    
    // ── Initialize DNS Analyzer ──────────────────────────────────────────────
    DnsAnalyzer& dnsAnalyzer = DnsAnalyzer::Instance();
    dnsAnalyzer.Initialize();
    std::cout << "[OK] DNS threat intelligence active (DGA + C2 detection)\n" << std::flush;
    
    // ── Initialize Response Engine (detect → kill → quarantine → block) ─────
    ResponseEngine& responseEngine = ResponseEngine::Instance();
    responseEngine.Initialize();
    responseEngine.SetCallback([](const ThreatIncident& incident, const std::wstring& actionTaken) {
        std::string detail = WStr(incident.detail);
        std::string action = WStr(actionTaken);
        std::cout << "\n\033[91;1m[RESPONSE] " << action << "\033[0m";
        std::cout << "\n  Detail: " << detail << "\n" << std::flush;
    });
    std::cout << "[OK] Response engine active (detect -> kill -> quarantine -> block)\n" << std::flush;

    // ── Initialize False Positive Filter & Auto-Updater ─────────────────────
    FalsePositiveFilter::Instance().Initialize();
    AutoUpdater::Instance().Initialize("1.0.0", "https://updates.asthaksecurity.com", 24);
    AutoUpdater::Instance().SetRulesUpdateCallback([](const std::string& /*rules*/) {
        std::cout << "\n[UPDATER] New YARA rules downloaded. Reloading engine...\n" << std::flush;
        YaraScanner::Instance().Initialize(); // Hot-reload rules
    });
    std::cout << "[OK] False positive filter active (Preventing alerts on system/signed files)\n" << std::flush;
    
    // ── Initialize Ransomware Guard ──────────────────────────────────────────
    RansomwareGuard& ransomGuard = RansomwareGuard::Instance();
    ransomGuard.Initialize();
    ransomGuard.Start([&responseEngine](const RansomwareAlert& alert) {
        std::string msg = "[RANSOMWARE] " + WStr(alert.detail);
        std::cout << "\n\033[91m" << msg << "\033[0m\n" << std::flush;
        
        // AUTO-RESPONSE: Kill ransomware process immediately
        ThreatIncident incident;
        incident.source = ThreatSource::RANSOMWARE_GUARD;
        incident.action = ResponseAction::FULL_RESPONSE;
        incident.pid = alert.pid;
        incident.processName = alert.processName;
        incident.detail = alert.detail;
        incident.confidenceScore = 0.95;
        responseEngine.HandleThreat(incident);

        // VSS ROLLBACK: Restore encrypted files from shadow copy
        RansomwareGuard::Instance().RollbackProcess(alert.pid);
    });
    std::cout << "[OK] Ransomware guard active (mass encryption detection + auto-kill + VSS rollback)\n" << std::flush;
    
    // ── Initialize AMSI (PowerShell/Script malware scanning) ─────────────────
    AmsiScanner& amsiScanner = AmsiScanner::Instance();
    if (amsiScanner.Initialize(L"Asthak")) {
        amsiScanner.SetCallback([](const AmsiAlert& alert) {
            std::cout << "\n\033[91;1m[AMSI] Malicious script blocked: " 
                      << WStr(alert.malwareName) << "\033[0m\n" << std::flush;
        });
        std::cout << "[OK] AMSI integration active (PowerShell/VBScript/JScript pre-execution scan)\n" << std::flush;
    } else {
        std::cout << "[INFO] AMSI not available (Windows 10 1511+ required)\n" << std::flush;
    }

    // ── Initialize YARA Engine (built-in rules, no external library needed) ────
    YaraScanner& yaraScanner = YaraScanner::Instance();
    yaraScanner.Initialize();
    yaraScanner.SetCallback([&responseEngine](const YaraMatch& match, DWORD pid) {
        std::string severity;
        ResponseAction action = ResponseAction::ALERT;
        switch (match.severity) {
            case YaraRuleSeverity::CRITICAL: severity = "\033[91;1mCRITICAL\033[0m"; action = ResponseAction::FULL_RESPONSE;  break;
            case YaraRuleSeverity::HIGH:     severity = "\033[91mHIGH\033[0m";     action = ResponseAction::KILL_PROCESS;   break;
            case YaraRuleSeverity::MEDIUM:   severity = "\033[93mMEDIUM\033[0m";   action = ResponseAction::ALERT;          break;
            case YaraRuleSeverity::LOW:      severity = "\033[92mLOW\033[0m";      action = ResponseAction::LOG_ONLY;       break;
        }
        std::cout << "\n[YARA] " << severity
                  << " | Rule: " << match.ruleName
                  << " | Family: " << match.malwareFamily
                  << " (PID: " << pid << ")" << std::flush;

        ThreatIncident inc;
        inc.source          = ThreatSource::YARA_SCANNER;
        inc.action          = action;
        inc.pid             = pid;
        inc.detail          = std::wstring(match.ruleName.begin(), match.ruleName.end()) +
                              L" — " +
                              std::wstring(match.malwareFamily.begin(), match.malwareFamily.end());
        inc.confidenceScore = (match.severity == YaraRuleSeverity::CRITICAL) ? 0.95 :
                              (match.severity == YaraRuleSeverity::HIGH)     ? 0.80 : 0.60;
        responseEngine.HandleThreat(inc);
    });
    std::cout << "[OK] YARA engine active (" << yaraScanner.RuleCount() << " built-in rules — no external library needed)\n" << std::flush;
    
    // ── Enable Self-Protection ───────────────────────────────────────────────
    SelfProtection& selfProtect = SelfProtection::Instance();
    selfProtect.Enable();
    std::cout << "[OK] Self-protection enabled (DACL hardened, watchdog active)\n" << std::flush;
    
    // ── Start ETW Consumer (deep OS telemetry) ──────────────────────────────
    EtwConsumer etwConsumer;
    bool etwStarted = etwConsumer.Start([&dnsAnalyzer, &peAnalyzer, &responseEngine](const EtwEvent& evt) {
        switch (evt.type) {
            case EtwEventType::DNS_QUERY: {
                // Run through DNS threat intelligence
                auto dnsResult = dnsAnalyzer.AnalyzeDomain(evt.detail);
                if (dnsResult.verdict != DnsVerdict::CLEAN) {
                    std::string msg = "[ETW:DNS] " + WStr(dnsResult.reason);
                    std::cout << "\n\033[93m" << msg << " (PID: " << evt.pid << ")\033[0m\n" << std::flush;
                    
                    // AUTO-RESPONSE: Block C2/DGA domains via response engine
                    if (dnsResult.verdict == DnsVerdict::KNOWN_C2 ||
                        dnsResult.verdict == DnsVerdict::DGA_DETECTED ||
                        dnsResult.verdict == DnsVerdict::DNS_TUNNELING) {
                        ThreatIncident incident;
                        incident.source = ThreatSource::DNS_ANALYZER;
                        incident.action = ResponseAction::BLOCK_NETWORK;
                        incident.pid = evt.pid;
                        incident.processName = evt.processName;
                        incident.detail = dnsResult.reason;
                        incident.confidenceScore = dnsResult.dgaScore;
                        responseEngine.HandleThreat(incident);
                    }
                }
                break;
            }
            case EtwEventType::POWERSHELL_SCRIPT: {
                std::wstring lower = evt.detail;
                std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
                bool suspicious = false;
                std::wstring reason;
                double confidence = 0.5;
                if (lower.find(L"invoke-expression") != std::wstring::npos ||
                    lower.find(L"iex(") != std::wstring::npos ||
                    lower.find(L"iex ") != std::wstring::npos) {
                    suspicious = true;
                    reason = L"Invoke-Expression detected";
                    confidence = 0.6;
                }
                if (lower.find(L"downloadstring") != std::wstring::npos ||
                    lower.find(L"downloadfile") != std::wstring::npos ||
                    lower.find(L"webclient") != std::wstring::npos ||
                    lower.find(L"net.webclient") != std::wstring::npos) {
                    suspicious = true;
                    reason = L"Remote download detected";
                    confidence = 0.7;
                }
                if (lower.find(L"bypass") != std::wstring::npos &&
                    lower.find(L"executionpolicy") != std::wstring::npos) {
                    suspicious = true;
                    reason = L"Execution policy bypass";
                    confidence = 0.6;
                }
                if (lower.find(L"-enc ") != std::wstring::npos ||
                    lower.find(L"-encodedcommand") != std::wstring::npos) {
                    suspicious = true;
                    reason = L"Encoded command detected";
                    confidence = 0.7;
                }
                if (lower.find(L"mimikatz") != std::wstring::npos ||
                    lower.find(L"sekurlsa") != std::wstring::npos ||
                    lower.find(L"kerberos::list") != std::wstring::npos) {
                    suspicious = true;
                    reason = L"Credential dumping tool detected";
                    confidence = 0.95;
                }
                if (lower.find(L"amsiutils") != std::wstring::npos ||
                    lower.find(L"amsiinitfailed") != std::wstring::npos) {
                    suspicious = true;
                    reason = L"AMSI bypass attempt detected";
                    confidence = 0.85;
                }
                // AMSI: scan PS script content through Windows Antimalware API
                if (AmsiScanner::Instance().IsAvailable()) {
                    AmsiScanner::Instance().ScanEtwPowerShellScript(evt.detail, evt.pid, evt.processName);
                }

                // YARA: scan script block content for known malware patterns
                if (YaraScanner::Instance().IsReady() && !evt.detail.empty()) {
                    YaraScanner::Instance().ScanWString(evt.detail, evt.pid);
                }

                if (suspicious) {
                    std::string msg = "[ETW:PS] Suspicious PowerShell: " + WStr(reason);
                    std::cout << "\n\033[91m" << msg << " (PID: " << evt.pid << ")\033[0m\n" << std::flush;
                    
                    // AUTO-RESPONSE: Kill malicious PowerShell (high confidence)
                    if (confidence >= 0.8) {
                        ThreatIncident incident;
                        incident.source = ThreatSource::ETW_CONSUMER;
                        incident.pid = evt.pid;
                        incident.processName = evt.processName;
                        incident.detail = L"Malicious PowerShell: " + reason;
                        incident.confidenceScore = confidence;
                        responseEngine.HandleThreat(incident);
                    }
                }
                break;
            }
            case EtwEventType::PROCESS_CREATE: {
                if (!evt.detail.empty()) {
                    Logger::Instance().Info(L"[ETW:PROC] New process: " + evt.processName + L" | CMD: " + evt.detail);
                }
                // HASH BLOCKING: Scan every new process EXE against local blocklist + VirusTotal
                // processPath has the EXE path; if not set, use detail (which has cmdline/path)
                std::wstring exePath = evt.processPath.empty() ? evt.detail : evt.processPath;
                // Trim command-line arguments — take only up to first space if it starts with a path
                if (!exePath.empty() && exePath[0] != L'"') {
                    auto spacePos = exePath.find(L' ');
                    if (spacePos != std::wstring::npos) exePath = exePath.substr(0, spacePos);
                }
                if (!exePath.empty()) {
                    ResponseEngine::Instance().ScanAndBlockOnLaunch(
                        evt.pid, exePath, evt.processName);
                    // YARA: scan the EXE file on disk for malware patterns
                    if (YaraScanner::Instance().IsReady()) {
                        YaraScanner::Instance().ScanFile(exePath, evt.pid);
                    }
                }
                break;
            }
            case EtwEventType::IMAGE_LOAD: {
                std::wstring lower = evt.detail;
                std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
                bool suspicious = lower.find(L"\\temp\\")    != std::wstring::npos ||
                                  lower.find(L"\\downloads\\") != std::wstring::npos ||
                                  lower.find(L"\\appdata\\local\\temp") != std::wstring::npos;
                if (suspicious) {
                    // Static PE analysis
                    auto peResult = peAnalyzer.AnalyzeFile(evt.detail);
                    if (peResult.verdict == PeVerdict::LIKELY_MALWARE ||
                        peResult.verdict == PeVerdict::SUSPICIOUS) {
                        std::string msg = "[ETW:DLL] Suspicious DLL: " + WStr(evt.detail);
                        std::cout << "\n\033[91m" << msg << " (PID: " << evt.pid << ")\033[0m\n" << std::flush;
                        ThreatIncident incident;
                        incident.source = ThreatSource::PE_ANALYZER;
                        incident.pid = evt.pid;
                        incident.processName = evt.processName;
                        incident.filePath = evt.detail;
                        incident.detail = L"Malicious DLL: " + peResult.detail;
                        incident.confidenceScore = peResult.overallScore;
                        responseEngine.HandleThreat(incident);
                    }
                    // YARA: also scan the DLL file bytes for rule matches
                    if (YaraScanner::Instance().IsReady()) {
                        YaraScanner::Instance().ScanFile(evt.detail, evt.pid);
                    }
                } else {
                    // Even for non-suspicious locations: YARA scan for process memory periodically
                    // (only on .exe image loads to avoid overhead)
                    if (YaraScanner::Instance().IsReady() &&
                        lower.find(L".exe") != std::wstring::npos) {
                        YaraScanner::Instance().ScanProcess(evt.pid);
                    }
                }
                break;
            }
            default: break;
        }
    });
    if (etwStarted) {
        std::cout << "[OK] ETW consumer active (DNS + PowerShell + Process + Image telemetry)\n" << std::flush;
    } else {
        std::cout << "[WARN] ETW consumer failed to start (may need admin rights)\n" << std::flush;
    }

    PrintHeader();
    
    // ── Start File Monitor (steganography + malware drop detection) ───────────
    FileMonitor fileMonitor;
    fileMonitor.Start([&responseEngine](const FileThreat& threat) {
        std::string msg = "[FILE THREAT] " + WStr(threat.detailMessage);
        std::cout << "\n" << msg << "\n" << std::flush;
        
        // AUTO-RESPONSE: Quarantine malicious files only (no PID to kill)
        ThreatIncident incident;
        incident.source = ThreatSource::FILE_MONITOR;
        incident.filePath = threat.filePath;      // set so quarantine path is used
        incident.detail = threat.detailMessage;
        incident.confidenceScore = 0.5;           // ALERT only — file threats have no valid PID
        responseEngine.HandleThreat(incident);
    });

    // ── Start Process Monitor (EDR-lite: child exploit + masquerade) ──────────
    ProcessMonitor procMonitor;
    procMonitor.Start([&responseEngine](const ProcessThreat& threat) {
        // ── EDR hook success is purely informational — NEVER treat as a threat ──
        // edrHookOnly == true means our Protective Ring injected successfully into
        // a benign process.  Show a green info line and stop — do NOT kill the process.
        if (threat.edrHookOnly) {
            std::string msg = "[EDR] " + WStr(threat.detailMessage);
            std::cout << "\n\033[92m" << msg << "\033[0m\n" << std::flush;
            return;
        }

        std::string msg = "[PROCESS THREAT] " + WStr(threat.detailMessage);
        std::cout << "\n" << msg << "\n" << std::flush;
        
        // AUTO-RESPONSE: Kill truly malicious processes
        ThreatIncident incident;
        incident.source = ThreatSource::PROCESS_MONITOR;
        incident.pid = threat.pid;
        incident.processName = threat.processName;
        incident.processPath = threat.processPath;
        incident.detail = threat.detailMessage;
        incident.confidenceScore = 0.75;
        responseEngine.HandleThreat(incident);
    });

    // ── Start Registry Monitor (persistence detection) ───────────────────────
    RegistryMonitor regMonitor;
    regMonitor.Start([&responseEngine](const RegistryThreat& threat) {
        std::string msg = "[REGISTRY] " + WStr(threat.detail);
        std::cout << "\n\033[95m" << msg << "\033[0m\n" << std::flush;
        
        // AUTO-RESPONSE: Alert on persistence (don't auto-kill — could be legit)
        ThreatIncident incident;
        incident.source = ThreatSource::REGISTRY_MONITOR;
        incident.detail = threat.detail;
        incident.confidenceScore = 0.5;
        responseEngine.HandleThreat(incident);
    });

    std::cout << "[OK] File system monitor active (watching 9 directories)\n" << std::flush;
    std::cout << "[OK] Process monitor active (watching for child exploits and masquerading)\n" << std::flush;
    std::cout << "[OK] Registry monitor active (watching 7 persistence keys)\n" << std::flush;
    
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
                            // Safety: NEVER terminate trusted developer / IDE processes.
                            // These may trigger behavioral false positives (many fast
                            // connections) but killing them breaks the developer's tools.
                            std::wstring lowerProc = conn.processName;
                            std::transform(lowerProc.begin(), lowerProc.end(),
                                           lowerProc.begin(), ::towlower);

                            // Trusted prefixes and exact names
                            static const std::vector<std::wstring> safeProcessPrefixes = {
                                L"language_server_", L"msedgewebview", L"microsoftedge",
                                L"chrome", L"firefox", L"brave", L"opera", L"vivaldi",
                                L"python", L"pypy", L"conda",
                            };
                            static const std::unordered_set<std::wstring> safeProcessExact = {
                                L"code.exe", L"code - insiders.exe", L"electron.exe",
                                L"node.exe", L"npm.exe", L"yarn.exe", L"pnpm.exe",
                                L"pip.exe",
                                L"git.exe", L"svchost.exe", L"system idle",
                                L"idea64.exe", L"clion64.exe", L"pycharm64.exe",
                                L"webstorm64.exe", L"rider64.exe", L"goland64.exe",
                                L"cmake.exe", L"ninja.exe", L"msbuild.exe",
                                L"cl.exe", L"link.exe",
                                L"gcc.exe", L"g++.exe", L"mingw32-make.exe",
                                L"clang.exe", L"clang++.exe",
                                // Browsers
                                L"chrome.exe", L"firefox.exe", L"msedge.exe",
                                L"opera.exe", L"brave.exe", L"vivaldi.exe",
                                L"iexplore.exe", L"arc.exe",
                                // High-connection apps
                                L"discord.exe", L"slack.exe", L"teams.exe",
                                L"spotify.exe", L"steam.exe", L"steamwebhelper.exe",
                                L"onedrive.exe", L"dropbox.exe",
                                L"outlook.exe", L"thunderbird.exe",
                                L"ollama.exe", L"ollama app.exe",
                                L"antigravity.exe",
                            };
                            bool isSafe = safeProcessExact.count(lowerProc) > 0;
                            if (!isSafe) {
                                for (const auto& pfx : safeProcessPrefixes) {
                                    if (lowerProc.size() >= pfx.size() &&
                                        lowerProc.compare(0, pfx.size(), pfx) == 0) {
                                        isSafe = true;
                                        break;
                                    }
                                }
                            }

                            if (!isSafe) {
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
                            } else {
                                // Log but do NOT kill trusted processes
                                Logger::Instance().Warning(
                                    L"[SKIP KILL] Trusted dev process: " + conn.processName +
                                    L" — behavioral alert suppressed");
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
    shutdownMsg << L"Asthak shutting down. Runtime: " << runtime.count() << L"s, "
                << L"Total connections: " << totalConnections;
    Logger::Instance().Info(shutdownMsg.str());
    
    selfProtect.Disable();    // Restore original DACL so the process can exit cleanly
    packetCapture.Shutdown();
    firewallBlocker.Shutdown();
    Logger::Instance().Shutdown();
    ProcessCache::Instance().Clear();
    
    std::cout << "\n[OK] Monitoring stopped cleanly\n" << std::flush;
    return 0;
}
