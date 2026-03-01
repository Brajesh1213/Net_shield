// response_engine.cpp — Automated threat response chain
// This is the CRITICAL module that connects detection to action.
//
// Flow:  Detection → ResponseEngine::HandleThreat() → DecideAction() → ExecuteResponse()
//
// Response actions (in order of severity):
//   1. LOG_ONLY      — Low confidence, just log
//   2. ALERT         — Medium confidence, alert user  
//   3. KILL_PROCESS  — Kill the malicious process
//   4. QUARANTINE    — Move malicious file to encrypted vault
//   5. BLOCK_NETWORK — Block C2 connection via WFP + Windows Firewall
//   6. FULL_RESPONSE — All of the above (high confidence threats)
//
// This turns Asthak from a "detection monitor" into an actual "endpoint protection" tool.
// Without this, Asthak just watches malware run. WITH this, Asthak stops it.

#include <windows.h>
#include "safety/response_engine.h"
#include "safety/quarantine.h"
#include "safety/firewall_blocker.h"
#include "risk/hash_scanner.h"
#include "risk/vt_lookup.h"
#include "utils/logger.h"
#include <shlobj.h>
#include <tlhelp32.h>
#include <sstream>
#include <algorithm>
#include <cwctype>

namespace Asthak {

namespace {
template<typename T>
std::wstring ToWStr(T v) { std::wostringstream o; o << v; return o.str(); }
} // anonymous namespace


ResponseEngine& ResponseEngine::Instance() {
    static ResponseEngine instance;
    return instance;
}

bool ResponseEngine::Initialize() {
    if (m_initialized) return true;

    // Initialize Quarantine vault
    WCHAR appData[MAX_PATH] = {};
    if (SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, appData) == S_OK) {
        std::wstring vaultDir = std::wstring(appData) + L"\\Asthak\\Quarantine";
        Quarantine::Instance().Initialize(vaultDir);
    }

    // Initialize Firewall Blocker
    FirewallBlocker::Instance().Initialize();

    m_initialized = true;
    Logger::Instance().Info(L"[ResponseEngine] Initialized — detect → kill → quarantine → block chain active");
    return true;
}


// ═══════════════════════════════════════════════════════════════════════════
// DECISION ENGINE — What action to take based on threat confidence
// ═══════════════════════════════════════════════════════════════════════════

ResponseAction ResponseEngine::DecideAction(const ThreatIncident& incident) {
    // If caller already specified an action, use it
    if (incident.action != ResponseAction::LOG_ONLY) {
        return incident.action;
    }

    // Otherwise, decide based on confidence score and source
    double score = incident.confidenceScore;

    // Very high confidence → full response
    if (score >= 0.9) return ResponseAction::FULL_RESPONSE;

    // High confidence → kill + quarantine
    if (score >= 0.7) return ResponseAction::KILL_PROCESS;

    // Medium confidence → alert
    if (score >= 0.4) return ResponseAction::ALERT;

    // Source-specific overrides
    switch (incident.source) {
        case ThreatSource::RANSOMWARE_GUARD:
            // Ransomware is always critical — kill immediately
            return ResponseAction::FULL_RESPONSE;

        case ThreatSource::HASH_SCANNER:
            // Known malware hash = high confidence
            return (score > 0.0) ? ResponseAction::FULL_RESPONSE : ResponseAction::ALERT;

        case ThreatSource::DNS_ANALYZER:
            // C2 domain = block network
            return ResponseAction::BLOCK_NETWORK;

        case ThreatSource::PE_ANALYZER:
            // PE analysis score > 0.6 = kill + quarantine
            if (score >= 0.6) return ResponseAction::KILL_PROCESS;
            return ResponseAction::ALERT;

        case ThreatSource::REGISTRY_MONITOR:
            // Persistence detection = alert (don't auto-kill, could be legitimate)
            return ResponseAction::ALERT;

        default:
            return ResponseAction::LOG_ONLY;
    }
}


// ═══════════════════════════════════════════════════════════════════════════
// EXECUTE RESPONSE — Perform the decided action
// ═══════════════════════════════════════════════════════════════════════════

void ResponseEngine::HandleThreat(ThreatIncident incident) {
    m_incidents.fetch_add(1);

    // Decide what to do
    incident.action = DecideAction(incident);

    // Execute the response
    ExecuteResponse(incident);
}

void ResponseEngine::ExecuteResponse(ThreatIncident& incident) {
    std::wstring actionsTaken;

    switch (incident.action) {
        case ResponseAction::FULL_RESPONSE: {
            // 1. Kill the process
            if (incident.pid != 0) {
                if (KillProcess(incident.pid, incident.detail)) {
                    actionsTaken += L"Process killed (PID: " + ToWStr(incident.pid) + L"). ";
                }
            }
            // 2. Quarantine the file
            if (!incident.filePath.empty()) {
                if (QuarantineFile(incident.filePath, incident.detail)) {
                    actionsTaken += L"File quarantined. ";
                }
            } else if (!incident.processPath.empty()) {
                if (QuarantineFile(incident.processPath, incident.detail)) {
                    actionsTaken += L"EXE quarantined. ";
                }
            }
            // 3. Block network connection
            if (!incident.remoteIp.empty()) {
                if (BlockConnection(incident.remoteIp, incident.remotePort,
                                    incident.protocol, incident.detail)) {
                    actionsTaken += L"Connection blocked. ";
                }
            }
            break;
        }

        case ResponseAction::KILL_PROCESS: {
            if (incident.pid != 0) {
                if (KillProcess(incident.pid, incident.detail)) {
                    actionsTaken += L"Process killed (PID: " + ToWStr(incident.pid) + L"). ";
                }
            }
            // Also quarantine if we have a file path
            if (!incident.filePath.empty()) {
                QuarantineFile(incident.filePath, incident.detail);
                actionsTaken += L"File quarantined. ";
            }
            break;
        }

        case ResponseAction::QUARANTINE_FILE: {
            if (!incident.filePath.empty()) {
                if (QuarantineFile(incident.filePath, incident.detail)) {
                    actionsTaken += L"File quarantined. ";
                }
            }
            break;
        }

        case ResponseAction::BLOCK_NETWORK: {
            if (!incident.remoteIp.empty()) {
                if (BlockConnection(incident.remoteIp, incident.remotePort,
                                    incident.protocol, incident.detail)) {
                    actionsTaken += L"Connection blocked via firewall. ";
                }
            }
            break;
        }

        case ResponseAction::ALERT: {
            actionsTaken = L"Alert raised (manual action recommended). ";
            break;
        }

        case ResponseAction::LOG_ONLY: {
            actionsTaken = L"Logged for analysis. ";
            break;
        }
    }

    // Log the response
    Logger::Instance().Info(L"[ResponseEngine] Incident #" + ToWStr(m_incidents.load()) +
                            L" | Source: " + ToWStr((int)incident.source) +
                            L" | Action: " + actionsTaken +
                            L" | Detail: " + incident.detail);

    // Notify UI
    if (m_callback) {
        m_callback(incident, actionsTaken);
    }
}


// ═══════════════════════════════════════════════════════════════════════════
// KILL PROCESS
// ═══════════════════════════════════════════════════════════════════════════

bool ResponseEngine::KillProcess(DWORD pid, const std::wstring& reason) {
    if (pid == 0 || pid == 4) return false; // Don't kill System
    if (pid == GetCurrentProcessId()) return false; // Don't kill ourselves

    std::lock_guard<std::mutex> lock(m_mutex);

    // Check if already killed
    if (m_killedPids.count(pid) > 0) return true;

    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        Logger::Instance().Warning(L"[ResponseEngine] Cannot open process PID=" + ToWStr(pid) +
                                    L" for termination (access denied?)");
        return false;
    }

    // Get process name for logging
    WCHAR processName[MAX_PATH] = {};
    DWORD nameSize = MAX_PATH;
    QueryFullProcessImageNameW(hProcess, 0, processName, &nameSize);

    BOOL terminated = TerminateProcess(hProcess, 1);
    CloseHandle(hProcess);

    if (terminated) {
        m_killedPids.insert(pid);
        m_killed.fetch_add(1);
        Logger::Instance().Critical(L"[ResponseEngine] KILLED process: " +
                                     std::wstring(processName) + L" PID=" + ToWStr(pid) +
                                     L" | Reason: " + reason);
        return true;
    }

    Logger::Instance().Warning(L"[ResponseEngine] Failed to kill PID=" + ToWStr(pid));
    return false;
}


// ═══════════════════════════════════════════════════════════════════════════
// QUARANTINE FILE
// ═══════════════════════════════════════════════════════════════════════════

bool ResponseEngine::QuarantineFile(const std::wstring& filePath, const std::wstring& reason) {
    if (filePath.empty()) return false;

    std::lock_guard<std::mutex> lock(m_mutex);

    // Check if already quarantined
    if (m_quarantinedFiles.count(filePath) > 0) return true;

    // Don't quarantine system files
    std::wstring lower = filePath;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    if (lower.find(L"\\windows\\system32\\") != std::wstring::npos ||
        lower.find(L"\\windows\\syswow64\\") != std::wstring::npos) {
        Logger::Instance().Warning(L"[ResponseEngine] Refusing to quarantine system file: " + filePath);
        return false;
    }

    // Check if file exists
    if (GetFileAttributesW(filePath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        return false;
    }

    QuarantineEntry entry;
    bool quarantined = Quarantine::Instance().QuarantineFile(filePath, reason, entry);

    if (quarantined) {
        m_quarantinedFiles.insert(filePath);
        m_quarantined.fetch_add(1);
        Logger::Instance().Critical(L"[ResponseEngine] QUARANTINED: " + filePath +
                                     L" → " + entry.quarantinePath +
                                     L" | Reason: " + reason);
    }

    return quarantined;
}


// ═══════════════════════════════════════════════════════════════════════════
// BLOCK NETWORK CONNECTION
// ═══════════════════════════════════════════════════════════════════════════

bool ResponseEngine::BlockConnection(const std::wstring& ip, uint16_t port,
                                      uint8_t protocol, const std::wstring& reason) {
    if (ip.empty()) return false;

    std::lock_guard<std::mutex> lock(m_mutex);

    // Check if already blocked
    std::wstring key = ip + L":" + ToWStr(port);
    if (m_blockedIps.count(key) > 0) return true;

    // Block via Windows Firewall (persists across reboots)
    Protocol proto = (protocol == 6) ? Protocol::TCP : Protocol::UDP;
    bool fwBlocked = FirewallBlocker::Instance().BlockIP(ip, port, proto,
                        L"Asthak: " + reason);

    if (fwBlocked) {
        m_blockedIps.insert(key);
        m_blocked.fetch_add(1);
        Logger::Instance().Critical(L"[ResponseEngine] BLOCKED: " + ip + L":" + ToWStr(port) +
                                     L" | Reason: " + reason);
    }

    return fwBlocked;
}

bool ResponseEngine::BlockDomain(const std::wstring& domain) {
    // Block domain by adding Windows Firewall rule
    // In practice, we'd resolve the domain and block all its IPs
    // For now, log and rely on DNS-level blocking
    Logger::Instance().Info(L"[ResponseEngine] Domain block requested: " + domain);
    m_blocked.fetch_add(1);
    return true;
}


// ═══════════════════════════════════════════════════════════════════════════
// HASH-BASED PROCESS LAUNCH BLOCKING
// Called immediately when a new process is created (from ETW IMAGE_LOAD event)
// This is the closest to "pre-execution" blocking we can do in user-mode.
// ═══════════════════════════════════════════════════════════════════════════

void ResponseEngine::ScanAndBlockOnLaunch(DWORD pid,
                                          const std::wstring& processPath,
                                          const std::wstring& processName) {
    if (processPath.empty() || pid == 0) return;

    // Ignore system / our own process
    if (pid == GetCurrentProcessId() || pid == 4) return;

    // Ignore known-safe system directories (fast path)
    std::wstring lower = processPath;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    if (lower.find(L"\\windows\\system32\\")  != std::wstring::npos ||
        lower.find(L"\\windows\\syswow64\\")  != std::wstring::npos ||
        lower.find(L"\\windows\\explorer.exe") != std::wstring::npos) {
        return;
    }

    // ── Step 1: Synchronous local hash check (< 5ms) ──────────────────────
    HashResult hr = HashScanner::Instance().ScanFile(processPath);

    if (hr.verdict == HashVerdict::KNOWN_MALWARE) {
        Logger::Instance().Critical(
            L"[ResponseEngine] HASH MATCH on launch! Process=" + processName +
            L" PID=" + ToWStr(pid) +
            L" Family=" + hr.malwareFamily +
            L" Hash=" + hr.sha256);

        ThreatIncident inc;
        inc.source          = ThreatSource::HASH_SCANNER;
        inc.action          = ResponseAction::FULL_RESPONSE;
        inc.pid             = pid;
        inc.processName     = processName;
        inc.processPath     = processPath;
        inc.confidenceScore = 1.0;
        inc.detail          = L"Known malware hash on launch: " + hr.malwareFamily;
        HandleThreat(inc);
        return; // No need to do VT lookup
    }

    // ── Step 2: Async VirusTotal check (non-blocking) ─────────────────────
    // We don't wait for the result — but if VT comes back malicious, we kill
    std::wstring sha256 = hr.sha256.empty() ?
        HashScanner::Instance().ComputeSHA256(processPath) : hr.sha256;

    if (!sha256.empty() && VtLookup::Instance().IsInitialized()) {
        // Capture values for lambda (MinGW compatible)
        struct VtAsyncArgs {
            DWORD pid;
            std::wstring processName;
            std::wstring processPath;
        };
        auto* args = new VtAsyncArgs{ pid, processName, processPath };

        VtLookup::Instance().LookupHashAsync(sha256,
            [args](const std::wstring& hash, const VtResult& result) {
                if (result.malicious) {
                    Logger::Instance().Critical(
                        L"[ResponseEngine] VT confirmed malware! " +
                        args->processName + L" | " + result.detail);

                    ThreatIncident inc;
                    inc.source          = ThreatSource::HASH_SCANNER;
                    inc.action          = ResponseAction::FULL_RESPONSE;
                    inc.pid             = args->pid;
                    inc.processName     = args->processName;
                    inc.processPath     = args->processPath;
                    inc.confidenceScore = 0.95;
                    inc.detail          = L"VirusTotal confirmed: " + result.detail;
                    ResponseEngine::Instance().HandleThreat(inc);
                }
                delete args;
            });
    }
}

} // namespace Asthak
