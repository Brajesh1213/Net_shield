// response_engine.h — Automated threat response chain
// detect → kill → quarantine → block
#pragma once

#include <windows.h>
#include <string>
#include <functional>
#include <atomic>
#include <mutex>
#include <vector>
#include <unordered_set>

namespace Asthak {

enum class ResponseAction {
    LOG_ONLY,
    ALERT,
    KILL_PROCESS,
    QUARANTINE_FILE,
    BLOCK_NETWORK,
    FULL_RESPONSE,
};

enum class ThreatSource {
    FILE_MONITOR,
    PROCESS_MONITOR,
    NETWORK_MONITOR,
    DNS_ANALYZER,
    PE_ANALYZER,
    HASH_SCANNER,
    ETW_CONSUMER,
    REGISTRY_MONITOR,
    RANSOMWARE_GUARD,
};

struct ThreatIncident {
    ThreatSource    source;
    ResponseAction  action;
    DWORD           pid;
    std::wstring    processName;
    std::wstring    processPath;
    std::wstring    filePath;
    std::wstring    remoteIp;
    uint16_t        remotePort;
    uint8_t         protocol;
    std::wstring    detail;
    double          confidenceScore;
};

using IncidentCallback = std::function<void(const ThreatIncident&, const std::wstring&)>;

class ResponseEngine {
public:
    static ResponseEngine& Instance();

    bool Initialize();
    void SetCallback(IncidentCallback callback) { m_callback = callback; }

    void HandleThreat(ThreatIncident incident);

    bool KillProcess(DWORD pid, const std::wstring& reason);
    bool QuarantineFile(const std::wstring& filePath, const std::wstring& reason);
    bool BlockConnection(const std::wstring& ip, uint16_t port, uint8_t protocol, const std::wstring& reason);
    bool BlockDomain(const std::wstring& domain);

    uint64_t GetProcessesKilled()    const { return m_killed.load(); }
    uint64_t GetFilesQuarantined()   const { return m_quarantined.load(); }
    uint64_t GetConnectionsBlocked() const { return m_blocked.load(); }
    uint64_t GetTotalIncidents()     const { return m_incidents.load(); }

private:
    ResponseEngine() = default;

    ResponseAction DecideAction(const ThreatIncident& incident);
    void ExecuteResponse(ThreatIncident& incident);

    IncidentCallback    m_callback;
    std::mutex          m_mutex;
    std::atomic<uint64_t> m_killed{0};
    std::atomic<uint64_t> m_quarantined{0};
    std::atomic<uint64_t> m_blocked{0};
    std::atomic<uint64_t> m_incidents{0};

    std::unordered_set<DWORD>        m_killedPids;
    std::unordered_set<std::wstring> m_quarantinedFiles;
    std::unordered_set<std::wstring> m_blockedIps;
    bool m_initialized{false};
};

} // namespace Asthak
