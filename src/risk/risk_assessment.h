// risk_assessment.h
// Production-hardened Zero Trust risk assessment engine
#pragma once
#include "asthak_common.h"
#include "utils/process_verification.h"
#include <unordered_map>
#include <chrono>

namespace Asthak {

// Connection frequency tracking for behavioral analysis
struct ConnectionBehavior {
    uint32_t connectionCount = 0;
    uint64_t totalBytesTransferred = 0;
    std::chrono::steady_clock::time_point firstSeen;
    std::chrono::steady_clock::time_point lastSeen;
    std::vector<uint16_t> portsUsed;
    bool isBeaconing = false;  // Regular interval connections
    uint32_t beaconHits = 0;   // Count of confirmed beacon intervals
};

class RiskEngine {
public:
    RiskEngine();
    ~RiskEngine();
    
    // Main assessment function
    void Assess(Connection& conn);
    
    // Behavioral analysis
    void TrackConnectionBehavior(const Connection& conn);
    bool DetectBeaconing(DWORD pid);
    
    // Alert management
    void SetAlertCallback(std::function<void(const Connection&, const std::wstring&)> callback);
    void EnableWindowsEventLog(bool enable);
    void EnableDesktopNotifications(bool enable);
    
private:
    // Risk assessment layers
    void CheckPortPolicy(Connection& conn);
    void CheckProcessIntegrity(Connection& conn);
    void CheckGeolocationPolicy(Connection& conn);
    void CheckBehavioralPatterns(Connection& conn);
    void CheckParentProcessChain(Connection& conn);
    
    // Helper functions
    void TriggerAlert(Connection& conn, const std::wstring& reason, bool blockConnection = false);
    void LogToWindowsEventLog(const Connection& conn, const std::wstring& message);
    void ShowDesktopNotification(const std::wstring& title, const std::wstring& message);
    
    std::wstring GenerateRiskReport(const Connection& conn, const ProcessVerificationResult& verification);
    
    // State tracking
    std::unordered_map<DWORD, ConnectionBehavior> m_behaviorMap;
    std::function<void(const Connection&, const std::wstring&)> m_alertCallback;
    
    bool m_windowsEventLogEnabled = true;
    bool m_desktopNotificationsEnabled = true;
};

} // namespace Asthak