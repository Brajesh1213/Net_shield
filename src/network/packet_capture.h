// packet_capture.h
#pragma once
#include "netsentinel_common.h"
#include <vector>
#include <string>
#include <functional>

namespace NetSentinel {

// Payload inspection result
struct PayloadInspection {
    bool suspicious = false;
    std::wstring threatType;  // e.g., "C2 Beacon", "Data Exfiltration", "Malware Communication"
    std::wstring signature;   // Detected pattern/signature
    std::vector<uint8_t> sample; // Sample of payload
};

class PacketCapture {
public:
    static PacketCapture& Instance();
    
    // Initialize packet capture (requires WinPcap/Npcap)
    bool Initialize();
    
    // Start capturing packets
    bool StartCapture();
    
    // Stop capturing
    void StopCapture();
    
    // Inspect payload for suspicious patterns
    PayloadInspection InspectPayload(const std::vector<uint8_t>& payload, 
                                     const Connection& conn);
    
    // Set callback for suspicious payloads
    void SetPayloadCallback(std::function<void(const Connection&, const PayloadInspection&)> callback);
    
    // Cleanup
    void Shutdown();
    
private:
    PacketCapture() = default;
    ~PacketCapture();
    PacketCapture(const PacketCapture&) = delete;
    PacketCapture& operator=(const PacketCapture&) = delete;
    
    bool initialized_ = false;
    bool capturing_ = false;
    std::function<void(const Connection&, const PayloadInspection&)> payloadCallback_;
    
    // Pattern detection
    bool DetectC2Beacon(const std::vector<uint8_t>& payload);
    bool DetectDataExfiltration(const std::vector<uint8_t>& payload);
    bool DetectMalwarePatterns(const std::vector<uint8_t>& payload);
    bool DetectBase64Encoding(const std::vector<uint8_t>& payload);
    bool DetectEncryptedTraffic(const std::vector<uint8_t>& payload);
};

} // namespace NetSentinel
