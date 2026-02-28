// packet_capture.cpp
#include "packet_capture.h"
#include "src/utils/logger.h"
#include <algorithm>
#include <cstring>
#include <iostream>

#ifdef USE_YARA
#include <yara.h>
#endif

namespace Asthak {

PacketCapture& PacketCapture::Instance() {
    static PacketCapture instance;
    return instance;
}

PacketCapture::~PacketCapture() {
    StopCapture();
    Shutdown();
}

bool PacketCapture::Initialize() {
    if (initialized_) {
        return true;
    }
    
#ifdef USE_YARA
    if (yr_initialize() != ERROR_SUCCESS) {
        Logger::Instance().Error(L"PacketCapture: Failed to initialize YARA engine");
    } else {
        Logger::Instance().Info(L"PacketCapture: YARA engine initialized successfully");
    }
#endif

    // Note: Full packet capture requires WinPcap/Npcap library
    // This is a stub implementation showing the structure
    
    // In production:
    // - Load wpcap.dll / npcap.dll
    // - Initialize pcap library
    // - Find network adapter
    // - Open adapter for packet capture
    
    Logger::Instance().Info(L"PacketCapture: Initialized (stub - requires WinPcap/Npcap)");
    initialized_ = true;
    return true;
}

bool PacketCapture::StartCapture() {
    if (!initialized_ && !Initialize()) {
        return false;
    }
    
    if (capturing_) {
        return true;
    }
    
    // Start packet capture thread
    // In production: use pcap_loop or pcap_next_ex
    
    capturing_ = true;
    Logger::Instance().Info(L"PacketCapture: Started capturing");
    return true;
}

void PacketCapture::StopCapture() {
    if (!capturing_) {
        return;
    }
    
    capturing_ = false;
    Logger::Instance().Info(L"PacketCapture: Stopped capturing");
}

PayloadInspection PacketCapture::InspectPayload(const std::vector<uint8_t>& payload, 
                                               const Connection& conn) {
    PayloadInspection result;
    
    if (payload.empty()) {
        return result;
    }
    
    // Check for C2 beacon patterns
    if (DetectC2Beacon(payload)) {
        result.suspicious = true;
        result.threatType = L"C2 Beacon";
        result.signature = L"Regular interval beacon pattern detected";
        result.sample = std::vector<uint8_t>(payload.begin(), 
                                            payload.begin() + std::min<size_t>(payload.size(), 64));
        return result;
    }
    
    // Check for data exfiltration
    if (DetectDataExfiltration(payload)) {
        result.suspicious = true;
        result.threatType = L"Data Exfiltration";
        result.signature = L"High entropy / encrypted data pattern";
        result.sample = std::vector<uint8_t>(payload.begin(), 
                                            payload.begin() + std::min<size_t>(payload.size(), 64));
        return result;
    }
    
    // Check for malware patterns
    if (DetectMalwarePatterns(payload)) {
        result.suspicious = true;
        result.threatType = L"Malware Communication";
        result.signature = L"Known malware signature detected";
        result.sample = std::vector<uint8_t>(payload.begin(), 
                                            payload.begin() + std::min<size_t>(payload.size(), 64));
        return result;
    }
    
    return result;
}

bool PacketCapture::DetectC2Beacon(const std::vector<uint8_t>& payload) {
    // Detect regular beacon patterns
    // C2 beacons often have:
    // - Fixed size packets
    // - Regular intervals (detected via timing, not payload)
    // - Specific patterns
    
    if (payload.size() < 4) {
        return false;
    }
    
    // Check for common C2 patterns
    // Example: Metasploit, Cobalt Strike patterns
    const uint8_t metasploitPattern[] = {0x00, 0x00, 0xBE, 0xEF};
    
    if (payload.size() >= sizeof(metasploitPattern)) {
        if (std::memcmp(payload.data(), metasploitPattern, sizeof(metasploitPattern)) == 0) {
            return true;
        }
    }
    
    return false;
}

bool PacketCapture::DetectDataExfiltration(const std::vector<uint8_t>& payload) {
    // Detect high entropy (encrypted/compressed) data
    // Simple heuristic: check for high byte diversity
    
    if (payload.size() < 32) {
        return false;
    }
    
    // Count unique bytes
    bool bytePresent[256] = {false};
    size_t uniqueBytes = 0;
    
    for (size_t i = 0; i < payload.size() && i < 256; ++i) {
        if (!bytePresent[payload[i]]) {
            bytePresent[payload[i]] = true;
            uniqueBytes++;
        }
    }
    
    // High entropy: > 200 unique bytes in 256 bytes
    if (uniqueBytes > 200) {
        return true;
    }
    
    return false;
}

#ifdef USE_YARA
// Callback function for YARA scanner
int YaraScanCallback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE* rule = (YR_RULE*)message_data;
        bool* matched = (bool*)user_data;
        *matched = true;
        // Optionally, we could log `rule->identifier` here.
    }
    return CALLBACK_CONTINUE;
}
#endif

bool PacketCapture::DetectMalwarePatterns(const std::vector<uint8_t>& payload) {
#ifdef USE_YARA
    // Dynamically scan using the loaded YARA rules
    if (yaraRules_) {
        bool matched = false;
        yr_rules_scan_mem(
            static_cast<YR_RULES*>(yaraRules_),
            payload.data(),
            payload.size(),
            0,
            YaraScanCallback,
            &matched,
            0
        );
        if (matched) return true;
    }
#endif

    // Fallback: Check for known malware signatures
    // In production, use YARA rules or signature database
    const char* suspiciousStrings[] = {
        "cmd.exe",
        "/c",
        "powershell",
        "base64",
        "download",
        "execute"
    };
    
    for (const char* str : suspiciousStrings) {
        if (payload.size() >= strlen(str)) {
            if (std::search(payload.begin(), payload.end(), 
                          str, str + strlen(str),
                          [](uint8_t a, char b) { return a == static_cast<uint8_t>(b); }) 
                != payload.end()) {
                return true;
            }
        }
    }
    
    return false;
}

bool PacketCapture::DetectBase64Encoding(const std::vector<uint8_t>& payload) {
    // Detect Base64 encoded data
    if (payload.size() < 4) {
        return false;
    }
    
    size_t base64Chars = 0;
    for (uint8_t byte : payload) {
        if ((byte >= 'A' && byte <= 'Z') || 
            (byte >= 'a' && byte <= 'z') || 
            (byte >= '0' && byte <= '9') || 
            byte == '+' || byte == '/' || byte == '=') {
            base64Chars++;
        }
    }
    
    // If > 80% Base64 characters, likely Base64 encoded
    return (base64Chars * 100 / payload.size()) > 80;
}

bool PacketCapture::DetectEncryptedTraffic(const std::vector<uint8_t>& payload) {
    // Simple heuristic: high entropy suggests encryption
    return DetectDataExfiltration(payload);
}

void PacketCapture::SetPayloadCallback(std::function<void(const Connection&, const PayloadInspection&)> callback) {
    payloadCallback_ = callback;
}

void PacketCapture::Shutdown() {
    StopCapture();
#ifdef USE_YARA
    if (yaraRules_) {
        yr_rules_destroy(static_cast<YR_RULES*>(yaraRules_));
        yaraRules_ = nullptr;
    }
    yr_finalize();
#endif
    initialized_ = false;
}

bool PacketCapture::LoadYaraRules(const std::string& rulesFile) {
#ifdef USE_YARA
    YR_COMPILER* compiler = nullptr;
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
        return false;
    }
    
    FILE* ruleFile = fopen(rulesFile.c_str(), "r");
    if (!ruleFile) {
        yr_compiler_destroy(compiler);
        return false;
    }
    
    int errors = yr_compiler_add_file(compiler, ruleFile, nullptr, rulesFile.c_str());
    fclose(ruleFile);
    
    if (errors > 0) {
        Logger::Instance().Error(L"PacketCapture: YARA compilation failed with errors");
        yr_compiler_destroy(compiler);
        return false;
    }
    
    YR_RULES* rules = nullptr;
    if (yr_compiler_get_rules(compiler, &rules) != ERROR_SUCCESS) {
        yr_compiler_destroy(compiler);
        return false;
    }
    
    if (yaraRules_) {
        yr_rules_destroy(static_cast<YR_RULES*>(yaraRules_));
    }
    
    yaraRules_ = rules;
    yr_compiler_destroy(compiler);
    Logger::Instance().Info(L"PacketCapture: YARA rules loaded successfully");
    return true;
#else
    Logger::Instance().Error(L"PacketCapture: YARA is not enabled in this build.");
    return false;
#endif
}

} // namespace Asthak
