// SPDX-License-Identifier: MIT
// Copyright 2026 Brajesh
// Common definitions for Asthak

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <cstdint>
#include <string>
#include <chrono>
#include <vector>
#include <functional>
#include <sstream>

namespace Asthak {

// Version info
constexpr uint16_t VERSION_MAJOR = 0;
constexpr uint16_t VERSION_MINOR = 3;
constexpr uint16_t VERSION_PATCH = 0;

// Risk levels
enum class RiskLevel : uint8_t {
    UNKNOWN = 0,
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3,
    CRITICAL = 4
};

// Connection direction
enum class Direction : uint8_t {
    OUTBOUND = 0,
    INBOUND = 1,
    BOTH = 2
};

// Connection protocol
enum class Protocol : uint8_t {
    TCP = 6,
    UDP = 17,
    BOTH = 255
};

// Unified connection structure (IPv4 and IPv6)
struct Connection {
    uint32_t id;                          // Unique connection ID
    uint32_t pid;                          // Process ID
    std::wstring processName;              // Executable name
    std::wstring processPath;              // Full path to executable
    std::wstring remoteIp;                 // Remote IP (string)
    std::wstring localIp;                  // Local IP (string)
    uint16_t remotePort;                  // Remote port (host byte order)
    uint16_t localPort;                   // Local port (host byte order)
    Protocol protocol;                     // TCP/UDP
    Direction direction;                   // Inbound/Outbound
    RiskLevel riskLevel;                   // Calculated risk
    std::wstring countryCode;              // GeoIP country (e.g., "RU", "US")
    std::wstring threatIntel;              // Threat category if known
    std::chrono::steady_clock::time_point timestamp; // When detected
    uint64_t bytesSent;                    // Stats (future)
    uint64_t bytesReceived;                // Stats (future)
    
    // Constructor with defaults
    Connection() : id(0), pid(0), remotePort(0), localPort(0),
                 protocol(Protocol::TCP), direction(Direction::OUTBOUND),
                 riskLevel(RiskLevel::LOW), bytesSent(0), bytesReceived(0) {}
    
    // Generate unique key for deduplication
    std::wstring GetKey() const {
        std::wostringstream key;
        key << pid << L":" << remoteIp << L":" << remotePort << L":" << static_cast<int>(protocol);
        return key.str();
    }
};

// Alert structure for notifications
struct Alert {
    uint32_t id;
    Connection connection;
    std::wstring message;
    std::wstring recommendedAction;
    bool blocked;
    std::chrono::steady_clock::time_point timestamp;
};

// Callback types for async operations
using ConnectionCallback = std::function<void(const Connection&)>;
using AlertCallback = std::function<void(const Alert&)>;
using LogCallback = std::function<void(const std::wstring&)>;

} // namespace Asthak
