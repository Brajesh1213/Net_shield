// string_utils.h
#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <ws2tcpip.h>

namespace Asthak::Utils {

// IPv4 DWORD to wstring (optimized, thread-safe)
std::wstring IPv4ToString(uint32_t ip);

// IPv6 bytes to wstring
std::wstring IPv6ToString(const uint8_t* ipBytes);

// String to IPv4 DWORD
bool StringToIPv4(const std::wstring& str, uint32_t& ip);

// Check if IP is private/RFC1918
bool IsPrivateIPv4(uint32_t ip);
bool IsPrivateIPv6(const uint8_t* ipBytes);

// Check if IP is loopback
bool IsLoopbackIPv4(uint32_t ip);
bool IsLoopbackIPv6(const uint8_t* ipBytes);

// Check if IP is multicast
bool IsMulticastIPv4(uint32_t ip);

// Wide string to UTF-8 (for logging)
std::string WideToUTF8(const std::wstring& wstr);
std::wstring UTF8ToWide(const std::string& str);

// Case-insensitive string compare
bool CaseInsensitiveEqual(const std::wstring& a, const std::wstring& b);

} // namespace Asthak::Utils