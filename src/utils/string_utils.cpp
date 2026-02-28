// string_utils.cpp
#include "string_utils.h"
#include <algorithm>
#include <cctype>
#include <cwctype>
#include <cstring>
#include <sstream>
#include <iomanip>

namespace Asthak::Utils {

std::wstring IPv4ToString(uint32_t ip) {
    in_addr addr;
    addr.S_un.S_addr = ip;

    const char* text = inet_ntoa(addr);
    if (!text) {
        return L"invalid";
    }

    std::wstring result;
    result.reserve(16);
    for (const char* p = text; *p; ++p) {
        result += static_cast<wchar_t>(*p);
    }
    return result;
}

std::wstring IPv6ToString(const uint8_t* ipBytes) {
    if (!ipBytes) {
        return L"invalid";
    }

    // Minimal IPv6 formatter for older MinGW toolchains without inet_ntop.
    std::wostringstream oss;
    oss << std::hex << std::nouppercase;
    for (int i = 0; i < 8; ++i) {
        uint16_t group = static_cast<uint16_t>(ipBytes[i * 2] << 8) |
                         static_cast<uint16_t>(ipBytes[i * 2 + 1]);
        oss << group;
        if (i != 7) {
            oss << L":";
        }
    }
    return oss.str();
}

bool StringToIPv4(const std::wstring& str, uint32_t& ip) {
    std::string narrow;
    narrow.reserve(str.length());
    for (wchar_t c : str) {
        if (c > 127) return false; // Invalid for IP
        narrow += static_cast<char>(c);
    }

    unsigned long parsed = inet_addr(narrow.c_str());
    if (parsed == INADDR_NONE && narrow != "255.255.255.255") {
        return false;
    }
    ip = parsed;
    return true;
}

bool IsPrivateIPv4(uint32_t ip) {
    const uint32_t hostIp = ntohl(ip);

    // 10.0.0.0/8
    if ((hostIp & 0xFF000000) == 0x0A000000) return true;
    // 172.16.0.0/12
    if ((hostIp & 0xFFF00000) == 0xAC100000) return true;
    // 192.168.0.0/16
    if ((hostIp & 0xFFFF0000) == 0xC0A80000) return true;
    // 127.0.0.0/8 (loopback, but also private)
    if ((hostIp & 0xFF000000) == 0x7F000000) return true;
    // 169.254.0.0/16 (link-local)
    if ((hostIp & 0xFFFF0000) == 0xA9FE0000) return true;
    return false;
}

bool IsLoopbackIPv4(uint32_t ip) {
    const uint32_t hostIp = ntohl(ip);
    return (hostIp & 0xFF000000) == 0x7F000000;
}

bool IsMulticastIPv4(uint32_t ip) {
    const uint32_t hostIp = ntohl(ip);
    return (hostIp & 0xF0000000) == 0xE0000000;
}

bool CaseInsensitiveEqual(const std::wstring& a, const std::wstring& b) {
    if (a.length() != b.length()) return false;
    return std::equal(a.begin(), a.end(), b.begin(),
        [](wchar_t a, wchar_t b) { return towlower(a) == towlower(b); });
}

std::string WideToUTF8(const std::wstring& wstr) {
    if (wstr.empty()) return {};

    int size = WideCharToMultiByte(
        CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()),
        nullptr, 0, nullptr, nullptr);
    if (size <= 0) return {};

    std::string result(static_cast<size_t>(size), '\0');
    WideCharToMultiByte(
        CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()),
        &result[0], size, nullptr, nullptr);
    return result;
}

std::wstring UTF8ToWide(const std::string& str) {
    if (str.empty()) return {};

    int size = MultiByteToWideChar(
        CP_UTF8, 0, str.data(), static_cast<int>(str.size()),
        nullptr, 0);
    if (size <= 0) return {};

    std::wstring result(static_cast<size_t>(size), L'\0');
    MultiByteToWideChar(
        CP_UTF8, 0, str.data(), static_cast<int>(str.size()),
        &result[0], size);
    return result;
}

} // namespace Asthak::Utils
