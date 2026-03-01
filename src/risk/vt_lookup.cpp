// vt_lookup.cpp — VirusTotal API cloud hash lookup
// Uses WinINet (built into Windows) for HTTPS requests — no external HTTP library needed.
// Free VT API key: 4 requests/minute, which is enough for on-demand scanning.
//
// How it works:
//   1. Hash scanner computes SHA-256 of suspicious file
//   2. VtLookup sends GET to https://www.virustotal.com/api/v3/files/{hash}
//   3. Parse JSON response for detection ratio and malware family
//   4. ResponseEngine acts on the result
//
// VT API v3 response format (simplified):
//   { "data": { "attributes": { "last_analysis_stats": { "malicious": 45, "undetected": 25 },
//     "last_analysis_results": { "Kaspersky": { "result": "Trojan.Win32.Emotet" } } } } }

#include <windows.h>
#include <wininet.h>
#include <shlobj.h>
#include "risk/vt_lookup.h"
#include "utils/logger.h"
#include <sstream>
#include <fstream>
#include <algorithm>
#include <cwctype>

// Link WinINet
#pragma comment(lib, "wininet.lib")

namespace Asthak {

namespace {
template<typename T>
std::wstring ToWStr(T v) { std::wostringstream o; o << v; return o.str(); }

std::wstring NarrowToWide(const std::string& s) {
    if (s.empty()) return L"";
    int sz = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(sz, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], sz);
    return w;
}

std::string WideToNarrow(const std::wstring& w) {
    if (w.empty()) return "";
    int sz = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(sz, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], sz, nullptr, nullptr);
    return s;
}

// Simple JSON value extractor (avoids needing a JSON library)
// Finds "key": value in JSON and returns value as string
std::string JsonGetInt(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\":";
    size_t pos = json.find(search);
    if (pos == std::string::npos) {
        search = "\"" + key + "\": ";
        pos = json.find(search);
        if (pos == std::string::npos) return "0";
    }
    pos += search.size();
    // Skip whitespace
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) pos++;

    size_t end = pos;
    while (end < json.size() && (json[end] >= '0' && json[end] <= '9')) end++;
    return json.substr(pos, end - pos);
}

std::string JsonGetString(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\":\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) {
        search = "\"" + key + "\": \"";
        pos = json.find(search);
        if (pos == std::string::npos) return "";
    }
    pos += search.size();
    size_t end = json.find("\"", pos);
    if (end == std::string::npos) return "";
    return json.substr(pos, end - pos);
}
} // anonymous namespace


VtLookup& VtLookup::Instance() {
    static VtLookup instance;
    return instance;
}

void VtLookup::SetApiKey(const std::wstring& apiKey) {
    m_apiKey = apiKey;
}

bool VtLookup::Initialize() {
    if (m_initialized) return true;

    // Try loading API key from config file
    if (m_apiKey.empty()) {
        WCHAR appData[MAX_PATH] = {};
        if (SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, appData) == S_OK) {
            std::wstring configPath = std::wstring(appData) + L"\\Asthak\\vt_apikey.txt";
            std::string path = WideToNarrow(configPath);
            std::ifstream file(path);
            if (file.is_open()) {
                std::string key;
                std::getline(file, key);
                if (!key.empty()) {
                    m_apiKey = NarrowToWide(key);
                }
            }
        }
    }

    m_initialized = true;

    if (m_apiKey.empty()) {
        Logger::Instance().Warning(L"[VtLookup] No API key configured. "
            L"Place your VirusTotal API key in %LOCALAPPDATA%\\Asthak\\vt_apikey.txt");
    } else {
        Logger::Instance().Info(L"[VtLookup] Initialized with API key (hash cloud lookup active)");
    }

    return true;
}


// ═══════════════════════════════════════════════════════════════════════════
// RATE LIMITING
// ═══════════════════════════════════════════════════════════════════════════

bool VtLookup::CanMakeRequest() const {
    DWORD now = GetTickCount();
    // Reset counter every minute
    if (now - m_minuteStartTick > 60000) {
        return true;
    }
    // Free tier: 4 requests per minute
    return m_requestsThisMinute < 4;
}


// ═══════════════════════════════════════════════════════════════════════════
// HTTP GET via WinINet
// ═══════════════════════════════════════════════════════════════════════════

std::string VtLookup::HttpGet(const std::wstring& url) {
    HINTERNET hInternet = InternetOpenW(L"Asthak/1.0", INTERNET_OPEN_TYPE_PRECONFIG,
                                         nullptr, nullptr, 0);
    if (!hInternet) return "";

    // Add API key header
    std::wstring headers = L"x-apikey: " + m_apiKey + L"\r\n";

    HINTERNET hUrl = InternetOpenUrlW(hInternet, url.c_str(), headers.c_str(),
                                       (DWORD)headers.size(),
                                       INTERNET_FLAG_SECURE | INTERNET_FLAG_NO_CACHE_WRITE,
                                       0);
    if (!hUrl) {
        InternetCloseHandle(hInternet);
        return "";
    }

    std::string response;
    char buffer[4096];
    DWORD bytesRead = 0;

    while (InternetReadFile(hUrl, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        response += buffer;
    }

    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInternet);

    return response;
}


// ═══════════════════════════════════════════════════════════════════════════
// HASH LOOKUP
// ═══════════════════════════════════════════════════════════════════════════

VtResult VtLookup::LookupHash(const std::wstring& sha256Hash) {
    VtResult result = {};
    result.found = false;
    result.malicious = false;

    if (m_apiKey.empty()) {
        result.detail = L"No API key configured";
        return result;
    }

    // Check cache first
    {
        std::lock_guard<std::mutex> lock(m_cacheMutex);
        auto it = m_cache.find(sha256Hash);
        if (it != m_cache.end()) {
            return it->second;
        }
    }

    // Rate limit check
    if (!CanMakeRequest()) {
        result.detail = L"Rate limited (4 req/min on free tier)";
        return result;
    }

    // Build URL: VT API v3
    std::wstring url = L"https://www.virustotal.com/api/v3/files/" + sha256Hash;

    // Make request
    m_lookups.fetch_add(1);
    DWORD now = GetTickCount();
    if (now - m_minuteStartTick > 60000) {
        m_minuteStartTick = now;
        m_requestsThisMinute = 0;
    }
    m_requestsThisMinute++;
    m_lastRequestTick = now;

    std::string response = HttpGet(url);

    if (response.empty()) {
        result.detail = L"No response from VirusTotal";
        return result;
    }

    // Parse response
    result = ParseResponse(response);

    // Cache the result
    {
        std::lock_guard<std::mutex> lock(m_cacheMutex);
        m_cache[sha256Hash] = result;
    }

    if (result.malicious) {
        m_malwareFound.fetch_add(1);
    }

    return result;
}

void VtLookup::LookupHashAsync(const std::wstring& sha256Hash, VtResultCallback callback) {
    // Create a copy of the hash for the thread
    std::wstring hashCopy = sha256Hash;
    VtResultCallback cb = callback;

    // Use CreateThread for MinGW compatibility
    struct AsyncArgs {
        VtLookup* self;
        std::wstring hash;
        VtResultCallback callback;
    };

    auto* args = new AsyncArgs{ this, hashCopy, cb };

    CreateThread(nullptr, 0, [](LPVOID param) -> DWORD {
        auto* a = static_cast<AsyncArgs*>(param);
        VtResult result = a->self->LookupHash(a->hash);
        if (a->callback) {
            a->callback(a->hash, result);
        }
        delete a;
        return 0;
    }, args, 0, nullptr);
}


// ═══════════════════════════════════════════════════════════════════════════
// PARSE VT API v3 RESPONSE
// ═══════════════════════════════════════════════════════════════════════════

VtResult VtLookup::ParseResponse(const std::string& json) {
    VtResult result = {};

    // Check for "not found" (404)
    if (json.find("\"error\"") != std::string::npos &&
        json.find("NotFoundError") != std::string::npos) {
        result.found = false;
        result.detail = L"Hash not found in VirusTotal database";
        return result;
    }

    // Check we got valid data
    if (json.find("\"data\"") == std::string::npos) {
        result.found = false;
        result.detail = L"Invalid response from VirusTotal";
        return result;
    }

    result.found = true;

    // Extract detection stats
    std::string malicious = JsonGetInt(json, "malicious");
    std::string suspicious = JsonGetInt(json, "suspicious");
    std::string undetected = JsonGetInt(json, "undetected");

    int nMalicious  = std::atoi(malicious.c_str());
    int nSuspicious = std::atoi(suspicious.c_str());
    int nUndetected = std::atoi(undetected.c_str());

    result.positives = nMalicious + nSuspicious;
    result.total     = nMalicious + nSuspicious + nUndetected;

    // If any engine detected it as malicious
    result.malicious = (nMalicious >= 3); // At least 3 engines agree

    // Try to get a malware family name from popular engines
    // Check Kaspersky, Microsoft, ESET, BitDefender results
    std::string kaspersky = JsonGetString(json, "result");  // Simplified extraction
    if (!kaspersky.empty()) {
        result.malwareFamily = NarrowToWide(kaspersky);
    }

    // Build detail string
    result.detail = L"VT: " + ToWStr(nMalicious) + L"/" + ToWStr(result.total) + L" engines detected as malicious";
    if (!result.malwareFamily.empty()) {
        result.detail += L" | Family: " + result.malwareFamily;
    }

    // Build VT permalink
    // The hash was the original input; we'll reconstruct the link
    result.permalink = L"https://www.virustotal.com/gui/file/";  // hash appended by caller

    return result;
}

} // namespace Asthak
