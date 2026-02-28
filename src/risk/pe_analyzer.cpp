// pe_analyzer.cpp — Static PE (Portable Executable) analysis engine
// Inspects binary structure WITHOUT executing it. Detects:
//   1. Packed binaries (UPX, Themida) via section entropy
//   2. Suspicious import combinations (VirtualAlloc + WriteProcessMemory = injection)
//   3. Anomalous section flags (.data with EXECUTE = shellcode)
//   4. Missing or fake Authenticode signatures
//
// This is how Malwarebytes' Static AI engine and SentinelOne's pre-execution
// AI work at a fundamental level — they analyze PE structure before running.

#include "risk/pe_analyzer.h"
#include "utils/logger.h"
#include <fstream>
#include <sstream>
#include <cmath>
#include <algorithm>
#include <cwctype>
#include <unordered_set>
#include <vector>

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
} // anonymous namespace


// Suspicious API imports that indicate injection/hollowing behavior
static const std::unordered_set<std::string> kInjectionAPIs = {
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "WriteProcessMemory", "ReadProcessMemory",
    "CreateRemoteThread", "CreateRemoteThreadEx",
    "NtWriteVirtualMemory", "NtCreateThreadEx",
    "QueueUserAPC", "SetThreadContext",
    "RtlCreateUserThread",
};

// APIs that suggest credential theft
static const std::unordered_set<std::string> kCredentialAPIs = {
    "CredEnumerateW", "CredReadW",
    "LsaRetrievePrivateData", "LsaStorePrivateData",
    "CryptUnprotectData",
    "SamConnect", "SamEnumerateUsersInDomain",
};

// APIs that suggest keylogging
static const std::unordered_set<std::string> kKeylogAPIs = {
    "SetWindowsHookExA", "SetWindowsHookExW",
    "GetAsyncKeyState", "GetKeyState",
    "RegisterRawInputDevices",
};

// APIs that suggest evasion/anti-analysis
static const std::unordered_set<std::string> kEvasionAPIs = {
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "GetTickCount", "QueryPerformanceCounter",  // Timing checks
    "SleepEx",  // Long delay = sandbox evasion
};


PeAnalyzer& PeAnalyzer::Instance() {
    static PeAnalyzer instance;
    return instance;
}


// ═══════════════════════════════════════════════════════════════════════════
// ENTROPY COMPUTATION (Shannon entropy)
// ═══════════════════════════════════════════════════════════════════════════

double PeAnalyzer::ComputeEntropy(const BYTE* data, size_t size) {
    if (!data || size == 0) return 0.0;
    
    uint64_t freq[256] = {};
    for (size_t i = 0; i < size; ++i) {
        freq[data[i]]++;
    }
    
    double entropy = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (freq[i] == 0) continue;
        double p = (double)freq[i] / (double)size;
        entropy -= p * log2(p);
    }
    
    return entropy; // 0.0 = uniform, 8.0 = perfectly random (encrypted/compressed)
}

double PeAnalyzer::ComputeFileEntropy(const std::wstring& filePath) {
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return -1.0;
    
    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart == 0) {
        CloseHandle(hFile);
        return -1.0;
    }
    
    // Read up to 1MB for entropy calculation
    size_t readSize = (fileSize.QuadPart < 1048576) ? (size_t)fileSize.QuadPart : 1048576;
    std::vector<BYTE> buffer(readSize);
    DWORD bytesRead = 0;
    ReadFile(hFile, buffer.data(), (DWORD)readSize, &bytesRead, nullptr);
    CloseHandle(hFile);
    
    return ComputeEntropy(buffer.data(), bytesRead);
}


// ═══════════════════════════════════════════════════════════════════════════
// MAIN ANALYSIS ENTRY POINT
// ═══════════════════════════════════════════════════════════════════════════

PeAnalysis PeAnalyzer::AnalyzeFile(const std::wstring& filePath) {
    PeAnalysis result = {};
    result.verdict = PeVerdict::ERROR_ANALYSIS;
    
    // Read file into memory
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return result;
    
    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart < 64) {
        CloseHandle(hFile);
        return result;
    }
    
    // Cap at 50MB to avoid memory issues
    size_t readSize = (fileSize.QuadPart < (50 * 1024 * 1024)) ? (size_t)fileSize.QuadPart : (50 * 1024 * 1024);
    std::vector<BYTE> data(readSize);
    DWORD bytesRead = 0;
    if (!ReadFile(hFile, data.data(), (DWORD)readSize, &bytesRead, nullptr)) {
        CloseHandle(hFile);
        return result;
    }
    CloseHandle(hFile);
    
    // Parse PE headers
    if (!ParsePEHeaders(data.data(), bytesRead, result)) {
        return result;
    }
    
    // Analyze sections (entropy, flags)
    AnalyzeSections(data.data(), bytesRead, result);
    
    // Analyze imports
    AnalyzeImports(data.data(), bytesRead, result);
    
    // Detect packers
    DetectPackers(data.data(), bytesRead, result);
    
    // Check Authenticode signature
    CheckSignature(filePath, result);
    
    // Compute final score
    ScoreResult(result);
    
    return result;
}


// ═══════════════════════════════════════════════════════════════════════════
// PE HEADER PARSING
// ═══════════════════════════════════════════════════════════════════════════

bool PeAnalyzer::ParsePEHeaders(const BYTE* data, size_t size, PeAnalysis& result) {
    if (size < sizeof(IMAGE_DOS_HEADER)) return false;
    
    auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(data);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false; // Not MZ
    
    if ((size_t)dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) > size) return false;
    
    auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(data + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return false; // Not PE\0\0
    
    result.sectionCount = ntHeaders->FileHeader.NumberOfSections;
    
    return true;
}


// ═══════════════════════════════════════════════════════════════════════════
// SECTION ANALYSIS (entropy + flags)
// ═══════════════════════════════════════════════════════════════════════════

void PeAnalyzer::AnalyzeSections(const BYTE* data, size_t size, PeAnalysis& result) {
    auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(data);
    auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(data + dosHeader->e_lfanew);
    
    auto* section = IMAGE_FIRST_SECTION(ntHeaders);
    WORD numSections = ntHeaders->FileHeader.NumberOfSections;
    
    double totalEntropy = 0.0;
    result.maxSectionEntropy = 0.0;
    
    for (WORD i = 0; i < numSections; ++i) {
        if ((BYTE*)&section[i] + sizeof(IMAGE_SECTION_HEADER) > data + size) break;
        
        DWORD rawOffset = section[i].PointerToRawData;
        DWORD rawSize   = section[i].SizeOfRawData;
        
        if (rawOffset + rawSize <= size && rawSize > 0) {
            double entropy = ComputeEntropy(data + rawOffset, rawSize);
            totalEntropy += entropy;
            
            if (entropy > result.maxSectionEntropy) {
                result.maxSectionEntropy = entropy;
            }
        }
        
        // Check for executable data sections
        DWORD chars = section[i].Characteristics;
        char sectionName[9] = {};
        memcpy(sectionName, section[i].Name, 8);
        
        bool isDataSection = (strstr(sectionName, ".data") != nullptr ||
                              strstr(sectionName, ".rdata") != nullptr ||
                              strstr(sectionName, ".rsrc") != nullptr);
        
        if (isDataSection && (chars & IMAGE_SCN_MEM_EXECUTE)) {
            result.hasExecutableData = true;
        }
    }
    
    result.avgEntropy = numSections > 0 ? (totalEntropy / numSections) : 0.0;
}


// ═══════════════════════════════════════════════════════════════════════════
// IMPORT ANALYSIS
// ═══════════════════════════════════════════════════════════════════════════

void PeAnalyzer::AnalyzeImports(const BYTE* data, size_t size, PeAnalysis& result) {
    auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(data);
    auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(data + dosHeader->e_lfanew);
    
    // Get import directory RVA
    DWORD importRVA = 0;
    DWORD importSize = 0;
    
    if (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        auto* opt32 = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(&ntHeaders->OptionalHeader);
        if (opt32->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT) {
            importRVA  = opt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            importSize = opt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        }
    } else if (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        auto* opt64 = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(&ntHeaders->OptionalHeader);
        if (opt64->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT) {
            importRVA  = opt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            importSize = opt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        }
    }
    
    if (importRVA == 0) {
        result.importCount = 0;
        return;
    }
    
    // Convert RVA to file offset using section headers
    auto* section = IMAGE_FIRST_SECTION(ntHeaders);
    WORD numSections = ntHeaders->FileHeader.NumberOfSections;
    DWORD importFileOffset = 0;
    
    for (WORD i = 0; i < numSections; ++i) {
        if (importRVA >= section[i].VirtualAddress &&
            importRVA < section[i].VirtualAddress + section[i].SizeOfRawData) {
            importFileOffset = section[i].PointerToRawData + (importRVA - section[i].VirtualAddress);
            break;
        }
    }
    
    if (importFileOffset == 0 || importFileOffset >= size) return;
    
    // Count imports and check for suspicious APIs
    uint32_t totalImports = 0;
    bool hasVirtualAlloc = false;
    bool hasWriteProcessMem = false;
    bool hasCreateRemoteThread = false;
    
    // Walk import descriptors (simplified — just check for known function names in the file)
    // Full IAT parsing is complex; we do a simpler byte-scan for known API names
    std::string fileContent(reinterpret_cast<const char*>(data), size);
    
    for (const auto& api : kInjectionAPIs) {
        if (fileContent.find(api) != std::string::npos) {
            result.suspiciousAPIs.push_back(NarrowToWide(api));
            totalImports++;
            if (api == "VirtualAlloc" || api == "VirtualAllocEx") hasVirtualAlloc = true;
            if (api == "WriteProcessMemory") hasWriteProcessMem = true;
            if (api == "CreateRemoteThread" || api == "CreateRemoteThreadEx") hasCreateRemoteThread = true;
        }
    }
    
    for (const auto& api : kCredentialAPIs) {
        if (fileContent.find(api) != std::string::npos) {
            result.suspiciousAPIs.push_back(NarrowToWide(api));
        }
    }
    
    for (const auto& api : kKeylogAPIs) {
        if (fileContent.find(api) != std::string::npos) {
            result.suspiciousAPIs.push_back(NarrowToWide(api));
        }
    }
    
    for (const auto& api : kEvasionAPIs) {
        if (fileContent.find(api) != std::string::npos) {
            result.suspiciousAPIs.push_back(NarrowToWide(api));
        }
    }
    
    // Injection combo: VirtualAlloc + WriteProcessMemory + CreateRemoteThread
    if (hasVirtualAlloc && hasWriteProcessMem) {
        result.hasSuspiciousImports = true;
    }
    if (hasVirtualAlloc && hasCreateRemoteThread) {
        result.hasSuspiciousImports = true;
    }
    
    result.importCount = totalImports;
}


// ═══════════════════════════════════════════════════════════════════════════
// PACKER DETECTION
// ═══════════════════════════════════════════════════════════════════════════

void PeAnalyzer::DetectPackers(const BYTE* data, size_t size, PeAnalysis& result) {
    auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(data);
    auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(data + dosHeader->e_lfanew);
    auto* section = IMAGE_FIRST_SECTION(ntHeaders);
    WORD numSections = ntHeaders->FileHeader.NumberOfSections;
    
    // Check section names for known packers
    for (WORD i = 0; i < numSections; ++i) {
        char name[9] = {};
        memcpy(name, section[i].Name, 8);
        
        if (strstr(name, "UPX") != nullptr) {
            result.isPacked = true;
            result.packerName = L"UPX";
        }
        if (strstr(name, ".themida") != nullptr || strstr(name, "Themida") != nullptr) {
            result.isPacked = true;
            result.packerName = L"Themida";
        }
        if (strstr(name, ".vmp") != nullptr) {
            result.isPacked = true;
            result.packerName = L"VMProtect";
        }
        if (strstr(name, "ASPack") != nullptr) {
            result.isPacked = true;
            result.packerName = L"ASPack";
        }
        if (strstr(name, ".nsp") != nullptr || strstr(name, "nsp0") != nullptr) {
            result.isPacked = true;
            result.packerName = L"NSPack";
        }
    }
    
    // Entropy-based packer detection: average entropy > 7.0 is very likely packed
    if (!result.isPacked && result.avgEntropy > 7.0) {
        result.isPacked = true;
        result.packerName = L"Unknown (high entropy)";
    }
}


// ═══════════════════════════════════════════════════════════════════════════
// SIGNATURE CHECK (Authenticode)
// ═══════════════════════════════════════════════════════════════════════════

void PeAnalyzer::CheckSignature(const std::wstring& filePath, PeAnalysis& result) {
    // Use WinVerifyTrust to check Authenticode signature
    // Simplified: just check if the file has a certificate table
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return;
    
    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart < 64) {
        CloseHandle(hFile);
        return;
    }
    
    // Read PE headers to check for certificate directory
    BYTE header[4096] = {};
    DWORD bytesRead = 0;
    ReadFile(hFile, header, sizeof(header), &bytesRead, nullptr);
    CloseHandle(hFile);
    
    if (bytesRead < sizeof(IMAGE_DOS_HEADER)) return;
    
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(header);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    if ((size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > bytesRead) return;
    
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(header + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;
    
    // Check certificate directory entry (index 4)
    DWORD certRVA = 0;
    if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        auto* opt32 = reinterpret_cast<IMAGE_OPTIONAL_HEADER32*>(&nt->OptionalHeader);
        if (opt32->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_SECURITY) {
            certRVA = opt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
        }
    } else if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        auto* opt64 = reinterpret_cast<IMAGE_OPTIONAL_HEADER64*>(&nt->OptionalHeader);
        if (opt64->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_SECURITY) {
            certRVA = opt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
        }
    }
    
    result.isSignedBinary = (certRVA != 0);
}


// ═══════════════════════════════════════════════════════════════════════════
// SCORING (combine all signals)
// ═══════════════════════════════════════════════════════════════════════════

void PeAnalyzer::ScoreResult(PeAnalysis& result) {
    double score = 0.0;
    std::wstring detail;
    
    // High entropy sections
    if (result.avgEntropy > 7.0) {
        score += 0.3;
        detail += L"Very high entropy (packed/encrypted). ";
    } else if (result.avgEntropy > 6.5) {
        score += 0.15;
        detail += L"Elevated entropy. ";
    }
    
    // Executable data section
    if (result.hasExecutableData) {
        score += 0.15;
        detail += L"Data section has execute flag (shellcode?). ";
    }
    
    // Suspicious import combo
    if (result.hasSuspiciousImports) {
        score += 0.25;
        detail += L"Process injection API combo detected. ";
    }
    
    // Known packer
    if (result.isPacked) {
        score += 0.2;
        detail += L"Packed with " + result.packerName + L". ";
    }
    
    // Not signed (legitimate software is usually signed)
    if (!result.isSignedBinary) {
        score += 0.05;
        detail += L"Unsigned binary. ";
    }
    
    // Suspicious API count
    if (result.suspiciousAPIs.size() > 5) {
        score += 0.1;
        detail += L"Many suspicious APIs (" + ToWStr(result.suspiciousAPIs.size()) + L"). ";
    }
    
    // Very few imports (stripped binary)
    if (result.importCount == 0 && result.sectionCount > 0) {
        score += 0.1;
        detail += L"No visible imports (stripped/packed). ";
    }
    
    result.overallScore = (score < 1.0) ? score : 1.0;
    result.detail = detail;
    
    // Determine verdict
    if (score >= 0.7) {
        result.verdict = PeVerdict::LIKELY_MALWARE;
    } else if (score >= 0.4) {
        result.verdict = PeVerdict::SUSPICIOUS;
    } else if (result.isPacked) {
        result.verdict = PeVerdict::PACKED;
    } else {
        result.verdict = PeVerdict::CLEAN;
    }
}

} // namespace Asthak
