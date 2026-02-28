// ransomware_guard.cpp — Ransomware detection via behavioral analysis
// Detects mass file encryption by monitoring per-process file modification
// patterns and entropy changes. Provides VSS-based recovery.
//
// Detection heuristics (same as used by Malwarebytes ransomware rollback):
//   1. High rate of file modifications by a single process
//   2. Significant entropy increase in modified files (plaintext → encrypted)
//   3. Suspicious rename patterns (.encrypted, .locked, .cry, random extensions)
//   4. File deletion after creating encrypted copies
//
// When ransomware is detected:
//   1. Alert is raised immediately
//   2. Process can be terminated via kill_switch
//   3. VSS snapshots can be used for rollback (if available)

#include "safety/ransomware_guard.h"
#include "utils/logger.h"
#include <algorithm>
#include <sstream>
#include <cwctype>
#include <cmath>

namespace Asthak {

namespace {
template<typename T>
std::wstring ToWStr(T v) { std::wostringstream o; o << v; return o.str(); }

// Known ransomware file extensions
static const std::vector<std::wstring> kRansomwareExtensions = {
    L".encrypted", L".locked", L".crypt", L".crypto", L".enc",
    L".locky", L".cerber", L".zepto", L".odin", L".aesir",
    L".thor", L".zzzzz", L".micro", L".ccc",
    L".vvv", L".xxx", L".abc", L".ecc",
    L".ezz", L".exx", L".xyz",
    L".crinf", L".r5a", L".xrtn",
    L".XTBL", L".crysis", L".dharma",
    L".wallet", L".arena", L".java",
    L".bip", L".combo", L".cmb",
    L".onion", L".mira", L".petra",
    L".wncry", L".wcry", L".wannacry", L".wanacry",
    L".WNCRYPT", L".WCRYT",
};

// Check if an extension is suspicious (ransomware-like)
bool IsRansomwareExtension(const std::wstring& path) {
    size_t dotPos = path.rfind(L'.');
    if (dotPos == std::wstring::npos) return false;
    
    std::wstring ext = path.substr(dotPos);
    std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);
    
    for (const auto& re : kRansomwareExtensions) {
        if (ext == re) return true;
    }
    
    // Check for random-looking extensions (8+ chars, all alphanumeric)
    if (ext.size() > 8) {
        bool allAlphaNum = true;
        for (size_t i = 1; i < ext.size(); ++i) {
            if (!std::iswalnum(ext[i])) { allAlphaNum = false; break; }
        }
        if (allAlphaNum) return true;
    }
    
    return false;
}
} // anonymous namespace


RansomwareGuard& RansomwareGuard::Instance() {
    static RansomwareGuard instance;
    return instance;
}

bool RansomwareGuard::Initialize() {
    Logger::Instance().Info(L"[RansomGuard] Initialized — monitoring for mass encryption behavior");
    return true;
}

DWORD WINAPI RansomwareGuard::CleanupThreadProc(LPVOID param) {
    auto* self = static_cast<RansomwareGuard*>(param);
    
    while (self->m_running.load()) {
        Sleep(30000); // Every 30 seconds
        
        std::lock_guard<std::mutex> lock(self->m_mutex);
        DWORD now = GetTickCount();
        
        // Remove old entries (older than 60 seconds)
        auto it = self->m_processActivity.begin();
        while (it != self->m_processActivity.end()) {
            if (now - it->second.firstSeenTick > 60000) {
                it = self->m_processActivity.erase(it);
            } else {
                ++it;
            }
        }
    }
    
    return 0;
}

void RansomwareGuard::Start(RansomwareCallback callback) {
    if (m_running.load()) return;
    
    m_callback = callback;
    m_running  = true;
    
    // Start cleanup thread
    m_cleanupThread = CreateThread(nullptr, 0, CleanupThreadProc, this, 0, nullptr);
    
    Logger::Instance().Info(L"[RansomGuard] Active protection started");
}

void RansomwareGuard::Stop() {
    m_running = false;
    if (m_cleanupThread) {
        WaitForSingleObject(m_cleanupThread, 5000);
        CloseHandle(m_cleanupThread);
        m_cleanupThread = nullptr;
    }
}


// ═══════════════════════════════════════════════════════════════════════════
// FILE MODIFICATION TRACKING
// ═══════════════════════════════════════════════════════════════════════════

double RansomwareGuard::ComputeFileEntropy(const std::wstring& filePath) {
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return -1.0;
    
    // Read first 64KB
    BYTE buffer[65536] = {};
    DWORD bytesRead = 0;
    ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, nullptr);
    CloseHandle(hFile);
    
    if (bytesRead == 0) return 0.0;
    
    uint64_t freq[256] = {};
    for (DWORD i = 0; i < bytesRead; ++i) {
        freq[buffer[i]]++;
    }
    
    double entropy = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (freq[i] == 0) continue;
        double p = (double)freq[i] / (double)bytesRead;
        entropy -= p * log2(p);
    }
    
    return entropy;
}

void RansomwareGuard::OnFileModified(const std::wstring& filePath, DWORD pid, const std::wstring& processName) {
    if (!m_running.load() || pid == 0) return;
    
    m_eventsProcessed.fetch_add(1);
    
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto& activity = m_processActivity[pid];
    if (activity.firstSeenTick == 0) {
        activity.firstSeenTick = GetTickCount();
    }
    
    activity.filesModified++;
    
    // Check for ransomware extension
    if (IsRansomwareExtension(filePath)) {
        activity.filesRenamed++;
    }
    
    // Track recent files (max 50)
    if (activity.recentFiles.size() < 50) {
        activity.recentFiles.push_back(filePath);
    }
    
    // Compute entropy of the modified file
    double entropy = ComputeFileEntropy(filePath);
    if (entropy > 7.0) {
        activity.totalEntropyDelta += 1.0; // High entropy contribution
    }
    
    // Check if this process looks like ransomware
    if (IsRansomwarePattern(activity)) {
        m_alertsRaised.fetch_add(1);
        
        if (m_callback) {
            RansomwareAlert alert;
            alert.pid           = pid;
            alert.processName   = processName;
            alert.filesAffected = activity.filesModified;
            alert.avgEntropy    = activity.totalEntropyDelta / activity.filesModified;
            alert.detail        = L"Mass file encryption detected! Process " + processName +
                                  L" (PID: " + ToWStr(pid) + L") modified " +
                                  ToWStr(activity.filesModified) + L" files with high entropy";
            
            m_callback(alert);
        }
        
        Logger::Instance().Critical(L"[RansomGuard] RANSOMWARE DETECTED: " + processName +
                                    L" PID=" + ToWStr(pid) +
                                    L" files=" + ToWStr(activity.filesModified));
        
        // Reset to avoid repeated alerts for same process
        activity.filesModified = 0;
        activity.filesRenamed  = 0;
        activity.totalEntropyDelta = 0;
        activity.recentFiles.clear();
    }
}

bool RansomwareGuard::IsRansomwarePattern(const ProcessActivity& activity) {
    DWORD elapsed = GetTickCount() - activity.firstSeenTick;
    if (elapsed == 0) elapsed = 1;
    
    // Heuristic 1: High file modification rate (> 20 files in 10 seconds)
    double filesPerSecond = (double)activity.filesModified / ((double)elapsed / 1000.0);
    bool highRate = (activity.filesModified >= 20 && filesPerSecond > 2.0);
    
    // Heuristic 2: Many files with ransomware extensions
    bool manyRenames = (activity.filesRenamed >= 5);
    
    // Heuristic 3: High average entropy in modified files
    double avgEntropy = (activity.filesModified > 0) ?
        (activity.totalEntropyDelta / activity.filesModified) : 0.0;
    bool highEntropy = (avgEntropy > 0.5 && activity.filesModified >= 10);
    
    // Combined: any two signals = ransomware
    int signals = (highRate ? 1 : 0) + (manyRenames ? 1 : 0) + (highEntropy ? 1 : 0);
    return signals >= 2;
}


// ═══════════════════════════════════════════════════════════════════════════
// VSS SNAPSHOT (Volume Shadow Copy)
// ═══════════════════════════════════════════════════════════════════════════

bool RansomwareGuard::CreateSnapshot() {
    // Execute vssadmin to create a shadow copy
    // This requires admin privileges
    STARTUPINFOW si = {};
    PROCESS_INFORMATION pi = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    WCHAR cmd[] = L"vssadmin create shadow /for=C:";
    
    BOOL success = CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE,
                                   CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    if (success) {
        WaitForSingleObject(pi.hProcess, 30000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        Logger::Instance().Info(L"[RansomGuard] VSS snapshot created for C:");
        return true;
    }
    
    Logger::Instance().Warning(L"[RansomGuard] Failed to create VSS snapshot (needs admin)");
    return false;
}

bool RansomwareGuard::RestoreFromSnapshot(const std::wstring& targetPath) {
    // In production: enumerate shadow copies via COM (IVssBackupComponents)
    // and restore specific files. For now, log the intent.
    Logger::Instance().Info(L"[RansomGuard] Restore requested for: " + targetPath);
    return false; // TODO: implement full VSS restore via COM
}

} // namespace Asthak
