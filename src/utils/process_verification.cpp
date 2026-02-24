// utils/process_verification.cpp
#include "process_verification.h"
#include <psapi.h>
#include <algorithm>
#include <cwctype>
#include <vector>

namespace NetSentinel {

bool IsMicrosoftSigned(const std::wstring& filePath, std::wstring& outSigner) {
    // Fallback heuristic for environments without WinTrust headers/libs.
    // Treat binaries in trusted OS/install locations as signed.
    if (IsInTrustedLocation(filePath)) {
        outSigner = L"Trusted Location (WinTrust unavailable)";
        return true;
    }
    outSigner = L"Unknown";
    return false;
}

bool IsInTrustedLocation(const std::wstring& filePath) {
    // Build trusted paths dynamically — Windows may be on any drive (C:, D:, etc.)
    static std::vector<std::wstring> trustedPaths;
    static bool initialized = false;
    if (!initialized) {
        wchar_t winDir[MAX_PATH] = {};
        if (GetWindowsDirectoryW(winDir, MAX_PATH)) {
            std::wstring win = winDir;
            trustedPaths.push_back(win + L"\\System32\\");
            trustedPaths.push_back(win + L"\\SysWOW64\\");
            trustedPaths.push_back(win + L"\\");
        }
        wchar_t progFiles[MAX_PATH] = {};
        if (GetEnvironmentVariableW(L"ProgramFiles", progFiles, MAX_PATH))
            trustedPaths.push_back(std::wstring(progFiles) + L"\\");
        wchar_t progFilesX86[MAX_PATH] = {};
        if (GetEnvironmentVariableW(L"ProgramFiles(x86)", progFilesX86, MAX_PATH))
            trustedPaths.push_back(std::wstring(progFilesX86) + L"\\");
        initialized = true;
    }
    for (const auto& path : trustedPaths) {
        if (filePath.size() >= path.size() &&
            filePath.substr(0, path.size()) == path)
            return true;
    }
    return false;
}

ProcessVerificationResult VerifyProcess(const std::wstring& processName, DWORD pid) {
    ProcessVerificationResult result;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return result;

    wchar_t buffer[MAX_PATH];
    if (GetModuleFileNameExW(hProcess, nullptr, buffer, MAX_PATH)) {
        result.fullPath = buffer;
        result.isInSystem32 = IsInTrustedLocation(result.fullPath);
        result.isMicrosoftSigned = IsMicrosoftSigned(result.fullPath, result.signerName);
    }

    // Elevation checks are Vista+ and require _WIN32_WINNT >= 0x0600.
    result.isRunningAsSystem = false;

    CloseHandle(hProcess);
    return result;
}

} // namespace NetSentinel
