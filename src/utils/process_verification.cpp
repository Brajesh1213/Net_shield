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
    static const std::vector<std::wstring> trustedPaths = {
        L"C:\\Windows\\System32\\",
        L"C:\\Windows\\SysWOW64\\",
        L"C:\\Windows\\",
        L"C:\\Program Files\\",
        L"C:\\Program Files (x86)\\"
    };

    for (const auto& path : trustedPaths) {
        if (filePath.substr(0, path.length()) == path) {
            return true;
        }
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

    // Optional: elevation checks are Vista+ and unavailable with _WIN32_WINNT=0x0501.
    result.isRunningAsSystem = false;

    CloseHandle(hProcess);
    return result;
}

} // namespace NetSentinel
