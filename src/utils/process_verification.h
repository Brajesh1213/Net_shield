// utils/process_verification.h
#pragma once
#include <string>
#include <windows.h>

namespace NetSentinel {

struct ProcessVerificationResult {
    bool isMicrosoftSigned = false;
    bool isInSystem32 = false;
    bool isRunningAsSystem = false; // Optional: Check token integrity
    std::wstring signerName;
    std::wstring fullPath;
};

ProcessVerificationResult VerifyProcess(const std::wstring& processName, DWORD pid);
bool IsMicrosoftSigned(const std::wstring& filePath, std::wstring& outSigner);
bool IsInTrustedLocation(const std::wstring& filePath);

} // namespace NetSentinel