// false_positive_filter.cpp — False positive whitelist implementation
// ─────────────────────────────────────────────────────────────────────────────
// Checks digital signatures, paths, and known-good hashes before alerting.
// Significantly reduces false positives from legitimate Microsoft/vendor software.
// ─────────────────────────────────────────────────────────────────────────────
#include "utils/false_positive_filter.h"
#include "utils/logger.h"

#include <wincrypt.h>
#include <mscat.h>
#include <fstream>
#include <sstream>
#include <filesystem>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

namespace Asthak {

// ─────────────────────────────────────────────────────────────────────────────
// Built-in trusted Microsoft system paths
// ─────────────────────────────────────────────────────────────────────────────
const std::vector<std::wstring> FalsePositiveFilter::s_systemPaths = {
    L"C:\\Windows\\System32\\",
    L"C:\\Windows\\SysWOW64\\",
    L"C:\\Windows\\WinSxS\\",
    L"C:\\Program Files\\Windows Defender\\",
    L"C:\\Program Files\\Windows Defender Advanced Threat Protection\\",
    L"C:\\Program Files\\Microsoft\\",
    L"C:\\Program Files (x86)\\Microsoft\\",
    L"C:\\Program Files\\Common Files\\Microsoft Shared\\",
    L"C:\\ProgramData\\Microsoft\\Windows Defender\\",
};

// ─────────────────────────────────────────────────────────────────────────────
// Built-in trusted process names (system processes — never block)
// ─────────────────────────────────────────────────────────────────────────────
const std::vector<std::wstring> FalsePositiveFilter::s_trustedProcesses = {
    // Core Windows
    L"smss.exe", L"csrss.exe", L"wininit.exe", L"winlogon.exe",
    L"services.exe", L"lsass.exe", L"svchost.exe", L"explorer.exe",
    L"dwm.exe", L"conhost.exe", L"dllhost.exe", L"spoolsv.exe",
    L"taskhostw.exe", L"sihost.exe", L"fontdrvhost.exe",

    // Windows Security
    L"MsMpEng.exe",      // Windows Defender engine
    L"MpCopyAccelerator.exe",
    L"SecurityHealthService.exe",
    L"wscsvc.exe",
    L"WdNisSvc.exe",     // Network Inspection Service

    // Windows Update
    L"TiWorker.exe", L"TrustedInstaller.exe", L"wuauclt.exe",

    // Shell / UI
    L"SearchHost.exe", L"StartMenuExperienceHost.exe",
    L"ShellExperienceHost.exe", L"RuntimeBroker.exe",
    L"ApplicationFrameHost.exe", L"SystemSettings.exe",

    // Drivers / Hardware
    L"DriverStore.exe",

    // Asthak itself
    L"Asthak.exe",
};

// ─────────────────────────────────────────────────────────────────────────────
// Trusted certificate signers (substring match on subject CN)
// ─────────────────────────────────────────────────────────────────────────────
const std::vector<std::string> FalsePositiveFilter::s_trustedSigners = {
    "Microsoft Windows",
    "Microsoft Corporation",
    "Microsoft Windows Publisher",
    "Microsoft Windows Production PCA",
    "Intel Corporation",
    "NVIDIA Corporation",
    "AMD Inc.",
    "Advanced Micro Devices, Inc.",
    "Qualcomm",
    "Realtek Semiconductor",
    "Google LLC",
    "Mozilla Corporation",
    "Apple Inc.",
    "Valve Corporation",
    "Asthak Security",   // Our own signature
};

// ─────────────────────────────────────────────────────────────────────────────
// Singleton
// ─────────────────────────────────────────────────────────────────────────────
FalsePositiveFilter& FalsePositiveFilter::Instance() {
    static FalsePositiveFilter inst;
    return inst;
}

FalsePositiveFilter::FalsePositiveFilter() = default;

// ─────────────────────────────────────────────────────────────────────────────
void FalsePositiveFilter::Initialize() {
    Logger::Instance().Info(L"[FP Filter] Initialized — " +
        std::to_wstring(s_trustedProcesses.size()) + L" trusted processes, " +
        std::to_wstring(s_systemPaths.size()) + L" trusted paths, " +
        std::to_wstring(s_trustedSigners.size()) + L" trusted signers");
}

// ─────────────────────────────────────────────────────────────────────────────
// IsWhitelisted — main API: check if a file/process is trusted
// ─────────────────────────────────────────────────────────────────────────────
WhitelistResult FalsePositiveFilter::IsWhitelisted(const std::wstring& filePath, DWORD /*pid*/) const {
    WhitelistResult result;
    if (filePath.empty()) return result;

    // 1. Check path whitelist
    if (IsPathTrusted(filePath)) {
        result.isTrusted = true;
        result.reason    = WhitelistReason::PATH_WHITELISTED;
        result.details   = "Path is in trusted system directory";
        return result;
    }

    // 2. Check user-added path whitelist
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        std::wstring lower = filePath;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
        for (const auto& p : m_whitelistedPaths) {
            std::wstring pl = p;
            std::transform(pl.begin(), pl.end(), pl.begin(), ::towlower);
            if (lower.find(pl) == 0) {
                result.isTrusted = true;
                result.reason    = WhitelistReason::USER_APPROVED;
                result.details   = "User-approved path";
                return result;
            }
        }
    }

    // 3. Check digital signature
    std::string signer;
    if (IsSignedByMicrosoft(filePath)) {
        result.isTrusted = true;
        result.reason    = WhitelistReason::MICROSOFT_SIGNED;
        result.details   = "Signed by Microsoft";
        return result;
    }
    if (IsSignedByTrustedVendor(filePath, signer)) {
        result.isTrusted = true;
        result.reason    = WhitelistReason::TRUSTED_VENDOR;
        result.details   = "Signed by: " + signer;
        return result;
    }

    return result; // Not whitelisted
}

// ─────────────────────────────────────────────────────────────────────────────
WhitelistResult FalsePositiveFilter::IsHashWhitelisted(const std::string& sha256) const {
    std::lock_guard<std::mutex> lk(m_mutex);
    WhitelistResult result;
    std::string lower = sha256;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    if (m_whitelistedHashes.count(lower)) {
        result.isTrusted = true;
        result.reason    = WhitelistReason::HASH_WHITELISTED;
        result.details   = "SHA-256 in trusted hash list";
    }
    return result;
}

// ─────────────────────────────────────────────────────────────────────────────
WhitelistResult FalsePositiveFilter::IsProcessWhitelisted(const std::wstring& processName) const {
    WhitelistResult result;
    std::wstring lower = processName;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

    // Check built-in list
    for (const auto& tp : s_trustedProcesses) {
        std::wstring tpl = tp;
        std::transform(tpl.begin(), tpl.end(), tpl.begin(), ::towlower);
        if (lower == tpl) {
            result.isTrusted = true;
            result.reason    = WhitelistReason::PROCESS_WHITELISTED;
            result.details   = "Built-in trusted process";
            return result;
        }
    }

    // Check user list
    std::lock_guard<std::mutex> lk(m_mutex);
    if (m_whitelistedProcesses.count(lower)) {
        result.isTrusted = true;
        result.reason    = WhitelistReason::USER_APPROVED;
        result.details   = "User-approved process";
    }
    return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// IsPathTrusted — check if file is under a trusted system directory
// ─────────────────────────────────────────────────────────────────────────────
bool FalsePositiveFilter::IsPathTrusted(const std::wstring& filePath) const {
    std::wstring lower = filePath;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

    for (const auto& p : s_systemPaths) {
        std::wstring pl = p;
        std::transform(pl.begin(), pl.end(), pl.begin(), ::towlower);
        if (lower.find(pl) == 0) return true;
    }
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// IsSignedByMicrosoft — WinVerifyTrust check for Microsoft signature
// ─────────────────────────────────────────────────────────────────────────────
bool FalsePositiveFilter::IsSignedByMicrosoft(const std::wstring& filePath) const {
    // Use WinVerifyTrust to check Authenticode signature
    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = filePath.c_str();

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA trustData = {};
    trustData.cbStruct          = sizeof(WINTRUST_DATA);
    trustData.dwUIChoice        = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice     = WTD_CHOICE_FILE;
    trustData.pFile             = &fileInfo;
    trustData.dwStateAction     = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags       = WTD_CACHE_ONLY_URL_RETRIEVAL |
                                  WTD_DISABLE_MD2_MD4;

    LONG status = WinVerifyTrust(NULL, &policyGUID, &trustData);

    // Close handle
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGUID, &trustData);

    if (status != ERROR_SUCCESS) return false;

    // Now check certificate subject for "Microsoft"
    std::string signer;
    return IsSignedByTrustedVendor(filePath, signer) &&
           signer.find("Microsoft") != std::string::npos;
}

// ─────────────────────────────────────────────────────────────────────────────
// IsSignedByTrustedVendor — extracts certificate signer name and checks list
// ─────────────────────────────────────────────────────────────────────────────
bool FalsePositiveFilter::IsSignedByTrustedVendor(const std::wstring& filePath,
                                                    std::string& signerOut) const {
    // Open the cert store embedded in the PE
    HCERTSTORE hStore = NULL;
    HCRYPTMSG  hMsg   = NULL;

    BOOL ok = CryptQueryObject(
        CERT_QUERY_OBJECT_FILE,
        filePath.c_str(),
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0, nullptr, nullptr, nullptr,
        &hStore, &hMsg, nullptr);

    if (!ok || !hStore) return false;

    bool trusted = false;
    PCCERT_CONTEXT pCert = CertEnumCertificatesInStore(hStore, nullptr);
    while (pCert) {
        char name[256] = {};
        CertGetNameStringA(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, name, 256);
        std::string nameStr(name);

        for (const auto& signer : s_trustedSigners) {
            if (nameStr.find(signer) != std::string::npos) {
                signerOut = nameStr;
                trusted = true;
                break;
            }
        }
        if (trusted) { CertFreeCertificateContext(pCert); break; }
        pCert = CertEnumCertificatesInStore(hStore, pCert);
    }

    if (hStore) CertCloseStore(hStore, 0);
    if (hMsg)   CryptMsgClose(hMsg);

    return trusted;
}

// ─────────────────────────────────────────────────────────────────────────────
// Runtime whitelist additions
// ─────────────────────────────────────────────────────────────────────────────
void FalsePositiveFilter::WhitelistPath(const std::wstring& path) {
    std::lock_guard<std::mutex> lk(m_mutex);
    m_whitelistedPaths.insert(path);
    Logger::Instance().Info(L"[FP Filter] Path whitelisted: " + path);
}

void FalsePositiveFilter::WhitelistHash(const std::string& sha256) {
    std::lock_guard<std::mutex> lk(m_mutex);
    std::string lower = sha256;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    m_whitelistedHashes.insert(lower);
    Logger::Instance().Info(L"[FP Filter] Hash whitelisted: " +
        std::wstring(lower.begin(), lower.end()));
}

void FalsePositiveFilter::WhitelistProcessName(const std::wstring& name) {
    std::lock_guard<std::mutex> lk(m_mutex);
    std::wstring lower = name;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    m_whitelistedProcesses.insert(lower);
    Logger::Instance().Info(L"[FP Filter] Process whitelisted: " + lower);
}

} // namespace Asthak
