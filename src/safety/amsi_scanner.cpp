// amsi_scanner.cpp — AMSI (Antimalware Scan Interface) integration
// Microsoft AMSI: https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal
//
// How it works:
//   1. Load amsi.dll at runtime (available since Windows 10 1511+)
//   2. Call AmsiInitialize to register as an AMSI consumer
//   3. For each script/buffer: AmsiOpenSession → AmsiScanBuffer → AmsiCloseSession
//   4. AMSI_RESULT tells us if it's malicious
//
// Malicious result codes:
//   AMSI_RESULT_CLEAN (0)             = safe
//   AMSI_RESULT_NOT_DETECTED (1)      = safe
//   AMSI_RESULT_BLOCKED_BY_ADMIN (...)= admin blocked
//   AMSI_RESULT_DETECTED (32768)      = MALWARE DETECTED — block execution!
//
// PowerShell, Office macros, WMI scripts, JS all go through AMSI.
// This is how we catch obfuscated PowerShell that signature scanners miss.

#include "safety/amsi_scanner.h"
#include "safety/response_engine.h"
#include "utils/logger.h"
#include <sstream>
#include <algorithm>

// amsi.h may not be in MinGW headers, define what we need manually
#ifndef AMSI_RESULT_DETECTED
    typedef void* HAMSICONTEXT;
    typedef void* HAMSISESSION;
    typedef enum AMSI_RESULT {
        AMSI_RESULT_CLEAN            = 0,
        AMSI_RESULT_NOT_DETECTED     = 1,
        AMSI_RESULT_BLOCKED_BY_ADMIN_BEGIN = 16384,
        AMSI_RESULT_BLOCKED_BY_ADMIN_END   = 20479,
        AMSI_RESULT_DETECTED         = 32768,
    } AMSI_RESULT;
    inline bool AmsiResultIsMalware(AMSI_RESULT r) { return r >= AMSI_RESULT_DETECTED; }
#endif

namespace Asthak {

namespace {
template<typename T>
std::wstring ToWStr(T v) { std::wostringstream o; o << v; return o.str(); }
} // anonymous namespace

AmsiScanner& AmsiScanner::Instance() {
    static AmsiScanner instance;
    return instance;
}

bool AmsiScanner::Initialize(const std::wstring& appName) {
    if (m_initialized) return true;

    // Load amsi.dll dynamically — it's available since Windows 10 1511
    m_amsiDll = LoadLibraryW(L"amsi.dll");
    if (!m_amsiDll) {
        Logger::Instance().Warning(L"[AMSI] amsi.dll not available (Windows 10 1511+ required)");
        return false;
    }

    // Get function pointers
    m_pfnInit         = (PFN_AmsiInitialize)   GetProcAddress(m_amsiDll, "AmsiInitialize");
    m_pfnUninit       = (PFN_AmsiUninitialize) GetProcAddress(m_amsiDll, "AmsiUninitialize");
    m_pfnScanBuf      = (PFN_AmsiScanBuffer)   GetProcAddress(m_amsiDll, "AmsiScanBuffer");
    m_pfnScanStr      = (PFN_AmsiScanString)   GetProcAddress(m_amsiDll, "AmsiScanString");
    m_pfnOpenSession  = (PFN_AmsiOpenSession)  GetProcAddress(m_amsiDll, "AmsiOpenSession");
    m_pfnCloseSession = (PFN_AmsiCloseSession) GetProcAddress(m_amsiDll, "AmsiCloseSession");

    if (!m_pfnInit || !m_pfnScanBuf || !m_pfnScanStr || !m_pfnOpenSession) {
        Logger::Instance().Warning(L"[AMSI] Failed to resolve AMSI function pointers");
        FreeLibrary(m_amsiDll);
        m_amsiDll = nullptr;
        return false;
    }

    // Initialize AMSI context
    HRESULT hr = m_pfnInit(appName.c_str(), &m_amsiCtx);
    if (FAILED(hr)) {
        Logger::Instance().Warning(L"[AMSI] AmsiInitialize failed: " + ToWStr(hr));
        FreeLibrary(m_amsiDll);
        m_amsiDll = nullptr;
        return false;
    }

    m_initialized = true;
    Logger::Instance().Info(L"[AMSI] Initialized — scanning PowerShell/scripts before execution");
    return true;
}

void AmsiScanner::Shutdown() {
    if (!m_initialized) return;
    if (m_pfnUninit && m_amsiCtx) {
        m_pfnUninit(m_amsiCtx);
        m_amsiCtx = nullptr;
    }
    if (m_amsiDll) {
        FreeLibrary(m_amsiDll);
        m_amsiDll = nullptr;
    }
    m_initialized = false;
}

AmsiVerdict AmsiScanner::ScanBuffer(const void* buffer, ULONG length,
                                     const std::wstring& contentName,
                                     AmsiAlert& outAlert) {
    if (!m_initialized || !buffer || length == 0) return AmsiVerdict::NOT_AVAILABLE;

    m_scansTotal.fetch_add(1);

    HAMSISESSION session = nullptr;
    if (m_pfnOpenSession) {
        m_pfnOpenSession(m_amsiCtx, &session);
    }

    AMSI_RESULT result = AMSI_RESULT_CLEAN;
    HRESULT hr = m_pfnScanBuf(m_amsiCtx, const_cast<PVOID>(buffer), length,
                               contentName.c_str(), session, &result);

    if (session && m_pfnCloseSession) {
        m_pfnCloseSession(m_amsiCtx, session);
    }

    if (FAILED(hr)) return AmsiVerdict::CLEAN;

    outAlert.contentName = contentName;
    outAlert.verdict     = AmsiVerdict::CLEAN;

    if (AmsiResultIsMalware(result)) {
        m_detections.fetch_add(1);
        outAlert.verdict    = AmsiVerdict::DETECTED;
        outAlert.blocked    = true;
        outAlert.malwareName = L"AMSI:Detected";

        Logger::Instance().Critical(L"[AMSI] MALICIOUS SCRIPT DETECTED: " + contentName);

        if (m_callback) m_callback(outAlert);
        return AmsiVerdict::DETECTED;
    }

    return AmsiVerdict::CLEAN;
}

AmsiVerdict AmsiScanner::ScanString(const std::wstring& script,
                                     const std::wstring& contentName,
                                     AmsiAlert& outAlert) {
    if (!m_initialized || script.empty()) return AmsiVerdict::NOT_AVAILABLE;

    m_scansTotal.fetch_add(1);

    HAMSISESSION session = nullptr;
    if (m_pfnOpenSession) {
        m_pfnOpenSession(m_amsiCtx, &session);
    }

    AMSI_RESULT result = AMSI_RESULT_CLEAN;
    HRESULT hr = m_pfnScanStr(m_amsiCtx, script.c_str(), contentName.c_str(),
                               session, &result);

    if (session && m_pfnCloseSession) {
        m_pfnCloseSession(m_amsiCtx, session);
    }

    if (FAILED(hr)) return AmsiVerdict::CLEAN;

    outAlert.contentName = contentName;
    outAlert.verdict     = AmsiVerdict::CLEAN;

    if (AmsiResultIsMalware(result)) {
        m_detections.fetch_add(1);

        // Capture first 512 chars of script for alert
        outAlert.scriptContent = script.substr(0, std::min((size_t)512, script.size()));
        outAlert.verdict       = AmsiVerdict::DETECTED;
        outAlert.blocked       = true;
        outAlert.malwareName   = L"AMSI:Script.Detected/" + contentName;

        Logger::Instance().Critical(L"[AMSI] MALICIOUS SCRIPT: " + contentName +
                                   L" | Preview: " + outAlert.scriptContent.substr(0, 100));

        if (m_callback) m_callback(outAlert);
        return AmsiVerdict::DETECTED;
    }

    return AmsiVerdict::CLEAN;
}

void AmsiScanner::ScanEtwPowerShellScript(const std::wstring& scriptBlock,
                                           DWORD pid,
                                           const std::wstring& processName) {
    if (!m_initialized || scriptBlock.empty()) return;

    std::wstring name = L"PS1:PID" + ToWStr(pid) + L":" + processName;
    AmsiAlert alert;
    AmsiVerdict v = ScanString(scriptBlock, name, alert);

    if (v == AmsiVerdict::DETECTED) {
        // Feed into ResponseEngine
        ThreatIncident inc;
        inc.source          = ThreatSource::ETW_CONSUMER;
        inc.action          = ResponseAction::KILL_PROCESS;
        inc.pid             = pid;
        inc.processName     = processName;
        inc.confidenceScore = 0.95;
        inc.detail          = L"AMSI detected malicious PowerShell: " + alert.malwareName;
        ResponseEngine::Instance().HandleThreat(inc);
    }
}

} // namespace Asthak
