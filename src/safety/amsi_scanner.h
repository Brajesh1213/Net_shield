// amsi_scanner.h — AMSI (Antimalware Scan Interface) integration
// AMSI lets us scan PowerShell scripts, VBScript, JScript BEFORE they run.
// Works by loading amsi.dll and calling AmsiScanBuffer/AmsiScanString.
// This is how Windows Defender and Malwarebytes hook into PowerShell.
#pragma once

#include <windows.h>
#include <string>
#include <functional>
#include <atomic>

// ── MinGW compatibility: amsi.h is NOT shipped with MinGW. ───────────────────
// Define the AMSI types manually. These are stable ABI-level opaque handles
// documented by Microsoft. Using void* is safe — that is what they really are.
#ifndef HAMSICONTEXT
    // Opaque handle to an AMSI context (one per app per process)
    typedef void* HAMSICONTEXT;
    // Opaque handle to an AMSI scan session (one per scan call)
    typedef void* HAMSISESSION;
    // AMSI scan result enum
    typedef enum tagAMSI_RESULT {
        AMSI_RESULT_CLEAN            = 0,
        AMSI_RESULT_NOT_DETECTED     = 1,
        AMSI_RESULT_BLOCKED_BY_ADMIN_BEGIN = 16384,
        AMSI_RESULT_BLOCKED_BY_ADMIN_END   = 20479,
        AMSI_RESULT_DETECTED         = 32768,
    } AMSI_RESULT;
    inline bool AmsiResultIsMalware(AMSI_RESULT r) {
        return (int)r >= (int)AMSI_RESULT_DETECTED;
    }
#endif
// ─────────────────────────────────────────────────────────────────────────────

namespace Asthak {

enum class AmsiVerdict {
    CLEAN,        // Script is safe
    DETECTED,     // Malicious script detected
    BLOCKED,      // Script blocked from executing
    NOT_AVAILABLE // AMSI not supported on this system
};

struct AmsiAlert {
    std::wstring contentName;     // e.g. "PS1:PID1234:powershell.exe"
    std::wstring scriptContent;   // First 512 chars of the script
    std::wstring appName;         // e.g. "PowerShell", "VBScript"
    AmsiVerdict  verdict;
    std::wstring malwareName;     // e.g. "Trojan:PS1/Meterpreter"
    bool         blocked;
};

using AmsiAlertCallback = std::function<void(const AmsiAlert&)>;

class AmsiScanner {
public:
    static AmsiScanner& Instance();

    // Initialize AMSI — loads amsi.dll, registers as an AMSI provider consumer
    bool Initialize(const std::wstring& appName = L"Asthak");
    void Shutdown();

    // Scan a buffer of script content before execution
    AmsiVerdict ScanBuffer(const void* buffer, ULONG length,
                           const std::wstring& contentName,
                           AmsiAlert& outAlert);

    // Scan a wide string (PowerShell script text)
    AmsiVerdict ScanString(const std::wstring& script,
                           const std::wstring& contentName,
                           AmsiAlert& outAlert);

    // Hook into ETW to intercept PowerShell ScriptBlock events
    // and scan them through AMSI before logging
    void ScanEtwPowerShellScript(const std::wstring& scriptBlock,
                                  DWORD pid,
                                  const std::wstring& processName);

    void SetCallback(AmsiAlertCallback cb) { m_callback = cb; }

    bool IsAvailable()          const { return m_initialized; }
    uint64_t GetScansTotal()    const { return m_scansTotal.load(); }
    uint64_t GetDetections()    const { return m_detections.load(); }

private:
    AmsiScanner() = default;

    // AMSI function pointer types — use typedef form; MinGW handles WINAPI
    // correctly in typedef but not in using-alias form.
    typedef HRESULT (__stdcall* PFN_AmsiInitialize)   (LPCWSTR appName, HAMSICONTEXT* amsiContext);
    typedef void    (__stdcall* PFN_AmsiUninitialize) (HAMSICONTEXT amsiContext);
    typedef HRESULT (__stdcall* PFN_AmsiScanBuffer)   (HAMSICONTEXT amsiContext, PVOID buffer,
                                                        ULONG length, LPCWSTR contentName,
                                                        HAMSISESSION session, AMSI_RESULT* result);
    typedef HRESULT (__stdcall* PFN_AmsiScanString)   (HAMSICONTEXT amsiContext, LPCWSTR string,
                                                        LPCWSTR contentName, HAMSISESSION session,
                                                        AMSI_RESULT* result);
    typedef HRESULT (__stdcall* PFN_AmsiOpenSession)  (HAMSICONTEXT amsiContext, HAMSISESSION* session);
    typedef void    (__stdcall* PFN_AmsiCloseSession) (HAMSICONTEXT amsiContext, HAMSISESSION session);

    HMODULE             m_amsiDll{nullptr};
    HAMSICONTEXT        m_amsiCtx{nullptr};

    PFN_AmsiInitialize   m_pfnInit{nullptr};
    PFN_AmsiUninitialize m_pfnUninit{nullptr};
    PFN_AmsiScanBuffer   m_pfnScanBuf{nullptr};
    PFN_AmsiScanString   m_pfnScanStr{nullptr};
    PFN_AmsiOpenSession  m_pfnOpenSession{nullptr};
    PFN_AmsiCloseSession m_pfnCloseSession{nullptr};

    AmsiAlertCallback   m_callback;
    bool                m_initialized{false};
    std::atomic<uint64_t> m_scansTotal{0};
    std::atomic<uint64_t> m_detections{0};
};

} // namespace Asthak