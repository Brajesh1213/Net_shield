// amsi_scanner.h — AMSI (Antimalware Scan Interface) integration
// AMSI lets us scan PowerShell scripts, VBScript, JScript BEFORE they run.
// Works by loading amsi.dll and calling AmsiScanBuffer/AmsiScanString.
// This is how Windows Defender and Malwarebytes hook into PowerShell.
#pragma once

#include <windows.h>
#include <string>
#include <functional>
#include <atomic>

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

    // AMSI function pointer types
    using PFN_AmsiInitialize    = HRESULT (WINAPI*)(LPCWSTR appName, HAMSICONTEXT* amsiContext);
    using PFN_AmsiUninitialize  = void    (WINAPI*)(HAMSICONTEXT amsiContext);
    using PFN_AmsiScanBuffer    = HRESULT (WINAPI*)(HAMSICONTEXT amsiContext, PVOID buffer,
                                                     ULONG length, LPCWSTR contentName,
                                                     HAMSISESSION session, AMSI_RESULT* result);
    using PFN_AmsiScanString    = HRESULT (WINAPI*)(HAMSICONTEXT amsiContext, LPCWSTR string,
                                                     LPCWSTR contentName, HAMSISESSION session,
                                                     AMSI_RESULT* result);
    using PFN_AmsiOpenSession   = HRESULT (WINAPI*)(HAMSICONTEXT amsiContext, HAMSISESSION* session);
    using PFN_AmsiCloseSession  = void    (WINAPI*)(HAMSICONTEXT amsiContext, HAMSISESSION session);

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
