#pragma once
#include <string>

namespace Asthak {

class KillSwitch {
public:
    static bool IsDisabled();
    static bool Disable(const std::wstring& reason);
    static bool Enable();
    static std::wstring GetDisableReason();

private:
    static constexpr wchar_t kRegistryPath[] =
        L"SOFTWARE\\CyberGuardian\\Asthak";

    static constexpr wchar_t kValueName[] =
        L"DisableMonitoring";

    static constexpr wchar_t kReasonValue[] =
        L"DisableReason";
};

} // namespace Asthak
