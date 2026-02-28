#include "kill_switch.h"
#include <windows.h>
#include <aclapi.h>

namespace Asthak {

constexpr wchar_t KillSwitch::kRegistryPath[];
constexpr wchar_t KillSwitch::kValueName[];
constexpr wchar_t KillSwitch::kReasonValue[];

/* ---------------- Helper: Lock Registry ACL ---------------- */

static bool LockRegistryAcl(HKEY hKey) {
    EXPLICIT_ACCESSW ea[2]{};
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;

    PSID systemSid = nullptr;
    PSID adminSid  = nullptr;

    AllocateAndInitializeSid(&ntAuth, 1,
        SECURITY_LOCAL_SYSTEM_RID,
        0,0,0,0,0,0,0,
        &systemSid);

    AllocateAndInitializeSid(&ntAuth, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0,0,0,0,0,0,
        &adminSid);

    // SYSTEM → FULL CONTROL
    ea[0].grfAccessPermissions = KEY_ALL_ACCESS;
    ea[0].grfAccessMode = SET_ACCESS;
    ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[0].Trustee.ptstrName = (LPWSTR)systemSid;

    // ADMIN → READ ONLY
    ea[1].grfAccessPermissions = KEY_READ;
    ea[1].grfAccessMode = SET_ACCESS;
    ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[1].Trustee.ptstrName = (LPWSTR)adminSid;

    PACL newDacl = nullptr;
    SetEntriesInAclW(2, ea, nullptr, &newDacl);

    bool ok = (SetSecurityInfo(
        hKey,
        SE_REGISTRY_KEY,
        DACL_SECURITY_INFORMATION,
        nullptr, nullptr,
        newDacl,
        nullptr) == ERROR_SUCCESS);

    LocalFree(newDacl);
    FreeSid(systemSid);
    FreeSid(adminSid);

    return ok;
}

/* ---------------- KillSwitch APIs ---------------- */

bool KillSwitch::IsDisabled() {
    HKEY hKey;
    DWORD val = 0, size = sizeof(val);

    if (RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            kRegistryPath,
            0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return false;

    bool disabled =
        (RegQueryValueExW(
            hKey, kValueName,
            nullptr, nullptr,
            (BYTE*)&val, &size) == ERROR_SUCCESS && val == 1);

    RegCloseKey(hKey);
    return disabled;
}

bool KillSwitch::Disable(const std::wstring& reason) {
    HKEY hKey;
    if (RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            kRegistryPath,
            0, nullptr, 0,
            KEY_ALL_ACCESS,
            nullptr, &hKey, nullptr) != ERROR_SUCCESS)
        return false;

    DWORD val = 1;
    RegSetValueExW(hKey, kValueName, 0, REG_DWORD,
                   (BYTE*)&val, sizeof(val));

    RegSetValueExW(hKey, kReasonValue, 0, REG_SZ,
                   (BYTE*)reason.c_str(),
                   (DWORD)((reason.size() + 1) * sizeof(wchar_t)));

    LockRegistryAcl(hKey);
    RegCloseKey(hKey);
    return true;
}

bool KillSwitch::Enable() {
    HKEY hKey;
    if (RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            kRegistryPath,
            0, KEY_ALL_ACCESS, &hKey) != ERROR_SUCCESS)
        return false;

    RegDeleteValueW(hKey, kValueName);
    RegDeleteValueW(hKey, kReasonValue);
    RegCloseKey(hKey);
    return true;
}

std::wstring KillSwitch::GetDisableReason() {
    HKEY hKey;
    wchar_t buf[512]{};
    DWORD size = sizeof(buf);

    if (RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            kRegistryPath,
            0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return L"";

    if (RegQueryValueExW(
            hKey, kReasonValue,
            nullptr, nullptr,
            (BYTE*)buf, &size) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return L"";
    }

    RegCloseKey(hKey);
    return buf;
}

} // namespace Asthak
