cmake # Quick Fix for UDP Table Issue

The `GetExtendedUdpTable` function is not available in MinGW's iphlpapi.lib. Here's a quick fix:

## Solution: Dynamic Loading

Replace the UDP table implementation to dynamically load the function:

```cpp
// In udp_table.cpp, add at top:
#include <windows.h>

namespace {
    typedef DWORD (WINAPI *PFN_GetExtendedUdpTable)(
        PVOID pUdpTable,
        PDWORD pdwSize,
        BOOL bOrder,
        ULONG ulAf,
        UDP_TABLE_CLASS TableClass,
        ULONG Reserved
    );
    
    PFN_GetExtendedUdpTable g_pfnGetExtendedUdpTable = nullptr;
    HMODULE g_hIphlpapi = nullptr;
    
    bool LoadUdpTableFunction() {
        if (g_pfnGetExtendedUdpTable) return true;
        
        g_hIphlpapi = LoadLibraryW(L"iphlpapi.dll");
        if (!g_hIphlpapi) return false;
        
        g_pfnGetExtendedUdpTable = (PFN_GetExtendedUdpTable)
            GetProcAddress(g_hIphlpapi, "GetExtendedUdpTable");
        
        return g_pfnGetExtendedUdpTable != nullptr;
    }
}

// Then in GetIPv4Table(), replace:
// GetExtendedUdpTable(...)
// with:
if (!LoadUdpTableFunction()) {
    return connections; // Empty if function not available
}
g_pfnGetExtendedUdpTable(...)
```

This will work on Windows systems even if MinGW's lib doesn't have it.
