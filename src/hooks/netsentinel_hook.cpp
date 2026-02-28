#include <windows.h>
#include <iostream>
#include <cstdint>

// Simple x64 JMP patch (Unconditional jump via RAX)
// WARNING: This is a destructive hook. It overwrites the first 12 bytes and does 
// not save the original trampoline. For an EDR, we just permanently block the function.
void PatchFunction(void* target, void* hook) {
    DWORD oldProtect;
    if (VirtualProtect(target, 12, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        // x64 assembly to jump to an absolutely 64-bit address:
        // mov rax, [hook_address]
        // jmp rax
        uint8_t jmp[] = {
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, hook
            0xFF, 0xE0 // jmp rax
        };
        *reinterpret_cast<void**>(&jmp[2]) = hook;

        memcpy(target, jmp, sizeof(jmp));
        VirtualProtect(target, 12, oldProtect, &oldProtect);
    }
}

// Our fake/protective replacement for CreateRemoteThread
HANDLE WINAPI Hooked_CreateRemoteThread(
    HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)
{
    // Alert the system!
    OutputDebugStringW(L"[NetSentinel-EDR] EXPLOIT MITIGATED: Blocked malicious attempt to inject code into another process!");
    
    // We deny the operation. Malware fails to inject.
    SetLastError(ERROR_ACCESS_DENIED);
    return NULL; 
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        
        // Find the real target function in Kernel32
        void* target = (void*)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "CreateRemoteThread");
        
        if (target) {
            PatchFunction(target, (void*)Hooked_CreateRemoteThread);
            OutputDebugStringW(L"[NetSentinel-EDR] Protective DLL successfully injected. API Hooks active.");
        }
    }
    return TRUE;
}
