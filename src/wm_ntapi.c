#include "internal/wm_ntapi.h"
#include "wm_log.h"

#ifdef WM_USE_NATIVE_API
NtReadVirtualMemoryFn     g_NtReadVirtualMemory     = NULL;
NtWriteVirtualMemoryFn    g_NtWriteVirtualMemory    = NULL;
NtAllocateVirtualMemoryFn g_NtAllocateVirtualMemory = NULL;
NtFreeVirtualMemoryFn     g_NtFreeVirtualMemory     = NULL;
NtQueryVirtualMemoryFn    g_NtQueryVirtualMemory    = NULL;
NtProtectVirtualMemoryFn  g_NtProtectVirtualMemory  = NULL;
#endif // WM_USE_NATIVE_API

/* ---------------------------------------------------------------------------
 * wmInit
 *
 * Must be called once before any other winmem function.
 *
 * Without WM_USE_NATIVE_API: no-op, always returns WM_OK.
 * With    WM_USE_NATIVE_API: resolves all NT function pointers from ntdll.dll
 *   via GetProcAddress. ntdll.dll is always mapped into every process before
 *   main() runs, so GetModuleHandle is sufficient — no LoadLibrary needed,
 *   and no trace is left in the IAT.
 *
 * Returns WM_ERROR_WINAPI_CALL if any pointer fails to resolve. This should
 * never happen on any supported Windows version; treat it as a fatal error.
 * --------------------------------------------------------------------------- */

WM_API WmResult wmNtInit(void)
{
#ifdef WM_USE_NATIVE_API
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        wmLogE(WM_STR("failed to get ntdll.dll handle"));
        return WM_ERROR_WINAPI_CALL;
    }

    g_NtReadVirtualMemory     = (NtReadVirtualMemoryFn)    GetProcAddress(ntdll, "NtReadVirtualMemory");
    g_NtWriteVirtualMemory    = (NtWriteVirtualMemoryFn)   GetProcAddress(ntdll, "NtWriteVirtualMemory");
    g_NtAllocateVirtualMemory = (NtAllocateVirtualMemoryFn)GetProcAddress(ntdll, "NtAllocateVirtualMemory");
    g_NtFreeVirtualMemory     = (NtFreeVirtualMemoryFn)    GetProcAddress(ntdll, "NtFreeVirtualMemory");
    g_NtQueryVirtualMemory    = (NtQueryVirtualMemoryFn)   GetProcAddress(ntdll, "NtQueryVirtualMemory");
    g_NtProtectVirtualMemory  = (NtProtectVirtualMemoryFn) GetProcAddress(ntdll, "NtProtectVirtualMemory");

    if (!g_NtReadVirtualMemory     || !g_NtWriteVirtualMemory   ||
        !g_NtAllocateVirtualMemory || !g_NtFreeVirtualMemory    ||
        !g_NtQueryVirtualMemory    || !g_NtProtectVirtualMemory) {
        wmLogE(WM_STR("failed to resolve one or more NT functions from ntdll.dll"));
        return WM_ERROR_WINAPI_CALL;
    }

    wmLogI(WM_STR("NT functions resolved from ntdll.dll"));
#endif // WM_USE_NATIVE_API
    return WM_OK;
}
