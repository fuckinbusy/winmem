#include "wm_internal.h"

#ifdef WM_USE_NATIVE_API
NtReadVirtualMemoryFn     NtReadVirtualMemory     = NULL;
NtWriteVirtualMemoryFn    NtWriteVirtualMemory    = NULL;
NtAllocateVirtualMemoryFn NtAllocateVirtualMemory = NULL;
NtFreeVirtualMemoryFn     NtFreeVirtualMemory     = NULL;
NtQueryVirtualMemoryFn    NtQueryVirtualMemory    = NULL;
NtProtectVirtualMemoryFn  NtProtectVirtualMemory  = NULL;
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

WM_API WmResult wmInit(void)
{
#ifdef WM_USE_NATIVE_API
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        wmLogE(WM_STR("failed to get ntdll.dll handle"));
        return WM_ERROR_WINAPI_CALL;
    }

    NtReadVirtualMemory     = (NtReadVirtualMemoryFn)    GetProcAddress(ntdll, "NtReadVirtualMemory");
    NtWriteVirtualMemory    = (NtWriteVirtualMemoryFn)   GetProcAddress(ntdll, "NtWriteVirtualMemory");
    NtAllocateVirtualMemory = (NtAllocateVirtualMemoryFn)GetProcAddress(ntdll, "NtAllocateVirtualMemory");
    NtFreeVirtualMemory     = (NtFreeVirtualMemoryFn)    GetProcAddress(ntdll, "NtFreeVirtualMemory");
    NtQueryVirtualMemory    = (NtQueryVirtualMemoryFn)   GetProcAddress(ntdll, "NtQueryVirtualMemory");
    NtProtectVirtualMemory  = (NtProtectVirtualMemoryFn) GetProcAddress(ntdll, "NtProtectVirtualMemory");

    if (!NtReadVirtualMemory     || !NtWriteVirtualMemory   ||
        !NtAllocateVirtualMemory || !NtFreeVirtualMemory    ||
        !NtQueryVirtualMemory    || !NtProtectVirtualMemory) {
        wmLogE(WM_STR("failed to resolve one or more NT functions from ntdll.dll"));
        return WM_ERROR_WINAPI_CALL;
    }

    wmLogI(WM_STR("NT functions resolved from ntdll.dll"));
#endif // WM_USE_NATIVE_API
    return WM_OK;
}
