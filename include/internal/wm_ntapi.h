#ifndef _WM_NTAPI_H
#define _WM_NTAPI_H
// NT API is very unstable and requires extensive testing.
// But, on the other hand, it's very stealthy.

/* ---------------------------------------------------------------------------
 * NT API layer
 *
 * Centralises everything related to native NT functions:
 *   - NTSTATUS / NT_SUCCESS
 *   - WM_MEMORY_INFORMATION_CLASS enum
 *   - Function pointer typedefs
 *   - extern declarations of the global pointers (defined in wm_ntapi.c)
 *   - Inline memory operation wrappers used by wm_memory.c
 *
 * Include chain: wm_memory.c -> wm_internal.h -> wm_ntapi.h
 * Never include this header directly from consuming code.
 * --------------------------------------------------------------------------- */

#include "wm_internal.h"

typedef LONG NTSTATUS;

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#endif

/* MemoryBasicInformation = 0 is stable across all Windows versions.
 * Defined as a local enum to avoid pulling in ntdef.h / winternl.h,
 * which conflict with windows.h in some SDK configurations. */
typedef enum _WM_MEMORY_INFORMATION_CLASS {
    WmMemoryBasicInformation = 0
} WM_MEMORY_INFORMATION_CLASS;

typedef NTSTATUS (NTAPI *NtReadVirtualMemoryFn)    (HANDLE, PVOID,  PVOID,     SIZE_T,    PSIZE_T);
typedef NTSTATUS (NTAPI *NtWriteVirtualMemoryFn)   (HANDLE, PVOID,  PVOID,     SIZE_T,    PSIZE_T);
typedef NTSTATUS (NTAPI *NtAllocateVirtualMemoryFn)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T,   ULONG, ULONG);
typedef NTSTATUS (NTAPI *NtFreeVirtualMemoryFn)    (HANDLE, PVOID*, PSIZE_T,   ULONG);
typedef NTSTATUS (NTAPI *NtQueryVirtualMemoryFn)   (HANDLE, PVOID,  WM_MEMORY_INFORMATION_CLASS, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (NTAPI *NtProtectVirtualMemoryFn) (HANDLE, PVOID*, PSIZE_T,   ULONG,     PULONG);

/* Global funtion pointers */
#ifdef WM_USE_NATIVE_API
extern NtReadVirtualMemoryFn     g_NtReadVirtualMemory;
extern NtWriteVirtualMemoryFn    g_NtWriteVirtualMemory;
extern NtAllocateVirtualMemoryFn g_NtAllocateVirtualMemory;
extern NtFreeVirtualMemoryFn     g_NtFreeVirtualMemory;
extern NtQueryVirtualMemoryFn    g_NtQueryVirtualMemory;
extern NtProtectVirtualMemoryFn  g_NtProtectVirtualMemory;
#endif // WM_USE_NATIVE_API

WM_API WmResult wmNtInit(void);

/* Wrappers */
static inline bool wm__readMem(HANDLE h, LPCVOID addr, LPVOID buf, SIZE_T size, SIZE_T *read)
{
#ifdef WM_USE_NATIVE_API
    return NT_SUCCESS(g_NtReadVirtualMemory(h, (PVOID)addr, buf, size, read));
#else
    return (bool)ReadProcessMemory(h, addr, buf, size, read);
#endif
}

static inline bool wm__writeMem(HANDLE h, LPVOID addr, LPCVOID buf, SIZE_T size, SIZE_T *written)
{
#ifdef WM_USE_NATIVE_API
    return NT_SUCCESS(g_NtWriteVirtualMemory(h, addr, (PVOID)buf, size, written));
#else
    return (bool)WriteProcessMemory(h, addr, buf, size, written);
#endif
}

static inline SIZE_T wm__queryMem(HANDLE h, LPCVOID addr, PMEMORY_BASIC_INFORMATION mbi, SIZE_T size)
{
#ifdef WM_USE_NATIVE_API
    SIZE_T returnLength = 0;
    NTSTATUS s = g_NtQueryVirtualMemory(h, (PVOID)addr, WmMemoryBasicInformation,
                                      mbi, size, &returnLength);
    return NT_SUCCESS(s) ? returnLength : 0;
#else
    return VirtualQueryEx(h, addr, mbi, size);
#endif
}

static inline bool wm__protectMem(HANDLE h, LPVOID addr, SIZE_T size, DWORD protect, PDWORD old)
{
#ifdef WM_USE_NATIVE_API
    PVOID  baseAddr   = addr;
    SIZE_T regionSize = size;
    return NT_SUCCESS(g_NtProtectVirtualMemory(h, &baseAddr, &regionSize, protect, old));
#else
    return (bool)VirtualProtectEx(h, addr, size, protect, old);
#endif
}

static inline void* wm__allocMem(HANDLE h, LPVOID addr, SIZE_T size, DWORD type, DWORD protect)
{
#ifdef WM_USE_NATIVE_API
    SIZE_T regionSize = size;
    NTSTATUS s = g_NtAllocateVirtualMemory(h, &addr, 0, &regionSize, type, protect);
    return NT_SUCCESS(s) ? addr : NULL;
#else
    return VirtualAllocEx(h, addr, size, type, protect);
#endif
}

static inline bool wm__freeMem(HANDLE h, LPVOID addr)
{
#ifdef WM_USE_NATIVE_API
    SIZE_T regionSize = 0;
    return NT_SUCCESS(g_NtFreeVirtualMemory(h, &addr, &regionSize, MEM_RELEASE));
#else
    return (bool)VirtualFreeEx(h, addr, 0, MEM_RELEASE);
#endif
}

#endif // _WM_NTAPI_H
