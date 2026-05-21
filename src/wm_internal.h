#ifndef _WM_INTERNAL_H
#define _WM_INTERNAL_H

#include "winmem.h"
#include <stdbool.h>
#include <malloc.h>
#include <string.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define WM_MAX_HANDLES 16
#define WM_STR(s) L##s

/* if debug macro is defined, default printf or any other function
 * with char* type of parameter cannot be used */
#ifdef WM__DEBUG
#include <stdio.h>
#include <io.h>
#include <fcntl.h>
static inline void wm__InitUnicodeConsole()
{
    static bool active = false;
    if (!active) {
        _setmode(_fileno(stderr), _O_U16TEXT);
        _setmode(_fileno(stdout), _O_U16TEXT);
        active = true;
    }
}
#define wmLogI(fmt, ...) do {wm__InitUnicodeConsole(); fwprintf(stderr, WM_STR("[WM:INF] %S:%d ") fmt WM_STR("\n"), __FILE__, __LINE__, ##__VA_ARGS__);} while (0)
#define wmLogW(fmt, ...) do {wm__InitUnicodeConsole(); fwprintf(stderr, WM_STR("[WM:WRN] %S:%d ") fmt WM_STR("\n"), __FILE__, __LINE__, ##__VA_ARGS__);} while (0)
#define wmLogE(fmt, ...) do {wm__InitUnicodeConsole(); fwprintf(stderr, WM_STR("[WM:ERR] %S:%d ") fmt WM_STR("\n"), __FILE__, __LINE__, ##__VA_ARGS__);} while (0)
#else
#define wmLogE(...) ((void)0)
#define wmLogW(...) ((void)0)
#define wmLogI(...) ((void)0)
#endif // WM__DEBUG

#ifdef WM_USE_NATIVE_API
    #define WM_IMPL_READ_MEM    NtReadVirtualMemory
    #define WM_IMPL_WRITE_MEM   NtWriteVirtualMemory

    #define WM_IMPL_QUERY_MEM   VirtualQueryEx
    #define WM_IMPL_PROTECT_MEM VirtualProtectEx
#else
    #define WM_IMPL_READ_MEM    ReadProcessMemory
    #define WM_IMPL_WRITE_MEM   WriteProcessMemory
    #define WM_IMPL_QUERY_MEM   VirtualQueryEx
    #define WM_IMPL_PROTECT_MEM VirtualProtectEx
#endif // WM_USE_NATIVE_API

typedef struct {
    bool active;
    HANDLE native;
    DWORD id;
    DWORD access;
    wchar_t name[WM_MAX_NAME];
} WmHandleEntry;

extern WmHandleEntry g_Handles[WM_MAX_HANDLES];

WmResult wm__handleAlloc(uint32_t *slot);
WmResult wm__handleFree(uint32_t slot);
WmResult wm__handleGet(uint32_t slot, WmHandleEntry **out);

DWORD wm__findPidByName(const wchar_t *name);
WmResult wm__openProcess(WmProcess *process, DWORD access, BOOL inheritHandle, DWORD id);

static inline
bool wm__isHandleValid(const WmProcess slot)
{
    if (slot == 0 || slot >= WM_MAX_HANDLES)
        return false;
    return g_Handles[slot].active;
}

static inline
bool wm__isMemoryReadable(const unsigned long protect)
{
    return
        (protect & PAGE_READONLY) ||
        (protect & PAGE_READWRITE) ||
        (protect & PAGE_EXECUTE_READ) ||
        (protect & PAGE_EXECUTE_READWRITE);
}

static inline
bool wm__isMemoryGuarded(const unsigned long protect)
{
    return (protect & PAGE_GUARD);
}

static inline
bool wm__isMemoryCommited(const unsigned long state)
{
    return (state & MEM_COMMIT);
}

static inline
bool wm__isHexChar(const char c)
{
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
}

static inline
uint8_t wm__charToHex(const char c)
{
    return
        (c >= '0' && c <= '9') ? c - '0'      :
        (c >= 'A' && c <= 'F') ? c - 'A' + 10 :
        (c >= 'a' && c <= 'f') ? c - 'a' + 10 :
        0;
}

#endif // _WM_INTERNAL_H
