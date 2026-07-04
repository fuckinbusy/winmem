#ifndef _WM_INTERNAL_H
#define _WM_INTERNAL_H

#define _CRT_SECURE_NO_WARNINGS
#include <stdbool.h>
#include <malloc.h>
#include <string.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define WM_MAX_HANDLES 16
#define WM_STR(s) L##s

#include "../wm_types.h"
// #include "wm_ntapi.h"

/* Handle tables */
#define WM__HANDLE_PROCESS 0x0
#define WM__HANDLE_THREAD  0x1

typedef struct {
    const char *name;        // label used in log messages, e.g. "process"
    void       *entries;     // pointer to the entry array
    size_t     slotSize;     // sizeof one entry
    size_t     capacity;     // total number of slots (including slot 0)
    size_t     activeOffset; // offsetof(EntryType, active)
    size_t     nativeOffset; // offsetof(EntryType, native)
} WmHandleTable;

WmResult wm__tableAlloc(WmHandleTable *t, uint32_t *slot);
WmResult wm__tableFree(WmHandleTable *t, uint32_t  slot);
WmResult wm__tableGet(WmHandleTable *t, uint32_t  slot, void **out);

// checks if slot is valid or not
static inline bool wm__tableIsValid(const WmHandleTable *t, const uint32_t slot)
{
    if (slot == 0 || slot >= t->capacity) return false;
    bool *active = (bool*)((uint8_t*)t->entries + slot * t->slotSize + t->activeOffset);
    return *active;
}

/* Process handle */
typedef struct {
    HANDLE native;
    DWORD id;
    DWORD access;
    wchar_t name[WM_MAX_NAME];
    bool active;
} WmProcessEntry;

extern WmProcessEntry g_Processes[WM_MAX_HANDLES];
extern WmHandleTable g_ProcessesTable;

static inline WmResult wm__processHandleAlloc(uint32_t *slot)
{
    return wm__tableAlloc(&g_ProcessesTable, slot);
}
static inline WmResult wm__processHandleFree(uint32_t slot)
{
    return wm__tableFree(&g_ProcessesTable, slot);
}
static inline WmResult wm__processHandleGet(uint32_t slot, WmProcessEntry **out)
{
    return wm__tableGet(&g_ProcessesTable, slot, (void**)out);
}
static inline bool wm__isProcessHandleValid(const WmProcess process)
{
    return wm__tableIsValid(&g_ProcessesTable, (const uint32_t)process);
}

/* Thread handle */
typedef struct {
    HANDLE native;
    DWORD id;
    DWORD access;
    DWORD ownerPid;
    bool active;
} WmThreadEntry;

extern WmThreadEntry g_Threads[WM_MAX_HANDLES];
extern WmHandleTable g_ThreadsTable;

static inline WmResult wm__threadHandleAlloc(uint32_t *slot)
{
    return wm__tableAlloc(&g_ThreadsTable, slot);
}
static inline WmResult wm__threadHandleFree(uint32_t slot)
{
    return wm__tableFree(&g_ThreadsTable, slot);
}
static inline WmResult wm__threadHandleGet(uint32_t slot, WmThreadEntry **out)
{
    return wm__tableGet(&g_ThreadsTable, slot, (void**)out);
}
static inline bool wm__isThreadHandleValid(WmThread slot)
{
    return wm__tableIsValid(&g_ThreadsTable, slot);
}

/* Utils and helpers */
DWORD wm__findPidByName(const wchar_t *name);
WmResult wm__openProcess(WmProcess *process, DWORD access, BOOL inheritHandle, DWORD id);

static inline
bool wm__isMemoryReadable(const unsigned long protect)
{
    return
        !(protect & PAGE_GUARD) && (
            (protect & PAGE_READONLY) ||
            (protect & PAGE_READWRITE) ||
            (protect & PAGE_EXECUTE_READ) ||
            (protect & PAGE_EXECUTE_READWRITE)
        );
}

static inline
bool wm__isMemoryWritable(const unsigned long protect)
{
    return
        !(protect & PAGE_GUARD) && (
            (protect & PAGE_READWRITE) ||
            (protect & PAGE_WRITECOPY) ||
            (protect & PAGE_EXECUTE_READWRITE) ||
            (protect & PAGE_EXECUTE_WRITECOPY)
        );
}

static inline
bool wm__isMemoryGuarded(const unsigned long protect)
{
    return (protect & (PAGE_NOACCESS | PAGE_GUARD));
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

static inline
wm_dword wm__hashROR13(const char *str)
{
    wm_dword hash = 0;
    while (*str) {
        hash = (hash >> 13) | (hash << 19);
        hash += (wm_byte)*str++;
    }
    return hash;
}

#endif // _WM_INTERNAL_H
