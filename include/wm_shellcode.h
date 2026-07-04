#ifndef _WINMEM_SHELLCODE_H
#define _WINMEM_SHELLCODE_H
#include "wm_types.h"

#define WM_SHELLCODE_MAX_STRING_LEN 128
#define WM_SHELLCODE_MAX_STRINGS    32
#define WM_SHELLCODE_MAX_FUNCTIONS  32
#define WM_SHELLCODE_MAX_ENTRIES    128
#define WM_SHELLCODE_MAX_DATA_SIZE  1024 // 1kb of data buffer

// #define WM_SHELLCODE_ENTRY_IMPORT  0
// #define WM_SHELLCODE_ENTRY_STRING  1
// #define WM_SHELLCODE_ENTRY_RAWDATA 2

typedef struct {
    size_t offset;
    size_t size;
} WmShellcodeEntry;

typedef struct WmShellcodeContext {
    void   *payload;
    size_t payloadSize;

    WmShellcodeEntry entries[WM_SHELLCODE_MAX_ENTRIES];
    wm_byte data[WM_SHELLCODE_MAX_DATA_SIZE];
    size_t entriesCount;
    size_t dataSize;
} WmShellcode;

typedef void (__stdcall *WmShellcodePayloaStartFn)(void*);
typedef void (__stdcall *WmShellcodePayloaEndFn)(void);

#define WM_SC_STARTFN(fnName) \
    __attribute__((noinline)) \
    __attribute__((optimize("O0"))) \
    void __stdcall  wmscfns__##fnName(void *data)

// using volatile variable here
// to make sure compiler won't remove this empty function
#define WM_SC_ENDFN(fnName) \
    __attribute__((noinline)) \
    __attribute__((optimize("O0"))) \
    void __stdcall wmscfne__##fnName(void) { volatile int _ = 0; }

#define WM_SC_GETSFN(startFnName) wmscfns__##startFnName
#define WM_SC_GETEFN(endFnName)   wmscfne__##endFnName

#define WM_SC_ENTRY(ctx, i) \
    ((WmShellcodeEntry*)((wm_uptr)(ctx) + (i) * sizeof(WmShellcodeEntry)))

#define WM_SC_RAWDATA_BASE(ctx) \
    ((wm_byte*)((wm_uptr)(ctx) + sizeof(WmShellcodeEntry) * WM_SHELLCODE_MAX_ENTRIES))

#define WM_SC_DATA(ctx, i)                                                 \
    __extension__ ({                                                       \
        const void *_ctx = (ctx);                                          \
        size_t _i = (i);                                                   \
        (void*)(WM_SC_RAWDATA_BASE(_ctx) + WM_SC_ENTRY(_ctx, _i)->offset); \
    })

WM_API WmResult wmShellcodeCreate(WmShellcode **out);
WM_API WmResult wmShellcodeSetPayload(WmShellcode *shellcode, WmShellcodePayloaStartFn fnStart, WmShellcodePayloaEndFn fnEnd);

WM_API WmResult wmShellcodeAddImport(WmShellcode *shellcode, const char *dllName, const char *fnName);
WM_API WmResult wmShellcodeAddString(WmShellcode *shellcode, const char *str);
WM_API WmResult wmShellcodeAddData(WmShellcode *shellcode, const void *data, size_t dataSize);

WM_API WmResult wmShellcodeExecute(WmProcess process, WmShellcode *shellcode);
WM_API WmResult wmShellcodeDestroy(WmShellcode *in);

#endif
