/* Public API */

#ifndef _WINMEM_H
#define _WINMEM_H
#include <stdint.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdbool.h>
#include <wchar.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WM__BUILD_DLL
    #define WM_API __declspec(dllexport)
#elif defined(WM_USE_DLL)
    #define WM_API __declspec(dllimport)
#else
    #define WM_API
#endif // WM__BUILD_DLL

#define WM_MAX_NAME 260

/* Handlers */
typedef uint32_t WmProcess;
typedef uint32_t WmModule;
typedef uint32_t WmThread;

/* Error codes */
typedef enum {
    WM_OK = 0,

    WM_ERROR_INVALID_ARG = -1,
    WM_ERROR_TABLE_FULL = -2,
    WM_ERROR_ACCESS_DENIED = -3,
    WM_ERROR_WINAPI_CALL = -4,
    WM_ERROR_ARRAY_FULL = -5,

    WM_ERROR_NOT_FOUND = -10,
    WM_ERROR_WINDOW_NOT_FOUND = -11,
    WM_ERROR_PROCESS_NOT_FOUND = -12,
    WM_ERROR_MODULE_NOT_FOUND = -13,
    WM_ERROR_THREAD_NOT_FOUND = -14,
    WM_ERROR_PARTIAL_COPY = -15,

    WM_ERROR_OUT_OF_MEMORY = -100
} WmResult;

/* Flags */
typedef enum {
    WM_ACCESS_READ          = 0x0010,  /* PROCESS_VM_READ */
    WM_ACCESS_WRITE         = 0x0020,  /* PROCESS_VM_WRITE */
    WM_ACCESS_OPERATION     = 0x0008,  /* PROCESS_VM_OPERATION */

    WM_ACCESS_QUERY         = 0x0400,  /* PROCESS_QUERY_INFORMATION */
    WM_ACCESS_QUERY_LIM     = 0x1000,  /* PROCESS_QUERY_LIMITED_INFORMATION */
    WM_ACCESS_SET_INFO      = 0x0200,  /* PROCESS_SET_INFORMATION */
    WM_ACCESS_SET_QUOTA     = 0x0100,  /* PROCESS_SET_QUOTA */

    WM_ACCESS_CREATE_THREAD  = 0x0002, /* PROCESS_CREATE_THREAD */
    WM_ACCESS_CREATE_PROCESS = 0x0080, /* PROCESS_CREATE_PROCESS */
    WM_ACCESS_TERMINATE      = 0x0001, /* PROCESS_TERMINATE */
    WM_ACCESS_SUSPEND_RESUME = 0x0800, /* PROCESS_SUSPEND_RESUME */
    WM_ACCESS_DUP_HANDLE     = 0x0040, /* PROCESS_DUP_HANDLE */

    WM_ACCESS_ALL            = 0x001FFFFF, /* PROCESS_ALL_ACCESS */
} WmAccessFlags;

typedef enum WmMemoryProtectFlags {
    WM_PROT_NOACCESS          = 0x01,
    WM_PROT_READONLY          = 0x02,
    WM_PROT_READWRITE         = 0x04,
    WM_PROT_WRITECOPY         = 0x08,
    WM_PROT_EXECUTE           = 0x10,
    WM_PROT_EXECUTE_READ      = 0x20,
    WM_PROT_EXECUTE_READWRITE = 0x40,
    WM_PROT_EXECUTE_WRITECOPY = 0x80,

    WM_PROT_GUARD             = 0x100,
    WM_PROT_NOCACHE           = 0x200,
    WM_PROT_WRITECOMBINE      = 0x400,

    /* WDDM */
    WM_PROT_GPU_NOACCESS          = 0x0800,
    WM_PROT_GPU_READONLY          = 0x1000,
    WM_PROT_GPU_READWRITE         = 0x2000,
    WM_PROT_GPU_EXECUTE           = 0x4000,
    WM_PROT_GPU_EXECUTE_READ      = 0x8000,
    WM_PROT_GPU_EXECUTE_READWRITE = 0x10000,
    WM_PROT_GPU_COHERENT          = 0x20000,
    WM_PROT_GPU_NOCACHE           = 0x40000,

    /* Intel SGX / VBS */
    WM_PROT_ENCLAVE_MASK           = 0x10000000,
    WM_PROT_ENCLAVE_DECOMMIT       = 0x10000000, /* (WM_PAGE_ENCLAVE_MASK | 0) */
    WM_PROT_ENCLAVE_SS_FIRST       = 0x10000001, /* (WM_PAGE_ENCLAVE_MASK | 1) */
    WM_PROT_ENCLAVE_SS_REST        = 0x10000002, /* (WM_PAGE_ENCLAVE_MASK | 2) */
    WM_PROT_ENCLAVE_UNVALIDATED    = 0x20000000,
    WM_PROT_ENCLAVE_THREAD_CONTROL = 0x80000000,

    WM_PROT_TARGETS_NO_UPDATE   = 0x40000000,
    WM_PROT_TARGETS_INVALID     = 0x40000000,
    WM_PROT_REVERT_TO_FILE_MAP  = 0x80000000
} WmMemoryProtectFlags;

typedef enum WmMemoryAllocFlags {
    WM_MEM_COMMIT   = 0x00001000,
    WM_MEM_RESERVE  = 0x00002000,
    WM_MEM_DECOMMIT = 0x00004000,
    WM_MEM_RELEASE  = 0x00008000,
    WM_MEM_FREE     = 0x00010000,

    WM_MEM_REPLACE_PLACEHOLDER     = 0x00004000,
    WM_MEM_RESERVE_PLACEHOLDER     = 0x00040000,
    WM_MEM_RESET                   = 0x00080000,
    WM_MEM_TOP_DOWN                = 0x00100000,
    WM_MEM_WRITE_WATCH             = 0x00200000,
    WM_MEM_PHYSICAL                = 0x00400000,
    WM_MEM_ROTATE                  = 0x00800000,
    WM_MEM_DIFFERENT_IMAGE_BASE_OK = 0x00800000,
    WM_MEM_RESET_UNDO              = 0x01000000,
    WM_MEM_LARGE_PAGES             = 0x20000000,
    WM_MEM_4MB_PAGES               = 0x80000000,
    WM_MEM_64K_PAGES               = (WM_MEM_LARGE_PAGES | WM_MEM_PHYSICAL),

    WM_MEM_UNMAP_WITH_TRANSIENT_BOOST = 0x00000001,
    WM_MEM_COALESCE_PLACEHOLDERS      = 0x00000001,
    WM_MEM_PRESERVE_PLACEHOLDER       = 0x00000002,

    WM_MEM_EXTENDED_PARAMETER_GRAPHICS            = 0x00000001,
    WM_MEM_EXTENDED_PARAMETER_NONPAGED            = 0x00000002,
    WM_MEM_EXTENDED_PARAMETER_ZERO_PAGES_OPTIONAL = 0x00000004,
    WM_MEM_EXTENDED_PARAMETER_NONPAGED_LARGE      = 0x00000008,
    WM_MEM_EXTENDED_PARAMETER_NONPAGED_HUGE       = 0x00000010,
    WM_MEM_EXTENDED_PARAMETER_SOFT_FAULT_PAGES    = 0x00000020,
    WM_MEM_EXTENDED_PARAMETER_EC_CODE             = 0x00000040,
    WM_MEM_EXTENDED_PARAMETER_NUMA_NODE_MANDATORY = 0x8000000000000000ULL /* MINLONG64 */
} WmMemoryAllocFlags;

/* Info structures */
typedef struct {
    uint32_t pid;
    uint32_t parentPid;
    uint32_t threadCount;
    wchar_t name[WM_MAX_NAME];
} WmProcessInfo;

typedef struct {
    uintptr_t base;
    uint32_t size;
    wchar_t name[WM_MAX_NAME];
} WmModuleInfo;

typedef struct {
    uint32_t threadId;
    uint32_t ownerPid;
    int32_t basePriority;
} WmThreadInfo;

/* Callback types */
#define WM_STOP     false
#define WM_CONTINUE true
typedef bool (*WmEnumProcessFn)(const WmProcessInfo *info, void *data);
typedef bool (*WmEnumModuleFn)(const WmModuleInfo *info, void *data);

/* Functions */
/* Process */
WM_API WmResult wmProcessOpen(WmProcess *out, const wchar_t *name, unsigned long access);
WM_API WmResult wmProcessOpenById(WmProcess *out, uint32_t id, unsigned long access);
WM_API WmResult wmProcessOpenByWindow(WmProcess *out, const wchar_t *windowName, unsigned long access);
WM_API WmResult wmProcessClose(WmProcess process);
WM_API WmResult wmProcessEnum(WmEnumProcessFn fn, void *data);

/* Module */
WM_API WmResult wmModuleFind(WmProcess process, const wchar_t *name, WmModuleInfo *out);
WM_API WmResult wmModuleEnum(WmProcess process, WmEnumModuleFn fn, void *data);
WM_API WmResult wmModuleBase(WmProcess process, const wchar_t *name, uintptr_t *out);

/* Memory */
WM_API WmResult wmMemoryRead(WmProcess process, uintptr_t address, void *out, size_t size);
WM_API WmResult wmMemoryWrite(WmProcess process, uintptr_t address, void *in, size_t size);
#define wmMemoryReadT(process, address, out, T) wmMemoryRead((WmProcess)(process), (uintptr_t)(address), (void*)(out), sizeof(T))
#define wmMemoryWriteT(process, address, in, T) wmMemoryWrite((WmProcess)(process), (uintptr_t)(address), (void*)(in), sizeof(T))
WM_API WmResult wmMemoryProtect(WmProcess process, uintptr_t address, size_t size, unsigned long protect, unsigned long *oldProtect);
WM_API WmResult wmMemoryScan(WmProcess process, uintptr_t address, const uint8_t *buffer, size_t size, uintptr_t *outAddr);
WM_API WmResult wmMemoryScanMask(WmProcess process, uintptr_t address, const char *pattern, uintptr_t *outAddr);
WM_API WmResult wmMemoryAllocAt(WmProcess process, uintptr_t address, size_t size, unsigned long protect, uintptr_t *outAddr);
WM_API WmResult wmMemoryFree(WmProcess process, uintptr_t address);

WM_API static inline WmResult wmMemoryWriteBuffer(WmProcess process, uintptr_t address, const uint8_t *buffer, size_t size)
{
    return wmMemoryWrite(process, address, (void*)buffer, size);
}

WM_API static inline WmResult wmMemoryAlloc(WmProcess process, size_t size, unsigned long protect, uintptr_t *outAddr)
{
    return wmMemoryAllocAt(process, 0, size, protect, outAddr);
}

/* Shellcode */
#define WM_SHELLCODE_MAX_STRING_LEN 128
#define WM_SHELLCODE_MAX_STRINGS    32
#define WM_SHELLCODE_MAX_FUNCTIONS  32

typedef struct {
    void *payload;
    size_t payloadSize;

    char dlls[WM_SHELLCODE_MAX_STRINGS][WM_SHELLCODE_MAX_STRING_LEN];
    char fns[WM_SHELLCODE_MAX_FUNCTIONS][WM_SHELLCODE_MAX_STRING_LEN];
    size_t fnsCount;

    char strs[WM_SHELLCODE_MAX_STRINGS][WM_SHELLCODE_MAX_STRING_LEN];
    size_t strsCount;
} WmShellcode;

typedef struct {
    void *functions[WM_SHELLCODE_MAX_FUNCTIONS];
    char strings[WM_SHELLCODE_MAX_STRINGS][WM_SHELLCODE_MAX_STRING_LEN];
} WmShellcodeRemoteData;

typedef void (__stdcall *WmShellcodePayloaStartFn)(void*) ;
typedef void (__stdcall *WmShellcodePayloaEndFn)(void);
#define WM_SHELLCODE_START_FN(fnName) \
    __attribute__((noinline)) \
    __attribute__((optimize("O0"))) \
    void __stdcall  wmscfns__##fnName(void *data)
#define WM_SHELLCODE_END_FN(fnName) \
    __attribute__((noinline)) \
    __attribute__((optimize("O0"))) \
    void __stdcall wmscfne__##fnName(void) { volatile int _ = 0; } // should be empty
#define WM_SHELLCODE_GETS(startFnName) wmscfns__##startFnName
#define WM_SHELLCODE_GETE(endFnName)   wmscfne__##endFnName
#define wmShellcodeGetString(remoteDataPtr, index) \
    ((const char*)((uintptr_t)remoteDataPtr + (WM_SHELLCODE_MAX_FUNCTIONS * sizeof(void*) + (index * WM_SHELLCODE_MAX_STRING_LEN))))
#define wmShellcodeGetFunction(remoteDataPtr, index) \
    (((void**)(remoteDataPtr))[index])

WM_API WmResult wmShellcodeCreate(WmShellcode **out);
WM_API WmResult wmShellcodeSetPayload(WmShellcode *shellcode, WmShellcodePayloaStartFn fnStart, WmShellcodePayloaEndFn fnEnd);
WM_API WmResult wmShellcodeAddFunction(WmShellcode *shellcode, const char *fnDll, const char *fnName);
WM_API WmResult wmShellcodeAddString(WmShellcode *shellcode, const char *str);
WM_API WmResult wmShellcodeExecute(WmProcess process, WmShellcode *shellcode);
WM_API WmResult wmShellcodeDestroy(WmShellcode *in);

/* Errors */
WM_API const char *wmGetErrorStr(WmResult error);
WM_API const wchar_t *wmGetErrorStrW(WmResult error);
WM_API int wmGetWinLastError();

#ifdef __cplusplus
}
#endif

#endif // _WINMEM_H
