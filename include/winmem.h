/* Public API */

#ifndef _WINMEM_H
#define _WINMEM_H
#define _CRT_SECURE_NO_WARNINGS
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
    WM_ERROR_NOT_FOUND = -10,
    WM_ERROR_WINDOW_NOT_FOUND = -11,
    WM_ERROR_PROCESS_NOT_FOUND = -12,
    WM_ERROR_MODULE_NOT_FOUND = -13,
    WM_ERROR_THREAD_NOT_FOUND = -14,
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
WM_API WmResult wmProcessOpen(WmProcess *out, const wchar_t *name, WmAccessFlags access);
WM_API WmResult wmProcessOpenById(WmProcess *out, uint32_t id, WmAccessFlags access);
WM_API WmResult wmProcessOpenByWindow(WmProcess *out, const wchar_t *windowName, WmAccessFlags access);
WM_API WmResult wmProcessClose(WmProcess process);
WM_API WmResult wmProcessEnum(WmEnumProcessFn fn, void *data);

/* Module */
WM_API WmResult wmModuleFind(WmProcess process, const wchar_t *name, WmModuleInfo *out);
WM_API WmResult wmModuleEnum(WmProcess process, WmEnumModuleFn fn, void *data);
WM_API WmResult wmModuleBase(WmProcess process, const wchar_t *name, uintptr_t *out);


/* Errors */
WM_API const char *wmGetErrorStr(WmResult error);

#ifdef __cplusplus
}
#endif

#endif // _WINMEM_H
