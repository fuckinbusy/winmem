#ifndef _WINMEM_PROCESS_H
#define _WINMEM_PROCESS_H
#include "wm_types.h"

#ifdef __cplusplus
extern "C" {
#endif

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
} WmProcessAccessFlags;

typedef struct {
    uint32_t pid;
    uint32_t parentPid;
    uint32_t threadCount;
    wchar_t name[WM_MAX_NAME];
} WmProcessInfo;

typedef bool (*WmEnumProcessFn)(const WmProcessInfo *info, void *data);

WM_API WmResult wmProcessOpen(WmProcess *out, const wchar_t *name, unsigned long access);
WM_API WmResult wmProcessOpenById(WmProcess *out, uint32_t id, unsigned long access);
WM_API WmResult wmProcessOpenByWindow(WmProcess *out, const wchar_t *windowName, unsigned long access);
WM_API WmResult wmProcessClose(WmProcess process);
WM_API WmResult wmProcessEnum(WmEnumProcessFn fn, void *data);

#ifdef __cplusplus
}
#endif

#endif
