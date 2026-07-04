#ifndef _WINMEM_MODULE_H
#define _WINMEM_MODULE_H
#include "wm_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uintptr_t base;
    uint32_t size;
    wchar_t name[WM_MAX_NAME];
} WmModuleInfo;

typedef bool (*WmEnumModuleFn)(const WmModuleInfo *info, void *data);

WM_API WmResult wmModuleFind(WmProcess process, const wchar_t *name, WmModuleInfo *out);
WM_API WmResult wmModuleEnum(WmProcess process, WmEnumModuleFn fn, void *data);
WM_API WmResult wmModuleBase(WmProcess process, const wchar_t *name, uintptr_t *out);

#ifdef __cplusplus
}
#endif

#endif
