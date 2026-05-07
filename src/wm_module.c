#include "wm_internal.h"
#include <tlhelp32.h>

static WmResult wm__traverseModules(WmProcess proc, const wchar_t *name, WmModuleInfo *info, WmEnumModuleFn fn, void *data)
{
    WmHandleEntry *entry = NULL;
    wm__handleGet(proc, &entry);
    if (!entry || entry->active == false) {
        wmLogE(WM_STR("invalid arg"));
        return WM_ERROR_INVALID_ARG;
    }

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, entry->id);
    if (snapshot == INVALID_HANDLE_VALUE) {
        wmLogE(WM_STR("failed to create snapshot"));
        return WM_ERROR_MODULE_NOT_FOUND;
    }

    MODULEENTRY32W module;
    module.dwSize = sizeof(MODULEENTRY32W);

    WmResult status = WM_ERROR_MODULE_NOT_FOUND;

    if (Module32FirstW(snapshot, &module)) {
        wmLogI(WM_STR("modules traverse in process %lu"), entry->id);
        do {
            WmModuleInfo mi;
            mi.base = (uintptr_t)module.modBaseAddr;
            mi.size = module.modBaseSize;
            if (name) {
                if (_wcsicmp(name, module.szModule) == 0) {
                    status = WM_OK;
                    if (info) {
                        wcscpy_s(mi.name, WM_MAX_NAME, module.szModule);
                        *info = mi;
                    }
                    wmLogI(WM_STR("module %s found"), name);
                    break;
                }
            } else if (fn) {
                status = WM_OK;
                wcscpy_s(mi.name, WM_MAX_NAME, module.szModule);
                if (fn(&mi, data) == WM_STOP) break;
            } else break;
        } while (Module32NextW(snapshot, &module));
    } else {
        wmLogE(WM_STR("failed to traverse modules"));
        status = WM_ERROR_ACCESS_DENIED;
    }

    CloseHandle(snapshot);
    wmLogI(WM_STR("modules traverse finished"));
    return status;
}

WM_API WmResult wmModuleEnum(WmProcess process, WmEnumModuleFn fn, void *data)
{
    if (!process || !fn) return WM_ERROR_INVALID_ARG;
    return wm__traverseModules(process, NULL, NULL, fn, data);
}

WM_API WmResult wmModuleFind(WmProcess process, const wchar_t *name, WmModuleInfo *out)
{
    if (!process || !name || !out) return WM_ERROR_INVALID_ARG;
    return wm__traverseModules(process, name, out, NULL, NULL);
}

WM_API WmResult wmModuleBase(WmProcess process, const wchar_t *name, uintptr_t *out)
{
    if (!out) return WM_ERROR_INVALID_ARG;
    WmModuleInfo info;
    WmResult status = wmModuleFind(process, name, &info);
    if (status == WM_OK) *out = info.base;
    return status;
}
