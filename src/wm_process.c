#include "wm_internal.h"
#include <tlhelp32.h>
#include <psapi.h>

#define WM_FIND_BY_NAME   0
#define WM_FIND_BY_WINDOW 1

WmResult wm__openProcess(WmProcess *process, DWORD access, BOOL inheritHandle, DWORD id)
{
    HANDLE native = OpenProcess(access, inheritHandle, id);
    if (!native) {
        wmLogE(WM_STR("failed to open process %lu"), id);
        return WM_ERROR_ACCESS_DENIED;
    }

    uint32_t slot = 0;
    WmResult allocRes = wm__handleAlloc(&slot);
    if (allocRes != WM_OK) {
        CloseHandle(native);
        return allocRes;
    }

    WmHandleEntry *entry = &g_Handles[slot];
    entry->active = true;
    entry->native = native;
    entry->id = id;
    entry->access = access;

    HMODULE module;
    DWORD cbNeeded;
    if (EnumProcessModules(native, &module, 8, &cbNeeded)) {
        GetModuleBaseNameW(native, module, entry->name, MAX_PATH - 1);
    } else {

        swprintf(entry->name, MAX_PATH, WM_STR("Process %lu"), id);
    }
    entry->name[MAX_PATH - 1] = '\0';
    *process = slot;

    wmLogI(WM_STR("process %lu opened"), id);
    return WM_OK;
}

DWORD wm__findPidByName(const wchar_t *name)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        wmLogE(WM_STR("failed to create snapshot"));
        return 0;
    }

    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(snapshot, &entry)) {
        wmLogE(WM_STR("failed to obtain first snapshot entry"));
        CloseHandle(snapshot);
        return 0;
    }

    DWORD id = 0;
    do {
        if (_wcsicmp(name, entry.szExeFile) == 0) {
            id = entry.th32ProcessID;
            wmLogI(WM_STR("process %lu found"), id);
            break;
        }
    } while (Process32NextW(snapshot, &entry));

    CloseHandle(snapshot);
    return id;
}

WM_API WmResult wmProcessOpen(WmProcess *out, const wchar_t *name, unsigned long access)
{
    if (!out || !name || wcslen(name) == 0) {
        wmLogE(WM_STR("invalid arg"));
        return WM_ERROR_INVALID_ARG;
    }

    DWORD pid = wm__findPidByName(name);
    if (pid == 0) {
        wmLogE(WM_STR("process %s not found"), name);
        return WM_ERROR_PROCESS_NOT_FOUND;
    }

    return wm__openProcess(out, access, FALSE, pid);
}

WM_API WmResult wmProcessOpenById(WmProcess *out, uint32_t id, unsigned long access)
{
    if (!out || id == 0) return WM_ERROR_INVALID_ARG;
    return wm__openProcess(out, access, FALSE, id);
}

WM_API WmResult wmProcessOpenByWindow(WmProcess *out, const wchar_t *windowName, unsigned long access)
{
    if (!out || !windowName) return WM_ERROR_INVALID_ARG;

    HWND wnd = FindWindowW(NULL, windowName);
    if (!wnd) {
        wmLogE(WM_STR("window %s not found"), windowName);
        return WM_ERROR_WINDOW_NOT_FOUND;
    }

    wmLogI(WM_STR("window %s found"), windowName);

    DWORD id;
    GetWindowThreadProcessId(wnd, &id);

    if (id == 0) {
        wmLogE(WM_STR("failed to find window %s process"), windowName);
        return WM_ERROR_PROCESS_NOT_FOUND;
    }

    return wm__openProcess(out, access, FALSE, id);
}

WM_API WmResult wmProcessClose(WmProcess process)
{
    if (!wm__isHandleValid(process)) {
        wmLogE(WM_STR("invalid arg"));
        return WM_ERROR_INVALID_ARG;
    }

    WmResult r = wm__handleFree(process);
    if (r != WM_OK)
        wmLogE(WM_STR("failed to close process (slot %u)"), process);
    else
        wmLogI(WM_STR("process closed (slot %u)"), process);
    return r;
}

WM_API WmResult wmProcessEnum(WmEnumProcessFn fn, void *data)
{
    if (!fn) {
        wmLogE(WM_STR("callback function cannot be NULL"));
        return WM_ERROR_INVALID_ARG;
    }

    HANDLE snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS,0);
    if (!snapshot) {
        wmLogE(WM_STR("failed to create tlhelp32 snapshot"));
        return WM_ERROR_WINAPI_CALL;
    }

    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(snapshot, &entry)) {
        wmLogE(WM_STR("failed to retrieve first snapshot entry"));
        CloseHandle(snapshot);
        return WM_ERROR_WINAPI_CALL;
    }

    do {
        WmProcessInfo info = { 0 };
        info.parentPid = entry.th32ParentProcessID;
        info.pid = entry.th32ProcessID;
        info.threadCount = entry.cntThreads;
        wcsncpy(info.name, entry.szExeFile, WM_MAX_NAME - 1);
        info.name[WM_MAX_NAME - 1] = '\0';
        if (fn(&info, data) == WM_STOP) break; // callback call
    } while (Process32NextW(snapshot, &entry));

    CloseHandle(snapshot);
    wmLogI(WM_STR("all processes enumerated"));
    return WM_OK;
}
