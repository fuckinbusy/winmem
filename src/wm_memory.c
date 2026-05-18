#include "winmem.h"
#include "wm_internal.h"

WM_API WmResult wmMemoryRead(WmProcess process, uintptr_t address, void *out, size_t size)
{
    if (!wm__isHandleValid(process) || address == 0 || !out || size == 0) return WM_ERROR_INVALID_ARG;

    WmHandleEntry *entry = NULL;
    wm__handleGet(process, &entry);

    size_t bytes = 0;
    if (!WM_READ_MEM_IMPL(entry->native, (LPCVOID)address, (LPVOID)out, size, &bytes)) {
        wmLogE(WM_STR("failed to read memory: address 0x%p size %zub"), (void*)address, size);
        return WM_ERROR_ACCESS_DENIED;
    }

    if (bytes < size) {
        wmLogE(WM_STR("expected to read %zu bytes, but read %zu"), size, bytes);
        return WM_ERROR_PARTIAL_COPY;
    }

    wmLogI(WM_STR("read %zu bytes from memory at 0x%p"), bytes, (void*)address);

    return WM_OK;
}

// TODO: should be tested
WM_API WmResult wmMemoryWrite(WmProcess process, uintptr_t address, void *in, size_t size)
{
    if (!wm__isHandleValid(process) || address == 0 || !in || size == 0) return WM_ERROR_INVALID_ARG;

    WmHandleEntry *entry = NULL;
    wm__handleGet(process, &entry);

    MEMORY_BASIC_INFORMATION mbi;
    DWORD oldProtect;
    bool protectChanged = false;

    if (WM_QUERY_MEM_IMPL(entry->native, (LPCVOID)address, &mbi, sizeof(mbi))) {
        if (mbi.State != MEM_COMMIT) {
            wmLogE(WM_STR("memory was not committed yet at 0x%p"), (void*)address);
            return WM_ERROR_ACCESS_DENIED;
        }

        if (!(mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY))) {
            if (WM_PROTECT_MEM_IMPL(entry->native, (LPVOID)address, size, PAGE_EXECUTE_READWRITE, &oldProtect))
                protectChanged = true;
        }
    }

    size_t bytes = 0;
    WmResult status = WM_OK;

    if (!WM_WRITE_MEM_IMPL(entry->native, (LPVOID)address, (LPCVOID)in, size, &bytes)) {
        wmLogE(WM_STR("failed to write memory: address 0x%p size %zub"), (void*)address, size);
        status = WM_ERROR_ACCESS_DENIED;
    } else if (bytes < size) {
        wmLogE(WM_STR("expected to write %zu bytes, but wrote %zu bytes"), size, bytes);
        status = WM_ERROR_PARTIAL_COPY;
    }

    if (protectChanged)
        WM_PROTECT_MEM_IMPL(entry->native, (LPVOID)address, size, oldProtect, &oldProtect);

    wmLogI(WM_STR("write %zu bytes to memory at 0x%p"), bytes, (void*)address);

    return status;
}

WM_API WmResult wmMemoryProtect(WmProcess process, uintptr_t address, size_t size, unsigned long protect, unsigned long *oldProtect)
{
    if (!wm__isHandleValid(process) || address == 0 || !oldProtect) return WM_ERROR_INVALID_ARG;

    WmHandleEntry *entry = NULL;
    if (wm__handleGet(process, &entry) != WM_OK) return WM_ERROR_INVALID_ARG;

    if (!WM_PROTECT_MEM_IMPL(entry->native, (LPVOID)address, size, protect, oldProtect)){
        wmLogE(WM_STR("failed to change memory page protection at 0x%p"""), (void*)address);
        return WM_ERROR_ACCESS_DENIED;
    }

    wmLogI(WM_STR("memory page protection changed at 0x%p"), (void*)address);
    
    return WM_OK;
}