#include "winmem.h"
#include "wm_internal.h"

WM_API WmResult wmMemoryRead(WmProcess process, uintptr_t address, void *out, size_t size)
{
    if (!wm__isHandleValid(process) || address == 0 || !out || size == 0) return WM_ERROR_INVALID_ARG;

    WmHandleEntry *entry = NULL;
    wm__handleGet(process, &entry);

    size_t bytes = 0;
    if (!WM_IMPL_READ_MEM(entry->native, (LPCVOID)address, (LPVOID)out, size, &bytes)) {
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

    if (WM_IMPL_QUERY_MEM(entry->native, (LPCVOID)address, &mbi, sizeof(mbi))) {
        if (mbi.State != MEM_COMMIT) {
            wmLogE(WM_STR("memory was not committed yet at 0x%p"), (void*)address);
            return WM_ERROR_ACCESS_DENIED;
        }

        if (!(mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY))) {
            if (WM_IMPL_PROTECT_MEM(entry->native, (LPVOID)address, size, PAGE_EXECUTE_READWRITE, &oldProtect))
                protectChanged = true;
        }
    }

    size_t bytes = 0;
    WmResult status = WM_OK;

    if (!WM_IMPL_WRITE_MEM(entry->native, (LPVOID)address, (LPCVOID)in, size, &bytes)) {
        wmLogE(WM_STR("failed to write memory: address 0x%p size %zub"), (void*)address, size);
        status = WM_ERROR_ACCESS_DENIED;
    } else if (bytes < size) {
        wmLogE(WM_STR("expected to write %zu bytes, but wrote %zu bytes"), size, bytes);
        status = WM_ERROR_PARTIAL_COPY;
    }

    if (protectChanged)
        WM_IMPL_PROTECT_MEM(entry->native, (LPVOID)address, size, oldProtect, &oldProtect);

    wmLogI(WM_STR("write %zu bytes to memory at 0x%p"), bytes, (void*)address);

    return status;
}

WM_API WmResult wmMemoryProtect(WmProcess process, uintptr_t address, size_t size, unsigned long protect, unsigned long *oldProtect)
{
    if (!wm__isHandleValid(process) || address == 0 || !oldProtect) return WM_ERROR_INVALID_ARG;

    WmHandleEntry *entry = NULL;
    wm__handleGet(process, &entry);

    if (!WM_IMPL_PROTECT_MEM(entry->native, (LPVOID)address, size, protect, oldProtect)){
        wmLogE(WM_STR("failed to change memory page protection at 0x%p"""), (void*)address);
        return WM_ERROR_ACCESS_DENIED;
    }

    wmLogI(WM_STR("memory page protection changed at 0x%p"), (void*)address);

    return WM_OK;
}

// TODO make a private func that accepts callbacks for DRY rule
WM_API WmResult wmMemoryScan(WmProcess process, uintptr_t address, const uint8_t *buffer, size_t size, uintptr_t *outAddr)
{
    if (!wm__isHandleValid(process) || !buffer || size == 0)
        return WM_ERROR_INVALID_ARG;

    WmHandleEntry *entry = NULL;
    wm__handleGet(process, &entry);

    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);

    uintptr_t cur = address == 0 ? (uintptr_t)sysinfo.lpMinimumApplicationAddress : address;
    uintptr_t end = (uintptr_t)sysinfo.lpMaximumApplicationAddress;

    MEMORY_BASIC_INFORMATION mbi;
    bool found = false;

    wmLogI(WM_STR("memory scan started"));

    // here we go main cycle
    while ((cur < end) && !found) {
        if (WM_IMPL_QUERY_MEM(entry->native, (LPCVOID)cur, &mbi, sizeof(mbi)) == 0)
            break;

        if (wm__isMemoryCommited(mbi.State) && !wm__isMemoryGuarded(mbi.Protect)) {
            if (wm__isMemoryReadable(mbi.Protect)) {
                uint8_t *regionBuffer = malloc(mbi.RegionSize);
                if (!regionBuffer) {
                    wmLogE(WM_STR("failed to create a buffer during the scan"));
                    cur = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
                    continue;
                }

                size_t bytesRead = 0;
                if (!WM_IMPL_READ_MEM(entry->native, (LPCVOID)cur, regionBuffer, mbi.RegionSize, &bytesRead)) {
                    wmLogE(WM_STR("failed to read the memory region during the scan"));
                    free(regionBuffer);
                    cur = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
                    continue;
                }

                uintptr_t lastRegionAddr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
                for (size_t i = 0; i < mbi.RegionSize; ++i) {
                    if (buffer[0] != regionBuffer[i]) continue;

                    uintptr_t curRegionAddr = (uintptr_t)mbi.BaseAddress + i;
                    if (lastRegionAddr - curRegionAddr < size) break;

                    if (memcmp((void*)((uintptr_t)regionBuffer + i), buffer, size) == 0) {
                        found = true;
                        *outAddr = (uintptr_t)mbi.BaseAddress + i;
                        break;
                    }
                }

                free(regionBuffer);
            }
        }

        cur = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    }

    wmLogI(WM_STR("memory scan finished"));
    if (!found) {
        wmLogI(WM_STR("pattern not found"));
        *outAddr = 0;
        return WM_ERROR_NOT_FOUND;
    }

    wmLogI(WM_STR("pattern found at 0x%p", (void*)*outAddr));
    return WM_OK;
}
