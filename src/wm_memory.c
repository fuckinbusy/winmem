#include "winmem.h"
#include "wm_internal.h"

typedef struct {
    const uint8_t *bytes;
    size_t size;
} WmScanDataRaw;

typedef struct {
    const uint8_t *bytes;
    const uint8_t *mask;
    size_t size;
} WmScanDataMask;

typedef bool (*WmScanCompareFn)(const uint8_t *regionBuffer, size_t offset, void *userData);

static bool wm__parseMask(const char *mask, uint8_t *outBytes, uint8_t *outMask, size_t maxMaskSize, size_t *outSize)
{
    size_t bytes = 0;
    const char *c = mask;

    while (*c) {
        if (*c == ' ' || *c == ',') {
            c++;
            continue;
        }

        if (bytes >= maxMaskSize) return false;

        if (*c == '?') {
            outBytes[bytes] = 0;
            outMask[bytes++]  = 0;
            c++;
            if (*c == '?') c++;
            continue;
        }

        if (wm__isHexChar(*c)) {
            unsigned char high = wm__charToHex(*c);
            unsigned char low = 0;

            c++;

            if (wm__isHexChar(*c)) {
                low = wm__charToHex(*c);
                c++;
            }

            outBytes[bytes] = (high << 4) | low;
            outMask[bytes++] = 1;
            continue;
        }

        return false;
    }

    *outSize = bytes;
    return bytes > 0;
}

static WmResult wm__memoryScanImpl(WmProcess process, uintptr_t address, size_t size, WmScanCompareFn fn, void *userData, uintptr_t *outAddr)
{
    WmHandleEntry *entry = NULL;
    wm__handleGet(process, &entry);

    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);

    uintptr_t cur = address == 0 ? (uintptr_t)sysinfo.lpMinimumApplicationAddress : address;
    uintptr_t end = (uintptr_t)sysinfo.lpMaximumApplicationAddress;

    size_t regionBufferSize = sysinfo.dwPageSize;
    uint8_t *regionBuffer = (uint8_t*)malloc(regionBufferSize);
    if (!regionBuffer) {
        // wmLogE(WM_STR("failed to create a buffer during the scan"));
        return WM_ERROR_OUT_OF_MEMORY;
    }

    MEMORY_BASIC_INFORMATION mbi;
    bool found = false;

    wmLogI(WM_STR("memory scan started"));

    // here we go main cycle
    while ((cur < end) && !found) {
        if (WM_IMPL_QUERY_MEM(entry->native, (LPCVOID)cur, &mbi, sizeof(mbi)) == 0)
            break;

        if (wm__isMemoryCommited(mbi.State) && !wm__isMemoryGuarded(mbi.Protect)) {
            if (wm__isMemoryReadable(mbi.Protect)) {
                if (mbi.RegionSize > regionBufferSize) {
                    uint8_t *newBuf = realloc(regionBuffer, mbi.RegionSize);
                    if (!newBuf) {
                        cur = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
                        continue;
                    }
                    regionBuffer = newBuf;
                    regionBufferSize = mbi.RegionSize;
                }
                
                size_t bytesRead = 0;
                if (!WM_IMPL_READ_MEM(entry->native, (LPCVOID)cur, regionBuffer, mbi.RegionSize, &bytesRead)) {
                    // wmLogE(WM_STR("failed to read the memory region during the scan"));
                    cur = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
                    continue;
                }

                if (bytesRead >= size) {
                    size_t maxIndex = bytesRead - size;
                    for (size_t i = 0; i <= maxIndex; ++i) {
                        if (fn(regionBuffer, i, userData) == WM_STOP) {
                            found = true;
                            *outAddr = (uintptr_t)mbi.BaseAddress + i;
                            break;
                        }
                    }
                }
            }
        }

        cur = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    }

    free(regionBuffer);
    return found ? WM_OK : WM_ERROR_NOT_FOUND;
}

static bool wm__cmpRawFn(const uint8_t *regionBuffer, size_t offset, void *userData)
{
    WmScanDataRaw *scanData = (WmScanDataRaw*)userData;

    if (scanData->bytes[0] != regionBuffer[offset])
        return WM_CONTINUE;

    if (memcmp(&regionBuffer[offset], scanData->bytes, scanData->size) == 0)
        return WM_STOP;

    return WM_CONTINUE;
}

static bool wm__cmpMaskFn(const uint8_t *regionBuffer, size_t offset, void *userData)
{
    WmScanDataMask *data = (WmScanDataMask*)userData;
    if (data->mask[0] && (data->bytes[0] != regionBuffer[offset])) return WM_CONTINUE;

    bool match = true;
    for (size_t i = 1; i < data->size; ++i) {
        if (data->mask[i] && (data->bytes[i] != regionBuffer[offset + i])) {
            match = false;
            break;
        }
    }

    return match ? WM_STOP : WM_CONTINUE;
}

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
        wmLogE(WM_STR("failed to change memory page protection at 0x%p"), (void*)address);
        return WM_ERROR_ACCESS_DENIED;
    }

    wmLogI(WM_STR("memory page protection changed at 0x%p"), (void*)address);

    return WM_OK;
}

WM_API WmResult wmMemoryScan(WmProcess process, uintptr_t address, const uint8_t *buffer, size_t size, uintptr_t *outAddr)
{
    if (!wm__isHandleValid(process) || !buffer || size == 0 || !outAddr)
        return WM_ERROR_INVALID_ARG;

    wmLogI(WM_STR("memory scan started"));

    WmScanDataRaw data = { buffer, size };
    WmResult result = wm__memoryScanImpl(process, address, size, wm__cmpRawFn, &data, outAddr);

    wmLogI(WM_STR("memory scan finished"));

    if (result != WM_OK) {
        wmLogI(WM_STR("pattern not found"));
        *outAddr = 0;
    } else {
        wmLogI(WM_STR("pattern found at 0x%p"), (void*)*outAddr);
    }

    return result;
}

WM_API WmResult wmMemoryScanMask(WmProcess process, uintptr_t address, const char *pattern, uintptr_t *outAddr)
{
    if (!wm__isHandleValid(process) || !pattern || !outAddr)
        return WM_ERROR_INVALID_ARG;

    wmLogI(WM_STR("memory scan started"));

    size_t maxBufSize = strlen(pattern);
    uint8_t *buffer = (uint8_t*)malloc(maxBufSize * 2);
    if (!buffer) return WM_ERROR_OUT_OF_MEMORY;
    uint8_t *mask = buffer + maxBufSize;
    size_t maskSize = 0;

    if (!wm__parseMask(pattern, buffer, mask, maxBufSize, &maskSize)) {
        free(buffer);
        return WM_ERROR_INVALID_ARG;
    }

    WmScanDataMask data = { buffer, mask, maskSize };
    WmResult result = wm__memoryScanImpl(process, address, maskSize, wm__cmpMaskFn, &data, outAddr);

    free(buffer);

    wmLogI(WM_STR("memory scan finished"));

    if (result != WM_OK) {
        wmLogI(WM_STR("pattern not found"));
        *outAddr = 0;
    } else {
        wmLogI(WM_STR("pattern found at 0x%p"), (void*)*outAddr);
    }

    return result;
}

WM_API WmResult wmMemoryAllocAt(WmProcess process, uintptr_t address, size_t size, unsigned long protect, uintptr_t *outAddr)
{
    if (!wm__isHandleValid(process) || size == 0) return WM_ERROR_INVALID_ARG;

    WmHandleEntry *entry = NULL;
    wm__handleGet(process, &entry);
    *outAddr = 0;

    void *alloc = WM_IMPL_ALLOC_MEM(entry->native, (LPVOID)address, size, MEM_COMMIT | MEM_RESERVE, protect);
    if (!alloc) {
        wmLogE(WM_STR("failed to allocate memory at 0x%p. win32 err: %lu"), (void*)address, GetLastError());
        return WM_ERROR_OUT_OF_MEMORY;
    }

    *outAddr = (uintptr_t)alloc;
    wmLogI(WM_STR("memory allocated at 0x%p"), alloc);
    return WM_OK;
}

WM_API WmResult wmMemoryFree(WmProcess process, uintptr_t address)
{
    if (!wm__isHandleValid(process) || address == 0) return WM_ERROR_INVALID_ARG;

    WmHandleEntry *entry = NULL;
    wm__handleGet(process, &entry);

    if (!WM_IMPL_FREE_MEM(entry->native, (LPVOID)address, 0, MEM_RELEASE)) {
        wmLogE(WM_STR("failed to free memory at 0x%p. win32 err: %lu"), (void*)address, GetLastError());
        return WM_ERROR_ACCESS_DENIED;
    }

    wmLogI(WM_STR("memory released at 0x%p"), (void*)address);
    return WM_OK;
}