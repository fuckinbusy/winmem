/* welcome to low level hell */
#include "winmem.h"
#include "wm_internal.h"

typedef struct {
    void *functions[WM_SHELLCODE_MAX_FUNCTIONS];
    char strings[WM_SHELLCODE_MAX_STRINGS][WM_SHELLCODE_MAX_STRING_LEN];
} WmShellcodeRemoteData;

WM_API WmResult wmShellcodeCreate(WmShellcode **out)
{
    if (!out) return WM_ERROR_INVALID_ARG;
    *out = NULL;

    WmShellcode *sc = (WmShellcode*)malloc(sizeof(WmShellcode));
    if (!sc) return WM_ERROR_OUT_OF_MEMORY;
    memset(sc, 0, sizeof(WmShellcode));
    *out = sc;

    return WM_OK;
}

WM_API WmResult wmShellcodeSetPayload(WmShellcode *shellcode, WmShellcodePayloaStartFn fnStart, WmShellcodePayloaEndFn fnEnd)
{
    if (!shellcode || !fnStart || !fnEnd) return WM_ERROR_INVALID_ARG;

    shellcode->payload = fnStart;
    shellcode->payloadSize = (size_t)((uintptr_t)fnEnd - (uintptr_t)fnStart);

    return WM_OK;
}

WM_API WmResult wmShellcodeAddImport(WmShellcode *shellcode, const char *dllName, const char *fnName)
{
    if (!shellcode || !dllName || !fnName) return WM_ERROR_INVALID_ARG;
    if (shellcode->entriesCount >= WM_SHELLCODE_MAX_ENTRIES) return WM_ERROR_ARRAY_FULL;

    size_t dllNameLen = strlen(dllName);
    size_t fnNameLen = strlen(fnName);
    size_t totalDataSize = dllNameLen + fnNameLen + 2;

    if (shellcode->dataSize + totalDataSize >= WM_SHELLCODE_MAX_DATA_SIZE) return WM_ERROR_ARRAY_FULL;

    void *dllNamePtr = &shellcode->data[shellcode->dataSize];
    void *fnNamePtr = &shellcode->data[shellcode->dataSize];

    memcpy(dllNamePtr, dllName, dllNameLen);
    memcpy(fnNamePtr, fnName, fnNameLen);
    shellcode->dataSize += totalDataSize;

    ((char*)dllNamePtr)[dllNameLen] = '\0';
    ((char*)fnNamePtr)[fnNameLen] = '\0';

    WmShellcodeEntry *entry = &shellcode->entries[shellcode->entriesCount++];
    entry->type = WM_SCENTRY_IMPORT;
    entry->imp.dllNameLen = dllNameLen;
    entry->imp.funcNameLen = fnNameLen;
    entry->imp.dllNameOffset = (wm_byte*)dllNamePtr - shellcode->data;
    entry->imp.funcNameOffset = (wm_byte*)fnNamePtr - shellcode->data;

    return WM_OK;
}

WM_API WmResult wmShellcodeAddString(WmShellcode *shellcode, const char *str)
{
    if (!shellcode || !str) return WM_ERROR_INVALID_ARG;
    if (shellcode->entriesCount >= WM_SHELLCODE_MAX_ENTRIES) return WM_ERROR_INVALID_ARG;

    size_t strLen = strlen(str);
    if (shellcode->dataSize + strLen + 1 >= WM_SHELLCODE_MAX_DATA_SIZE) return WM_ERROR_ARRAY_FULL;

    void *strPtr = shellcode->data + shellcode->dataSize;

    WmShellcodeEntry *entry = &shellcode->entries[shellcode->entriesCount++];
    entry->type = WM_SCENTRY_STRING;
    entry->raw.offset = (wm_byte*)strPtr - shellcode->data;
    entry->raw.size = strLen + 1;

    memcpy(strPtr, str, strLen);
    ((wm_byte*)strPtr)[strLen] = '\0';
    shellcode->dataSize += strLen + 1;

    return WM_OK;
}

WM_API WmResult wmShellcodeAddData(WmShellcode *shellcode, const void *data, size_t dataSize)
{
    if (!shellcode || !data || dataSize == 0) return WM_ERROR_INVALID_ARG;
    if (shellcode->dataSize + dataSize >= WM_SHELLCODE_MAX_DATA_SIZE
        || shellcode->entriesCount >= WM_SHELLCODE_MAX_ENTRIES) return WM_ERROR_ARRAY_FULL;

    void *dataPtr = &shellcode->data[shellcode->dataSize];
    memcpy(dataPtr, data, dataSize);
    shellcode->dataSize += dataSize;

    WmShellcodeEntry *entry = &shellcode->entries[shellcode->entriesCount++];
    entry->type = WM_SCENTRY_RAWDATA;
    entry->raw.offset = 0;
    entry->raw.size = dataSize;

    return WM_OK;
}

static void wm__scResolveFns(WmShellcode *sc, WmShellcodeRemoteData *scrmd) // not used for now
{
    // for (size_t i = 0; i < sc->fnsCount; ++i) {
    //     const char *dll = sc->dlls[i];
    //     const char *fn = sc->fns[i];

    //     HMODULE module = GetModuleHandleA(dll);

    //     if (!module) {
    //         wmLogW(WM_STR("could not find dll %hs, trying to load..."), dll);
    //         module = LoadLibraryA(dll);
    //         if (!module) {
    //             wmLogW(WM_STR("failed to load library %hs, skipping"), dll);
    //             continue;
    //         } else {
    //             wmLogI(WM_STR("library %hs loaded"), dll);
    //         }
    //     }

    //     void *fnPtr = (void*)GetProcAddress(module, fn);
    //     if (!fnPtr) {
    //         wmLogW(WM_STR("failed to load function %hs from library %hs, skipping"), fn, dll);
    //         continue;
    //     }

    //     scrmd->functions[i] = fnPtr;
    // }
}

WM_API WmResult wmShellcodeExecute(WmProcess process, WmShellcode *shellcode)
{
    if (!wm__isProcessHandleValid(process) || !shellcode) return WM_ERROR_INVALID_ARG;

    WmProcessEntry *entry = NULL;
    wm__processHandleGet(process, &entry);

    WmShellcodeRemoteData remoteData = { 0 };
    wm__scResolveFns(shellcode, &remoteData);
    memcpy(remoteData.strings, shellcode->strs, sizeof(shellcode->strs));

    size_t totalWriteSize = sizeof(remoteData) + shellcode->payloadSize;

    uintptr_t remotePtr = 0;
    WmResult result = wmMemoryAlloc(process, totalWriteSize, WM_PROT_EXECUTE_READWRITE, &remotePtr);
    if (result != WM_OK) return result;

    uintptr_t remotePayloadPtr = remotePtr;
    uintptr_t remoteDataPtr = remotePtr + shellcode->payloadSize;

    result = wmMemoryWriteBuffer(process, remotePayloadPtr, (const uint8_t*)shellcode->payload, shellcode->payloadSize);
    if (result != WM_OK) {
        wmLogE(WM_STR("failed to write remote payload"));
        wmMemoryFree(process, remotePtr);
        return result;
    }
    result = wmMemoryWriteBuffer(process, remoteDataPtr, (const uint8_t*)&remoteData, sizeof(remoteData));
    if (result != WM_OK) {
        wmLogE(WM_STR("failed to write remote data"));
        wmMemoryFree(process, remotePtr);
        return result;
    }

    HANDLE thread = CreateRemoteThread(entry->native, NULL, 0, (LPTHREAD_START_ROUTINE)remotePtr, (LPVOID)remoteDataPtr, 0, NULL);
    if (!thread) {
        wmLogE(WM_STR("failed to create remote thread. win32 err: %lu"), GetLastError());
        wmMemoryFree(process, remotePtr);
        return WM_ERROR_ACCESS_DENIED;
    }

    wmLogI(WM_STR("function call in remote process"));

    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);

    wmMemoryFree(process, remotePtr);
    wmLogI(WM_STR("shellcode injection success"));
    return WM_OK;
}

WM_API WmResult wmShellcodeDestroy(WmShellcode *in)
{
    if (!in) return WM_ERROR_INVALID_ARG;
    free(in);
    return WM_OK;
}
