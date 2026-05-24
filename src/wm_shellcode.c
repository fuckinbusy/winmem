/* welcome to low level hell */
#include "winmem.h"
#include "wm_internal.h"

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

WM_API WmResult wmShellcodeAddFunction(WmShellcode *shellcode, const char *fnDll, const char *fnName)
{
    if (!shellcode || !fnDll || !fnName) return WM_ERROR_INVALID_ARG;
    if (shellcode->fnsCount >= WM_SHELLCODE_MAX_FUNCTIONS) return WM_ERROR_ARRAY_FULL;

    strncpy(shellcode->dlls[shellcode->fnsCount], fnDll, WM_SHELLCODE_MAX_STRING_LEN - 1);
    strncpy(shellcode->fns[shellcode->fnsCount], fnName, WM_SHELLCODE_MAX_STRING_LEN - 1);
    shellcode->fnsCount++;

    return WM_OK;
}

WM_API WmResult wmShellcodeAddString(WmShellcode *shellcode, const char *str)
{
    if (!shellcode || !str) return WM_ERROR_INVALID_ARG;
    if (shellcode->strsCount >= WM_SHELLCODE_MAX_STRINGS) return WM_ERROR_ARRAY_FULL;

    strncpy(shellcode->strs[shellcode->strsCount++], str, WM_SHELLCODE_MAX_STRING_LEN - 1);

    return WM_OK;
}

static void wm__scResolveFns(WmShellcode *sc, WmShellcodeRemoteData *scrmd)
{
    for (size_t i = 0; i < sc->fnsCount; ++i) {
        const char *dll = sc->dlls[i];
        const char *fn = sc->fns[i];

        HMODULE module = GetModuleHandleA(dll);

        if (!module) {
            wmLogW(WM_STR("could not find dll %hs, trying to load..."), dll);
            module = LoadLibraryA(dll);
            if (!module) {
                wmLogW(WM_STR("failed to load library %hs, skipping"), dll);
                continue;
            } else {
                wmLogI(WM_STR("library %hs loaded"), dll);
            }
        }

        void *fnPtr = (void*)GetProcAddress(module, fn);
        if (!fnPtr) {
            wmLogW(WM_STR("failed to load function %hs from library %hs, skipping"), fn, dll);
            continue;
        }

        scrmd->functions[i] = fnPtr;
    }
}

WM_API WmResult wmShellcodeExecute(WmProcess process, WmShellcode *shellcode)
{
    if (!wm__isHandleValid(process) || !shellcode) return WM_ERROR_INVALID_ARG;

    WmHandleEntry *entry = NULL;
    wm__handleGet(process, &entry);

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
