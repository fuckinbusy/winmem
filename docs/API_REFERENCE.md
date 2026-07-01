# winmem — API Reference (OUTDATED)

## Overview

`winmem` is a C library for Windows process memory management. It provides a handle-based abstraction over Win32 APIs for reading, writing, scanning memory, enumerating processes/modules, and injecting shellcode into remote processes.

---

## Types

### Handles

```c
typedef uint32_t WmProcess;
typedef uint32_t WmModule;
typedef uint32_t WmThread;
```

Opaque integer handles. `0` is always invalid. Handles are indices into an internal table of up to `WM_MAX_HANDLES` (16) entries.

### WmResult

```c
typedef enum {
    WM_OK = 0,
    WM_ERROR_INVALID_ARG     = -1,
    WM_ERROR_TABLE_FULL      = -2,
    WM_ERROR_ACCESS_DENIED   = -3,
    WM_ERROR_WINAPI_CALL     = -4,
    WM_ERROR_ARRAY_FULL      = -5,
    WM_ERROR_NOT_FOUND       = -10,
    WM_ERROR_WINDOW_NOT_FOUND   = -11,
    WM_ERROR_PROCESS_NOT_FOUND  = -12,
    WM_ERROR_MODULE_NOT_FOUND   = -13,
    WM_ERROR_THREAD_NOT_FOUND   = -14,
    WM_ERROR_PARTIAL_COPY       = -15,
    WM_ERROR_OUT_OF_MEMORY   = -100
} WmResult;
```

All functions return `WmResult`. Check against `WM_OK` before using output parameters.

### WmProcessInfo

```c
typedef struct {
    uint32_t pid;
    uint32_t parentPid;
    uint32_t threadCount;
    wchar_t  name[WM_MAX_NAME]; // WM_MAX_NAME = 260
} WmProcessInfo;
```

### WmModuleInfo

```c
typedef struct {
    uintptr_t base;
    uint32_t  size;
    wchar_t   name[WM_MAX_NAME];
} WmModuleInfo;
```

### WmThreadInfo

```c
typedef struct {
    uint32_t threadId;
    uint32_t ownerPid;
    int32_t  basePriority;
} WmThreadInfo;
```

### WmShellcode

Opaque structure. Allocate with `wmShellcodeCreate`, populate with `wmShellcodeSet*` / `wmShellcodeAdd*`, execute with `wmShellcodeExecute`, then free with `wmShellcodeDestroy`.

---

## Callbacks

```c
typedef bool (*WmEnumProcessFn)(const WmProcessInfo *info, void *data);
typedef bool (*WmEnumModuleFn)(const WmModuleInfo *info, void *data);
```

Return `WM_CONTINUE` (`true`) to keep enumerating, `WM_STOP` (`false`) to abort early.

---

## Process API

### wmProcessOpen

```c
WmResult wmProcessOpen(WmProcess *out, const wchar_t *name, unsigned long access);
```

Opens a process by executable name (e.g. `L"notepad.exe"`). Sets `*out` to a valid handle on success.

### wmProcessOpenById

```c
WmResult wmProcessOpenById(WmProcess *out, uint32_t id, unsigned long access);
```

Opens a process by PID.

### wmProcessOpenByWindow

```c
WmResult wmProcessOpenByWindow(WmProcess *out, const wchar_t *windowName, unsigned long access);
```

Finds a window by title via `FindWindowW`, then opens its owning process.

### wmProcessClose

```c
WmResult wmProcessClose(WmProcess process);
```

Releases the handle and frees the internal slot. Always call this when done.

### wmProcessEnum

```c
WmResult wmProcessEnum(WmEnumProcessFn fn, void *data);
```

Enumerates all running processes via a TlHelp32 snapshot, calling `fn` for each entry. `data` is forwarded to every callback call.

### Access flags (WmAccessFlags)

Pass a combination of these as the `access` argument:

| Flag | Win32 equivalent | Description |
|---|---|---|
| `WM_ACCESS_READ` | `PROCESS_VM_READ` | Read process memory |
| `WM_ACCESS_WRITE` | `PROCESS_VM_WRITE` | Write process memory |
| `WM_ACCESS_OPERATION` | `PROCESS_VM_OPERATION` | Required for VirtualAllocEx / VirtualProtectEx |
| `WM_ACCESS_QUERY` | `PROCESS_QUERY_INFORMATION` | Query process info |
| `WM_ACCESS_CREATE_THREAD` | `PROCESS_CREATE_THREAD` | Required for CreateRemoteThread |
| `WM_ACCESS_ALL` | `PROCESS_ALL_ACCESS` | All permissions |

---

## Module API

### wmModuleFind

```c
WmResult wmModuleFind(WmProcess process, const wchar_t *name, WmModuleInfo *out);
```

Finds a module loaded in the target process by name (case-insensitive). Fills `*out` with base address, size, and name.

### wmModuleBase

```c
WmResult wmModuleBase(WmProcess process, const wchar_t *name, uintptr_t *out);
```

Convenience wrapper. Returns only the base address of the named module.

### wmModuleEnum

```c
WmResult wmModuleEnum(WmProcess process, WmEnumModuleFn fn, void *data);
```

Enumerates all modules loaded in the process via a TlHelp32 snapshot.

---

## Memory API

### wmMemoryRead

```c
WmResult wmMemoryRead(WmProcess process, uintptr_t address, void *out, size_t size);
```

Reads `size` bytes from `address` in the target process into `out`.

### wmMemoryWrite

```c
WmResult wmMemoryWrite(WmProcess process, uintptr_t address, void *in, size_t size);
```

Writes `size` bytes from `in` to `address` in the target process. Temporarily changes page protection to `PAGE_EXECUTE_READWRITE` if the page is not already writable, restoring it afterwards.

### wmMemoryReadT / wmMemoryWriteT

```c
#define wmMemoryReadT(process, address, out, T)
#define wmMemoryWriteT(process, address, in, T)
```

Typed convenience macros. `sizeof(T)` is used as the size argument.

### wmMemoryWriteBuffer

```c
WmResult wmMemoryWriteBuffer(WmProcess process, uintptr_t address, const uint8_t *buffer, size_t size);
```

Inline wrapper around `wmMemoryWrite` accepting a `const uint8_t*` buffer.

### wmMemoryProtect

```c
WmResult wmMemoryProtect(WmProcess process, uintptr_t address, size_t size,
                         unsigned long protect, unsigned long *oldProtect);
```

Changes page protection flags. The previous flags are written to `*oldProtect`.

### wmMemoryScan

```c
WmResult wmMemoryScan(WmProcess process, uintptr_t address,
                      const uint8_t *buffer, size_t size, uintptr_t *outAddr);
```

Scans the target process memory starting from `address` (pass `0` to scan from the lowest application address) for an exact byte sequence. On success `*outAddr` holds the found address; on failure it is set to `0`.

### wmMemoryScanMask

```c
WmResult wmMemoryScanMask(WmProcess process, uintptr_t address,
                          const char *pattern, uintptr_t *outAddr);
```

Scans with a mask pattern string. Format: space- or comma-separated hex bytes and `?` / `??` wildcards.

Examples:
```
"48 8B 05 ?? ?? ?? ??"
"48,8B,05,?,?,?,?"
```

### wmMemoryAlloc

```c
WmResult wmMemoryAlloc(WmProcess process, size_t size, unsigned long protect, uintptr_t *outAddr);
```

Allocates `size` bytes in the target process at any available address (`VirtualAllocEx` with `MEM_COMMIT | MEM_RESERVE`).

### wmMemoryAllocAt

```c
WmResult wmMemoryAllocAt(WmProcess process, uintptr_t address, size_t size,
                         unsigned long protect, uintptr_t *outAddr);
```

Same as `wmMemoryAlloc` but hints at a specific base address. Pass `0` for no hint (equivalent to `wmMemoryAlloc`).

### wmMemoryFree

```c
WmResult wmMemoryFree(WmProcess process, uintptr_t address);
```

Releases a previously allocated region (`VirtualFreeEx` with `MEM_RELEASE`).

### Memory protection flags (WmMemoryProtectFlags)

Mirrors Win32 `PAGE_*` constants. Common values:

| Flag | Description |
|---|---|
| `WM_PROT_READONLY` | Read only |
| `WM_PROT_READWRITE` | Read / write |
| `WM_PROT_EXECUTE_READ` | Execute / read |
| `WM_PROT_EXECUTE_READWRITE` | Execute / read / write |
| `WM_PROT_NOACCESS` | No access |
| `WM_PROT_GUARD` | Guard page modifier |

---

## Shellcode API

Used to build and inject a position-independent payload into a remote process. The payload runs as a remote thread and receives a `WmShellcodeRemoteData*` argument containing resolved function pointers and string data.

### wmShellcodeCreate

```c
WmResult wmShellcodeCreate(WmShellcode **out);
```

Allocates and zero-initializes a `WmShellcode` descriptor.

### wmShellcodeSetPayload

```c
WmResult wmShellcodeSetPayload(WmShellcode *shellcode,
                               WmShellcodePayloaStartFn fnStart,
                               WmShellcodePayloaEndFn fnEnd);
```

Sets the payload function range. The byte range `[fnStart, fnEnd)` is copied verbatim into the target process. Define the bounds with the provided macros.

### wmShellcodeAddFunction

```c
WmResult wmShellcodeAddFunction(WmShellcode *shellcode, const char *fnDll, const char *fnName);
```

Registers a function to resolve in the calling process and inject into `WmShellcodeRemoteData.functions[]`. Up to `WM_SHELLCODE_MAX_FUNCTIONS` (32) entries.

### wmShellcodeAddString

```c
WmResult wmShellcodeAddString(WmShellcode *shellcode, const char *str);
```

Adds a string into `WmShellcodeRemoteData.strings[]`. Up to `WM_SHELLCODE_MAX_STRINGS` (32) entries, max `WM_SHELLCODE_MAX_STRING_LEN` (128) chars each.

### wmShellcodeExecute

```c
WmResult wmShellcodeExecute(WmProcess process, WmShellcode *shellcode);
```

Injects and executes the payload. Steps:
1. Resolves all registered functions via `GetProcAddress` in the calling process.
2. Allocates `RWX` memory in the target process (payload + data struct).
3. Writes the payload bytes and the `WmShellcodeRemoteData` struct.
4. Creates a remote thread at the payload address, passing `WmShellcodeRemoteData*` as the argument.
5. Waits for completion, then frees the remote allocation.

### wmShellcodeDestroy

```c
WmResult wmShellcodeDestroy(WmShellcode *in);
```

Frees the `WmShellcode` descriptor.

### Payload definition macros

```c
WM_SHELLCODE_START_FN(myFn)   // defines void __stdcall wmscfns__myFn(void *data)
WM_SHELLCODE_END_FN(myFn)     // defines the sentinel end function

WM_SHELLCODE_GETS(myFn)       // expands to function pointer wmscfns__myFn
WM_SHELLCODE_GETE(myFn)       // expands to function pointer wmscfne__myFn
```

Both the start and end functions are decorated with `__attribute__((noinline, optimize("O0")))` to prevent the compiler from reordering or inlining them.

### Payload data access macros

Inside the payload, use these to access the `WmShellcodeRemoteData*` argument:

```c
wmShellcodeGetFunction(remoteDataPtr, index)  // void* — resolved function pointer
wmShellcodeGetString(remoteDataPtr, index)    // const char* — injected string
```

### Minimal example

```c
WM_SHELLCODE_START_FN(myPayload)
{
    typedef int (__stdcall *MessageBoxFn)(void*, const char*, const char*, unsigned);
    MessageBoxFn fn = (MessageBoxFn)wmShellcodeGetFunction(data, 0);
    const char *msg = wmShellcodeGetString(data, 0);
    fn(NULL, msg, msg, 0);
}
WM_SHELLCODE_END_FN(myPayload)

// Injection site:
WmShellcode *sc;
wmShellcodeCreate(&sc);
wmShellcodeSetPayload(sc, WM_SHELLCODE_GETS(myPayload), WM_SHELLCODE_GETE(myPayload));
wmShellcodeAddFunction(sc, "user32.dll", "MessageBoxA");
wmShellcodeAddString(sc, "hello from injected code");
wmShellcodeExecute(process, sc);
wmShellcodeDestroy(sc);
```

---

## Error API

### wmGetErrorStr

```c
const char *wmGetErrorStr(WmResult error);
```

Returns a human-readable description of a `WmResult` error code.

### wmGetErrorStrW

```c
const wchar_t *wmGetErrorStrW(WmResult error);
```

Wide-character version of `wmGetErrorStr`.

### wmGetWinLastError

```c
int wmGetWinLastError();
```

Returns the last Win32 error code (`GetLastError()`). Call immediately after a function returns `WM_ERROR_WINAPI_CALL` or `WM_ERROR_ACCESS_DENIED` for diagnostics.

---

## Build macros

| Macro | Effect |
|---|---|
| `WM__BUILD_DLL` | Decorates public symbols with `__declspec(dllexport)` |
| `WM_USE_DLL` | Decorates public symbols with `__declspec(dllimport)` |
| `WM__DEBUG` | Enables `wmLogI` / `wmLogW` / `wmLogE` output to `stderr` |
| `WM_USE_NATIVE_API` | Replaces `ReadProcessMemory` / `WriteProcessMemory` with `Nt*` equivalents |
