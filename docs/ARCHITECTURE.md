# winmem — Architecture (OUTDATED)

## Project structure

```
winmem/
├── winmem.h          # Public API — the only header consumers include
├── wm_internal.h     # Internal definitions, shared across all .c units
├── wm_handle.c       # Handle table management + debug logging init
├── wm_process.c      # Process open/close/enum
├── wm_module.c       # Module find/enum
├── wm_memory.c       # Memory read/write/protect/scan/alloc/free
├── wm_shellcode.c    # Shellcode build + remote injection
└── wm_error.c        # Error code to string mapping
```

Each `.c` file owns exactly one functional domain. No `.c` file may reach into another domain's internal state — all cross-domain communication goes through the public API or shared internal primitives declared in `wm_internal.h`.

---

## Header separation rule

**`winmem.h`** — public surface only.
- Types, enums, structs, and function signatures that consumers need.
- No Win32 headers. No implementation details. No internal types.
- `WM_API` decoration on every exported symbol.

**`wm_internal.h`** — implementation-only.
- Included by `.c` files, never by consumers.
- Pulls in `<windows.h>` (with `WIN32_LEAN_AND_MEAN`).
- Declares `WmHandleEntry`, `g_Handles`, internal helpers, and logging macros.
- Defines `WM_IMPL_*` aliases that switch between Win32 and native NT implementations.

Adding a new symbol to `winmem.h` is a public API change and should be treated accordingly. Internal helpers stay in `wm_internal.h` or are `static` inside their `.c` file.

---

## Handle table

```c
// wm_internal.h
#define WM_MAX_HANDLES 16

typedef struct {
    bool    active;
    HANDLE  native;   // Win32 HANDLE
    DWORD   id;       // PID
    DWORD   access;   // access flags used at OpenProcess time
    wchar_t name[WM_MAX_NAME];
} WmHandleEntry;

extern WmHandleEntry g_Handles[WM_MAX_HANDLES]; // defined in wm_handle.c
```

`WmProcess` (and similarly `WmModule`, `WmThread`) is a `uint32_t` index into `g_Handles`. Slot `0` is permanently invalid — it acts as a null sentinel.

Lifecycle:
1. `wm__handleAlloc` — finds the first inactive slot (index 1..15), marks it active, returns the index.
2. Caller fills `entry->native`, `entry->id`, `entry->access`, `entry->name`.
3. `wm__handleGet` — resolves a slot index to `WmHandleEntry*`; validates bounds and `active` flag.
4. `wm__handleFree` — calls `CloseHandle`, then `memset`s the slot to zero.

Every public function that accepts a `WmProcess` must validate it first:

```c
// Fast inline check — use before any operation
if (!wm__isHandleValid(process)) return WM_ERROR_INVALID_ARG;

// Full lookup — use when you need the entry
WmHandleEntry *entry = NULL;
wm__handleGet(process, &entry);
```

`wm__isHandleValid` is an inline bounds + active check. `wm__handleGet` additionally returns the pointer and is used when the native `HANDLE` is needed.

---

## Error handling contract

- Every public function returns `WmResult`.
- Output parameters are set only on `WM_OK`. On any error they are left unmodified unless explicitly documented otherwise (e.g. `wmMemoryScan` sets `*outAddr = 0` on failure).
- Win32 calls that fail map to the closest semantic `WmResult`:
  - Access / permission failure → `WM_ERROR_ACCESS_DENIED`
  - Object not found → `WM_ERROR_*_NOT_FOUND`
  - Allocation failure → `WM_ERROR_OUT_OF_MEMORY`
  - Generic Win32 failure with no better mapping → `WM_ERROR_WINAPI_CALL`
- `WM_ERROR_PARTIAL_COPY` is returned when a memory transfer succeeds but transfers fewer bytes than requested.
- The raw Win32 error code is available via `wmGetWinLastError()` immediately after failure.

---

## Logging

Controlled by the `WM__DEBUG` compile-time macro.

```c
// wm_internal.h
#ifdef WM__DEBUG
#define wmLogI(fmt, ...)  // info  → stderr, wide format
#define wmLogW(fmt, ...)  // warn  → stderr, wide format
#define wmLogE(fmt, ...)  // error → stderr, wide format
#else
#define wmLogI(...) ((void)0)
#define wmLogW(...) ((void)0)
#define wmLogE(...) ((void)0)
#endif
```

All format strings use `WM_STR(s)` (`L##s`) so that they are wide literals, consistent with the rest of the Unicode-oriented codebase. Debug builds call `wm__InitUnicodeConsole()` on first use to configure `stdout`/`stderr` for UTF-16.

Logging is diagnostic only. It must never influence control flow or return values.

---

## Unicode policy

All string-facing public API uses `wchar_t*`. This applies to process names, module names, window titles, and error strings. Narrow `char*` is used only internally where Win32 APIs require it (e.g. `GetProcAddress`, `LoadLibraryA`) and inside the shellcode subsystem (injected strings are narrow by design due to the fixed-size flat buffer layout).

`WM_MAX_NAME` (260) is the maximum name length in `wchar_t` characters, matching `MAX_PATH`.

---

## Memory scan architecture

```
wmMemoryScan / wmMemoryScanMask
        │
        └─► wm__memoryScanImpl(process, address, size, compareFn, userData, outAddr)
                    │
                    ├─ VirtualQueryEx    — iterate committed, readable, non-guarded regions
                    ├─ ReadProcessMemory — read each region into a realloc'd local buffer
                    └─ compareFn(buffer, offset, userData)
                            ├─ wm__cmpRawFn   — exact byte match (memcmp)
                            └─ wm__cmpMaskFn  — masked match with ?? wildcard support
```

`wm__memoryScanImpl` is a generic scanner. New scan strategies are added by implementing `WmScanCompareFn` and calling the impl directly (internally). The region buffer is grown with `realloc` as needed and freed after the scan.

Pattern string format for `wmMemoryScanMask`: space- or comma-separated hex bytes; `?` or `??` marks a wildcard byte. Parsed by `wm__parseMask` into parallel `bytes[]` / `mask[]` arrays.

---

## Shellcode injection pipeline

```
wmShellcodeExecute
    │
    ├─ wm__scResolveFns          — GetProcAddress for each registered (dll, fn) pair
    │                              LoadLibraryA if the module is not already loaded
    │
    ├─ wmMemoryAlloc             — single RWX allocation: [payload bytes][WmShellcodeRemoteData]
    │
    ├─ wmMemoryWriteBuffer x2    — write payload, then write data struct
    │
    ├─ CreateRemoteThread        — entry = remotePayloadPtr, param = remoteDataPtr
    │
    ├─ WaitForSingleObject       — synchronous execution
    │
    └─ wmMemoryFree              — release the allocation regardless of outcome
```

`WmShellcodeRemoteData` layout (flat, position-independent):

```c
typedef struct {
    void *functions[WM_SHELLCODE_MAX_FUNCTIONS];          // resolved fn pointers
    char  strings[WM_SHELLCODE_MAX_STRINGS][WM_SHELLCODE_MAX_STRING_LEN]; // injected strings
} WmShellcodeRemoteData;
```

Payloads access this struct through the two macros `wmShellcodeGetFunction(ptr, i)` and `wmShellcodeGetString(ptr, i)`, which perform direct pointer arithmetic and require no runtime library. This is intentional: the payload must be self-contained.

Payload functions are declared with `__attribute__((noinline, optimize("O0")))` to prevent the compiler from merging or reordering them. The byte range `[fnStart, fnEnd)` is used verbatim; the end sentinel function contains a `volatile int _ = 0` to prevent it from being optimized away.

---

## Implementation switch (WM_USE_NATIVE_API)

`wm_internal.h` defines `WM_IMPL_*` aliases:

```c
#ifdef WM_USE_NATIVE_API
    #define WM_IMPL_READ_MEM    NtReadVirtualMemory
    #define WM_IMPL_WRITE_MEM   NtWriteVirtualMemory
    // ...
#else
    #define WM_IMPL_READ_MEM    ReadProcessMemory
    #define WM_IMPL_WRITE_MEM   WriteProcessMemory
    // ...
#endif
```

`wm_memory.c` uses only these aliases, never the Win32 or NT names directly. This keeps the swap to a single compile-time flag and avoids scattered `#ifdef` blocks in implementation code.

---

## Naming conventions

| Category | Convention | Example |
|---|---|---|
| Public functions | `wmCamelCase` | `wmMemoryRead`, `wmProcessOpen` |
| Public types/structs | `Wm` prefix, PascalCase | `WmResult`, `WmProcessInfo` |
| Public enums | `WM_UPPER_SNAKE` values | `WM_OK`, `WM_ACCESS_READ` |
| Internal functions | `wm__lowerCamel` (double underscore) | `wm__handleAlloc`, `wm__parseMask` |
| Internal static functions | `wm__lowerCamel` in their `.c` file | `wm__cmpRawFn`, `wm__traverseModules` |
| Internal globals | `g_PascalCase` | `g_Handles` |
| Macros (public) | `WM_UPPER_SNAKE` | `WM_MAX_NAME`, `WM_SHELLCODE_START_FN` |
| Macros (internal) | `WM_UPPER_SNAKE` | `WM_IMPL_READ_MEM`, `WM_STR` |

The double-underscore prefix on internal functions (`wm__`) signals that they are not part of the public API and may change without notice. Do not use them from consuming code.

---

## Constraints and limits

| Constant | Value | Defined in |
|---|---|---|
| `WM_MAX_HANDLES` | 16 | `wm_internal.h` |
| `WM_MAX_NAME` | 260 | `winmem.h` |
| `WM_SHELLCODE_MAX_FUNCTIONS` | 32 | `winmem.h` |
| `WM_SHELLCODE_MAX_STRINGS` | 32 | `winmem.h` |
| `WM_SHELLCODE_MAX_STRING_LEN` | 128 | `winmem.h` |

`WM_MAX_HANDLES` is intentionally small. It is a debugging/tooling library, not a process manager. If 15 simultaneous open process handles are not enough for a use case, the constant should be raised with care (linear scan in `wm__handleAlloc`).
