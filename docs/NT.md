# winmem — NT API Layer

> ⚠️ **WARNING: NT API is untested**
>
> The entire NT API layer is experimental. It has **not been tested**, provides no correctness guarantees, and very likely contains bugs. Using NT API in production code is **strongly discouraged**. If you need reliable behavior, stick with the default Win32 path (no `WM_USE_NATIVE_API`).

---

## What is the NT API and why does it exist

Windows exposes two levels of API for process memory operations:

- **Win32 API** — public, documented, stable. Functions like `ReadProcessMemory`, `WriteProcessMemory`, `VirtualAllocEx`. This is what winmem uses by default.
- **Native NT API** — the low-level, largely undocumented layer that Win32 is built on top of. Functions like `NtReadVirtualMemory`, `NtWriteVirtualMemory`, and friends live in `ntdll.dll` and have no official Microsoft headers.

The main practical reason to use NT API is **stealth**. Some anti-cheat and protection systems hook or monitor Win32 calls (especially `ReadProcessMemory` / `WriteProcessMemory`) but leave direct NT calls undetected. That is the only reason this path exists in winmem.

The trade-off is real: NT API is unstable across Windows versions, its signatures can change in any update, and Microsoft provides zero compatibility guarantees.

---

## Enabling NT API

NT API is activated by a single compile-time flag:

```c
#define WM_USE_NATIVE_API
```

Define it before including any winmem headers, or pass it through your build system:

```sh
# gcc / clang
-DWM_USE_NATIVE_API

# MSVC
/DWM_USE_NATIVE_API
```

Without this flag the entire NT code path is excluded from the build — no overhead whatsoever.

In addition to the flag, you **must** call `wmInit()` before any other winmem function. `wmInit` is responsible for loading NT function pointers from `ntdll.dll` via `GetProcAddress`. Without it, all NT wrappers will call null pointers and immediately crash.

```c
#define WM_USE_NATIVE_API
#include "winmem.h"

int main(void) {
    WmResult r = wmInit();
    if (r != WM_OK) {
        // NT functions failed to load — cannot continue
        return 1;
    }
    // ...
}
```

---

## Architecture of the NT layer

### Files

| File | Role |
|---|---|
| `wm_ntapi.h` | Types, function pointer typedefs, extern declarations of global pointers, inline wrappers |
| `wm_ntapi.c` | Definitions of global pointers + `wmInit` implementation (loads from ntdll) |
| `wm_memory.c` | Consumes the wrappers from `wm_ntapi.h` via `WM_IMPL_*` aliases |

Consumer code (`winmem.h`) knows nothing about the NT API — `wm_ntapi.h` is an **internal** header and must never be included directly from user code.

### Global function pointers

```c
// Declared in wm_ntapi.h, defined in wm_ntapi.c
extern NtReadVirtualMemoryFn     NtReadVirtualMemory;
extern NtWriteVirtualMemoryFn    NtWriteVirtualMemory;
extern NtAllocateVirtualMemoryFn NtAllocateVirtualMemory;
extern NtFreeVirtualMemoryFn     NtFreeVirtualMemory;
extern NtQueryVirtualMemoryFn    NtQueryVirtualMemory;
extern NtProtectVirtualMemoryFn  NtProtectVirtualMemory;
```

These variables exist only when `WM_USE_NATIVE_API` is defined. `wmInit` populates them at startup via `GetProcAddress(ntdll, "Nt...")`.

### Function pointer typedefs

```c
typedef NTSTATUS (NTAPI *NtReadVirtualMemoryFn)    (HANDLE, PVOID,  PVOID,     SIZE_T,    PSIZE_T);
typedef NTSTATUS (NTAPI *NtWriteVirtualMemoryFn)   (HANDLE, PVOID,  PVOID,     SIZE_T,    PSIZE_T);
typedef NTSTATUS (NTAPI *NtAllocateVirtualMemoryFn)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T,   ULONG, ULONG);
typedef NTSTATUS (NTAPI *NtFreeVirtualMemoryFn)    (HANDLE, PVOID*, PSIZE_T,   ULONG);
typedef NTSTATUS (NTAPI *NtQueryVirtualMemoryFn)   (HANDLE, PVOID,  WM_MEMORY_INFORMATION_CLASS, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (NTAPI *NtProtectVirtualMemoryFn) (HANDLE, PVOID*, PSIZE_T,   ULONG,     PULONG);
```

Unlike Win32, NT functions return `NTSTATUS` instead of `BOOL`. Success is checked with the `NT_SUCCESS(status)` macro — any non-negative value is a success.

### WM_MEMORY_INFORMATION_CLASS enum

```c
typedef enum _WM_MEMORY_INFORMATION_CLASS {
    WmMemoryBasicInformation = 0
} WM_MEMORY_INFORMATION_CLASS;
```

Defined locally to avoid pulling in `ntdef.h` / `winternl.h`, which conflict with `windows.h` in a number of SDK configurations.

---

## Inline wrappers

`wm_ntapi.h` provides six `static inline` functions that hide the Win32 / NT choice behind a unified interface. These are what `wm_memory.c` actually calls.

### wm__readMem

```c
static inline bool wm__readMem(HANDLE h, LPCVOID addr, LPVOID buf, SIZE_T size, SIZE_T *read)
```

Reads `size` bytes from `addr` into `buf`. With `WM_USE_NATIVE_API` calls `NtReadVirtualMemory`, otherwise `ReadProcessMemory`.

### wm__writeMem

```c
static inline bool wm__writeMem(HANDLE h, LPVOID addr, LPCVOID buf, SIZE_T size, SIZE_T *written)
```

Writes `size` bytes from `buf` into `addr`.

### wm__queryMem

```c
static inline SIZE_T wm__queryMem(HANDLE h, LPCVOID addr, PMEMORY_BASIC_INFORMATION mbi, SIZE_T size)
```

Queries memory region information (equivalent of `VirtualQueryEx`). Used by `wmMemoryScan` to iterate committed, readable regions. The NT path calls `NtQueryVirtualMemory` with class `WmMemoryBasicInformation = 0`.

### wm__protectMem

```c
static inline bool wm__protectMem(HANDLE h, LPVOID addr, SIZE_T size, DWORD protect, PDWORD old)
```

Changes page protection flags (equivalent of `VirtualProtectEx`). The NT signature differs: `NtProtectVirtualMemory` takes `PVOID*` and `PSIZE_T` rather than `LPVOID` and `SIZE_T`, so the wrapper creates local copies of those arguments transparently.

### wm__allocMem

```c
static inline void* wm__allocMem(HANDLE h, LPVOID addr, SIZE_T size, DWORD type, DWORD protect)
```

Allocates memory in the target process. The NT version takes `PVOID*` instead of `LPVOID` and passes the size as `PSIZE_T`. The wrapper normalises these differences and returns the allocated address (or `NULL` on failure).

### wm__freeMem

```c
static inline bool wm__freeMem(HANDLE h, LPVOID addr)
```

Releases a memory region (`MEM_RELEASE`). The NT version also requires `PVOID*` and `PSIZE_T`; region size is passed as `0`.

---

`wm_memory.c` only ever uses these aliases, never the Win32 or NT names directly. Switching between the two paths requires exactly one compiler flag and leaves no scattered `#ifdef` blocks in implementation code.

In practice, `wm_memory.c` calls the inline wrappers (`wm__readMem`, `wm__writeMem`, etc.) rather than the aliases directly — the wrappers add parameter normalisation and a uniform `bool` return value.

---

## Win32 ↔ NT function mapping

| Operation | Win32 | NT API |
|---|---|---|
| Read memory | `ReadProcessMemory` | `NtReadVirtualMemory` |
| Write memory | `WriteProcessMemory` | `NtWriteVirtualMemory` |
| Allocate memory | `VirtualAllocEx` | `NtAllocateVirtualMemory` |
| Free memory | `VirtualFreeEx` | `NtFreeVirtualMemory` |
| Query region | `VirtualQueryEx` | `NtQueryVirtualMemory` |
| Change protection | `VirtualProtectEx` | `NtProtectVirtualMemory` |

---

## Known risks and limitations

### API instability

NT API is not officially documented. Microsoft may change signatures, add parameters, or remove functions entirely in any Windows update. The signatures used in winmem are accurate for Windows 10/11 at the time of writing, but are **not guaranteed** to hold for future releases.

### No testing

The NT path has **not been tested at all**. Incorrect results, broken error handling, and crashes on certain system configurations are all plausible. The entire `#ifdef WM_USE_NATIVE_API` branch should be treated as a draft, not production-ready code.

### wmInit is mandatory

Without calling `wmInit()`, all global NT function pointers remain null. Calling any NT wrapper in that state will cause an immediate crash. Under the Win32 path `wmInit` is also declared but is far less critical.

### Access rights

NT functions require the same process access rights as their Win32 equivalents. Switching to NT API does not bypass UAC, Protected Process Light, or any other Windows isolation mechanism.

### Header conflicts

The official Microsoft NT headers (`ntdef.h`, `winternl.h`) conflict with `windows.h`. This is why `wm_ntapi.h` defines necessary types locally (`NTSTATUS`, `WM_MEMORY_INFORMATION_CLASS`) instead of including the official headers.

---

## Recommendation

Unless you have a specific, proven reason to use NT API — such as a concrete protection layer that is known to hook Win32 calls and leave NT calls untouched — **use the default Win32 path**. It is stable, documented, tested, and fully supported. The NT API option exists for narrow specialist use cases and still needs substantial work before it can be considered reliable.
