#ifndef _WINMEM_MEMORY_H
#define _WINMEM_MEMORY_H
#include "wm_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum WmMemoryProtectFlags {
    WM_PROT_NOACCESS          = 0x01,
    WM_PROT_READONLY          = 0x02,
    WM_PROT_READWRITE         = 0x04,
    WM_PROT_WRITECOPY         = 0x08,
    WM_PROT_EXECUTE           = 0x10,
    WM_PROT_EXECUTE_READ      = 0x20,
    WM_PROT_EXECUTE_READWRITE = 0x40,
    WM_PROT_EXECUTE_WRITECOPY = 0x80,

    WM_PROT_GUARD             = 0x100,
    WM_PROT_NOCACHE           = 0x200,
    WM_PROT_WRITECOMBINE      = 0x400,

    /* WDDM */
    WM_PROT_GPU_NOACCESS          = 0x0800,
    WM_PROT_GPU_READONLY          = 0x1000,
    WM_PROT_GPU_READWRITE         = 0x2000,
    WM_PROT_GPU_EXECUTE           = 0x4000,
    WM_PROT_GPU_EXECUTE_READ      = 0x8000,
    WM_PROT_GPU_EXECUTE_READWRITE = 0x10000,
    WM_PROT_GPU_COHERENT          = 0x20000,
    WM_PROT_GPU_NOCACHE           = 0x40000,

    /* Intel SGX / VBS */
    WM_PROT_ENCLAVE_MASK           = 0x10000000,
    WM_PROT_ENCLAVE_DECOMMIT       = 0x10000000, /* (WM_PAGE_ENCLAVE_MASK | 0) */
    WM_PROT_ENCLAVE_SS_FIRST       = 0x10000001, /* (WM_PAGE_ENCLAVE_MASK | 1) */
    WM_PROT_ENCLAVE_SS_REST        = 0x10000002, /* (WM_PAGE_ENCLAVE_MASK | 2) */
    WM_PROT_ENCLAVE_UNVALIDATED    = 0x20000000,
    WM_PROT_ENCLAVE_THREAD_CONTROL = 0x80000000,

    WM_PROT_TARGETS_NO_UPDATE   = 0x40000000,
    WM_PROT_TARGETS_INVALID     = 0x40000000,
    WM_PROT_REVERT_TO_FILE_MAP  = 0x80000000
} WmMemoryProtectFlags;

typedef enum WmMemoryAllocFlags {
    WM_MEM_COMMIT   = 0x00001000,
    WM_MEM_RESERVE  = 0x00002000,
    WM_MEM_DECOMMIT = 0x00004000,
    WM_MEM_RELEASE  = 0x00008000,
    WM_MEM_FREE     = 0x00010000,

    WM_MEM_REPLACE_PLACEHOLDER     = 0x00004000,
    WM_MEM_RESERVE_PLACEHOLDER     = 0x00040000,
    WM_MEM_RESET                   = 0x00080000,
    WM_MEM_TOP_DOWN                = 0x00100000,
    WM_MEM_WRITE_WATCH             = 0x00200000,
    WM_MEM_PHYSICAL                = 0x00400000,
    WM_MEM_ROTATE                  = 0x00800000,
    WM_MEM_DIFFERENT_IMAGE_BASE_OK = 0x00800000,
    WM_MEM_RESET_UNDO              = 0x01000000,
    WM_MEM_LARGE_PAGES             = 0x20000000,
    WM_MEM_4MB_PAGES               = 0x80000000,
    WM_MEM_64K_PAGES               = (WM_MEM_LARGE_PAGES | WM_MEM_PHYSICAL),

    WM_MEM_UNMAP_WITH_TRANSIENT_BOOST = 0x00000001,
    WM_MEM_COALESCE_PLACEHOLDERS      = 0x00000001,
    WM_MEM_PRESERVE_PLACEHOLDER       = 0x00000002,

    WM_MEM_EXTENDED_PARAMETER_GRAPHICS            = 0x00000001,
    WM_MEM_EXTENDED_PARAMETER_NONPAGED            = 0x00000002,
    WM_MEM_EXTENDED_PARAMETER_ZERO_PAGES_OPTIONAL = 0x00000004,
    WM_MEM_EXTENDED_PARAMETER_NONPAGED_LARGE      = 0x00000008,
    WM_MEM_EXTENDED_PARAMETER_NONPAGED_HUGE       = 0x00000010,
    WM_MEM_EXTENDED_PARAMETER_SOFT_FAULT_PAGES    = 0x00000020,
    WM_MEM_EXTENDED_PARAMETER_EC_CODE             = 0x00000040,
    WM_MEM_EXTENDED_PARAMETER_NUMA_NODE_MANDATORY = 0x8000000000000000ULL /* MINLONG64 */
} WmMemoryAllocFlags;

WM_API WmResult wmMemoryRead(WmProcess process, uintptr_t address, void *out, size_t size);
WM_API WmResult wmMemoryWrite(WmProcess process, uintptr_t address, void *in, size_t size);
#define wmMemoryReadT(process, address, out, T) wmMemoryRead((WmProcess)(process), (uintptr_t)(address), (void*)(out), sizeof(T))
#define wmMemoryWriteT(process, address, in, T) wmMemoryWrite((WmProcess)(process), (uintptr_t)(address), (void*)(in), sizeof(T))
WM_API WmResult wmMemoryProtect(WmProcess process, uintptr_t address, size_t size, unsigned long protect, unsigned long *oldProtect);
WM_API WmResult wmMemoryScan(WmProcess process, uintptr_t address, const uint8_t *buffer, size_t size, uintptr_t *outAddr);
WM_API WmResult wmMemoryScanMask(WmProcess process, uintptr_t address, const char *pattern, uintptr_t *outAddr);
WM_API WmResult wmMemoryAllocAt(WmProcess process, uintptr_t address, size_t size, unsigned long protect, uintptr_t *outAddr);
WM_API WmResult wmMemoryFree(WmProcess process, uintptr_t address);

WM_API static inline
WmResult wmMemoryWriteBuffer(WmProcess process, uintptr_t address, const uint8_t *buffer, size_t size)
{
    return wmMemoryWrite(process, address, (void*)buffer, size);
}

WM_API static inline
WmResult wmMemoryAlloc(WmProcess process, size_t size, unsigned long protect, uintptr_t *outAddr)
{
    return wmMemoryAllocAt(process, 0, size, protect, outAddr);
}

#ifdef __cplusplus
}
#endif

#endif
