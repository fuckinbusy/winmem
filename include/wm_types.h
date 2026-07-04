#ifndef _WINMEM_TYPES_H
#define _WINMEM_TYPES_H
#include <stdint.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdbool.h>
#include <wchar.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint8_t   wm_byte;
typedef uint8_t   wm_u8;
typedef uint16_t  wm_u16;
typedef uint32_t  wm_u32;
typedef uint64_t  wm_u64;
typedef int8_t    wm_i8;
typedef int16_t   wm_i16;
typedef int32_t   wm_i32;
typedef int64_t   wm_i64;
typedef size_t    wm_usize;
typedef wm_u16    wm_word;
typedef wm_u32    wm_dword;
typedef wm_u64    wm_qword;
typedef uintptr_t wm_uptr;
typedef void      wm_void;

#ifdef WM__BUILD_DLL
    #define WM_API __declspec(dllexport)
#elif defined(WM__USE_DLL)
    #define WM_API __declspec(dllimport)
#else
    #define WM_API
#endif // WM__BUILD_DLL

#define WM_MAX_NAME 260 

#define WM_STOP     false
#define WM_CONTINUE true

/* Handlers */
typedef uint32_t WmProcess;
typedef uint32_t WmModule;
typedef uint32_t WmThread;

typedef enum {
    WM_OK = 0,

    WM_ERROR_INVALID_ARG = -1,
    WM_ERROR_TABLE_FULL = -2,
    WM_ERROR_ACCESS_DENIED = -3,
    WM_ERROR_WINAPI_CALL = -4,
    WM_ERROR_ARRAY_FULL = -5,

    WM_ERROR_NOT_FOUND = -10,
    WM_ERROR_WINDOW_NOT_FOUND = -11,
    WM_ERROR_PROCESS_NOT_FOUND = -12,
    WM_ERROR_MODULE_NOT_FOUND = -13,
    WM_ERROR_THREAD_NOT_FOUND = -14,
    WM_ERROR_PARTIAL_COPY = -15,

    WM_ERROR_OUT_OF_MEMORY = -100
} WmResult;


#ifdef __cplusplus
}
#endif

#endif
