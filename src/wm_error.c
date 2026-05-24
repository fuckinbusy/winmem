#include "winmem.h"
#include "wm_internal.h"

#define WM_ERROR_LIST(X)                                         \
    X(WM_OK, "No errors.")                                       \
    X(WM_ERROR_INVALID_ARG, "Error: Invalid argument.")          \
    X(WM_ERROR_TABLE_FULL, "Error: Table is full.")              \
    X(WM_ERROR_ACCESS_DENIED, "Error: Operation access denied.") \
    X(WM_ERROR_NOT_FOUND, "Error: Not found.")                   \
    X(WM_ERROR_WINDOW_NOT_FOUND, "Error: Window not found.")     \
    X(WM_ERROR_PROCESS_NOT_FOUND, "Error: Process not found.")   \
    X(WM_ERROR_MODULE_NOT_FOUND, "Error: Module not found.")     \
    X(WM_ERROR_THREAD_NOT_FOUND, "Error: Thread not found.")     \
    X(WM_ERROR_PARTIAL_COPY, "Error: Partial copy. Copied less data than expected.") \
    X(WM_ERROR_OUT_OF_MEMORY, "Error: Memory allocation failed.") \
    X(WM_ERROR_ARRAY_FULL, "Error: Attempt to write to a full array.")

WM_API const char *wmGetErrorStr(WmResult error)
{
    switch (error) {
        #define X_CHAR(id, str) case id: return str;
        WM_ERROR_LIST(X_CHAR)
        #undef X_CHAR
        default: return "Error: Unknown.";
    }
}

WM_API const wchar_t *wmGetErrorStrW(WmResult error)
{
    switch (error) {
        #define X_WCHAR(id, str) case id: return L##str;
        WM_ERROR_LIST(X_WCHAR)
        #undef X_WCHAR
        default: return L"Error: Unknown.";
    }
}

#undef WM_ERROR_LIST

WM_API int wmGetWinLastError()
{
    return GetLastError();
}
