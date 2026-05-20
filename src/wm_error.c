#include "winmem.h"
#include "wm_internal.h"

WM_API const char *wmGetErrorStr(WmResult error)
{
    switch (error) {
        case WM_OK:                      return "No errors.";
        case WM_ERROR_INVALID_ARG:       return "Error: Invalid arguement.";
        case WM_ERROR_TABLE_FULL:        return "Error: Table is full.";
        case WM_ERROR_ACCESS_DENIED:     return "Error: Operation access denied.";
        case WM_ERROR_NOT_FOUND:         return "Error: Not found.";
        case WM_ERROR_WINDOW_NOT_FOUND:  return "Error: Window not found.";
        case WM_ERROR_PROCESS_NOT_FOUND: return "Error: Process not found.";
        case WM_ERROR_MODULE_NOT_FOUND:  return "Error: Module not found.";
        case WM_ERROR_THREAD_NOT_FOUND:  return "Error: Thread not found.";
        case WM_ERROR_PARTIAL_COPY:      return "Error: Partial copy. Copied less data than expected.";
        default:                         return "Error: Unkown.";
    }
}

WM_API const wchar_t *wmGetErrorStrW(WmResult error)
{
    switch (error) {
        case WM_OK:                      return L"No errors.";
        case WM_ERROR_INVALID_ARG:       return L"Error: Invalid arguement.";
        case WM_ERROR_TABLE_FULL:        return L"Error: Table is full.";
        case WM_ERROR_ACCESS_DENIED:     return L"Error: Operation access denied.";
        case WM_ERROR_NOT_FOUND:         return L"Error: Not found.";
        case WM_ERROR_WINDOW_NOT_FOUND:  return L"Error: Window not found.";
        case WM_ERROR_PROCESS_NOT_FOUND: return L"Error: Process not found.";
        case WM_ERROR_MODULE_NOT_FOUND:  return L"Error: Module not found.";
        case WM_ERROR_THREAD_NOT_FOUND:  return L"Error: Thread not found.";
        case WM_ERROR_PARTIAL_COPY:      return L"Error: Partial copy. Copied less data than expected.";
        default:                         return L"Error: Unkown.";
    }
}

WM_API int wmGetWinLastError()
{
    return GetLastError();
}