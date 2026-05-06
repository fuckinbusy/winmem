#include "winmem.h"

WM_API const char *wmGetErrorStr(WmResult error)
{
    switch (error) {
        case WM_OK:                      return "WM_OK";
        case WM_ERROR_INVALID_ARG:       return "WM_ERROR_INVALID_ARG";
        case WM_ERROR_TABLE_FULL:        return "WM_ERROR_TABLE_FULL";
        case WM_ERROR_ACCESS_DENIED:     return "WM_ERROR_ACCESS_DENIED";
        case WM_ERROR_NOT_FOUND:         return "WM_ERROR_NOT_FOUND";
        case WM_ERROR_WINDOW_NOT_FOUND:  return "WM_ERROR_WINDOW_NOT_FOUND";
        case WM_ERROR_PROCESS_NOT_FOUND: return "WM_ERROR_PROCESS_NOT_FOUND";
        case WM_ERROR_MODULE_NOT_FOUND:  return "WM_ERROR_MODULE_NOT_FOUND";
        case WM_ERROR_THREAD_NOT_FOUND:  return "WM_ERROR_THREAD_NOT_FOUND";
        default:                         return "WM_ERROR_UNKNOWN";
    }
}
