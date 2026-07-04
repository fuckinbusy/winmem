#ifndef _WINMEM_ERROR_H
#define _WINMEM_ERROR_H
#include "wm_types.h"

#ifdef __cplusplus
extern "C" {
#endif

WM_API const char *wmGetErrorStr(WmResult error);
WM_API const wchar_t *wmGetErrorStrW(WmResult error);
WM_API int wmGetWinLastError();

#ifdef __cplusplus
}
#endif

#endif
