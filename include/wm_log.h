#ifndef _WINMEM_LOG_H
#define _WINMEM_LOG_H

#ifdef __cplusplus
extern "C" {
#endif

/* if debug macro is defined, default printf or any other function
 * with char* type of parameter cannot be used */
#ifdef WM__DEBUG
#include <stdio.h>
#include <io.h>
#include <fcntl.h>
void wm__InitUnicodeConsole(void);
#define wmLogI(fmt, ...) do {wm__InitUnicodeConsole(); fwprintf(stderr, WM_STR("[WM:INF] %hs:%d ") fmt WM_STR("\n"), __FILE__, __LINE__, ##__VA_ARGS__);} while (0)
#define wmLogW(fmt, ...) do {wm__InitUnicodeConsole(); fwprintf(stderr, WM_STR("[WM:WRN] %hs:%d ") fmt WM_STR("\n"), __FILE__, __LINE__, ##__VA_ARGS__);} while (0)
#define wmLogE(fmt, ...) do {wm__InitUnicodeConsole(); fwprintf(stderr, WM_STR("[WM:ERR] %hs:%d ") fmt WM_STR("\n"), __FILE__, __LINE__, ##__VA_ARGS__);} while (0)
#else
#define wmLogE(...) ((void)0)
#define wmLogW(...) ((void)0)
#define wmLogI(...) ((void)0)
#endif // WM__DEBUG

#ifdef __cplusplus
}
#endif

#endif
