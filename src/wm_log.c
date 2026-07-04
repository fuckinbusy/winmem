#include "wm_log.h"
#include <stdbool.h>

#ifdef WM__DEBUG
void wm__InitUnicodeConsole(void)
{
    static bool active = false;
    if (!active) {
        _setmode(_fileno(stderr), _O_U16TEXT);
        _setmode(_fileno(stdout), _O_U16TEXT);
        active = true;
    }
}
#endif
