#include "wm_internal.h"
#include "string.h"

WmHandleEntry g_Handles[WM_MAX_HANDLES] = { 0 };

WmResult wm__handleAlloc(uint32_t *slot)
{
    if (!slot) {
        wmLogE(WM_STR("slot is NULL"));
        return WM_ERROR_INVALID_ARG;
    }

    for (uint32_t i = 1; i < WM_MAX_HANDLES; ++i) {
        if (!g_Handles[i].active) {
            g_Handles[i].active = true;
            *slot = i;
            wmLogI(WM_STR("allocated slot %u"), i);
            return WM_OK;
        }
    }

    wmLogE(WM_STR("handle table is full (%d slots)"), WM_MAX_HANDLES);
    return WM_ERROR_TABLE_FULL;
}

WmResult wm__handleFree(uint32_t slot)
{
    if (slot == 0 || slot >= WM_MAX_HANDLES) {
        wmLogE(WM_STR("slot is invalid value"));
        return WM_ERROR_INVALID_ARG;
    }

    if (!g_Handles[slot].active) {
        wmLogE(WM_STR("active handle not found (slot %u)"), slot);
        return WM_ERROR_NOT_FOUND;
    }

    CloseHandle(g_Handles[slot].native);
    memset(&g_Handles[slot], 0, sizeof(WmHandleEntry));

    wmLogI(WM_STR("slot handle %u released"), slot);
    return WM_OK;
}

WmResult wm__handleGet(uint32_t slot, WmHandleEntry **entry)
{
    if (!entry || slot == 0 || slot >= WM_MAX_HANDLES) {
        wmLogE(WM_STR("invalid entry arg or slot is invalid value"));
        return WM_ERROR_INVALID_ARG;
    }

    if (!g_Handles[slot].active) {
        wmLogE(WM_STR("active handle not found (slot %u)"), slot);
        return WM_ERROR_NOT_FOUND;
    }

    *entry = &g_Handles[slot];
    wmLogI(WM_STR("entry retrieved (slot %u)"), slot);
    return WM_OK;
}
