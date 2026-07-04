#include "internal/wm_internal.h"
#include "wm_log.h"
#include "wm_types.h"

WmResult wm__tableAlloc(WmHandleTable *t, uint32_t *slot)
{
    if (!t || !slot) return WM_ERROR_INVALID_ARG;

    for (uint32_t i = 1; i < (uint32_t)t->capacity; ++i) {
        bool *active = (bool*)((uint8_t*)t->entries + i * t->slotSize + t->activeOffset);
        if (!*active) {
            *active = true;
            *slot   = i;
            wmLogI(WM_STR("allocated %hs slot %u"), t->name, i);
            return WM_OK;
        }
    }

    wmLogE(WM_STR("%hs handle table is full (%zu slots)"), t->name, t->capacity);
    return WM_ERROR_TABLE_FULL;
}

WmResult wm__tableFree(WmHandleTable *t, uint32_t slot)
{
    if (!t || slot == 0 || slot >= (uint32_t)t->capacity) return WM_ERROR_INVALID_ARG;

    void *entry    = (uint8_t*)t->entries + slot * t->slotSize;
    bool *active   = (bool*)((uint8_t*)entry + t->activeOffset);
    HANDLE *native = (HANDLE*)((uint8_t*)entry + t->nativeOffset);

    if (!*active) {
        wmLogE(WM_STR("%hs slot %u is not active"), t->name, slot);
        return WM_ERROR_NOT_FOUND;
    }

    CloseHandle(*native);
    memset(entry, 0, t->slotSize);

    wmLogI(WM_STR("released %hs slot %u"), t->name, slot);
    return WM_OK;
}

WmResult wm__tableGet(WmHandleTable *t, uint32_t slot, void **out)
{
    if (!t || !out || slot == 0 || slot >= (uint32_t)t->capacity) return WM_ERROR_INVALID_ARG;

    void *entry  = (uint8_t*)t->entries + slot * t->slotSize;
    bool *active = (bool*)((uint8_t*)entry + t->activeOffset);

    if (!*active) return WM_ERROR_NOT_FOUND;

    *out = entry;
    return WM_OK;
}
