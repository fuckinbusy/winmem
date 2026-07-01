#include "wm_internal.h"

WmThreadEntry g_Threads[WM_MAX_HANDLES] = { 0 };
WmHandleTable g_ThreadsTable = {
    .name         = "threads",
    .entries      = g_Threads,
    .slotSize     = sizeof(WmThreadEntry),
    .capacity     = WM_MAX_HANDLES,
    .activeOffset = offsetof(WmThreadEntry, active),
    .nativeOffset = offsetof(WmThreadEntry, native),
};