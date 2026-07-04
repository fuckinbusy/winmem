#ifndef _WINMEM_THREAD_H
#define _WINMEM_THREAD_H
#include "wm_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t threadId;
    uint32_t ownerPid;
    int32_t basePriority;
} WmThreadInfo;

#ifdef __cplusplus
}
#endif

#endif
