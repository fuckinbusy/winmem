/*
 * @fuckinbusy
 *
 * single-header collections library
 *
 * private functions are named with _vcollections prefix
 * they are designed to be internal and used only by this library itself
 * do not use them, its a bad idea
 *
 * -----------------------------------------------------------------------------
 * USAGE
 * -----------------------------------------------------------------------------
 *   In exactly ONE .c file:
 *       #define VCOLLECTIONS_IMPLEMENTATION
 *       #include "vcollections.h"
 *   Everywhere else just:
 *       #include "vcollections.h"
 *
 * -----------------------------------------------------------------------------
 * SELECTIVE COMPILATION (optional)
 * -----------------------------------------------------------------------------
 *   By default every collection is enabled. If you want only a subset:
 *       #define VCOLLECTIONS_SELECTIVE
 *       #define VCOLLECTIONS_USING_VARRAY
 *       #define VCOLLECTIONS_USING_VSTR
 *       #include "vcollections.h"
 *   Dependencies are resolved automatically:
 *       VSTACK -> VARRAY
 *       VSTR   -> VSTR_VIEW
 *   <stdio.h> is only pulled in when VFILE is enabled.
 * -----------------------------------------------------------------------------
 */

#ifndef _VCOLLECTIONS_H
#define _VCOLLECTIONS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h> /* memcpy/strlen used by the always-visible inline accessors */

/* ============================================================
 *  FEATURE SELECTION
 * ============================================================ */
#ifndef VCOLLECTIONS_SELECTIVE
    /* default: everything on, zero boilerplate for the common case */
    #define VCOLLECTIONS_USING_VARRAY
    #define VCOLLECTIONS_USING_VSTACK
    #define VCOLLECTIONS_USING_VQUEUE
    #define VCOLLECTIONS_USING_VFILE
    #define VCOLLECTIONS_USING_VSTR
#endif

/* dependency resolution */
#ifdef VCOLLECTIONS_USING_VSTACK
    #ifndef VCOLLECTIONS_USING_VARRAY
        #define VCOLLECTIONS_USING_VARRAY
    #endif
#endif
#ifdef VCOLLECTIONS_USING_VSTR
    #ifndef VCOLLECTIONS_USING_VSTR_VIEW
        #define VCOLLECTIONS_USING_VSTR_VIEW
    #endif
#endif

/* small overflow guard used by the growable containers */
#define _VCOLLECTIONS_MUL_OVERFLOWS(a, b) ((b) != 0 && (a) > (SIZE_MAX / (b)))

/* ============================================================
 *  VARRAY  -  interface
 * ============================================================ */
#ifdef VCOLLECTIONS_USING_VARRAY

#ifndef VCOLLECTIONS_ARRAY_INIT_CAP
#define VCOLLECTIONS_ARRAY_INIT_CAP 16
#endif

#ifndef VCOLLECTIONS_ARRAY_GROW_MUL
#define VCOLLECTIONS_ARRAY_GROW_MUL 2
#endif

typedef struct varray {
    void    *data;
    size_t  size;
    size_t  capacity;
    size_t  elem_size;
} varray;

/* pass init_cap == 0 to fall back to VCOLLECTIONS_ARRAY_INIT_CAP */
bool varray_create(size_t elem_size, size_t init_cap, varray *out);
void varray_destroy(varray *arr);
bool varray_reserve(varray *arr, size_t new_cap);
bool varray_shrink(varray *arr);
bool varray_push(varray *arr, const void *elem);
bool varray_pop(varray *arr, void *out);
bool varray_remove(varray *arr, size_t i);

/* inline accessors: no heap ops, just pointer math or a field write.
 * They live in the interface (not behind IMPLEMENTATION) because a
 * `static inline` definition must be visible in every TU that calls it. */
static inline void varray_clear(varray *arr)
{
    if (arr) arr->size = 0;
}

static inline void *varray_get(const varray *arr, size_t i)
{
    if (!arr || i >= arr->size) return NULL;
    return (char *)arr->data + i * arr->elem_size;
}

static inline bool varray_set(varray *arr, size_t i, const void *elem)
{
    if (!arr || !elem || i >= arr->size) return false;
    memcpy((char *)arr->data + i * arr->elem_size, elem, arr->elem_size);
    return true;
}

#endif /* VCOLLECTIONS_USING_VARRAY */

/* ============================================================
 *  VSTACK  -  interface  (thin wrappers over varray)
 * ============================================================ */
#ifdef VCOLLECTIONS_USING_VSTACK

typedef varray vstack;

static inline bool vstack_create(size_t elem_size, size_t init_cap, vstack *out)
{
    return varray_create(elem_size, init_cap, out);
}

static inline void vstack_destroy(vstack *stack)
{
    varray_destroy(stack);
}

static inline bool vstack_push(vstack *stack, const void *elem)
{
    return varray_push(stack, elem);
}

static inline bool vstack_pop(vstack *stack, void *out)
{
    return varray_pop(stack, out);
}

static inline void *vstack_peek(const vstack *stack)
{
    if (!stack || !stack->size) return NULL;
    return varray_get(stack, stack->size - 1);
}

#endif /* VCOLLECTIONS_USING_VSTACK */

/* ============================================================
 *  VQUEUE  -  interface  (ring buffer)
 * ============================================================ */
#ifdef VCOLLECTIONS_USING_VQUEUE

typedef struct vqueue {
    void    *data;
    size_t  size;
    size_t  capacity;
    size_t  elem_size;
    size_t  head;
} vqueue;

bool vqueue_create(size_t elem_size, size_t init_cap, vqueue *out);
void vqueue_destroy(vqueue *queue);
bool vqueue_push(vqueue *queue, const void *elem);
bool vqueue_pop(vqueue *queue, void *out);

static inline void *vqueue_peek(const vqueue *queue)
{
    if (!queue || !queue->size) return NULL;
    return (char *)queue->data + queue->head * queue->elem_size;
}

static inline void vqueue_clear(vqueue *queue)
{
    if (!queue) return;
    queue->size = 0;
    queue->head = 0;
}

#endif /* VCOLLECTIONS_USING_VQUEUE */

/* ============================================================
 *  VFILE  -  interface
 * ============================================================ */
#ifdef VCOLLECTIONS_USING_VFILE

typedef struct vfile {
    uint8_t *data;
    size_t   size;
} vfile;

/* none of these are inline: all do I/O or heavy loops.
 * vfile_read overwrites *out; the caller must zero-init it or have
 * called vfile_destroy on it first (it does not inspect old contents). */
void vfile_destroy(vfile *f);
bool vfile_read(const char *path, vfile *out);
bool vfile_write(const char *path, const vfile *f);
bool vfile_write_to(void *dst, size_t dst_size, const vfile *f);
bool vfile_crc32(const vfile *f, uint32_t *out);

#endif /* VCOLLECTIONS_USING_VFILE */

/* ============================================================
 *  VSTR_VIEW  -  interface  (non-owning slice)
 * ============================================================ */
#ifdef VCOLLECTIONS_USING_VSTR_VIEW

typedef struct vstr_view {
    const char *data;
    size_t      length;
} vstr_view;

static inline vstr_view vstr_view_from_cstr(const char *s)
{
    return (vstr_view){ s, s ? strlen(s) : 0 };
}

/* half-open [start, stop). out-of-range stop is clamped to length.
 * start past the end (or start > stop) yields an empty view. */
static inline vstr_view vstr_view_slice(vstr_view v, size_t start, size_t stop)
{
    if (stop > v.length) stop = v.length;
    if (start > stop)    return (vstr_view){ v.data + v.length, 0 };
    return (vstr_view){ v.data + start, stop - start };
}

static inline vstr_view vstr_view_slice_from_cstr(const char *s, size_t start, size_t stop)
{
    return vstr_view_slice(vstr_view_from_cstr(s), start, stop);
}

#endif /* VCOLLECTIONS_USING_VSTR_VIEW */

/* ============================================================
 *  VSTR  -  interface  (owning string with SSO)
 * ============================================================ */
#ifdef VCOLLECTIONS_USING_VSTR

#define VSTR_SSO_CAPACITY 64

typedef struct vstr {
    union {
        struct {
            char   *data;
            size_t  length;
        } heap_str;
        struct {
            char    buffer[VSTR_SSO_CAPACITY];
            uint8_t length;
        } stack_str;
    };
    bool is_heap;
} vstr;

bool vstr_from_cstr(const char *s, vstr *out);
bool vstr_from_view(vstr_view v, vstr *out);
void vstr_destroy(vstr *s);

static inline size_t vstr_len(const vstr *s)
{
    return s->is_heap ? s->heap_str.length : s->stack_str.length;
}

static inline const char *vstr_cstr(const vstr *s)
{
    return s->is_heap ? s->heap_str.data : s->stack_str.buffer;
}

#endif /* VCOLLECTIONS_USING_VSTR */

/* ============================================================
 *  IMPLEMENTATION
 * ============================================================ */
#ifdef VCOLLECTIONS_IMPLEMENTATION

#include <stdlib.h>
#include <string.h>
#ifdef VCOLLECTIONS_USING_VFILE
#include <stdio.h>
#endif

/* ============================================================
 *  VARRAY  -  implementation
 * ============================================================ */
#ifdef VCOLLECTIONS_USING_VARRAY

bool varray_create(size_t elem_size, size_t init_cap, varray *out)
{
    if (!out || elem_size == 0) return false;

    size_t cap = init_cap ? init_cap : VCOLLECTIONS_ARRAY_INIT_CAP;
    if (_VCOLLECTIONS_MUL_OVERFLOWS(cap, elem_size)) return false;

    void *mem = malloc(cap * elem_size);
    if (!mem) return false;

    out->data      = mem;
    out->size      = 0;
    out->capacity  = cap;
    out->elem_size = elem_size;
    return true;
}

void varray_destroy(varray *arr)
{
    if (!arr) return;
    free(arr->data);
    arr->data      = NULL;
    arr->size      = 0;
    arr->capacity  = 0;
    arr->elem_size = 0;
}

bool varray_reserve(varray *arr, size_t new_cap)
{
    if (!arr) return false;
    if (new_cap <= arr->capacity) return true;
    if (_VCOLLECTIONS_MUL_OVERFLOWS(new_cap, arr->elem_size)) return false;

    void *mem = realloc(arr->data, new_cap * arr->elem_size);
    if (!mem) return false;

    arr->data     = mem;
    arr->capacity = new_cap;
    return true;
}

bool varray_shrink(varray *arr)
{
    if (!arr) return false;
    if (arr->size == arr->capacity) return true;

    size_t size = arr->size ? arr->size : 1;
    void *mem = realloc(arr->data, size * arr->elem_size);
    if (!mem) return false;

    arr->data     = mem;
    arr->capacity = size;
    return true;
}

bool varray_push(varray *arr, const void *elem)
{
    if (!arr || !elem) return false;

    if (arr->size == arr->capacity) {
        size_t new_cap = arr->capacity ? arr->capacity * VCOLLECTIONS_ARRAY_GROW_MUL
                                        : VCOLLECTIONS_ARRAY_INIT_CAP;
        if (!varray_reserve(arr, new_cap))
            return false;
    }

    memcpy((char *)arr->data + arr->size * arr->elem_size, elem, arr->elem_size);
    arr->size++;
    return true;
}

bool varray_pop(varray *arr, void *out)
{
    if (!arr || !arr->size) return false;

    arr->size--;
    if (out)
        memcpy(out, (char *)arr->data + arr->size * arr->elem_size, arr->elem_size);

    return true;
}

bool varray_remove(varray *arr, size_t i)
{
    if (!arr || i >= arr->size) return false;

    size_t tail = arr->size - i - 1;
    if (tail > 0) {
        char *dst = (char *)arr->data + i * arr->elem_size;
        char *src = (char *)arr->data + (i + 1) * arr->elem_size;
        memmove(dst, src, tail * arr->elem_size);
    }

    arr->size--;
    return true;
}

#endif /* VCOLLECTIONS_USING_VARRAY */

/* ============================================================
 *  VQUEUE  -  implementation
 * ============================================================ */
#ifdef VCOLLECTIONS_USING_VQUEUE

bool vqueue_create(size_t elem_size, size_t init_cap, vqueue *out)
{
    if (!out || elem_size == 0) return false;

    size_t cap = init_cap ? init_cap : VCOLLECTIONS_ARRAY_INIT_CAP;
    if (_VCOLLECTIONS_MUL_OVERFLOWS(cap, elem_size)) return false;

    void *mem = malloc(cap * elem_size);
    if (!mem) return false;

    out->data      = mem;
    out->size      = 0;
    out->capacity  = cap;
    out->elem_size = elem_size;
    out->head      = 0;
    return true;
}

void vqueue_destroy(vqueue *queue)
{
    if (!queue) return;
    free(queue->data);
    queue->data      = NULL;
    queue->size      = 0;
    queue->capacity  = 0;
    queue->elem_size = 0;
    queue->head      = 0;
}

bool vqueue_push(vqueue *queue, const void *elem)
{
    if (!queue || !elem) return false;

    if (queue->size == queue->capacity) {
        /* full -> grow. compaction never helps here: when size==capacity
         * every slot is occupied, so we always need more memory. */
        size_t old_cap = queue->capacity;
        size_t new_cap = old_cap ? old_cap * VCOLLECTIONS_ARRAY_GROW_MUL
                                  : VCOLLECTIONS_ARRAY_INIT_CAP;
        if (_VCOLLECTIONS_MUL_OVERFLOWS(new_cap, queue->elem_size)) return false;

        void *mem = realloc(queue->data, new_cap * queue->elem_size);
        if (!mem) return false;
        queue->data = mem;

        /* realloc preserves the linear byte image, but the live elements may
         * have wrapped: physical [head, old_cap) holds the front, physical
         * [0, head) holds the back. Unwrap by moving [0, head) to just past
         * the old end so the elements become contiguous starting at head. */
        if (queue->head > 0) {
            memcpy((char *)queue->data + old_cap * queue->elem_size,
                   queue->data,
                   queue->head * queue->elem_size);
        }
        queue->capacity = new_cap;
    }

    size_t tail = (queue->head + queue->size) % queue->capacity;
    memcpy((char *)queue->data + tail * queue->elem_size, elem, queue->elem_size);
    queue->size++;
    return true;
}

bool vqueue_pop(vqueue *queue, void *out)
{
    if (!queue || !queue->size) return false;

    if (out)
        memcpy(out, (char *)queue->data + queue->head * queue->elem_size, queue->elem_size);

    queue->head = (queue->head + 1) % queue->capacity;
    queue->size--;
    return true;
}

#endif /* VCOLLECTIONS_USING_VQUEUE */

/* ============================================================
 *  VFILE  -  implementation
 * ============================================================ */
#ifdef VCOLLECTIONS_USING_VFILE

bool vfile_read(const char *path, vfile *out)
{
    if (!path || !out) return false;

    FILE *f = fopen(path, "rb");
    if (!f) return false;

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return false; }
    long fsize = ftell(f);
    if (fsize < 0) { fclose(f); return false; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return false; }

    /* allocate at least 1 byte so a 0-byte file still yields a valid pointer */
    void *mem = malloc((size_t)fsize ? (size_t)fsize : 1);
    if (!mem) { fclose(f); return false; }

    size_t bytes_read = fread(mem, 1, (size_t)fsize, f);
    fclose(f);

    if (bytes_read < (size_t)fsize) {
        free(mem);
        return false;
    }

    out->data = (uint8_t *)mem;
    out->size = bytes_read;
    return true;
}

bool vfile_write(const char *path, const vfile *f)
{
    if (!path || !f || !f->data) return false;

    FILE *fp = fopen(path, "wb");
    if (!fp) return false;

    size_t written = fwrite(f->data, 1, f->size, fp);
    fclose(fp);

    return written == f->size;
}

bool vfile_write_to(void *dst, size_t dst_size, const vfile *f)
{
    if (!dst || !f || !f->data || dst_size < f->size) return false;

    memcpy(dst, f->data, f->size);
    return true;
}

void vfile_destroy(vfile *f)
{
    if (!f) return;
    free(f->data);
    f->data = NULL;
    f->size = 0;
}

bool vfile_crc32(const vfile *f, uint32_t *out)
{
    if (!f || !out) return false;
    if (f->size && !f->data) return false;

    static uint32_t crc_table[256];
    static bool      crc_ready = false;

    if (!crc_ready) {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k)
                c = (c & 1) ? ((c >> 1) ^ 0xEDB88320u) : (c >> 1);
            crc_table[i] = c;
        }
        crc_ready = true; /* NB: not thread-safe on first call */
    }

    uint32_t crc       = 0xFFFFFFFFu;
    const uint8_t *p   = f->data;
    const uint8_t *end = f->data + f->size;

    while (p < end)
        crc = crc_table[(crc ^ *p++) & 0xFF] ^ (crc >> 8);

    *out = crc ^ 0xFFFFFFFFu;
    return true;
}

#endif /* VCOLLECTIONS_USING_VFILE */

/* ============================================================
 *  VSTR  -  implementation
 * ============================================================ */
#ifdef VCOLLECTIONS_USING_VSTR

bool vstr_from_cstr(const char *s, vstr *out)
{
    if (!s || !out) return false;

    size_t slen = strlen(s);

    if (slen <= VSTR_SSO_CAPACITY - 1) {
        memcpy(out->stack_str.buffer, s, slen + 1);
        out->stack_str.length = (uint8_t)slen;
        out->is_heap = false;
    } else {
        char *p = (char *)malloc(slen + 1);
        if (!p) return false;
        memcpy(p, s, slen + 1);
        out->heap_str.data   = p;
        out->heap_str.length = slen;
        out->is_heap = true;
    }

    return true;
}

bool vstr_from_view(vstr_view v, vstr *out)
{
    if (!out) return false;
    if (v.length && !v.data) return false;

    size_t slen = v.length;

    if (slen <= VSTR_SSO_CAPACITY - 1) {
        if (slen) memcpy(out->stack_str.buffer, v.data, slen);
        out->stack_str.buffer[slen] = '\0';
        out->stack_str.length = (uint8_t)slen;
        out->is_heap = false;
    } else {
        char *p = (char *)malloc(slen + 1);
        if (!p) return false;
        memcpy(p, v.data, slen);
        p[slen] = '\0';
        out->heap_str.data   = p;
        out->heap_str.length = slen;
        out->is_heap = true;
    }

    return true;
}

void vstr_destroy(vstr *s)
{
    if (!s) return;
    if (s->is_heap) {
        free(s->heap_str.data);
        s->heap_str.data   = NULL;
        s->heap_str.length = 0;
    } else {
        s->stack_str.buffer[0] = '\0';
        s->stack_str.length = 0;
    }
    s->is_heap = false; /* leave the object in a safe, re-destroyable state */
}

#endif /* VCOLLECTIONS_USING_VSTR */

#ifdef VCOLLECTIONS_USING_VMAP
// TODO
#endif /* VCOLLECTIONS_USING_VMAP */

#endif /* VCOLLECTIONS_IMPLEMENTATION */
#endif /* _VCOLLECTIONS_H */
