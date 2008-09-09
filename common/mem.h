/******************************************************************************/
/*          pfixtools: a collection of postfix related tools                  */
/*          ~~~~~~~~~                                                         */
/*  ________________________________________________________________________  */
/*                                                                            */
/*  Redistribution and use in source and binary forms, with or without        */
/*  modification, are permitted provided that the following conditions        */
/*  are met:                                                                  */
/*                                                                            */
/*  1. Redistributions of source code must retain the above copyright         */
/*     notice, this list of conditions and the following disclaimer.          */
/*  2. Redistributions in binary form must reproduce the above copyright      */
/*     notice, this list of conditions and the following disclaimer in the    */
/*     documentation and/or other materials provided with the distribution.   */
/*  3. The names of its contributors may not be used to endorse or promote    */
/*     products derived from this software without specific prior written     */
/*     permission.                                                            */
/*                                                                            */
/*  THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND   */
/*  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE     */
/*  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR        */
/*  PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS    */
/*  BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR    */
/*  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF      */
/*  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS  */
/*  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN   */
/*  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)   */
/*  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF    */
/*  THE POSSIBILITY OF SUCH DAMAGE.                                           */
/******************************************************************************/

/*
 * Copyright © 2006 Pierre Habouzit
 */

#ifndef PFIXTOOLS_MEM_H
#define PFIXTOOLS_MEM_H

#include <assert.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#define MIN(a, b)               ((a) < (b) ? (a) : (b))
#define MAX(a, b)               ((a) > (b) ? (a) : (b))

#define ssizeof(foo)            (ssize_t)sizeof(foo)
#define countof(foo)            (ssizeof(foo) / ssizeof(foo[0]))

#define p_new(type, count)      ((type *)xmalloc(sizeof(type) * (count)))
#define p_clear(p, count)       ((void)memset((p), 0, sizeof(*(p)) * (count)))
#define p_dup(p, count)         xmemdup((p), sizeof(*(p)) * (count))
#define p_dupstr(p, len)        xmemdupstr((p), (len))
#define p_realloc(pp, count)    xrealloc((void*)(pp), sizeof(**(pp)) * (count))

#  define p_alloc_nr(x) (((x) + 16) * 3 / 2)
#  define p_allocgrow(pp, goalnb, allocnb)                  \
    do {                                                    \
        if ((goalnb) > *(allocnb)) {                        \
            if (p_alloc_nr(goalnb) > *(allocnb)) {          \
                *(allocnb) = (goalnb);                      \
            } else {                                        \
                *(allocnb) = p_alloc_nr(goalnb);            \
            }                                               \
            p_realloc(pp, *(allocnb));                      \
        }                                                   \
    } while (0)

#ifdef __GNUC__

#  define p_delete(mem_pp)                          \
        do {                                        \
            typeof(**(mem_pp)) **__ptr = (mem_pp);  \
            free(*__ptr);                           \
            *__ptr = NULL;                          \
        } while(0)

#else

#  define p_delete(mem_p)                           \
        do {                                        \
            void *__ptr = (mem_p);                  \
            free(*__ptr);                           \
            *(void **)__ptr = NULL;                 \
        } while (0)

#endif

static inline void *xmalloc(ssize_t size) {
    void *mem;

    if (size <= 0)
        return NULL;

    mem = calloc(size, 1);
    if (!mem)
        abort();
    return mem;
}

static inline void xmemfree(void **ptr) {
    p_delete(ptr);
}

static inline void xrealloc(void **ptr, ssize_t newsize) {
    if (newsize <= 0) {
        p_delete(ptr);
    } else {
        *ptr = realloc(*ptr, newsize);
        if (!*ptr)
            abort();
    }
}

static inline void *xmemdup(const void *src, ssize_t size) {
    return memcpy(xmalloc(size), src, size);
}

static inline void *xmemdupstr(const void *src, ssize_t len) {
    char *res = memcpy(xmalloc(len + 1), src, len);
    res[len] = '\0';
    return res;
}


#define DO_INIT(type, prefix) \
    static inline type * prefix##_init(type *var) {         \
        p_clear(var, 1);                                    \
        return var;                                         \
    }
#define DO_WIPE(type, prefix) \
    static inline void prefix##_wipe(type *var __attribute__((unused))) { }

#define DO_NEW(type, prefix) \
    static inline type * prefix##_new(void) {               \
        return prefix##_init(p_new(type, 1));               \
    }
#define DO_DELETE(type, prefix) \
    static inline void __attribute__((nonnull))             \
    prefix##_delete(type **var) {                           \
        if (*var) {                                         \
            prefix##_wipe(*var);                            \
            p_delete(var);                                  \
        }                                                   \
    }

#endif /* PFIXTOOLS_MEM_H */
