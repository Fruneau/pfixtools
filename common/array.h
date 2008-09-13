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
 * Copyright © 2008 Florent Bruneau
 */

#ifndef PFIXTOOLS_ARRAY_H
#define PFIXTOOLS_ARRAY_H

#include "common.h"
#include "mem.h"
#include <sys/mman.h>

#define PRIV_ARRAY(Type)                                                       \
    struct {                                                                   \
        Type    *data;                                                         \
        ssize_t len;                                                           \
        ssize_t size;                                                          \
    }
#define ARRAY(Type)                                                            \
    typedef PRIV_ARRAY(Type) Type ## _array_t;                                 \
                                                                               \
    static inline Type ## _array_t *Type ## _array_new(void)                   \
    {                                                                          \
        return p_new(Type ## _array_t, 1);                                     \
    }                                                                          \
                                                                               \
    static inline void Type ## _array_delete(Type ## _array_t **array)         \
    {                                                                          \
        if (*array) {                                                          \
            array_wipe(**array);                                               \
            p_delete(array);                                                   \
        }                                                                      \
    }
#define A(Type) Type ## _array_t

#define ARRAY_INIT { NULL, 0, 0 }

#define array_init(array) (array) = ARRAY_INIT
#define array_wipe(array)                                                      \
    do {                                                                       \
        p_delete(&(array).data);                                               \
        (array).len  = 0;                                                      \
        (array).size = 0;                                                      \
    } while (0)
#define array_add(array, obj)                                                  \
    do {                                                                       \
        array_ensure_capacity_delta(array, 1);                                 \
        (array).data[(array).len++] = (obj);                                   \
    } while (0)
#define array_append(array, objs, len)                                         \
    do {                                                                       \
        const ssize_t __len = (len);                                           \
        array_ensure_capacity_delta(array, __len);                             \
        memcpy((array).data + (array).len, objs,                               \
               __len * sizeof(*(array).data));                                 \
        (array).len += __len;                                                  \
    } while (0)
#define array_ensure_capacity(array, goal)                                     \
    do {                                                                       \
        if ((array).size < (goal)) {                                           \
            const ssize_t required_size = (goal);                              \
            ssize_t next_size = (array).size;                                  \
            do {                                                               \
                next_size = p_alloc_nr(next_size);                             \
            } while (next_size < required_size);                               \
            p_allocgrow(&(array).data, next_size, &(array).size);              \
        }                                                                      \
    } while (0)
#define array_ensure_capacity_delta(array, delta)                              \
    array_ensure_capacity(array, (array).len + (delta))
#define array_ensure_exact_capacity(array, goal)                               \
    if (array_size(array) < (goal)) {                                          \
        p_allocgrow(&(array).data, (goal), &(array).size);                     \
    }
#define array_adjust(array)                                                    \
    do {                                                                       \
        p_shrink(&(array).data, (array).len, &(array).size);                   \
    } while (0)
#define array_elt(array, n) (array).data[(n)]
#define array_ptr(array, n) (array).data + (n)

#define foreach(var, array)                                                    \
    for (int __Ai = 0 ; __Ai < (array).len ; ++__Ai) {                         \
        var = array_ptr(array, __Ai);

#define array_foreach(array, action)                                           \
    for (int __Ai = 0 ; __Ai < (array).len ; ++__Ai) {                         \
        action(array_ptr(array, __Ai));                                        \
    }
#define array_deep_wipe(array, wipe)                                           \
    do {                                                                       \
        array_foreach(array, wipe);                                            \
        array_wipe(array);                                                     \
    } while (0)

#define array_lock(array)                                                      \
    !(mlock((array).data, (array).len * sizeof(*(array).data)) != 0)
#define array_unlock(array)                                                    \
    (void)munlock((array).data, (array).len * sizeof(*(array).data))

ARRAY(char)
ARRAY(int)
ARRAY(uint32_t)

#endif
