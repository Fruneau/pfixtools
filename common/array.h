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
/*  THIS SOFTWARE IS PROVIDED BY THE CONTRIBUTORS ``AS IS'' AND ANY EXPRESS   */
/*  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED         */
/*  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE    */
/*  DISCLAIMED.  IN NO EVENT SHALL THE CONTRIBUTORS BE LIABLE FOR ANY         */
/*  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL        */
/*  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS   */
/*  OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)     */
/*  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,       */
/*  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN  */
/*  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE           */
/*  POSSIBILITY OF SUCH DAMAGE.                                               */
/*                                                                            */
/*   Copyright (c) 2006-2008 the Authors                                      */
/*   see AUTHORS and source files for details                                 */
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
        uint32_t len;                                                          \
        uint32_t size;                                                         \
        unsigned locked : 1;                                                   \
    }

/** Declare type PA(Type).
 */
#define PARRAY(Type)                                                           \
    typedef PRIV_ARRAY(Type*) Type ## _ptr_array_t;                            \
    static inline Type ## _ptr_array_t *Type ## _ptr_array_new(void)           \
    {                                                                          \
        return p_new(Type ## _ptr_array_t, 1);                                 \
    }                                                                          \
                                                                               \
    static inline void Type ## _ptr_array_delete(Type ## _ptr_array_t **array) \
    {                                                                          \
        if (*array) {                                                          \
            if ((*array)->locked) {                                            \
                array_unlock(**array);                                         \
            }                                                                  \
            array_wipe(**array);                                               \
            p_delete(array);                                                   \
        }                                                                      \
    }

/** Declare types A(Type) and PA(Type).
 */
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
            if ((*array)->locked) {                                            \
                array_unlock(**array);                                         \
            }                                                                  \
            array_wipe(**array);                                               \
            p_delete(array);                                                   \
        }                                                                      \
    }                                                                          \
                                                                               \
    PARRAY(Type)

/** Type A(Type) is a dynamic array of elements of type @c Type.
 */
#define A(Type) Type ## _array_t

/** Type PA(Type) is a dynamic array of pointers to type @c Type.
 */
#define PA(Type) Type ## _ptr_array_t

#define ARRAY_INIT { NULL, 0, 0, false }

#define array_init(array) (array) = ARRAY_INIT

#define array_can_edit(array) (!(array).locked)

#define array_ensure_can_edit(array)                                           \
    assert(array_can_edit(array) && "Trying to edit array while it is locked")

#define array_wipe(array)                                                      \
    do {                                                                       \
        array_ensure_can_edit(array);                                          \
        p_delete(&(array).data);                                               \
        (array).len  = 0;                                                      \
        (array).size = 0;                                                      \
    } while (0)


/******* MEMORY MANAGEMENT *******/

/** Return the len of the array (number of elements contained in the array).
 */
#define array_len(array) ((array).len)

/** Return the capacity of the array (number of elements the array can contain
 * without growing its internal buffer).
 */
#define array_size(array) ((array).size)

/** Return the number of free places in the array.
 */
#define array_free_space(array) (array_size(array) - array_len(array))

/** Return the size of an element of the array.
 */
#define array_elt_len(array) (sizeof(*(array).data))

/** Return the number of bytes used by the content of the array.
 */
#define array_byte_len(array) ((array).len * array_elt_len(array))

/** Ensure the capacity of the array if *at least* @c goal *elements*.
 */
#define array_ensure_capacity(array, goal)                                     \
    do {                                                                       \
        array_ensure_can_edit(array);                                          \
        if ((array).size < (goal)) {                                           \
            const typeof((array).size) required_size = (goal);                 \
            typeof((array).size) next_size = (array).size;                     \
            do {                                                               \
                next_size = p_alloc_nr(next_size);                             \
            } while (next_size < required_size);                               \
            p_allocgrow(&(array).data, next_size, &(array).size);              \
        }                                                                      \
    } while (0)

/** Ensure the array contains place for *at least* @c delta more elements.
 */
#define array_ensure_capacity_delta(array, delta)                              \
    array_ensure_capacity(array, (array).len + (delta))

/** Ensure the array can contain @c goal elements.
 */
#define array_ensure_exact_capacity(array, goal)                               \
    if ((array).size < (goal)) {                                               \
        array_ensure_can_edit(array);                                          \
        p_allocgrow(&(array).data, (goal), &(array).size);                     \
    }

/** Shrink capacity of the array to MAX(len, @c cap).
 */
#define array_shrink(array, cap)                                               \
    do {                                                                       \
        array_ensure_can_edit(array);                                          \
        if ((cap) < (array).size && (array).size != (array).len) {             \
            p_shrink(&(array).data, MAX((array).len, (cap)), &(array).size);   \
        }                                                                      \
    } while (0)

/** Ensure the capacity of the array does not exceed its len.
 */
#define array_adjust(array) array_shrink(array, 0)

#define array_lock(array)                                                      \
    ((array).locked                                                            \
     || (mlock((array).data, array_byte_len(array)) == 0                       \
         && ((array).locked = true)))

#define array_unlock(array)                                                    \
    if ((array).locked) {                                                      \
        (void)munlock((array).data, array_byte_len(array));                    \
        (array).locked = false;                                                \
    }


/******* ADDING ELEMENTS *******/

#define array_add(array, obj)                                                  \
    do {                                                                       \
        array_ensure_capacity_delta(array, 1);                                 \
        (array).data[(array).len++] = (obj);                                   \
    } while (0)

#define array_append(array, objs, Len)                                         \
    do {                                                                       \
        const typeof((array).len) __len = (Len);                               \
        array_ensure_capacity_delta(array, __len);                             \
        memcpy((array).data + (array).len, objs,                               \
               __len * sizeof(*(array).data));                                 \
        (array).len += __len;                                                  \
    } while (0)


/******* ACCESSSING ELEMENTS ********/

/** Getting the n'th element of the array.
 */
#define array_elt(array, n) ((array).data[(n)])

#define array_first(array) array_elt(array, 0)
#define array_last(array) array_elt(array, (array).len - 1)

#define array_pop_last(array) array_elt(array, --((array).len))

/** Getting a pointer to the n'th element of the array.
 */
#define array_ptr(array, n) ((array).data + (n))

#define array_start(array) array_ptr((array), 0)
#define array_end(array) array_ptr((array), array_len(array))

/****** TRAVERSING AN ARRAY *******/

/** Gives the position of pointer ptr in the array.
 * This macro may only be used withing a loop. @ref foreach.
 */
#define array_pos(array, ptr) ((ptr) - array_start(array))

/** Build a loop over the elements of an array.
 *
 * <code>
 * A(MyType) array;
 * ...
 * foreach (MyType* element, array) {
 *    do_something(element);
 * }}
 * </code>
 *
 * Warnings:
 *  * remember the loop must be ended with }} (the foreach macro contains 
 *    a not-matched opening brace).
 *  * the macro uses a counter name __Ai, so you cannot build imbricated
 *    array enumerations. You SHOULD NOT use this counter in your code since
 *    it is part of the internal API and may change in the future.
 */

#define foreach(var, array)                                                    \
    for (uint32_t __Ai = 0 ; __Ai < (array).len ; ++__Ai) {                    \
        var = array_ptr(array, __Ai);

/** Execute @c action for each element of the array.
 *
 * <code>
 * static void do_something(MyType *element) { ... }
 *
 * A(MyType) array;
 * ...
 * array_foreach(array, do_something);
 * </code>
 */
#define array_foreach(array, action)                                           \
    for (uint32_t __Ai = 0 ; __Ai < (array).len ; ++__Ai) {                    \
        action(array_ptr(array, __Ai));                                        \
    }

/** Wipe each element of the array using @c wipe, then wipe the array.
 */
#define array_deep_wipe(array, wipe)                                           \
    do {                                                                       \
        array_foreach(array, wipe);                                            \
        array_wipe(array);                                                     \
    } while (0)



ARRAY(char)
ARRAY(int)
ARRAY(bool)
ARRAY(uint16_t)
ARRAY(uint32_t)

PARRAY(void)

#endif
