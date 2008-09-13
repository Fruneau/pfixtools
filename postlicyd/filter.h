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

#ifndef PFIXTOOLS_FILTER_H
#define PFIXTOOLS_FILTER_H

#include "common.h"
#include "filter_tokens.h"
#include "query.h"
#include "array.h"

typedef filter_token filter_type_t;

typedef struct filter_hook_t {
    char *name;
    char *value;

    bool postfix;
    int filter_id;
} filter_hook_t;
ARRAY(filter_hook_t)

typedef struct filter_params_t {
    char *name;
    char *value;
} filter_params_t;
ARRAY(filter_params_t)

typedef struct filter_t {
    char *name;
    filter_type_t type;

    A(filter_hook_t)   hooks;
    void *data;

    A(filter_params_t) params;
} filter_t;
ARRAY(filter_t)

#define FILTER_INIT { NULL, FTK_UNKNOWN, ARRAY_INIT, NULL, ARRAY_INIT }

typedef const char *filter_result_t;
typedef filter_result_t (*filter_runner_t)(const filter_t *filter,
                                           const query_t *query);
typedef bool (*filter_constructor_t)(filter_t *filter);
typedef void (*filter_destructor_t)(filter_t *filter);

__attribute__((nonnull(1,4)))
void filter_register(const char *type, filter_constructor_t constructor,
                     filter_destructor_t destructor, filter_runner_t runner);

__attribute__((nonnull(1)))
static inline void filter_init(filter_t *filter)
{
    const filter_t f = FILTER_INIT;
    *filter = f;
}

__attribute__((nonnull(1,2)))
void filter_set_name(filter_t *filter, const char *name, ssize_t len);

__attribute__((nonnull(1,2)))
bool filter_set_type(filter_t *filter, const char *type, ssize_t len);

__attribute__((nonnull(1,2,4)))
bool filter_add_param(filter_t *filter, const char *name, ssize_t name_len,
                      const char *value, ssize_t value_len);

__attribute__((nonnull(1,2,4)))
bool filter_add_hook(filter_t *filter, const char *name, ssize_t name_len,
                     const char *value, ssize_t value_len);

__attribute__((nonnull(1)))
bool filter_build(filter_t *filter);

__attribute__((nonnull(1,2)))
static inline int filter_find_with_name(A(filter_t) *array, const char *name)
{
    int start = 0;
    int end   = array->len;

    while (start < end) {
        int mid = (start + end) / 2;
        int cmp = strcmp(name, array_elt(*array, mid).name);

        if (cmp == 0) {
            return mid;
        } else if (cmp < 0) {
            end = mid;
        } else {
            start = mid + 1;
        }
    }
    return -1;
}

__attribute__((nonnull(1,2)))
bool filter_update_references(filter_t *filter, A(filter_t) *array);

__attribute__((nonnull(1)))
static inline void filter_hook_wipe(filter_hook_t *hook)
{
    p_delete(&hook->name);
    p_delete(&hook->value);
}

__attribute__((nonnull(1)))
static inline void filter_params_wipe(filter_params_t *param)
{
    p_delete(&param->name);
    p_delete(&param->value);
}

__attribute__((nonnull(1)))
void filter_wipe(filter_t *filter);

__attribute__((nonnull(1,2)))
filter_result_t filter_run(const filter_t *filter, const query_t *query);


#endif
