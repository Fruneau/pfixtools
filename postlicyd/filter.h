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
/*   Copyright (c) 2006-2009 the Authors                                      */
/*   see AUTHORS and source files for details                                 */
/******************************************************************************/

/*
 * Copyright © 2008 Florent Bruneau
 */

#ifndef PFIXTOOLS_FILTER_H
#define PFIXTOOLS_FILTER_H

#include "common.h"
#include "filter_tokens.h"
#include "hook_tokens.h"
#include "param_tokens.h"
#include "query.h"
#include "array.h"


typedef filter_token filter_type_t;
typedef hook_token   filter_result_t;
typedef param_token  filter_param_id_t;

typedef struct filter_hook_t {
    filter_result_t type;
    char *value;

    int counter;
    int cost;

    unsigned postfix:1;
    unsigned async:1;
    int filter_id;

} filter_hook_t;
ARRAY(filter_hook_t)

typedef struct filter_param_t {
    filter_param_id_t type;
    char  *value;
    int    value_len;
} filter_param_t;
ARRAY(filter_param_t)

/** Description of a filter.
 */
typedef struct filter_t {
    char *name;
    filter_type_t type;

    A(filter_hook_t)   hooks;
    void *data;

    A(filter_param_t) params;

    /* Loop checking flags.
     */
    int last_seen;
} filter_t;
ARRAY(filter_t)

#define MAX_COUNTERS (64)

/** Context of the query. To be filled with data to use when
 * performing asynchronous filtering.
 */
typedef struct filter_context_t {
    /* filter context
     */
    const filter_t *current_filter;
    void *contexts[FTK_count];

    /* message context
     */
    char instance[64];
    uint32_t counters[MAX_COUNTERS];

    /* connection context
     */
    void *data;
} filter_context_t;


#define FILTER_INIT { NULL, FTK_UNKNOWN, ARRAY_INIT, NULL, ARRAY_INIT, -1 }
#define CHECK_FILTER(Filter)                                                   \
    assert(Filter != FTK_UNKNOWN && Filter != FTK_count                        \
           && "Unknown filter type")
#define CHECK_HOOK(Hook)                                                       \
    assert(Hook != HTK_UNKNOWN && Hook != HTK_count                            \
           && "Unknown hook")
#define CHECK_PARAM(Param)                                                     \
    assert(Param != ATK_UNKNOWN && Param != ATK_count                          \
           && "Unknown param")


/* Callback to be implemented by a filter.
 */

typedef filter_result_t (*filter_runner_t)(const filter_t *filter,
                                           const query_t *query,
                                           filter_context_t *context);
typedef bool (*filter_constructor_t)(filter_t *filter);
typedef void (*filter_destructor_t)(filter_t *filter);

typedef void *(*filter_context_constructor_t)(void);
typedef void (*filter_context_destructor_t)(void*);

typedef void (*filter_async_handler_t)(filter_context_t *context,
                                       const filter_hook_t *result);

/** Number of filter currently running.
 */
extern uint32_t filter_running;

/* Registration.
 */

__attribute__((nonnull(1,4)))
filter_type_t filter_register(const char *type, filter_constructor_t constructor,
                              filter_destructor_t destructor, filter_runner_t runner,
                              filter_context_constructor_t context_constructor,
                              filter_context_destructor_t context_destructor);

__attribute__((nonnull(2)))
filter_result_t filter_hook_register(filter_type_t filter, const char *name);

__attribute__((nonnull(2)))
filter_param_id_t filter_param_register(filter_type_t filter, const char *name);

__attribute__((nonnull))
void filter_async_handler_register(filter_async_handler_t handler);

/* Filter builder.
 */

__attribute__((nonnull(1)))
static inline void filter_init(filter_t *filter)
{
    const filter_t f = FILTER_INIT;
    *filter = f;
}

__attribute__((nonnull(1,2)))
void filter_set_name(filter_t *filter, const char *name, int len);

__attribute__((nonnull(1,2)))
bool filter_set_type(filter_t *filter, const char *type, int len);

__attribute__((nonnull(1,2,4)))
bool filter_add_param(filter_t *filter, const char *name, int name_len,
                      const char *value, int value_len);

__attribute__((nonnull(1,2,4)))
bool filter_add_hook(filter_t *filter, const char *name, int name_len,
                     const char *value, int value_len);

__attribute__((nonnull(1)))
bool filter_build(filter_t *filter);

__attribute__((nonnull(1,2)))
static inline int filter_find_with_name(const A(filter_t) *array, const char *name)
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
bool filter_check_safety(A(filter_t) *array);

__attribute__((nonnull(1)))
static inline void filter_hook_wipe(filter_hook_t *hook)
{
    p_delete(&hook->value);
}

__attribute__((nonnull(1)))
static inline void filter_params_wipe(filter_param_t *param)
{
    p_delete(&param->value);
}

__attribute__((nonnull(1)))
void filter_wipe(filter_t *filter);


/* Runner.
 */

__attribute__((nonnull(1,2)))
const filter_hook_t *filter_run(const filter_t *filter, const query_t *query,
                                filter_context_t *context);

__attribute__((nonnull(1,2)))
bool filter_test(const filter_t *filter, const query_t *query,
                 filter_context_t *context, filter_result_t expt);


/* Parsing Helpers
 */

#define FILTER_PARAM_PARSE_STRING(Param, Dest, Copy)                           \
    case ATK_ ## Param: {                                                      \
        (Dest) = (Copy) ? m_strdup(param->value) : param->value;               \
    } break

#define FILTER_PARAM_PARSE_INT(Param, Dest)                                    \
    case ATK_ ## Param: {                                                      \
        char *next;                                                            \
        (Dest) = strtol(param->value, &next, 10);                              \
        PARSE_CHECK(!*next, "invalid %s value %.*s", atokens[ATK_ ## Param],   \
                    param->value_len, param->value);                           \
     } break

#define FILTER_PARAM_PARSE_BOOLEAN(Param, Dest)                                \
    case ATK_ ## Param: {                                                      \
        if (param->value_len == 1 && param->value[0] == '1') {                 \
            (Dest) = true;                                                     \
        } else if (param->value_len == 1 && param->value[0] == '0') {          \
            (Dest) = false;                                                    \
        } else if (param->value_len == 4                                       \
                   && ascii_tolower(param->value[0]) == 't'                    \
                   && ascii_tolower(param->value[1]) == 'r'                    \
                   && ascii_tolower(param->value[2]) == 'u'                    \
                   && ascii_tolower(param->value[3]) == 'e') {                 \
            (Dest) = true;                                                     \
        } else if (param->value_len == 5                                       \
                   && ascii_tolower(param->value[0]) == 'f'                    \
                   && ascii_tolower(param->value[1]) == 'a'                    \
                   && ascii_tolower(param->value[2]) == 'l'                    \
                   && ascii_tolower(param->value[3]) == 's'                    \
                   && ascii_tolower(param->value[4]) == 'e') {                 \
            (Dest) = false;                                                    \
        } else {                                                               \
            PARSE_CHECK(false, "invalid %s value %.*s", atokens[ATK_ ## Param],\
                        param->value_len, param->value);                       \
        }                                                                      \
    } break


/* Filter context
 */

__attribute__((nonnull(1)))
void filter_context_prepare(filter_context_t *context, void* qctx);

__attribute__((nonnull))
void filter_context_wipe(filter_context_t *context);

__attribute__((nonnull))
void filter_context_clean(filter_context_t *context);

__attribute__((nonnull))
void filter_post_async_result(filter_context_t *context, filter_result_t result);

#endif

/* vim:set et sw=4 sts=4 sws=4: */
