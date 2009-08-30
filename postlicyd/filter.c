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

#include "str.h"
#include "buffer.h"
#include "filter.h"

static filter_runner_t      runners[FTK_count];
static filter_constructor_t constructors[FTK_count];
static filter_destructor_t  destructors[FTK_count];
static bool                 hooks[FTK_count][HTK_count];
static filter_result_t      forward[FTK_count][HTK_count];
static bool                 params[FTK_count][ATK_count];

static filter_context_constructor_t ctx_constructors[FTK_count];
static filter_context_destructor_t  ctx_destructors[FTK_count];
static filter_async_handler_t       async_handler = NULL;

static const filter_hook_t default_hook = {
    .type      = 0,
    .value     = (char*)"DUNNO",
    .counter   = -1,
    .cost      = 0,
    .postfix   = true,
    .async     = false,
    .filter_id = 0
};

static const filter_hook_t async_hook = {
    .type      = 0,
    .value     = NULL,
    .counter   = -1,
    .cost      = 0,
    .postfix   = false,
    .async     = true,
    .filter_id = 0
};

uint32_t filter_running = 0;

static int filter_module_init(void)
{
    for (int i = 0 ; i < FTK_count ; ++i) {
        for (int j = 0 ; j < HTK_count ; ++j) {
            forward[i][j] = HTK_UNKNOWN;
        }
    }
    return 0;
}
module_init(filter_module_init);

filter_type_t filter_register(const char *type, filter_constructor_t constructor,
                              filter_destructor_t destructor, filter_runner_t runner,
                              filter_context_constructor_t context_constructor,
                              filter_context_destructor_t context_destructor)
{
    filter_token tok = filter_tokenize(type, m_strlen(type));
    CHECK_FILTER(tok);

    runners[tok] = runner;
    constructors[tok] = constructor;
    destructors[tok] = destructor;

    ctx_constructors[tok] = context_constructor;
    ctx_destructors[tok]  = context_destructor;
    return tok;
}

filter_result_t filter_hook_register(filter_type_t filter,
                                     const char *name)
{
    filter_result_t tok = hook_tokenize(name, m_strlen(name));
    CHECK_FILTER(filter);
    CHECK_HOOK(tok);

    hooks[filter][tok] = true;
    return tok;
}

void filter_hook_forward_register(filter_type_t filter,
                                  filter_result_t source, filter_result_t target)
{
    CHECK_FILTER(filter);
    CHECK_HOOK(source);
    CHECK_HOOK(target);
    assert(target != HTK_ASYNC && target != HTK_ABORT && "Cannot forward async or abort");
    assert(target != HTK_ASYNC && "Cannot forward result to async");

    forward[filter][source] = target;
}

filter_param_id_t filter_param_register(filter_type_t filter,
                                        const char *name)
{
    filter_param_id_t tok = param_tokenize(name, m_strlen(name));
    CHECK_FILTER(filter);
    CHECK_PARAM(tok);

    params[filter][tok] = true;
    return tok;
}

void filter_async_handler_register(filter_async_handler_t handler)
{
    async_handler = handler;
}

bool filter_build(filter_t *filter)
{
    bool ret = true;
    if (filter->type == FTK_UNKNOWN || filter->name == NULL) {
        return false;
    }
    if (filter->hooks.len > 0) {
#       define QSORT_TYPE filter_hook_t
#       define QSORT_BASE filter->hooks.data
#       define QSORT_NELT filter->hooks.len
#       define QSORT_LT(a,b) a->type < b->type
#       include "qsort.c"
    }
    filter_constructor_t constructor = constructors[filter->type];
    if (constructor) {
        ret = constructor(filter);
    }
    array_deep_wipe(filter->params, filter_params_wipe);
    return ret;
}

bool filter_update_references(filter_t *filter, A(filter_t) *filter_list)
{
    foreach (filter_hook_t *hook, filter->hooks) {
        if (!hook->postfix) {
            hook->filter_id = filter_find_with_name(filter_list, hook->value);
            if (hook->filter_id == -1) {
                err("invalid filter name %s for hook %s",
                    hook->value, htokens[hook->type]);
                return false;
            }
            p_delete(&hook->value);
        }
    }}
    return true;
}

static inline bool filter_check_loop(filter_t *filter, A(filter_t) *array, int level)
{
    if (filter->last_seen == level) {
        return true;
    }
    filter->last_seen = level;
    foreach (filter_hook_t *hook, filter->hooks) {
        if (hook->postfix) {
            continue;
        }
        if (hook->filter_id == level) {
            return false;
        }
        if (!filter_check_loop(array_ptr(*array, hook->filter_id), array, level)) {
            return false;
        }
    }}
    return true;
}

bool filter_check_safety(A(filter_t) *array)
{
    foreach (filter_t *filter, *array) {
        if (!filter_check_loop(filter, array, __Ai)) {
            err("the filter tree contains a loop");
            return false;
        }
    }}
    return true;
}

void filter_wipe(filter_t *filter)
{
    filter_destructor_t destructor = destructors[filter->type];
    if (destructor) {
        destructor(filter);
    }
    array_deep_wipe(filter->hooks, filter_hook_wipe);
    array_deep_wipe(filter->params, filter_params_wipe);
    p_delete(&filter->name);
}

static inline const filter_hook_t *filter_hook_for_result(const filter_t *filter,
                                                          filter_result_t res)
{
    int start = 0;
    int end   = filter->hooks.len;

    if (res == HTK_ABORT) {
        return NULL;
    }
    if (res == HTK_ASYNC) {
        return &async_hook;
    }

    while (start < end) {
        int mid = (start + end) / 2;
        filter_hook_t *hook = array_ptr(filter->hooks, mid);
        if (hook->type == res) {
            debug("return hook of type %s, value %s",
                  htokens[hook->type], hook->value);
            return hook;
        } else if (res < hook->type) {
            end = mid;
        } else {
            start = mid + 1;
        }
    }

    if (forward[filter->type][res] != HTK_UNKNOWN) {
        debug("no hook for result %s, forwarding to %s", htokens[res], htokens[forward[filter->type][res]]);
        return filter_hook_for_result(filter, forward[filter->type][res]);
    } else {
        warn("missing hook %s for filter %s", htokens[res], filter->name);
        return &default_hook;
    }
}

const filter_hook_t *filter_run(const filter_t *filter, const query_t *query,
                                filter_context_t *context)
{
    debug("running filter %s (%s)", filter->name, ftokens[filter->type]);
    ++filter_running;
    filter_result_t res = runners[filter->type](filter, query, context);

    if (res == HTK_ASYNC) {
        context->current_filter = filter;
    } else {
        --filter_running;
        context->current_filter = NULL;
    }

    debug("filter run, result is %s", htokens[res]);
    return filter_hook_for_result(filter, res);
}

bool filter_test(const filter_t *filter, const query_t *query,
                 filter_context_t *context, filter_result_t result)
{
    return !!(runners[filter->type](filter, query, context) == result);
}

void filter_set_name(filter_t *filter, const char *name, int len)
{
    filter->name = p_dupstr(name, len);
}

bool filter_set_type(filter_t *filter, const char *type, int len)
{
    filter->type = filter_tokenize(type, len);
    return filter->type != FTK_UNKNOWN;
}

bool filter_add_param(filter_t *filter, const char *name, int name_len,
                      const char *value, int value_len)
{
    filter_param_t param;
    param.type = param_tokenize(name, name_len);
    if (param.type == ATK_UNKNOWN) {
        err("unknown parameter %.*s", name_len, name);
        return false;
    }
    if (!params[filter->type][param.type]) {
        err("hook %s is not valid for filter %s",
            atokens[param.type], ftokens[filter->type]);
        return false;
    }
    param.value     = p_dupstr(value, value_len);
    param.value_len = value_len;
    array_add(filter->params, param);
    return true;
}

bool filter_add_hook(filter_t *filter, const char *name, int name_len,
                     const char *value, int value_len)
{
    filter_hook_t hook;
    hook.filter_id = -1;
    hook.type  = hook_tokenize(name, name_len);
    if (hook.type == HTK_UNKNOWN) {
        err("unknown hook type %.*s", name_len, name);
        return false;
    }
    if (!hooks[filter->type][hook.type] || hook.type == HTK_ABORT) {
        err("hook %s not is valid for filter %s",
            htokens[hook.type], ftokens[filter->type]);
        return false;
    }
    hook.async   = false;

    /* Value format is (counter:id:incr)?(postfix:reply|filter_name)
     */
    hook.value = NULL;
    if (strncmp(value, "counter:", 8) == 0) {
        char *end = NULL;
        value += 8;
        hook.counter = strtol(value, &end, 10);
        if (end == value || *end != ':') {
              err("hook %s, cannot read counter id", htokens[hook.type]);
              return false;
        } else if (hook.counter < 0 || hook.counter >= MAX_COUNTERS) {
            err("hook %s, invalid counter id %d", htokens[hook.type], hook.counter);
            return false;
        }
        value = end + 1;
        hook.cost = strtol(value, &end, 10);
        if (end == value || *end != ':') {
            err("hook %s, cannot read counter increment", htokens[hook.type]);
            return false;
        } else if (hook.cost < 0) {
            err("hook %s, invalid counter increment value %d", htokens[hook.type],
                hook.cost);
            return false;
        }
        value = end + 1;
    } else {
        hook.counter = -1;
        hook.cost    = 0;
    }
    hook.postfix = (strncmp(value, "postfix:", 8) == 0);
    if (hook.postfix && !query_format_check(value + 8)) {
        err("invalid formatted text \"%s\"", value + 8);
        return false;
    }
    hook.value = m_strdup(hook.postfix ? value + 8 : value);
    array_add(filter->hooks, hook);
    return true;
}

void filter_context_prepare(filter_context_t *context, void *qctx)
{
    for (int i = 0 ; i < FTK_count ; ++i) {
        if (ctx_constructors[i] != NULL) {
            context->contexts[i] = ctx_constructors[i]();
        }
    }
    context->current_filter = NULL;
    context->data = qctx;
}

void filter_context_wipe(filter_context_t *context)
{
    for (int i = 0 ; i < FTK_count ; ++i) {
        if (ctx_destructors[i] != NULL) {
            ctx_destructors[i](context->contexts[i]);
        }
    }
}

void filter_context_clean(filter_context_t *context)
{
    p_clear(&context->counters, 1);
    context->instance[0] = '\0';
}

void filter_post_async_result(filter_context_t *context, filter_result_t result)
{
    const filter_t *filter = context->current_filter;
    const filter_hook_t *hook = NULL;

    if (result == HTK_ASYNC) {
        return;
    }
    --filter_running;
    hook = filter_hook_for_result(filter, result);
    async_handler(context, hook);
}

/* vim:set et sw=4 sts=4 sws=4: */
