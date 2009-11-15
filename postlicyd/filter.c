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

struct filter_description_t {
    /* Name of the description
     */
    filter_token id;
    const char* name;

    /* Filter execution function
     */
    filter_runner_t      runner;

    /* Construction/destruction
     */
    filter_constructor_t constructor;
    filter_destructor_t  destructor;

    /* Filter context construction/destruction
     */
    filter_context_constructor_t ctx_constructor;
    filter_context_destructor_t  ctx_destructor;

    /* Valid hooks
     */
    bool hooks[HTK_count];
    filter_result_t forward[HTK_count];

    /* Valid parameters
     */
    bool params[ATK_count];
};

static filter_description_t filter_descriptions[FTK_count];

static filter_async_handler_t async_handler = NULL;

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

static bool init_done  = false;
uint32_t filter_running = 0;

#define filter_declare(filter)                                                 \
    filter_constructor_prototype(filter);                                      \
    module_init(filter ## _init_filter);
filter_declare(iplist)
filter_declare(greylist)
filter_declare(strlist)
filter_declare(match)
filter_declare(counter)
filter_declare(spf)
filter_declare(hang)
filter_declare(rate)

static int filter_module_init(void)
{
    if (init_done) {
        return 0;
    }
    init_done = true;
    for (int i = 0 ; i < FTK_count ; ++i) {
        filter_descriptions[i].id = (filter_token)i;
        filter_descriptions[i].name = ftokens[i];
        for (int j = 0 ; j < HTK_count ; ++j) {
            filter_descriptions[i].forward[j] = HTK_UNKNOWN;
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

    filter_description_t* description = &filter_descriptions[tok];
    description->runner = runner;
    description->constructor = constructor;
    description->destructor = destructor;

    description->ctx_constructor = context_constructor;
    description->ctx_destructor = context_destructor;
    return description;
}

filter_result_t filter_hook_register(filter_type_t filter,
                                     const char *name)
{
    filter_result_t tok = hook_tokenize(name, m_strlen(name));
    CHECK_FILTER(filter->id);
    CHECK_HOOK(tok);

    ((filter_description_t*)filter)->hooks[tok] = true;
    return tok;
}

void filter_hook_forward_register(filter_type_t filter,
                                  filter_result_t source, filter_result_t target)
{
    filter_module_init();
    CHECK_FILTER(filter->id);
    CHECK_HOOK(source);
    CHECK_HOOK(target);
    assert(target != HTK_ASYNC && target != HTK_ABORT && "Cannot forward async or abort");
    assert(target != HTK_ASYNC && "Cannot forward result to async");

    ((filter_description_t*)filter)->forward[source] = target;
}

filter_param_id_t filter_param_register(filter_type_t filter,
                                        const char *name)
{
    filter_param_id_t tok = param_tokenize(name, m_strlen(name));
    CHECK_FILTER(filter->id);
    CHECK_PARAM(tok);

    ((filter_description_t*)filter)->params[tok] = true;
    return tok;
}

void filter_async_handler_register(filter_async_handler_t handler)
{
    async_handler = handler;
}

bool filter_build(filter_t *filter)
{
    bool ret = true;
    if (filter->type == NULL || filter->name == NULL) {
        return false;
    }
    if (filter->hooks.len > 0) {
#       define QSORT_TYPE filter_hook_t
#       define QSORT_BASE filter->hooks.data
#       define QSORT_NELT filter->hooks.len
#       define QSORT_LT(a,b) a->type < b->type
#       include "qsort.c"
    }
    if (filter->type->constructor) {
        ret = filter->type->constructor(filter);
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
    if (filter->type->destructor) {
        filter->type->destructor(filter);
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

    if (filter->type->forward[res] != HTK_UNKNOWN) {
        debug("no hook for result %s, forwarding to %s", htokens[res], htokens[filter->type->forward[res]]);
        return filter_hook_for_result(filter,  filter->type->forward[res]);
    } else {
        warn("missing hook %s for filter %s", htokens[res], filter->name);
        return &default_hook;
    }
}

const filter_hook_t *filter_run(const filter_t *filter, const query_t *query,
                                filter_context_t *context)
{
    debug("running filter %s (%s)", filter->name, filter->type->name);
    ++filter_running;
    filter_result_t res = filter->type->runner(filter, query, context);

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
    context->explanation.str = 0;
    context->explanation.len = 0;
    return !!(filter->type->runner(filter, query, context) == result);
}

void filter_set_name(filter_t *filter, const char *name, int len)
{
    filter->name = p_dupstr(name, len);
}

bool filter_set_type(filter_t *filter, const char *type, int len)
{
    filter_token tok = filter_tokenize(type, len);
    if (tok == FTK_UNKNOWN) {
        return false;
    }
    filter->type = &filter_descriptions[tok];
    return true;
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
    if (!filter->type->params[param.type]) {
        err("hook %s is not valid for filter %s",
            atokens[param.type], filter->type->name);
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
#define PARSE_CHECK(Cond, Message, ...)                                        \
    if (!(Cond)) {                                                             \
        err("hook %s, " Message, htokens[hook.type], ##__VA_ARGS__);           \
        filter_hook_wipe(&hook);                                               \
        return false;                                                          \
    }
    filter_hook_t hook;
    hook.filter_id = -1;
    hook.value = NULL;
    hook.warn  = NULL;
    hook.counter = -1;
    hook.cost    = 0;
    hook.type  = hook_tokenize(name, name_len);
    if (hook.type == HTK_UNKNOWN) {
        err("unknown hook type %.*s", name_len, name);
        return false;
    }
    PARSE_CHECK(filter->type->hooks[hook.type] && hook.type != HTK_ABORT,
                "not is valid for filter %s", filter->type->name);
    hook.async   = false;

    /* Value format is (counter:id:incr)?(postfix:reply|filter_name)
     */
    while (true) {
        if (strncmp(value, "counter:", 8) == 0) {
            PARSE_CHECK(hook.counter == -1, "cannot specify more than one counter");
            char *end = NULL;
            value += 8;
            hook.counter = strtol(value, &end, 10);
            PARSE_CHECK(end != value && *end == ':', "cannot read counter id");
            PARSE_CHECK(hook.counter >= 0 && hook.counter < MAX_COUNTERS,
                        "invalid counter id %d", hook.counter);
            value = end + 1;
            hook.cost = strtol(value, &end, 10);
            PARSE_CHECK(end != value && *end == ':', "cannot read counter increment");
            PARSE_CHECK(hook.cost >= 0, "invalid counter increment value %d", hook.cost);
            value = end + 1;
        } else if (strncmp(value, "warn:", 5) == 0) {
            PARSE_CHECK(hook.warn == NULL, "cannot specify more than one warning message");
            value += 5;
            const char* end = strchr(value, ':');
            PARSE_CHECK(end != NULL, "invalid unterminated warning message");
            PARSE_CHECK(end != value, "empty warning message");
            hook.warn = p_dupstr(value, end - value);
            PARSE_CHECK(query_format_check(hook.warn), "invalid message format: \"%s\"", hook.warn);
            value = end + 1;
        } else {
            break;
        }
    }
    hook.postfix = (strncmp(value, "postfix:", 8) == 0);
    if (hook.postfix) {
        value += 8;
    }
    PARSE_CHECK(!hook.postfix || query_format_check(value),
                "invalid postfix reply format: \"%s\"", value);
    hook.value = m_strdup(value);
    array_add(filter->hooks, hook);
#undef PARSE_CHECK
    return true;
}

void filter_context_prepare(filter_context_t *context, void *qctx)
{
    for (int i = 0 ; i < FTK_count ; ++i) {
        if (filter_descriptions[i].ctx_constructor != NULL) {
            context->contexts[i] = filter_descriptions[i].ctx_constructor();
        }
    }
    context->current_filter = NULL;
    context->explanation.str = NULL;
    context->explanation.len = 0;
    context->data = qctx;
}

void filter_context_wipe(filter_context_t *context)
{
    for (int i = 0 ; i < FTK_count ; ++i) {
        if (filter_descriptions[i].ctx_destructor != NULL) {
            filter_descriptions[i].ctx_destructor(context->contexts[i]);
        }
    }
}

void* filter_context(const filter_t* filter, filter_context_t* context) {
    return context->contexts[filter->type->id];
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

void filter_set_explanation(filter_context_t *context, const char* str, ssize_t len)
{
    context->explanation.str = str;
    context->explanation.len = len >= 0 ? len : m_strlen(str);
}

void filter_post_async_result_with_explanation(filter_context_t *context, filter_result_t result,
                                               const char* str, ssize_t len)
{
    filter_set_explanation(context, str, len);
    filter_post_async_result(context, result);
}

/* vim:set et sw=4 sts=4 sws=4: */
