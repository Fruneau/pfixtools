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

#include "str.h"
#include "buffer.h"
#include "filter.h"

static filter_runner_t      runners[FTK_count];
static filter_constructor_t constructors[FTK_count];
static filter_destructor_t  destructors[FTK_count];
static bool                 hooks[FTK_count][HTK_count];
static bool                 params[FTK_count][ATK_count];

static const filter_hook_t default_hook = {
    .type      = 0,
    .value     = (char*)"DUNNO",
    .postfix   = true,
    .filter_id = 0
};

filter_type_t filter_register(const char *type, filter_constructor_t constructor,
                              filter_destructor_t destructor, filter_runner_t runner)
{
    filter_token tok = filter_tokenize(type, m_strlen(type));
    CHECK_FILTER(tok);

    runners[tok] = runner;
    constructors[tok] = constructor;
    destructors[tok] = destructor;
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

filter_param_id_t filter_param_register(filter_type_t filter,
                                        const char *name)
{
    filter_param_id_t tok = param_tokenize(name, m_strlen(name));
    CHECK_FILTER(filter);
    CHECK_PARAM(tok);

    params[filter][tok] = true;
    return tok;
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
                syslog(LOG_ERR, "invalid filter name %s for hook %s",
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
            syslog(LOG_ERR, "the filter tree contains a loop");
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

const filter_hook_t *filter_run(const filter_t *filter, const query_t *query)
{
    int start = 0;
    int end   = filter->hooks.len;
    //syslog(LOG_DEBUG, "running filter %s (%s)",
    //       filter->name, ftokens[filter->type]);
    filter_result_t res = runners[filter->type](filter, query);

    if (res == HTK_ABORT) {
        return NULL;
    }
    //syslog(LOG_DEBUG, "filter run, result is %s", htokens[res]);

    while (start < end) {
        int mid = (start + end) / 2;
        filter_hook_t *hook = array_ptr(filter->hooks, mid);
        if (hook->type == res) {
            //syslog(LOG_DEBUG, "return hook of type %s, value %s",
            //       htokens[hook->type], hook->value);
            return hook;
        } else if (res < hook->type) {
            end = mid;
        } else {
            start = mid + 1;
        }
    }
    syslog(LOG_WARNING, "missing hook %s for filter %s", 
           htokens[res], filter->name);
    return &default_hook;
}

void filter_set_name(filter_t *filter, const char *name, ssize_t len)
{
    filter->name = p_dupstr(name, len);
}

bool filter_set_type(filter_t *filter, const char *type, ssize_t len)
{
    filter->type = filter_tokenize(type, len);
    return filter->type != FTK_UNKNOWN;
}

bool filter_add_param(filter_t *filter, const char *name, ssize_t name_len,
                      const char *value, ssize_t value_len)
{
    filter_param_t param;
    param.type = param_tokenize(name, name_len);
    if (param.type == ATK_UNKNOWN) {
        syslog(LOG_ERR, "unknown parameter %.*s", name_len, name);
        return false;
    }
    if (!params[filter->type][param.type]) {
        syslog(LOG_ERR, "hook %s is not valid for filter %s",
               atokens[param.type], ftokens[filter->type]);
        return false;
    }
    param.value     = p_dupstr(value, value_len);
    param.value_len = value_len;
    array_add(filter->params, param);
    return true;
}

bool filter_add_hook(filter_t *filter, const char *name, ssize_t name_len,
                     const char *value, ssize_t value_len)
{
    filter_hook_t hook;
    hook.type  = hook_tokenize(name, name_len);
    if (hook.type == HTK_UNKNOWN) {
        syslog(LOG_ERR, "unknown hook type %.*s", name_len, name);
        return false;
    }
    if (!hooks[filter->type][hook.type] || hook.type == HTK_ABORT) {
        syslog(LOG_ERR, "hook %s not is valid for filter %s",
               htokens[hook.type], ftokens[filter->type]);
        return false;
    }
    hook.postfix = (strncmp(value, "postfix:", 8) == 0);
    hook.value = m_strdup(hook.postfix ? value + 8 : value);
    hook.filter_id = -1;
    array_add(filter->hooks, hook);
    return true;
}
