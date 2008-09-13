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

void filter_register(const char *type, filter_constructor_t constructor,
                     filter_destructor_t destructor, filter_runner_t runner)
{
    filter_token tok = filter_tokenize(type, m_strlen(type));
    assert(tok != FTK_UNKNOWN && "Unknown filter type");

    syslog(LOG_INFO, "filter type %s registered", type);

    runners[tok] = runner;
    constructors[tok] = constructor;
    destructors[tok] = destructor;
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
#       define QSORT_LT(a,b) strcmp(a->name, b->name) < 0
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
                       hook->value, hook->name);
                return false;
            }
            p_delete(&hook->value);
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

filter_result_t filter_run(const filter_t *filter, const query_t *query)
{
    return runners[filter->type](filter, query);
}

void filter_set_name(filter_t *filter, const char *name, ssize_t len)
{
    filter->name = p_new(char, len + 1);
    memcpy(filter->name, name, len);
    filter->name[len] = '\0';
}

bool filter_set_type(filter_t *filter, const char *type, ssize_t len)
{
    filter->type = filter_tokenize(type, len);
    return filter->type != FTK_UNKNOWN;
}

bool filter_add_param(filter_t *filter, const char *name, ssize_t name_len,
                      const char *value, ssize_t value_len)
{
    filter_params_t param;
    param.name = m_strdup(name);
    param.value = m_strdup(value);
    array_add(filter->params, param);
    return true;
}

bool filter_add_hook(filter_t *filter, const char *name, ssize_t name_len,
                     const char *value, ssize_t value_len)
{
    filter_hook_t hook;
    hook.name  = m_strdup(name);
    hook.postfix = (strncmp(value, "postfix:", 8) == 0);
    hook.value = m_strdup(hook.postfix ? value + 8 : value);
    hook.filter_id = -1;
    array_add(filter->hooks, hook);
    return true;
}
