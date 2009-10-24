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
 * Copyright © 2009 Florent Bruneau
 */

#include "server.h"

/* postlicyd filter declaration */

#include "filter.h"

typedef struct hang_filter_t {
    int timeout;
} hang_filter_t;


static hang_filter_t* hang_filter_new(void)
{
    return p_new(hang_filter_t, 1);
}

static void hang_filter_delete(hang_filter_t** filter)
{
    if (*filter) {
        p_delete(filter);
    }
}

static bool hang_filter_constructor(filter_t *filter)
{
    hang_filter_t* data = hang_filter_new();

#define PARSE_CHECK(Expr, Str, ...)                                            \
    if (!(Expr)) {                                                             \
        err(Str, ##__VA_ARGS__);                                               \
        hang_filter_delete(&data);                                              \
        return false;                                                          \
    }

    foreach (filter_param_t* param, filter->params) {
        switch (param->type) {
          /* timeout_ms is an integer
           *  number of milliseconds to hang.
           */
          FILTER_PARAM_PARSE_INT(TIMEOUT_MS, data->timeout);

          default: break;
        }
    }}

    PARSE_CHECK(data->timeout > 0, "invalid timeout given: %d, must be a strictly positive integer", data->timeout);
    filter->data = data;
    return true;
}

static void hang_filter_destructor(filter_t *filter)
{
    hang_filter_t* data = filter->data;
    hang_filter_delete(&data);
    filter->data = data;
}

static void hang_filter_async(void* arg)
{
    filter_context_t* context = arg;
    filter_post_async_result(context, HTK_TIMEOUT);
}

static filter_result_t hang_filter(const filter_t* filter, const query_t* query,
                                   filter_context_t* context)
{
    const hang_filter_t* data = filter->data;
    start_timer(data->timeout, hang_filter_async, context);
    return HTK_ASYNC;
}


static int hang_init(void)
{
    filter_type_t filter_type = filter_register("hang", hang_filter_constructor,
                                                hang_filter_destructor, hang_filter,
                                                NULL, NULL);

    /* Hooks
     */
    (void)filter_hook_register(filter_type, "timeout");
    (void)filter_hook_register(filter_type, "async");

    /* Parameters
     */
    (void)filter_param_register(filter_type, "timeout_ms");
    return 0;
}
module_init(hang_init);


/* vim:set et sw=4 sts=4 sws=4: */
