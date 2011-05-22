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
/*   Copyright (c) 2006-2011 the Authors                                      */
/*   see AUTHORS and source files for details                                 */
/******************************************************************************/

/*
 * Copyright © 2008 Florent Bruneau
 */

#include "filter.h"
#include "config.h"
#include "query.h"

typedef struct counter_config_t {
    int counter;
    uint32_t hard_threshold;
    uint32_t soft_threshold;
} counter_config_t;

DO_ALL(counter_config_t, counter_config);

static bool counter_filter_constructor(filter_t *filter)
{
    counter_config_t *config = counter_config_new();
    config->counter = -1;

#define PARSE_CHECK(Expr, Str, ...)                                            \
    if (!(Expr)) {                                                             \
        err(Str, ##__VA_ARGS__);                                               \
        counter_config_delete(&config);                                          \
        return false;                                                          \
    }

    config->hard_threshold = 1;
    config->soft_threshold = 1;
    foreach (param, filter->params) {
        switch (param->type) {
          FILTER_PARAM_PARSE_INT(COUNTER, config->counter);
          FILTER_PARAM_PARSE_INT(HARD_THRESHOLD, config->hard_threshold);
          FILTER_PARAM_PARSE_INT(SOFT_THRESHOLD, config->soft_threshold);
          default: break;
        }
    }

    PARSE_CHECK(config->counter >= 0 && config->counter < MAX_COUNTERS,
                "invalid counter number: %d", config->counter);
    filter->data = config;
    return true;
}

static void counter_filter_destructor(filter_t *filter)
{
    counter_config_t *config = filter->data;
    counter_config_delete(&config);
    filter->data = config;
}

static filter_result_t counter_filter(const filter_t *filter, const query_t *query,
                                      filter_context_t *context)
{
    const counter_config_t *counter = filter->data;
    const uint32_t val = context->counters[counter->counter];

    if (val >= counter->hard_threshold) {
        return HTK_HARD_MATCH;
    } else if (val >= counter->soft_threshold) {
        return HTK_SOFT_MATCH;
    } else {
        return HTK_FAIL;
    }
}

filter_constructor(counter)
{
    filter_type_t type =  filter_register("counter", counter_filter_constructor,
                                          counter_filter_destructor, counter_filter,
                                          NULL, NULL);
    /* Hooks.
     */
    (void)filter_hook_register(type, "fail");
    (void)filter_hook_register(type, "hard_match");
    (void)filter_hook_register(type, "soft_match");

    filter_hook_forward_register(type, HTK_SOFT_MATCH, HTK_HARD_MATCH);

    /* Parameters.
     */
    (void)filter_param_register(type, "counter");
    (void)filter_param_register(type, "hard_threshold");
    (void)filter_param_register(type, "soft_threshold");
    return 0;
}

/* vim:set et sw=4 sts=4 sws=4: */
