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
/*   Copyright (c) 2006-2010 the Authors                                      */
/*   see AUTHORS and source files for details                                 */
/******************************************************************************/

/*
 * Copyright © 2009 Florent Bruneau
 */

#include "spf.h"

/* postlicyd filter declaration */

#include "filter.h"

typedef struct spf_filter_t {
    unsigned use_spf_record : 1;
    unsigned check_helo     : 1;
    unsigned use_explanation: 1;
} spf_filter_t;

static buffer_t domain = ARRAY_INIT;
static buffer_t sender = ARRAY_INIT;
static buffer_t ip     = ARRAY_INIT;

static spf_filter_t* spf_filter_new(void)
{
    return p_new(spf_filter_t, 1);
}

static void spf_filter_delete(spf_filter_t** spf)
{
    if (*spf) {
        p_delete(spf);
    }
}

static bool spf_filter_constructor(filter_t *filter)
{
    spf_filter_t* data = spf_filter_new();

#define PARSE_CHECK(Expr, Str, ...)                                            \
    if (!(Expr)) {                                                             \
        err(Str, ##__VA_ARGS__);                                               \
        spf_filter_delete(&data);                                              \
        return false;                                                          \
    }

    foreach (param, filter->params) {
        switch (param->type) {
          /* use_spf_record parameter is a boolean.
           *  If use_spf_record is true, SPF records are looked for in both
           *  SPF records (RR Type 99) and TXT records (RR Type 15).
           * default is false.
           */
          FILTER_PARAM_PARSE_BOOLEAN(USE_SPF_RECORD, data->use_spf_record);

          /* use_explanation parameter is a boolean.
           *  If use_explanation is true, the SPF 'exp' modifier is used to
           *  fetch an explanation when SPF lookup fails.
           */
          FILTER_PARAM_PARSE_BOOLEAN(USE_EXPLANATION, data->use_explanation);

          /* check_helo parameter is a boolean.
           *  If check_helo is true, SPF check is done on the HELO/EHLO domain
           *  instead of the MAIL FROM domain.
           * default is false.
           */
          FILTER_PARAM_PARSE_BOOLEAN(CHECK_HELO, data->check_helo);

          default: break;
        }
    }

    filter->data = data;
    return true;
}

static void spf_filter_destructor(filter_t *filter)
{
    spf_filter_t* data = filter->data;
    spf_filter_delete(&data);
    filter->data = data;
}

static filter_result_t spf_code_to_result(spf_code_t code) {
    switch (code) {
      case SPF_NONE:
        return HTK_NONE;
      case SPF_NEUTRAL:
        return HTK_NEUTRAL;
      case SPF_PASS:
        return HTK_PASS;
      case SPF_FAIL:
        return HTK_FAIL;
      case SPF_SOFTFAIL:
        return HTK_SOFT_FAIL;
      case SPF_TEMPERROR:
        return HTK_TEMP_ERROR;
      case SPF_PERMERROR:
        return HTK_PERM_ERROR;
    }
    return HTK_NONE;
}

static void spf_filter_async(spf_code_t result, const char* exp, void *arg)
{
    filter_context_t* context = arg;
    filter_post_async_result_with_explanation(context, spf_code_to_result(result), exp, -1);
}


static filter_result_t spf_filter(const filter_t *filter, const query_t *query,
                                  filter_context_t *context)
{
    const spf_filter_t* data = filter->data;
    array_len(domain) = 0;
    array_len(sender) = 0;
    array_len(ip)     = 0;
    buffer_add(&ip, query->client_address.str, query->client_address.len);
    if (data->check_helo || query->sender_domain.len == 0) {
        buffer_add(&domain, query->helo_name.str, query->helo_name.len);
        buffer_addstr(&sender, "postmaster@");
        buffer_add(&sender, array_start(domain), array_len(domain));
    } else {
        buffer_add(&domain, query->sender_domain.str, query->sender_domain.len);
        buffer_add(&sender, query->sender.str, query->sender.len);
    }

    spf_code_t res;
    if (spf_check(array_start(ip), array_start(domain), array_start(sender), query->helo_name.str,
                  spf_filter_async, !data->use_spf_record, !data->use_explanation, context, &res) == NULL) {
        err("filter %s: error while trying to run spf check", filter->name);
        return spf_code_to_result(res);
    }
    return HTK_ASYNC;
}


static void spf_exit(void)
{
    array_wipe(domain);
    array_wipe(sender);
}
module_exit(spf_exit);


filter_constructor(spf)
{
    filter_type_t filter_type = filter_register("spf", spf_filter_constructor,
                                                spf_filter_destructor, spf_filter,
                                                NULL, NULL);

    /* Hooks.
     */
    (void)filter_hook_register(filter_type, "none");
    (void)filter_hook_register(filter_type, "neutral");
    (void)filter_hook_register(filter_type, "pass");
    (void)filter_hook_register(filter_type, "fail");
    (void)filter_hook_register(filter_type, "soft_fail");
    (void)filter_hook_register(filter_type, "temp_error");
    (void)filter_hook_register(filter_type, "perm_error");
    (void)filter_hook_register(filter_type, "async");

    filter_hook_forward_register(filter_type, HTK_NEUTRAL, HTK_NONE);
    filter_hook_forward_register(filter_type, HTK_TEMP_ERROR, HTK_NONE);
    filter_hook_forward_register(filter_type, HTK_PERM_ERROR, HTK_NONE);
    filter_hook_forward_register(filter_type, HTK_SOFT_FAIL, HTK_FAIL);

    /* Parameters.
     */
    (void)filter_param_register(filter_type, "use_spf_record");
    (void)filter_param_register(filter_type, "use_explanation");
    (void)filter_param_register(filter_type, "check_helo");
    return 0;
}

/* vim:set et sw=4 sts=4 sws=4: */
