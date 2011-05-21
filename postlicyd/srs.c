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
 * Copyright © 2011 Florent Bruneau
 */

#include "common.h"
#include "str.h"
#include "filter.h"
#include <srs2.h>

typedef struct srs_config_t {
    clstr_t bounce_domain;
    srs_t  *srs;
} srs_config_t;

/* postlicyd filter declaration */

static srs_config_t *srs_config_new(void)
{
    srs_config_t *config = p_new(srs_config_t, 1);
    p_clear(config, 1);
    return config;
}

static void srs_config_delete(srs_config_t **pconfig)
{
    if (*pconfig) {
        srs_config_t *config = *pconfig;
        if (config->srs) {
            srs_free(config->srs);
        }
        if (config->bounce_domain.str != NULL) {
            p_delete((char **)&config->bounce_domain.str);
        }
        p_delete(pconfig);
    }
}

static srs_t *srs_read_secrets(const char *sfile)
{
    srs_t *srs;
    char buf[BUFSIZ];
    FILE *f;
    int lineno = 0;

    f = fopen(sfile, "r");
    if (!f) {
        UNIXERR("fopen");
        return NULL;
    }

    srs = srs_new();

    while (fgets(buf, sizeof(buf), f)) {
        int n = strlen(buf);

        ++lineno;
        if (n == sizeof(buf) - 1 && buf[n - 1] != '\n') {
            err("%s:%d: line too long", sfile, lineno);
            goto error;
        }
        m_strrtrim(buf);
        srs_add_secret(srs, skipspaces(buf));
    }

    if (!lineno) {
        err("%s: empty file, no secrets", sfile);
        goto error;
    }

    fclose(f);
    return srs;

  error:
    fclose(f);
    srs_free(srs);
    return NULL;
}

static bool srs_filter_constructor(filter_t *filter)
{
    char *bounce_domain = NULL;
    const char *secret_file   = NULL;
    srs_config_t *config = srs_config_new();

#define PARSE_CHECK(Expr, Str, ...)                                          \
    if (!(Expr)) {                                                           \
        err(Str, ##__VA_ARGS__);                                             \
        srs_config_delete(&config);                                          \
        p_delete(&bounce_domain);                                            \
        return false;                                                        \
    }

    foreach (param, filter->params) {
        switch (param->type) {
          FILTER_PARAM_PARSE_STRING(BOUNCE_DOMAIN, bounce_domain, true);
          FILTER_PARAM_PARSE_STRING(SECRET_FILE, secret_file, false);

          default: break;
        }
    }

    PARSE_CHECK(bounce_domain, "bounce domain not given");
    PARSE_CHECK(secret_file, "secret file not given");

    config->srs = srs_read_secrets(secret_file);
    PARSE_CHECK(config->srs, "cannot read srs configuration");
    config->bounce_domain = (clstr_t){
        .str = bounce_domain,
        .len = m_strlen(bounce_domain)
    };
    filter->data = config;
    return true;
}

static void srs_filter_destructor(filter_t *filter)
{
    srs_config_t *data = filter->data;
    srs_config_delete(&data);
    filter->data = data;
}

static filter_result_t srs_filter(const filter_t *filter,
                                  const query_t *query,
                                  filter_context_t *context)
{
    char buf[BUFSIZ];
    const srs_config_t *config = filter->data;

    if (query->state != SMTP_RCPT) {
        warn("srs only works as smtpd_recipient_restrictions");
        return HTK_ABORT;
    }

    if (!clstr_equals(query->recipient_domain, config->bounce_domain)) {
        return HTK_NONE;
    }

    if (srs_reverse(config->srs, buf, ssizeof(buf), query->recipient.str) == SRS_SUCCESS) {
        return HTK_MATCH;
    } else {
        return HTK_FAIL;
    }
}

filter_constructor(srs)
{
    filter_type_t filter_type = filter_register("srs", srs_filter_constructor,
                                                srs_filter_destructor, srs_filter,
                                                NULL, NULL);

    /* Hooks.
     */
    (void)filter_hook_register(filter_type, "match");
    (void)filter_hook_register(filter_type, "fail");
    (void)filter_hook_register(filter_type, "none");
    (void)filter_hook_register(filter_type, "abort");

    /* Parameters.
     */
    (void)filter_param_register(filter_type, "bounce_domain");
    (void)filter_param_register(filter_type, "secret_file");
    return 0;
}
