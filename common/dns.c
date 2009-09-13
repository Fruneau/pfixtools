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
 * Copyright © 2008-2009 Florent Bruneau
 */

#include <netdb.h>
#include "array.h"
#include "server.h"
#include "dns.h"


typedef struct dns_context_t {
    dns_result_t *result;
    dns_result_callback_t call;
    void *data;
} dns_context_t;
ARRAY(dns_context_t);

static char *use_local_config = false;
static struct ub_ctx *ctx = NULL;
static client_t *async_event = NULL;
static PA(dns_context_t) ctx_pool = ARRAY_INIT;

static dns_context_t *dns_context_new(void)
{
    return p_new(dns_context_t, 1);
}

static void dns_context_delete(dns_context_t **context)
{
    if (*context) {
        p_delete(context);
    }
}

static void dns_context_wipe(dns_context_t *context)
{
    p_clear(context, 1);
}

static dns_context_t *dns_context_acquire(void)
{
    if (array_len(ctx_pool) > 0) {
        return array_pop_last(ctx_pool);
    } else {
        return dns_context_new();
    }
}

static void dns_context_release(dns_context_t *context)
{
    dns_context_wipe(context);
    array_add(ctx_pool, context);
}

static void dns_exit(void)
{
    if (async_event != NULL) {
        client_io_none(async_event);
    }
    if (ctx != NULL) {
        ub_ctx_delete(ctx);
        ctx = NULL;
    }
    if (async_event != NULL) {
        client_release(async_event);
        async_event = NULL;
    }
    p_delete(&use_local_config);
    array_deep_wipe(ctx_pool, dns_context_delete);
}
module_exit(dns_exit);

static void dns_callback(void *arg, int err, struct ub_result *result)
{
    dns_context_t *context = arg;
    if (err != 0) {
        debug("asynchronous request led to an error");
        *context->result = DNS_ERROR;
    } else if (result->nxdomain) {
        debug("asynchronous request done, %s NOT FOUND", result->qname);
        *context->result = DNS_NOTFOUND;
    } else {
        debug("asynchronous request done, %s FOUND", result->qname);
        *context->result = DNS_FOUND;
    }
    if (context->call != NULL) {
        context->call(context->result, context->data);
    }
    ub_resolve_free(result);
    dns_context_release(context);
}

static int dns_handler(client_t *event, void *config)
{
    int retval = 0;
    debug("dns_handler called: ub_fd triggered");
    client_io_none(event);
    if ((retval = ub_process(ctx)) != 0) {
        err("error in DNS resolution: %s", ub_strerror(retval));
    }
    client_io_ro(event);
    return 0;
}

bool dns_resolve(const char *hostname, dns_rrtype_t type, ub_callback_t callback, void *data)
{
    if (ctx == NULL) {
        ctx = ub_ctx_create();
        if (use_local_config != NULL) {
            debug("using local dns configuration");
            ub_ctx_resolvconf(ctx, use_local_config);
        }
        ub_ctx_async(ctx, true);
        if ((async_event = client_register(ub_fd(ctx), dns_handler, NULL)) == NULL) {
            crit("cannot register asynchronous DNS event handler");
            abort();
        }
    }
    debug("running dns resolution on %s (type: %d)", hostname, type);
    return (ub_resolve_async(ctx, (char*)hostname, type, DNS_RRC_IN, data, callback, NULL) == 0);
}

bool dns_check(const char *hostname, dns_rrtype_t type, dns_result_t *result,
               dns_result_callback_t callback, void *data)
{
    dns_context_t *context = dns_context_acquire();
    context->result = result;
    context->call   = callback;
    context->data   = data;
    if (dns_resolve(hostname, type, dns_callback, context)) {
        *result = DNS_ASYNC;
        return true;
    } else {
        *result = DNS_ERROR;
        dns_context_release(context);
        return false;
    }
}

bool dns_rbl_check(const char *rbl, uint32_t ip, dns_result_t *result,
                   dns_result_callback_t callback, void *data)
{
    char host[257];
    int len;

    len = snprintf(host, 257, "%d.%d.%d.%d.%s.",
                   ip & 0xff, (ip >> 8) & 0xff, (ip >> 16) & 0xff, (ip >> 24) & 0xff,
                   rbl);
    if (len >= (int)sizeof(host))
        return DNS_ERROR;
    if (host[len - 2] == '.')
        host[len - 1] = '\0';
    return dns_check(host, DNS_RRT_A, result, callback, data);
}

bool dns_rhbl_check(const char *rhbl, const char *hostname, dns_result_t *result,
                    dns_result_callback_t callback, void *data)
{
    char host[257];
    int len;

    len = snprintf(host, 257, "%s.%s.", hostname, rhbl);
    if (len >= (int)sizeof(host))
        return DNS_ERROR;
    if (host[len - 2] == '.')
        host[len - 1] = '\0';
    return dns_check(host, DNS_RRT_A, result, callback, data);
}

void dns_use_local_conf(const char* resolv) {
    p_delete(&use_local_config);
    use_local_config = m_strdup(resolv);
}

/* vim:set et sw=4 sts=4 sws=4: */
