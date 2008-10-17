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

#include <unbound.h>
#include <netdb.h>
#include "array.h"
#include "server.h"
#include "rbl.h"


typedef struct rbl_context_t {
    rbl_result_t *result;
    rbl_result_callback_t call;
    void *data;
} rbl_context_t;
ARRAY(rbl_context_t);

static struct ub_ctx *ctx = NULL;
static client_t *async_event = NULL;
static PA(rbl_context_t) ctx_pool = ARRAY_INIT;

static rbl_context_t *rbl_context_new(void)
{
    return p_new(rbl_context_t, 1);
}

static void rbl_context_delete(rbl_context_t **context)
{
    if (*context) {
        p_delete(context);
    }
}

static void rbl_context_wipe(rbl_context_t *context)
{
    p_clear(context, 1);
}

static rbl_context_t *rbl_context_acquire(void)
{
    if (array_len(ctx_pool) > 0) {
        return array_pop_last(ctx_pool);
    } else {
        return rbl_context_new();
    }
}

static void rbl_context_release(rbl_context_t *context)
{
    rbl_context_wipe(context);
    array_add(ctx_pool, context);
}

static void rbl_exit(void)
{
    if (ctx != NULL) {
        ub_ctx_delete(ctx);
        ctx = NULL;
    }
    if (async_event != NULL) {
        client_release(async_event);
        async_event = NULL;
    }
    array_deep_wipe(ctx_pool, rbl_context_delete);
}
module_exit(rbl_exit);

static void rbl_callback(void *arg, int err, struct ub_result *result)
{
    rbl_context_t *context = arg;
    if (err != 0) {
        debug("asynchronous request led to an error");
        *context->result = RBL_ERROR;
    } else if (result->nxdomain) {
        debug("asynchronous request done, %s NOT FOUND", result->qname);
        *context->result = RBL_NOTFOUND;
    } else {
        debug("asynchronous request done, %s FOUND", result->qname);
        *context->result = RBL_FOUND;
    }
    if (context->call != NULL) {
        context->call(context->result, context->data);
    }
    ub_resolve_free(result);
    rbl_context_release(context);
}

static int rbl_handler(client_t *event, void *config)
{
    int retval = 0;
    debug("rbl_handler called: ub_fd triggered");
    client_io_none(event);
    if ((retval = ub_process(ctx)) != 0) {
        err("error in DNS resolution: %s", ub_strerror(retval));
    }
    client_io_ro(event);
    return 0;
}

static inline bool rbl_dns_check(const char *hostname, rbl_result_t *result,
                                 rbl_result_callback_t callback, void *data)
{
    if (ctx == NULL) {
        ctx = ub_ctx_create();
        ub_ctx_async(ctx, true);
        if ((async_event = client_register(ub_fd(ctx), rbl_handler, NULL)) == NULL) {
            crit("cannot register asynchronous DNS event handler");
            abort();
        }
    }
    rbl_context_t *context = rbl_context_acquire();
    context->result = result;
    context->call   = callback;
    context->data   = data;
    debug("running dns resolution on %s", hostname);
    if (ub_resolve_async(ctx, (char*)hostname, 1, 1, context, rbl_callback, NULL) == 0) {
        *result = RBL_ASYNC;
        return true;
    } else {
        *result = RBL_ERROR;
        rbl_context_release(context);
        return false;
    }
}

bool rbl_check(const char *rbl, uint32_t ip, rbl_result_t *result,
               rbl_result_callback_t callback, void *data)
{
    char host[257];
    int len;

    len = snprintf(host, 257, "%d.%d.%d.%d.%s.",
                   ip & 0xff, (ip >> 8) & 0xff, (ip >> 16) & 0xff, (ip >> 24) & 0xff,
                   rbl);
    if (len >= (int)sizeof(host))
        return RBL_ERROR;
    if (host[len - 2] == '.')
        host[len - 1] = '\0';
    return rbl_dns_check(host, result, callback, data);
}

bool rhbl_check(const char *rhbl, const char *hostname, rbl_result_t *result,
                rbl_result_callback_t callback, void *data)
{
    char host[257];
    int len;

    len = snprintf(host, 257, "%s.%s.", hostname, rhbl);
    if (len >= (int)sizeof(host))
        return RBL_ERROR;
    if (host[len - 2] == '.')
        host[len - 1] = '\0';
    return rbl_dns_check(host, result, callback, data);
}
