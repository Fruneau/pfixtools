/******************************************************************************/
/*          postlicyd: a postfix policy daemon with a lot of features         */
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
 * Copyright © 2007 Pierre Habouzit
 */

#include <assert.h>
#include <signal.h>
#include <stdlib.h>
#include <sysexits.h>
#include <syslog.h>

#include "gai.h"

#define GAI_SIGNO  (SIGRTMIN+0)

static struct {
    gai_req **ring;
    int start, len, size;
} fifo = {
    .ring = NULL,
    .start = 0,
    .len   = 0,
    .size  = 0,
};

static int gai_fifo_end(void)
{
    int res = fifo.start + fifo.len;
    return res >= fifo.size ? res - fifo.size : fifo.size;
}

static void gai_fifo_append(gai_req *rq)
{
    if (fifo.len >= fifo.size) {
        p_realloc(&fifo.ring, fifo.size += 16);
    }

    fifo.ring[gai_fifo_end()] = rq;
    fifo.len++;
}

static gai_req *gai_fifo_pop(void)
{
    gai_req *res = NULL;

    while (!res && fifo.len) {
        res = fifo.ring[fifo.start];
        fifo.start++, fifo.len--;
        if (fifo.start >= fifo.size)
            fifo.start = 0;
    }

    return res;
}

static void gai_fifo_remove(gai_req *rq)
{
    int i, end = gai_fifo_end();

    if (fifo.start + fifo.len <= fifo.size) {
        for (i = fifo.start; i < end; i++) {
            if (fifo.ring[i] == rq)
                fifo.ring[i] = NULL;
        }
    } else {
        for (i = fifo.start; i < fifo.size; i++) {
            if (fifo.ring[i] == rq)
                fifo.ring[i] = NULL;
        }
        for (i = 0; i < end; i++) {
            if (fifo.ring[i] == rq)
                fifo.ring[i] = NULL;
        }
    }
}

static gai_req *gai_req_new(void)
{
    gai_req *rq = p_new(gai_req, 1);
    rq->cbp = &rq->cb;
    return rq;
}
static void gai_req_delete(gai_req **rqp)
{
    if (*rqp) {
        gai_req *rq = *rqp;

        switch (gai_error(rq->cbp)) {
          case EAI_INPROGRESS:
            if (gai_cancel(rq->cbp) == EAI_NOTCANCELED) {
                rq->caller = NULL;
                *rqp = NULL;
                return;
            }
            break;

          case EAI_CANCELED:
            break;

          default: /* we are likely in the notify list remove us ! */
            if (rq->caller) {
                gai_fifo_remove(rq);
            }
        }

        p_delete((char **)&rq->cb.ar_name);
        freeaddrinfo(rq->cb.ar_result);
        rq->cb.ar_result = NULL;
        p_delete(rqp);
    }
}

gai_req *gai_query(job_t *caller, const char *lookup)
{
    struct sigevent se = {
        .sigev_signo  = GAI_SIGNO,
        .sigev_notify = SIGEV_SIGNAL,
    };
    gai_req *res;

    se.sigev_value.sival_ptr = res = gai_req_new();
    res->cb.ar_name = strdup(lookup);
    res->caller     = caller;
    getaddrinfo_a(GAI_NOWAIT, &res->cbp, 1, &se);

    return res;
}

void gai_abort(gai_req **rqp)
{
    gai_req_delete(rqp);
}


static void gai_sigaction(int sig, siginfo_t *si, void *ctx)
{
    gai_req *req = si->_sifields._rt.si_sigval.sival_ptr;

    assert (sig == GAI_SIGNO);
    assert (req && gai_error(req->cbp) != EAI_INPROGRESS);

    if (req->caller) {
        gai_fifo_append(req);
    } else {
        gai_req_delete(&req);
    }
}

void gai_initialize(void)
{
    struct sigaction sa = {
        .sa_sigaction = &gai_sigaction,
        .sa_flags     = SA_SIGINFO,
    };
    if (sigaction(GAI_SIGNO, &sa, NULL) < 0) {
        syslog(LOG_ERR, "cannot hook SIGRTMIN+0: %m");
        exit(EX_OSERR);
    }
}

void gai_process(void)
{
    gai_req *req;

    while ((req = gai_fifo_pop())) {
        assert (req->caller && req->caller->process);
        req->caller->process(req->caller);
        req->caller = NULL; /* make delete faster: avoid gai_fifo_remove() */
    }
}

void gai_shutdown(void)
{
    /* TODO: deallocate the fifo properly */
}
