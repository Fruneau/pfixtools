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

#include "spf.h"

struct spf_t {
    unsigned txt_received : 1;
    unsigned txt_inerror  : 1;
    unsigned spf_received : 1;
    unsigned spf_inerror  : 1;

    char *spf_record;
};

static spf_t *spf_new(void)
{
    return p_new(spf_t, 1);
}

__attribute__((used))
static void spf_delete(spf_t **context)
{
    if (*context) {
        p_delete(context);
    }
}

__attribute__((used))
static void spf_wipe(spf_t *context)
{
    p_clear(context, 1);
}


static void spf_line_callback(void *arg, int err, struct ub_result *result)
{
    spf_t *spf = arg;
    if (spf->spf_record == NULL) {
        return;
    }
    if (result->qtype == DNS_RRT_SPF) {
        spf->spf_received = true;
        spf->spf_inerror  = (result->rcode != 0 && result->rcode != 3);
    }
    if (result->qtype == DNS_RRT_TXT) {
        spf->txt_received = true;
        spf->txt_inerror  = (result->rcode != 0 && result->rcode != 3);
    }
    if (result->rcode == 0) {
        int i = 0;
        while (result->data[i] != NULL) {
            printf("%.*s\n", result->len[i], result->data[i]);
            ++i;
        }
    }
}

bool spf_check(const char *ip, const char *domain, const char *sender) {
    spf_t *spf = spf_new();
    return dns_resolve(domain, DNS_RRT_TXT, spf_line_callback, spf);
}

/* vim:set et sw=4 sts=4 sws=4: */
