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
 * Copyright © 2006-2007 Pierre Habouzit
 */

#ifndef PFIXTOOLS_POSTFIX_H
#define PFIXTOOLS_POSTFIX_H

#include <stddef.h>

#include "buffer.h"

enum smtp_state {
    SMTP_UNKNOWN,
    SMTP_CONNECT,
    SMTP_EHLO,
    SMTP_HELO = SMTP_EHLO,
    SMTP_MAIL,
    SMTP_RCPT,
    SMTP_DATA,
    SMTP_END_OF_MESSAGE,
    SMTP_VRFY,
    SMTP_ETRN,
};

/* \see http://www.postfix.org/SMTPD_POLICY_README.html */
typedef struct query_t {
    unsigned state : 4;
    unsigned esmtp : 1;

    const char *helo_name;
    const char *queue_id;
    const char *sender;
    const char *recipient;
    const char *recipient_count;
    const char *client_address;
    const char *client_name;
    const char *rclient_name;
    const char *instance;

    /* postfix 2.2+ */
    const char *sasl_method;
    const char *sasl_username;
    const char *sasl_sender;
    const char *size;
    const char *ccert_subject;
    const char *ccert_issuer;
    const char *ccsert_fingerprint;

    /* postfix 2.3+ */
    const char *encryption_protocol;
    const char *encryption_cipher;
    const char *encryption_keysize;
    const char *etrn_domain;

    buffer_t data;
} query_t;

static inline query_t *query_init(query_t *rq) {
    memset(rq, 0, offsetof(query_t, data));
    buffer_init(&rq->data);
    return rq;
}
static inline query_t *query_reset(query_t *rq) {
    memset(rq, 0, offsetof(query_t, data));
    buffer_reset(&rq->data);
    return rq;
}
static inline void query_wipe(query_t *rq) {
    buffer_wipe(&rq->data);
}
DO_NEW(query_t, query);
DO_DELETE(query_t, query);

#endif
