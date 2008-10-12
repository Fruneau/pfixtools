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
 * Copyright © 2007 Pierre Habouzit
 * Copyright © 2008 Florent Bruneau
 */

#ifndef PFIXTOOLS_QUERY_H
#define PFIXTOOLS_QUERY_H

#include "mem.h"
#include "common.h"
#include "policy_tokens.h"

enum smtp_state {
    SMTP_CONNECT,
    SMTP_EHLO,
    SMTP_HELO = SMTP_EHLO,
    SMTP_MAIL,
    SMTP_RCPT,
    SMTP_DATA,
    SMTP_END_OF_MESSAGE,
    SMTP_VRFY,
    SMTP_ETRN,
    SMTP_count,
    SMTP_UNKNOWN,
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
    const char *reverse_client_name;
    const char *instance;

    /* useful data extracted from previous ones */
    const char *sender_domain;
    const char *recipient_domain;

    /* postfix 2.2+ */
    const char *sasl_method;
    const char *sasl_username;
    const char *sasl_sender;
    const char *size;
    const char *ccert_subject;
    const char *ccert_issuer;
    const char *ccert_fingerprint;

    /* postfix 2.3+ */
    const char *encryption_protocol;
    const char *encryption_cipher;
    const char *encryption_keysize;
    const char *etrn_domain;

    /* postfix 2.5+ */
    const char *stress;

    const char *eoq;
} query_t;

/** Parse the content of the text to fill the query.
 * The text pointed by \p p is segmented (and modified to add
 * a \0 at the end of each segment) and used to fill the query
 * object.
 */
__attribute__((nonnull(1,2)))
bool query_parse(query_t *query, char *p);

/** Return the value of the field with the given name.
 */
__attribute__((nonnull(1,2)))
const char *query_field_for_name(const query_t *query, const char *name);

/** Returns the value of the field with the given id.
 */
__attribute__((nonnull))
const char *query_field_for_id(const query_t *query, postlicyd_token id);

#endif
