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
 * Copyright © 2007 Pierre Habouzit
 * Copyright © 2008 Florent Bruneau
 */

#ifndef PFIXTOOLS_QUERY_H
#define PFIXTOOLS_QUERY_H

#include "mem.h"
#include "common.h"
#include "buffer.h"
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

extern const static_str_t smtp_state_names[SMTP_count];

/* \see http://www.postfix.org/SMTPD_POLICY_README.html */
typedef struct query_t {
    unsigned state : 4;
    unsigned esmtp : 1;

    static_str_t helo_name;
    static_str_t queue_id;
    static_str_t sender;
    static_str_t recipient;
    static_str_t recipient_count;
    static_str_t client_address;
    static_str_t client_name;
    static_str_t reverse_client_name;
    static_str_t instance;

    /* useful data extracted from previous ones */
    static_str_t sender_domain;
    static_str_t recipient_domain;
    static_str_t normalized_sender;
    static_str_t normalized_client;

    /* postfix 2.2+ */
    static_str_t sasl_method;
    static_str_t sasl_username;
    static_str_t sasl_sender;
    static_str_t size;
    static_str_t ccert_subject;
    static_str_t ccert_issuer;
    static_str_t ccert_fingerprint;

    /* postfix 2.3+ */
    static_str_t encryption_protocol;
    static_str_t encryption_cipher;
    static_str_t encryption_keysize;
    static_str_t etrn_domain;

    /* postfix 2.5+ */
    static_str_t stress;

    const char *eoq;

    char n_sender[256];
    char n_client[64];
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
const static_str_t *query_field_for_name(const query_t *query, const char *name);

/** Returns the value of the field with the given id.
 */
__attribute__((nonnull))
const static_str_t *query_field_for_id(const query_t *query, postlicyd_token id);

/** Formats the given string by replacing ${field_name} with the content
 * of the query.
 * Unknown and empty fields are filled with (null).
 */
__attribute__((nonnull(3)))
ssize_t query_format(char *dest, size_t len, const char* fmt, const query_t *query);

/** Writes a query-formated string in a buffer.
 */
__attribute__((nonnull(1,2)))
bool query_format_buffer(buffer_t *buf, const char *fmt, const query_t *query);

/** Check the query-format string.
 */
#define query_format_check(fmt) (query_format(NULL, 0, fmt, NULL) >= 0)

#endif

/* vim:set et sw=4 sts=4 sws=4: */
