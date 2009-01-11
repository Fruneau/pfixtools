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
/*   Copyright (c) 2006-2008 the Authors                                      */
/*   see AUTHORS and source files for details                                 */
/******************************************************************************/

/*
 * Copyright © 2007 Pierre Habouzit
 * Copyright © 2008 Florent Bruneau
 */

#include "query.h"
#include "policy_tokens.h"
#include "str.h"

const static_str_t smtp_state_names[SMTP_count] = {
  { "CONNECT", 7 },
  { "HELO", 4 },
  { "MAIL", 4 },
  { "RCPT", 4 },
  { "DATA", 4 },
  { "END-OF-MESSAGE", 14 },
  { "VRFY", 4 },
  { "ETRN", 4 },
};

static const static_str_t static_ESMTP = { "ESMTP", 5 };
static const static_str_t static_SMTP  = { "SMTP",  4 };

bool query_parse(query_t *query, char *p)
{
#define PARSE_CHECK(expr, error, ...)                                        \
    do {                                                                     \
        if (!(expr)) {                                                       \
            err(error, ##__VA_ARGS__);                                       \
            return false;                                                    \
        }                                                                    \
    } while (0)

    p_clear(query, 1);
    query->state = SMTP_UNKNOWN;
    while (*p != '\n') {
        char *k, *v;
        int klen, vlen, vtk;

        while (isblank(*p))
            p++;
        p = strchr(k = p, '=');
        PARSE_CHECK(p, "could not find '=' in line");
        for (klen = p - k; klen && isblank(k[klen]); klen--);
        p += 1; /* skip = */

        while (isblank(*p))
            p++;
        p = strchr(v = p, '\n');
        PARSE_CHECK(p, "could not find final \\n in line");
        for (vlen = p - v; vlen && isblank(v[vlen]); vlen--);
        p += 1; /* skip \n */

        vtk = policy_tokenize(v, vlen);
        switch (policy_tokenize(k, klen)) {
#define CASE(up, low)  case PTK_##up: query->low.str = v; query->low.len = vlen; v[vlen] = '\0';  break;
            CASE(HELO_NAME,           helo_name);
            CASE(QUEUE_ID,            queue_id);
            CASE(RECIPIENT_COUNT,     recipient_count);
            CASE(CLIENT_ADDRESS,      client_address);
            CASE(CLIENT_NAME,         client_name);
            CASE(REVERSE_CLIENT_NAME, reverse_client_name);
            CASE(INSTANCE,            instance);
            CASE(SASL_METHOD,         sasl_method);
            CASE(SASL_USERNAME,       sasl_username);
            CASE(SASL_SENDER,         sasl_sender);
            CASE(SIZE,                size);
            CASE(CCERT_SUBJECT,       ccert_subject);
            CASE(CCERT_ISSUER,        ccert_issuer);
            CASE(CCERT_FINGERPRINT,   ccert_fingerprint);
            CASE(ENCRYPTION_PROTOCOL, encryption_protocol);
            CASE(ENCRYPTION_CIPHER,   encryption_cipher);
            CASE(ENCRYPTION_KEYSIZE,  encryption_keysize);
            CASE(ETRN_DOMAIN,         etrn_domain);
            CASE(STRESS,              stress);
#undef CASE

          case PTK_SENDER:
            query->sender.str = v;
            query->sender.len = vlen;
            v[vlen] = '\0';
            query->sender_domain.str = memchr(query->sender.str, '@', vlen);
            if (query->sender_domain.str != NULL) {
                ++query->sender_domain.str;
                query->sender_domain.len = query->sender.len
                                         - (query->sender_domain.str - query->sender.str);
            }
            break;

          case PTK_RECIPIENT:
            query->recipient.str = v;
            query->recipient.len = vlen;
            v[vlen] = '\0';
            query->recipient_domain.str = memchr(query->recipient.str, '@', vlen);
            if (query->recipient_domain.str != NULL) {
                ++query->recipient_domain.str;
                query->recipient_domain.len = query->recipient.len
                                         - (query->recipient_domain.str - query->recipient.str);

            }
            break;

          case PTK_REQUEST:
            PARSE_CHECK(vtk == PTK_SMTPD_ACCESS_POLICY,
                        "unexpected `request' value: %.*s", vlen, v);
            break;

          case PTK_PROTOCOL_NAME:
            PARSE_CHECK(vtk == PTK_SMTP || vtk == PTK_ESMTP,
                        "unexpected `protocol_name' value: %.*s", vlen, v);
            query->esmtp = vtk == PTK_ESMTP;
            break;

          case PTK_PROTOCOL_STATE:
            switch (vtk) {
#define CASE(name)  case PTK_##name: query->state = SMTP_##name; break;
                CASE(CONNECT);
                CASE(EHLO);
                CASE(HELO);
                CASE(MAIL);
                CASE(RCPT);
                CASE(DATA);
                CASE(END_OF_MESSAGE);
                CASE(VRFY);
                CASE(ETRN);
              default:
                PARSE_CHECK(false, "unexpected `protocol_state` value: %.*s",
                            vlen, v);
#undef CASE
            }
            break;

          default:
            warn("unexpected key, skipped: %.*s", klen, k);
            continue;
        }
    }

    return query->state != SMTP_UNKNOWN;
#undef PARSE_CHECK
}

const static_str_t *query_field_for_id(const query_t *query, postlicyd_token id)
{
    switch (id) {
#define CASE(Up, Low)                                                          \
      case PTK_ ## Up: return &query->Low;
      CASE(HELO_NAME, helo_name)
      CASE(QUEUE_ID, queue_id)
      CASE(SENDER, sender)
      CASE(SENDER_DOMAIN, sender_domain)
      CASE(RECIPIENT, recipient)
      CASE(RECIPIENT_DOMAIN, recipient_domain)
      CASE(RECIPIENT_COUNT, recipient_count)
      CASE(CLIENT_ADDRESS, client_address)
      CASE(CLIENT_NAME, client_name)
      CASE(REVERSE_CLIENT_NAME, reverse_client_name)
      CASE(INSTANCE, instance)
      CASE(SASL_METHOD, sasl_method)
      CASE(SASL_USERNAME, sasl_username)
      CASE(SASL_SENDER, sasl_sender)
      CASE(SIZE, size)
      CASE(CCERT_SUBJECT, ccert_subject)
      CASE(CCERT_ISSUER, ccert_issuer)
      CASE(CCERT_FINGERPRINT, ccert_fingerprint)
      CASE(ENCRYPTION_PROTOCOL, encryption_protocol)
      CASE(ENCRYPTION_CIPHER, encryption_cipher)
      CASE(ENCRYPTION_KEYSIZE, encryption_keysize)
      CASE(ETRN_DOMAIN, etrn_domain)
      CASE(STRESS, stress)
#undef CASE
      case PTK_PROTOCOL_NAME:
        return query->esmtp ? &static_ESMTP : &static_SMTP;

      case PTK_PROTOCOL_STATE:
        return &smtp_state_names[query->state];

      default: return NULL;
    }
}

const static_str_t *query_field_for_name(const query_t *query, const char *name)
{
    postlicyd_token id = policy_tokenize(name, strlen(name));
    if (id == PTK_UNKNOWN) {
        warn("unknown query field %s", name);
        return NULL;
    }
    return query_field_for_id(query, id);
}

ssize_t query_format(char *dest, size_t len, const char *fmt, const query_t *query)
{
    size_t written = 0;
    size_t pos = 0;

#define WRITE(Src, Len)                                                        \
    do {                                                                       \
        size_t __len     = (Len);                                              \
        if (written < len) {                                                   \
            size_t __to_write = MIN(len - written - 1, __len);                 \
            memcpy(dest + written, (Src), __to_write);                         \
            written += __to_write;                                             \
        }                                                                      \
        pos += __len;                                                          \
    } while (0)
    while (*fmt != '\0') {
        const char *next_format = strchr(fmt, '$');
        while (next_format != NULL && next_format[1] != '{') {
            next_format = strchr(next_format + 1, '$');
        }
        if (next_format == NULL) {
            next_format = fmt + m_strlen(fmt);
        }
        WRITE(fmt, next_format - fmt);
        fmt = next_format;
        if (*fmt != '\0') {
            fmt += 2;
            next_format = strchr(fmt, '}');
            if (next_format == NULL) {
                return -1;
            }

            postlicyd_token tok = policy_tokenize(fmt, next_format - fmt);
            if (tok == PTK_UNKNOWN) {
                warn("unknown field name \"%.*s\"", (int)(next_format - fmt), fmt);
            }
            const static_str_t *field = query == NULL ? NULL
                                                      : query_field_for_id(query, tok);
            if (field == NULL) {
                WRITE("(null)", 6);
            } else {
                WRITE(field->str, field->len);
            }
            fmt = next_format + 1;
        }
    }

    if (written > 0 && len > 0) {
        dest[written] = '\0';
    }
    return pos;
}

bool query_format_buffer(buffer_t *buf, const char *fmt, const query_t *query)
{
    buffer_ensure(buf, m_strlen(fmt) + 64);

    ssize_t size = array_free_space(*buf);
    ssize_t format_size = query_format(array_end(*buf),
                                       size, fmt, query);
    if (format_size == -1) {
        return false;
    } else if (format_size > size) {
        buffer_ensure(buf, format_size + 1);
        query_format(array_end(*buf),
                     array_free_space(*buf),
                     fmt, query);
        array_len(*buf) += format_size;
    } else {
        array_len(*buf) += format_size;
    }
    return true;
}
