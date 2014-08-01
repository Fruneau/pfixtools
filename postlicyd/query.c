/****************************************************************************/
/*          pfixtools: a collection of postfix related tools                */
/*          ~~~~~~~~~                                                       */
/*  ______________________________________________________________________  */
/*                                                                          */
/*  Redistribution and use in source and binary forms, with or without      */
/*  modification, are permitted provided that the following conditions      */
/*  are met:                                                                */
/*                                                                          */
/*  1. Redistributions of source code must retain the above copyright       */
/*     notice, this list of conditions and the following disclaimer.        */
/*  2. Redistributions in binary form must reproduce the above copyright    */
/*     notice, this list of conditions and the following disclaimer in      */
/*     the documentation and/or other materials provided with the           */
/*     distribution.                                                        */
/*  3. The names of its contributors may not be used to endorse or promote  */
/*     products derived from this software without specific prior written   */
/*     permission.                                                          */
/*                                                                          */
/*  THIS SOFTWARE IS PROVIDED BY THE CONTRIBUTORS ``AS IS'' AND ANY         */
/*  EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE       */
/*  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR      */
/*  PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE CONTRIBUTORS BE LIABLE   */
/*  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR            */
/*  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF    */
/*  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR         */
/*  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,   */
/*  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE    */
/*  OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,       */
/*  EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.                      */
/*                                                                          */
/*   Copyright (c) 2006-2011 the Authors                                    */
/*   see AUTHORS and source files for details                               */
/****************************************************************************/

#include "query.h"
#include "policy_tokens.h"
#include "str.h"

const clstr_t smtp_state_names_g[] = {
    [SMTP_CONNECT]        = CLSTR_IMMED("CONNECT"),
    [SMTP_HELO]           = CLSTR_IMMED("HELO"),
    [SMTP_MAIL]           = CLSTR_IMMED("MAIL"),
    [SMTP_RCPT]           = CLSTR_IMMED("RCPT"),
    [SMTP_DATA]           = CLSTR_IMMED("DATA"),
    [SMTP_END_OF_MESSAGE] = CLSTR_IMMED("END-OF-MESSAGE"),
    [SMTP_VRFY]           = CLSTR_IMMED("VRFY"),
    [SMTP_ETRN]           = CLSTR_IMMED("ETRN"),
};

static struct {
    const clstr_t static_ESMTP;
    const clstr_t static_SMTP;
} query_g = {
#define _G  query_g
    .static_SMTP  = CLSTR_IMMED("SMTP"),
    .static_ESMTP = CLSTR_IMMED("ESMTP"),
};

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
#define CASE(up, low)                                                        \
          case PTK_##up:                                                     \
            query->low.str = v;                                              \
            query->low.len = vlen;                                           \
            v[vlen] = '\0';                                                  \
            break;
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
            CASE(CCERT_PUBKEY_FINGERPRINT, ccert_pubkey_fingerprint);
            CASE(CLIENT_PORT,         client_port);
#undef CASE

          case PTK_SENDER:
            query->sender.str = v;
            query->sender.len = vlen;
            v[vlen] = '\0';
            query->sender_domain.str = memchr(query->sender.str, '@', vlen);
            if (query->sender_domain.str != NULL) {
                ++query->sender_domain.str;
                query->sender_domain.len = query->sender.len
                                         - (query->sender_domain.str
                                            - query->sender.str);
            }
            break;

          case PTK_RECIPIENT:
            query->recipient.str = v;
            query->recipient.len = vlen;
            v[vlen] = '\0';
            query->recipient_domain.str
                = memchr(query->recipient.str, '@', vlen);
            if (query->recipient_domain.str != NULL) {
                ++query->recipient_domain.str;
                query->recipient_domain.len = query->recipient.len
                                            - (query->recipient_domain.str
                                               - query->recipient.str);

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

static void query_compute_normalized_client(query_t *query)
{
    char ip2[4], ip3[4];
    const char *dot, *p;

    query->normalized_client = query->client_address;
    if (query->client_name.len == 0) {
        return;
    }
    if (!(dot = strchr(query->client_address.str, '.'))) {
        return;
    }
    if (!(dot = strchr(dot + 1, '.'))) {
        return;
    }
    p = ++dot;
    if (!(dot = strchr(dot, '.')) || dot - p > 3) {
        return;
    }
    m_strncpy(ip2, sizeof(ip2), p, dot - p);

    const char *end = query->client_address.str + query->client_address.len;
    p = dot + 1;
    if (strchr(dot + 1, '.') || end - p > 3) {
        return;
    }
    m_strncpy(ip3, sizeof(ip3), p, end - p);

    /* skip if contains the last two ip numbers in the hostname,
       we assume it's a pool of dialup of a provider */
    if (strstr(query->client_name.str, ip2)
        && strstr(query->client_name.str, ip3)) {
        return;
    }

    m_strncpy(query->n_client, 64, query->client_address.str,
              dot - query->client_address.str);
    query->normalized_client.str = query->n_client;
    query->normalized_client.len = m_strlen(query->n_client);
}

static void query_compute_normalized_sender(query_t *query)
{
    const char *at = strchr(query->sender.str, '@');
    int rpos = 0, wpos = 0, userlen;

    query->normalized_sender = query->sender;
    if (!at) {
        return;
    }

    /* strip extension used for VERP or alike */
    userlen = ((char *)memchr(query->sender.str, '+',
                              at - query->sender.str) ?: at)
            - query->sender.str;

    while (rpos < userlen) {
        int count = 0;

        while (isdigit(query->sender.str[rpos + count])
               && rpos + count < userlen) {
            count++;
        }
        if (count && !isalnum(query->sender.str[rpos + count])) {
            /* replace \<\d+\> with '#' */
            wpos += m_strputc(query->n_sender + wpos, 256 - wpos, '#');
            rpos += count;
            count = 0;
        }
        while (isalnum(query->sender.str[rpos + count])
               && rpos + count < userlen) {
            count++;
        }
        while (!isalnum(query->sender.str[rpos + count])
               && rpos + count < userlen) {
            count++;
        }
        wpos += m_strncpy(query->n_sender + wpos, 256 - wpos,
                          query->sender.str + rpos, count);
        rpos += count;
    }

    wpos += m_strputc(query->n_sender + wpos, 256 - wpos, '#');
    m_strcpy(query->n_sender + wpos, 256 - wpos, at + 1);
    query->normalized_sender.str = query->n_sender;
    query->normalized_sender.len = m_strlen(query->n_sender);
}

const clstr_t *query_field_for_id(const query_t *query, postlicyd_token id)
{
    switch (id) {
#define CASE(Up, Low)  case PTK_ ## Up: return &query->Low;
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
      CASE(CCERT_PUBKEY_FINGERPRINT, ccert_pubkey_fingerprint);
      CASE(CLIENT_PORT, client_port);
#undef CASE
      case PTK_NORMALIZED_SENDER:
        if (query->normalized_sender.len == 0) {
            query_compute_normalized_sender((query_t*)query);
        }
        return &query->normalized_sender;

      case PTK_NORMALIZED_CLIENT:
        if (query->normalized_client.len == 0) {
            query_compute_normalized_client((query_t*)query);
        }
        return &query->normalized_client;

      case PTK_PROTOCOL_NAME:
        return query->esmtp ? &_G.static_ESMTP : &_G.static_SMTP;

      case PTK_PROTOCOL_STATE:
        return &smtp_state_names_g[query->state];

      default: return NULL;
    }
}

const clstr_t *query_field_for_name(const query_t *query, const char *name)
{
    postlicyd_token id = policy_tokenize(name, strlen(name));
    if (id == PTK_UNKNOWN) {
        warn("unknown query field %s", name);
        return NULL;
    }
    return query_field_for_id(query, id);
}

static bool query_format_field_content(const char* field, ssize_t field_len,
                                       int part, const query_t *query,
                                       clstr_t *res)
{
    postlicyd_token tok = policy_tokenize(field, field_len);
    if (tok == PTK_UNKNOWN) {
        warn("unknown field name \"%.*s\"", (int)field_len, field);
    }
    const clstr_t *f = query_field_for_id(query, tok);
    if (f == NULL) {
        res->str = "(null)";
        res->len = 6;
    } else {
        *res = *f;
        if (part == 0 && res->len == 0) {
            return true;
        } else if (part >= 0) {
            const char* start = res->str;
            const char* end = memchr(start, '.', res->len);
            for (int i = 0 ; i < part ; ++i) {
                if (end == NULL) {
                    res->str = "(none)";
                    res->len = 6;
                    return true;
                }
                start = end + 1;
                end = memchr(start, '.', res->len - (start - res->str));
            }
            if (end == NULL) {
                res->len = res->len - (start - res->str);
            } else {
                res->len = end - start;
            }
            res->str = start;
        } else if (part < 0 && part != INT_MIN) {
            const char* end = res->str + res->len;
            const char* start = m_memrchr(res->str, '.', res->len);
            for (int i = part ; i != -1 ; ++i) {
                if (start == NULL) {
                    res->str = "(none)";
                    res->len = 6;
                    return true;
                }
                end = start;
                start = m_memrchr(res->str, '.', end - res->str - 1);
            }
            if (start == NULL) {
                res->len = end - res->str;
            } else {
                res->str = start + 1;
                res->len = end - start - 1;
            }
        }
    }
    return true;
}

ssize_t query_format(char *dest, size_t len, const char *fmt,
                     const query_t *query)
{
    size_t written = 0;
    size_t pos = 0;

#define WRITE(Src, Len)                                                      \
    do {                                                                     \
        size_t __len     = (Len);                                            \
        if (written < len) {                                                 \
            size_t __to_write = MIN(len - written - 1, __len);               \
            memcpy(dest + written, (Src), __to_write);                       \
            written += __to_write;                                           \
        }                                                                    \
        pos += __len;                                                        \
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
                debug("query format: unmatched { in \"%s\"", fmt);
                return -1;
            }

            ssize_t fmt_len = next_format - fmt;
            int part = INT_MIN;
            if (fmt[fmt_len - 1] == ']') {
                fmt_len -= 2;
                while (fmt_len > 0 && fmt[fmt_len] != '[') {
                    --fmt_len;
                }
                char* end = NULL;
                part = strtol(fmt + fmt_len + 1, &end, 10);
                if (end == NULL || *end != ']') {
                    debug("query format: invalid part id in \"%.*s\"",
                          (int)(next_format - fmt), fmt);
                    return -1;
                }
            }

            if (query == NULL) {
                WRITE("(null)", 6);
            } else {
                clstr_t field;
                if (query_format_field_content(fmt, fmt_len, part, query,
                                               &field)) {
                    WRITE(field.str, field.len);
                } else {
                    WRITE("(none)", 6);
                }
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

/* vim:set et sw=4 sts=4 sws=4: */
