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

#include "common.h"
#include "policy.h"
#include "buffer.h"
#include "tokens.h"

#if 0

#define ishspace(c)  ((c) == ' ' || (c) == '\t')

typedef struct jpriv_t {
    buffer_t ibuf;
    buffer_t obuf;
    query_t query;
} jpriv_t;

static jpriv_t *postfix_jpriv_init(jpriv_t *jp)
{
    buffer_init(&jp->ibuf);
    buffer_init(&jp->obuf);
    query_init(&jp->query);
    return jp;
}
static void postfix_jpriv_wipe(jpriv_t *jp)
{
    query_wipe(&jp->query);
    buffer_wipe(&jp->ibuf);
    buffer_wipe(&jp->obuf);
}
DO_NEW(jpriv_t, postfix_jpriv);
DO_DELETE(jpriv_t, postfix_jpriv);

static int postfix_parsejob(query_t *query)
{
#define PARSE_CHECK(expr, error, ...)                                        \
    do {                                                                     \
        if (!(expr)) {                                                       \
            syslog(LOG_ERR, error, ##__VA_ARGS__);                           \
            return -1;                                                       \
        }                                                                    \
    } while (0)

    char *p = vskipspaces(query->data.data);

    while (*p) {
        char *k, *v;
        int klen, vlen, vtk;

        while (ishspace(*p))
            p++;
        p = strchr(k = p, '=');
        PARSE_CHECK(p, "could not find '=' in line");
        for (klen = p - k; klen && ishspace(k[klen]); klen--);
        p += 1; /* skip = */

        while (ishspace(*p))
            p++;
        p = strstr(v = p, "\r\n");
        PARSE_CHECK(p, "could not find final \\r\\n in line");
        for (vlen = p - v; vlen && ishspace(v[vlen]); vlen--);
        p += 2; /* skip \r\n */

        vtk = tokenize(v, vlen);
        switch (tokenize(k, klen)) {
#define CASE(up, low)  case PTK_##up: query->low = v; v[vlen] = '\0'; break;
            CASE(HELO_NAME,           helo_name);
            CASE(QUEUE_ID,            queue_id);
            CASE(SENDER,              sender);
            CASE(RECIPIENT,           recipient);
            CASE(RECIPIENT_COUNT,     recipient_count);
            CASE(CLIENT_ADDRESS,      client_address);
            CASE(CLIENT_NAME,         client_name);
            CASE(RCLIENT_NAME,        rclient_name);
            CASE(INSTANCE,            instance);
            CASE(SASL_METHOD,         sasl_method);
            CASE(SASL_USERNAME,       sasl_username);
            CASE(SASL_SENDER,         sasl_sender);
            CASE(SIZE,                size);
            CASE(CCERT_SUBJECT,       ccert_subject);
            CASE(CCERT_ISSUER,        ccert_issuer);
            CASE(CCSERT_FINGERPRINT,  ccsert_fingerprint);
            CASE(ENCRYPTION_PROTOCOL, encryption_protocol);
            CASE(ENCRYPTION_CIPHER,   encryption_cipher);
            CASE(ENCRYPTION_KEYSIZE,  encryption_keysize);
            CASE(ETRN_DOMAIN,         etrn_domain);
#undef CASE

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
            return -1;
        }
    }

    return query->state == SMTP_UNKNOWN ? -1 : 0;

#undef PARSE_CHECK
}

static void postfix_process(job_t *job)
{
    int nb;
    const char *p;

    switch (job->mode) {
      case JOB_LISTEN:
        if ((job = job_accept(job, JOB_READ))) {
            job->jdata   = postfix_jpriv_new();
            job->process = &postfix_process;
            job->stop    = &postfix_stop;
        }
        return;

      case JOB_WRITE:
        nb = write(job->fd, job->jdata->obuf.data, job->jdata->obuf.len);
        if (nb < 0) {
            if ((job->error = errno != EINTR && errno != EAGAIN)) {
                syslog(LOG_ERR, "unexpected problem on the socket: %m");
            }
            return;
        }

        buffer_consume(&job->jdata->obuf, nb);
        if (job->jdata->obuf.len)
            return;

        /* fall through */

      case JOB_READ:
        nb = buffer_read(&job->jdata->ibuf, job->fd, -1);
        if (nb < 0) {
            if ((job->error = errno != EINTR && errno != EAGAIN)) {
                syslog(LOG_ERR, "unexpected problem on the socket: %m");
            }
            return;
        }
        if (nb == 0) {
            syslog(LOG_ERR, "unexpected eof");
            job->error = true;
            return;
        }

        p = strstr(skipspaces(job->jdata->ibuf.data), "\r\n\r\n");
        if (!p) {
            if (job->jdata->ibuf.len > SHRT_MAX) {
                syslog(LOG_ERR, "too much data without CRLFCRLF");
                job->error = true;
            }
            return;
        }
        p += 4;

        query_reset(&job->jdata->query);
        buffer_add(&job->jdata->query.data, job->jdata->ibuf.data,
                   p - 2 - job->jdata->ibuf.data);
        buffer_consume(&job->jdata->query.data, p - job->jdata->ibuf.data);

        if (postfix_parsejob(&job->jdata->query) < 0) {
            job->error = true;
            return;
        }

        /* TODO: run the scenario */
        return;

      default:
        job->error = true;
        return;
    }
}
#endif

void *policy_run(int fd, void *data)
{
    close(fd);
    return NULL;
}
