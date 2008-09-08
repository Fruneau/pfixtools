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
 * Copyright © 2008 Florent Bruneau
 */

#include <getopt.h>

#include "buffer.h"
#include "common.h"
#include "epoll.h"
#include "tokens.h"
#include "server.h"

#define DAEMON_NAME             "postlicyd"
#define DEFAULT_PORT            10000
#define RUNAS_USER              "nobody"
#define RUNAS_GROUP             "nogroup"

DECLARE_MAIN

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
    const char *reverse_client_name;
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

    const char *eoq;
} query_t;

static query_t *query_new(void)
{
    return p_new(query_t, 1);
}

static void query_delete(query_t **query)
{
    if (*query) {
        p_delete(query);
    }
}

static void *query_starter(server_t* server)
{
    return query_new();
}

static int postfix_parsejob(query_t *query, char *p)
{
#define PARSE_CHECK(expr, error, ...)                                        \
    do {                                                                     \
        if (!(expr)) {                                                       \
            syslog(LOG_ERR, error, ##__VA_ARGS__);                           \
            return -1;                                                       \
        }                                                                    \
    } while (0)

    p_clear(query, 1);
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
            CASE(REVERSE_CLIENT_NAME, reverse_client_name);
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
            syslog(LOG_WARNING, "unexpected key, skipped: %.*s", klen, k);
            break;
        }
    }

    return query->state == SMTP_UNKNOWN ? -1 : 0;
#undef PARSE_CHECK
}

__attribute__((format(printf,2,0)))
static void policy_answer(server_t *pcy, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    buffer_addvf(&pcy->obuf, fmt, args);
    va_end(args);
    buffer_addstr(&pcy->obuf, "\n\n");
    buffer_consume(&pcy->ibuf, ((query_t*)(pcy->data))->eoq - pcy->ibuf.data);
    epoll_modify(pcy->fd, EPOLLIN | EPOLLOUT, pcy);
}

static void policy_process(server_t *pcy)
{
    policy_answer(pcy, "DUNNO");
}

static int policy_run(server_t *pcy, void* config)
{
    ssize_t search_offs = MAX(0, pcy->ibuf.len - 1);
    int nb = buffer_read(&pcy->ibuf, pcy->fd, -1);
    const char *eoq;

    if (nb < 0) {
        if (errno == EAGAIN || errno == EINTR)
            return 0;
        UNIXERR("read");
        return -1;
    }
    if (nb == 0) {
        if (pcy->ibuf.len)
            syslog(LOG_ERR, "unexpected end of data");
        return -1;
    }

    if (!(eoq = strstr(pcy->ibuf.data + search_offs, "\n\n")))
        return 0;

    if (postfix_parsejob(pcy->data, pcy->ibuf.data) < 0)
        return -1;
    ((query_t*)pcy->data)->eoq = eoq + strlen("\n\n");
    epoll_modify(pcy->fd, 0, pcy);
    policy_process(pcy);
    return 0;
}

int start_listener(int port)
{
    return start_server(port, NULL, NULL);
}

/* administrivia {{{ */

void usage(void)
{
    fputs("usage: "DAEMON_NAME" [options] config\n"
          "\n"
          "Options:\n"
          "    -l <port>    port to listen to\n"
          "    -p <pidfile> file to write our pid to\n"
          "    -f           stay in foreground\n"
         , stderr);
}

/* }}} */

int main(int argc, char *argv[])
{
    const char *pidfile = NULL;
    bool daemonize = true;
    int port = DEFAULT_PORT;

    for (int c = 0; (c = getopt(argc, argv, "hf" "l:p:")) >= 0; ) {
        switch (c) {
          case 'p':
            pidfile = optarg;
            break;
          case 'l':
            port = atoi(optarg);
            break;
          case 'f':
            daemonize = false;
            break;
          default:
            usage();
            return EXIT_FAILURE;
        }
    }

    if (argc - optind != 1) {
        usage();
        return EXIT_FAILURE;
    }

    if (common_setup(pidfile, false, RUNAS_USER, RUNAS_GROUP, daemonize)
          != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }

    if (start_listener(port) < 0)
        return EXIT_FAILURE;

    return server_loop(query_starter, (delete_client_t)query_delete,
                       policy_run, NULL);
}
