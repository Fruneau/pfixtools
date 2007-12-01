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

#include <getopt.h>

#include "buffer.h"
#include "common.h"
#include "threads.h"
#include "tokens.h"

#define DAEMON_NAME             "postlicyd"
#define DEFAULT_PORT            10000
#define RUNAS_USER              "nobody"
#define RUNAS_GROUP             "nogroup"

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
} query_t;

static int postfix_parsejob(query_t *query, char *p)
{
#define PARSE_CHECK(expr, error, ...)                                        \
    do {                                                                     \
        if (!(expr)) {                                                       \
            syslog(LOG_ERR, error, ##__VA_ARGS__);                           \
            return -1;                                                       \
        }                                                                    \
    } while (0)

    p_clear(&query, 1);
    while (p[0] != '\r' || p[1] != '\n') {
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
        p = strstr(v = p, "\r\n");
        PARSE_CHECK(p, "could not find final \\r\\n in line");
        for (vlen = p - v; vlen && isblank(v[vlen]); vlen--);
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
            syslog(LOG_WARNING, "unexpected key, skipped: %.*s", klen, k);
            break;
        }
    }

    return query->state == SMTP_UNKNOWN ? -1 : 0;
#undef PARSE_CHECK
}

static void *policy_run(int fd, void *data)
{
    buffer_t buf;

    buffer_init(&buf);
    for (;;) {
        int nb = buffer_read(&buf, fd, -1);
        const char *eoq;
        query_t q;

        if (nb < 0) {
            if (errno == EAGAIN || errno == EINTR)
                continue;
            UNIXERR("read");
            break;
        }
        if (nb == 0) {
            if (buf.len)
                syslog(LOG_ERR, "unexpected end of data");
            break;
        }

        eoq = strstr(buf.data + MAX(0, buf.len - 3), "\r\n\r\n");
        if (!eoq)
            continue;

        if (postfix_parsejob(&q, buf.data) < 0)
            break;

        buffer_consume(&buf, eoq + strlen("\r\n\r\n") - buf.data);
        if (xwrite(fd, "DUNNO\r\n", strlen("DUNNO\r\n"))) {
            UNIXERR("write");
            break;
        }
    }
    buffer_wipe(&buf);

    close(fd);
    return NULL;
}

/* administrivia {{{ */

static int main_initialize(void)
{
    openlog("postlicyd", LOG_PID, LOG_MAIL);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT,  &common_sighandler);
    signal(SIGTERM, &common_sighandler);
    signal(SIGHUP,  &common_sighandler);
    signal(SIGSEGV, &common_sighandler);
    syslog(LOG_INFO, "Starting...");
    return 0;
}

static void main_shutdown(void)
{
    closelog();
}

module_init(main_initialize);
module_exit(main_shutdown);

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
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr   = { htonl(INADDR_LOOPBACK) },
    };
    const char *pidfile = NULL;
    bool daemonize = true;
    int port = DEFAULT_PORT;
    int sock = -1;

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

    if (pidfile_open(pidfile) < 0) {
        syslog(LOG_CRIT, "unable to write pidfile %s", pidfile);
        return EXIT_FAILURE;
    }

    if (drop_privileges(RUNAS_USER, RUNAS_GROUP) < 0) {
        syslog(LOG_CRIT, "unable to drop privileges");
        return EXIT_FAILURE;
    }

    if (daemonize && daemon_detach() < 0) {
        syslog(LOG_CRIT, "unable to fork");
        return EXIT_FAILURE;
    }

    pidfile_refresh();

    addr.sin_port = htons(port);
    sock = tcp_listen((struct sockaddr *)&addr, sizeof(addr));
    if (sock < 0)
        return EXIT_FAILURE;

    while (!sigint) {
        int fd = accept(sock, NULL, 0);
        if (fd < 0) {
            if (errno != EINTR && errno != EAGAIN)
                UNIXERR("accept");
            continue;
        }
        thread_launch(policy_run, fd, NULL);
        threads_join();
    }

    close(sock);
    syslog(LOG_INFO, "Stopping...");
    return EXIT_SUCCESS;
}
