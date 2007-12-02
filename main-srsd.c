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
 * Copyright © 2005-2007 Pierre Habouzit
 */

#include "common.h"

#include <srs2.h>

#include "epoll.h"
#include "mem.h"
#include "buffer.h"

#define DAEMON_NAME             "pfix-srsd"
#define DEFAULT_ENCODER_PORT    10001
#define DEFAULT_DECODER_PORT    10002
#define RUNAS_USER              "nobody"
#define RUNAS_GROUP             "nogroup"

#define __tostr(x)  #x
#define STR(x)      __tostr(x)

/* srs encoder/decoder/listener worker {{{ */

typedef struct srsd_t {
    unsigned listener : 1;
    unsigned decoder  : 1;
    unsigned watchwr  : 1;
    int fd;
    buffer_t ibuf;
    buffer_t obuf;
} srsd_t;

static srsd_t *srsd_new(void)
{
    srsd_t *srsd = p_new(srsd_t, 1);
    srsd->fd = -1;
    return srsd;
}

static void srsd_delete(srsd_t **srsd)
{
    if (*srsd) {
        if ((*srsd)->fd >= 0)
            close((*srsd)->fd);
        buffer_wipe(&(*srsd)->ibuf);
        buffer_wipe(&(*srsd)->obuf);
        p_delete(srsd);
    }
}

void urldecode(char *s, char *end)
{
    char *p = s;

    while (*p) {
        if (*p == '%' && end - p >= 3) {
            int h = (hexval(p[1]) << 4) | hexval(p[2]);

            if (h >= 0) {
                *s++ = h;
                p += 3;
                continue;
            }
        }

        *s++ = *p++;
    }
    *s++ = '\0';
}

int process_srs(srs_t *srs, const char *domain, srsd_t *srsd)
{
    while (srsd->ibuf.len > 4) {
        char buf[BUFSIZ], *p, *q, *nl;
        int err;

        nl = strchr(srsd->ibuf.data + 4, '\n');
        if (!nl) {
            if (srsd->ibuf.len > BUFSIZ) {
                syslog(LOG_ERR, "unreasonnable amount of data without a \\n");
                return -1;
            }
            return 0;
        }

        if (strncmp("get ", srsd->ibuf.data, 4)) {
            syslog(LOG_ERR, "bad request, not starting with \"get \"");
            return -1;
        }

        for (p = srsd->ibuf.data + 4; p < nl && isspace(*p); p++);
        for (q = nl++; q >= p && isspace(*q); *q-- = '\0');

        if (p == q) {
            buffer_addstr(&srsd->obuf, "400 empty request ???\n");
            syslog(LOG_WARNING, "empty request");
            goto skip;
        }

        urldecode(p, q);

        if (srsd->decoder) {
            err = srs_reverse(srs, buf, ssizeof(buf), p);
        } else {
            err = srs_forward(srs, buf, ssizeof(buf), p, domain);
        }

        if (err == 0) {
            buffer_addstr(&srsd->obuf, "200 ");
            buffer_addstr(&srsd->obuf, buf);
        } else {
            switch (SRS_ERROR_TYPE(err)) {
              case SRS_ERRTYPE_SRS:
              case SRS_ERRTYPE_SYNTAX:
                buffer_addstr(&srsd->obuf, "500 ");
                break;
              default:
                buffer_addstr(&srsd->obuf, "400 ");
                break;
            }
            buffer_addstr(&srsd->obuf, srs_strerror(err));
        }
        buffer_addch(&srsd->obuf, '\n');

      skip:
        buffer_consume(&srsd->ibuf, nl - srsd->ibuf.data);
    }

    return 0;
}

int start_listener(int port, bool decoder)
{
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr   = { htonl(INADDR_LOOPBACK) },
    };
    struct epoll_event evt = { .events = EPOLLIN };
    srsd_t *tmp;
    int sock;

    addr.sin_port = htons(port);
    sock = tcp_listen_nonblock((const struct sockaddr *)&addr, sizeof(addr));
    if (sock < 0) {
        return -1;
    }

    evt.data.ptr  = tmp = srsd_new();
    tmp->fd       = sock;
    tmp->decoder  = decoder;
    tmp->listener = true;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sock, &evt) < 0) {
        UNIXERR("epoll_ctl");
        return -1;
    }
    return 0;
}

void start_client(srsd_t *srsd)
{
    struct epoll_event evt = { .events = EPOLLIN };
    srsd_t *tmp;
    int sock;

    sock = accept_nonblock(srsd->fd);
    if (sock < 0) {
        UNIXERR("accept");
        return;
    }

    evt.data.ptr = tmp = srsd_new();
    tmp->decoder = srsd->decoder;
    tmp->fd      = sock;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sock, &evt) < 0) {
        UNIXERR("epoll_ctl");
        srsd_delete(&tmp);
        close(sock);
    }
}

/* }}} */
/* administrivia {{{ */

static int main_initialize(void)
{
    openlog(DAEMON_NAME, LOG_PID, LOG_MAIL);
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
    fputs("usage: "DAEMON_NAME" [options] domain secrets\n"
          "\n"
          "Options:\n"
          "    -e <port>    port to listen to for encoding requests\n"
          "                 (default: "STR(DEFAULT_ENCODER_PORT)")\n"
          "    -d <port>    port to listen to for decoding requests\n"
          "                 (default: "STR(DEFAULT_DECODER_PORT)")\n"
          "    -p <pidfile> file to write our pid to\n"
          "    -u           unsafe mode: don't drop privilegies\n"
          "    -f           stay in foreground\n"
         , stderr);
}

/* }}} */

int main_loop(srs_t *srs, const char *domain, int port_enc, int port_dec)
{
    if (start_listener(port_enc, false) < 0)
        return EXIT_FAILURE;
    if (start_listener(port_dec, true) < 0)
        return EXIT_FAILURE;

    while (!sigint) {
        struct epoll_event evts[1024];
        int n;

        n = epoll_wait(epollfd, evts, countof(evts), -1);
        if (n < 0) {
            if (errno != EAGAIN && errno != EINTR) {
                UNIXERR("epoll_wait");
                return EXIT_FAILURE;
            }
            continue;
        }

        while (--n >= 0) {
            srsd_t *srsd = evts[n].data.ptr;

            if (srsd->listener) {
                start_client(srsd);
                continue;
            }

            if (evts[n].events & EPOLLIN) {
                int res = buffer_read(&srsd->ibuf, srsd->fd, -1);

                if ((res < 0 && errno != EINTR && errno != EAGAIN)
                ||  res == 0)
                {
                    srsd_delete(&srsd);
                    continue;
                }

                if (process_srs(srs, domain, srsd) < 0) {
                    srsd_delete(&srsd);
                    continue;
                }
            }

            if ((evts[n].events & EPOLLOUT) && srsd->obuf.len) {
                int res = buffer_write(&srsd->obuf, srsd->fd);
                if (res < 0) {
                    srsd_delete(&srsd);
                    continue;
                }
            }

            if (srsd->watchwr == !srsd->obuf.len) {
                struct epoll_event evt = {
                    .events   = EPOLLIN | (srsd->obuf.len ? EPOLLOUT : 0),
                    .data.ptr = srsd,
                };
                if (epoll_ctl(epollfd, EPOLL_CTL_MOD, srsd->fd, &evt) < 0) {
                    UNIXERR("epoll_ctl");
                    srsd_delete(&srsd);
                    continue;
                }
                srsd->watchwr = srsd->obuf.len != 0;
            }
        }
    }

    return EXIT_SUCCESS;
}

static srs_t *srs_read_secrets(const char *sfile)
{
    srs_t *srs;
    char buf[BUFSIZ];
    FILE *f;
    int lineno = 0;

    f = fopen(sfile, "r");
    if (!f) {
        UNIXERR("fopen");
        return NULL;
    }

    srs = srs_new();

    while (fgets(buf, sizeof(buf), f)) {
        int n = strlen(buf);

        ++lineno;
        if (n == sizeof(buf) - 1 && buf[n - 1] != '\n') {
            syslog(LOG_CRIT, "%s:%d: line too long", sfile, lineno);
            goto error;
        }
        m_strrtrim(buf);
        srs_add_secret(srs, skipspaces(buf));
    }

    if (!lineno) {
        syslog(LOG_CRIT, "%s: empty file, no secrets", sfile);
        goto error;
    }

    fclose(f);
    return srs;

  error:
    fclose(f);
    srs_free(srs);
    return NULL;
}

int main(int argc, char *argv[])
{
    bool unsafe  = false;
    bool daemonize = true;
    int port_enc = DEFAULT_ENCODER_PORT;
    int port_dec = DEFAULT_DECODER_PORT;
    const char *pidfile = NULL;

    int res;
    srs_t *srs;

    for (int c = 0; (c = getopt(argc, argv, "hfu" "e:d:p:")) >= 0; ) {
        switch (c) {
          case 'e':
            port_enc = atoi(optarg);
            break;
          case 'f':
            daemonize = false;
            break;
          case 'd':
            port_dec = atoi(optarg);
            break;
          case 'p':
            pidfile = optarg;
            break;
          case 'u':
            unsafe = true;
            break;
          default:
            usage();
            return EXIT_FAILURE;
        }
    }

    if (argc - optind != 2) {
        usage();
        return EXIT_FAILURE;
    }

    srs = srs_read_secrets(argv[optind + 1]);
    if (!srs) {
        return EXIT_FAILURE;
    }

    if (pidfile_open(pidfile) < 0) {
        syslog(LOG_CRIT, "unable to write pidfile %s", pidfile);
        return EXIT_FAILURE;
    }

    if (!unsafe && drop_privileges(RUNAS_USER, RUNAS_GROUP) < 0) {
        syslog(LOG_CRIT, "unable to drop privileges");
        return EXIT_FAILURE;
    }

    if (daemonize && daemon_detach() < 0) {
        syslog(LOG_CRIT, "unable to fork");
        return EXIT_FAILURE;
    }

    pidfile_refresh();
    res = main_loop(srs, argv[optind], port_enc, port_dec);
    syslog(LOG_INFO, "Stopping...");
    return res;
}
