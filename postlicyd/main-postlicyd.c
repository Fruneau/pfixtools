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
#include "policy_tokens.h"
#include "server.h"
#include "query.h"
#include "config.h"

#define DAEMON_NAME             "postlicyd"
#define DEFAULT_PORT            10000
#define RUNAS_USER              "nobody"
#define RUNAS_GROUP             "nogroup"

DECLARE_MAIN

static void *query_starter(server_t* server)
{
    return query_new();
}

static bool config_refresh(void *config)
{
    return config_reload(config);
}

__attribute__((format(printf,2,0)))
static void policy_answer(server_t *pcy, const char *fmt, ...)
{
    va_list args;
    const query_t* query = pcy->data;

    buffer_addstr(&pcy->obuf, "action=");
    va_start(args, fmt);
    buffer_addvf(&pcy->obuf, fmt, args);
    va_end(args);
    buffer_addstr(&pcy->obuf, "\n\n");
    buffer_consume(&pcy->ibuf, query->eoq - pcy->ibuf.data);
    epoll_modify(pcy->fd, EPOLLIN | EPOLLOUT, pcy);
}

static bool policy_process(server_t *pcy, const config_t *config)
{
    const query_t* query = pcy->data;
    const filter_t *filter;
    if (config->entry_points[query->state] == -1) {
        warn("no filter defined for current protocol_state (%d)", query->state);
        return false;
    }
    filter = array_ptr(config->filters, config->entry_points[query->state]);
    while (true) {
        const filter_hook_t *hook = filter_run(filter, query);
        if (hook == NULL) {
            warn("request client=%s, from=<%s>, to=<%s>: aborted",
                 query->client_name,
                 query->sender == NULL ? "undefined" : query->sender,
                 query->recipient == NULL ? "undefined" : query->recipient);
            return false;
        } else if (hook->postfix) {
            info("request client=%s, from=<%s>, to=<%s>: "
                 "awswer %s from filter %s: \"%s\"",
                 query->client_name,
                 query->sender == NULL ? "undefined" : query->sender,
                 query->recipient == NULL ? "undefined" : query->recipient,
                 htokens[hook->type], filter->name, hook->value);
            policy_answer(pcy, "%s", hook->value);
            return true;
        } else {
            notice("request client=%s, from=<%s>, to=<%s>: "
                   "awswer %s from filter %s: next filter %s",
                   query->client_name,
                   query->sender == NULL ? "undefined" : query->sender,
                   query->recipient == NULL ? "undefined" : query->recipient,
                   htokens[hook->type], filter->name,
                   (array_ptr(config->filters, hook->filter_id))->name);
            filter = array_ptr(config->filters, hook->filter_id);
        }
    }
}

static int policy_run(server_t *pcy, void* vconfig)
{
    int search_offs = MAX(0, (int)(pcy->ibuf.len - 1));
    int nb = buffer_read(&pcy->ibuf, pcy->fd, -1);
    const char *eoq;
    query_t  *query  = pcy->data;
    const config_t *config = vconfig;

    if (nb < 0) {
        if (errno == EAGAIN || errno == EINTR)
            return 0;
        UNIXERR("read");
        return -1;
    }
    if (nb == 0) {
        if (pcy->ibuf.len)
            err("unexpected end of data");
        return -1;
    }

    if (!(eoq = strstr(pcy->ibuf.data + search_offs, "\n\n")))
        return 0;

    if (!query_parse(pcy->data, pcy->ibuf.data))
        return -1;
    query->eoq = eoq + strlen("\n\n");
    epoll_modify(pcy->fd, 0, pcy);
    return policy_process(pcy, config) ? 0 : -1;
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
          "    -d           grow logging level\n"
          "    -u           unsafe mode (don't drop privileges)\n"
         , stderr);
}

/* }}} */

int main(int argc, char *argv[])
{
    bool unsafe = false;
    const char *pidfile = NULL;
    bool daemonize = true;
    int port = DEFAULT_PORT;
    bool port_from_cli = false;

    for (int c = 0; (c = getopt(argc, argv, "ufd" "l:p:")) >= 0; ) {
        switch (c) {
          case 'p':
            pidfile = optarg;
            break;
          case 'u':
            unsafe = true;
            break;
          case 'l':
            port = atoi(optarg);
            port_from_cli = true;
            break;
          case 'f':
            daemonize = false;
            break;
          case 'd':
            ++log_level;
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
        crit("unable to write pidfile %s", pidfile);
        return EXIT_FAILURE;
    }

    if (drop_privileges(RUNAS_USER, RUNAS_GROUP) < 0) {
        crit("unable to drop privileges");
        return EXIT_FAILURE;
    }

    config_t *config = config_read(argv[optind]);
    if (config == NULL) {
        return EXIT_FAILURE;
    }
    if (port_from_cli || config->port == 0) {
        config->port = port;
    }

    if (daemonize && daemon_detach() < 0) {
        crit("unable to fork");
        return EXIT_FAILURE;
    }

    pidfile_refresh();

    if (start_listener(config->port) < 0) {
        return EXIT_FAILURE;
    } else {
        return server_loop(query_starter, (delete_client_t)query_delete,
                           policy_run, config_refresh, config);
    }
}
