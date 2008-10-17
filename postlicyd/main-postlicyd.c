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
#include "policy_tokens.h"
#include "server.h"
#include "config.h"
#include "query.h"

#define DAEMON_NAME             "postlicyd"
#define DAEMON_VERSION          "0.3"
#define DEFAULT_PORT            10000
#define RUNAS_USER              "nobody"
#define RUNAS_GROUP             "nogroup"

DECLARE_MAIN

typedef struct query_context_t {
    query_t query;
    filter_context_t context;
    client_t *client;
} query_context_t;

static config_t *config  = NULL;
static bool refresh      = false;
static PA(client_t) busy = ARRAY_INIT;

static void *query_starter(listener_t* server)
{
    query_context_t *context = p_new(query_context_t, 1);
    filter_context_prepare(&context->context, context);
    return context;
}

static void query_stopper(void *data)
{
    query_context_t **context = data;
    if (*context) {
        filter_context_wipe(&(*context)->context);
        p_delete(context);
    }
}

static bool config_refresh(void *mconfig)
{
    refresh = true;
    if (filter_running > 0) {
        return true;
    }
    bool ret = config_reload(mconfig);
    foreach (client_t **server, busy) {
        client_io_ro(*server);
    }}
    array_len(busy) = 0;
    refresh = false;
    return ret;
}

static void policy_answer(client_t *pcy, const char *message)
{
    query_context_t *context = client_data(pcy);
    const query_t* query = &context->query;
    buffer_t *buf = client_output_buffer(pcy);

    /* Write reply "action=ACTION [text]" */
    buffer_addstr(buf, "action=");
    buffer_ensure(buf, m_strlen(message) + 64);

    ssize_t size = array_size(*buf) - array_len(*buf);
    ssize_t format_size = query_format(array_ptr(*buf, array_len(*buf)),
                                       size, message, query);
    if (format_size == -1) {
        buffer_addstr(buf, message);
    } else if (format_size > size) {
        buffer_ensure(buf, format_size + 1);
        query_format(array_ptr(*buf, array_len(*buf)),
                     array_size(*buf) - array_len(*buf),
                     message, query);
        array_len(*buf) += format_size;
    } else {
        array_len(*buf) += format_size;
    }
    buffer_addstr(buf, "\n\n");

    /* Finalize query. */
    buf = client_input_buffer(pcy);
    buffer_consume(buf, query->eoq - buf->data);
    client_io_rw(pcy);
}

static const filter_t *next_filter(client_t *pcy, const filter_t *filter,
                                   const query_t *query, const filter_hook_t *hook, bool *ok) {
#define MESSAGE_FORMAT "request client=%s from=<%s> to=<%s> at %s: "
#define MESSAGE_PARAMS query->client_name,                                          \
                  query->sender == NULL ? "undefined" : query->sender,              \
                  query->recipient == NULL ? "undefined" : query->recipient,        \
                  smtp_state_names[query->state]

    if (hook != NULL) {
        query_context_t *context = client_data(pcy);
        if (hook->counter >= 0 && hook->counter < MAX_COUNTERS && hook->cost > 0) {
            context->context.counters[hook->counter] += hook->cost;
            debug(MESSAGE_FORMAT "added %d to counter %d (now %u)", MESSAGE_PARAMS,
                  hook->cost, hook->counter, context->context.counters[hook->counter]);
        }
    }
    if (hook == NULL) {
        warn(MESSAGE_FORMAT "aborted", MESSAGE_PARAMS);
        *ok = false;
        return NULL;
    } else if (hook->async) {
        debug(MESSAGE_FORMAT "asynchronous filter from filter %s",
              MESSAGE_PARAMS, filter->name);
        *ok = true;
        return NULL;
    } else if (hook->postfix) {
        info(MESSAGE_FORMAT "awswer %s from filter %s: \"%s\"", MESSAGE_PARAMS,
             htokens[hook->type], filter->name, hook->value);
        policy_answer(pcy, hook->value);
        *ok = true;
        return NULL;
    } else {
        debug(MESSAGE_FORMAT "awswer %s from filter %s: next filter %s",
              MESSAGE_PARAMS, htokens[hook->type], filter->name,
              (array_ptr(config->filters, hook->filter_id))->name);
        return array_ptr(config->filters, hook->filter_id);
    }
#undef MESSAGE_PARAMS
#undef MESSAGE_FORMAT
}

static bool policy_process(client_t *pcy, const config_t *mconfig)
{
    query_context_t *context = client_data(pcy);
    const query_t* query = &context->query;
    const filter_t *filter;
    if (mconfig->entry_points[query->state] == -1) {
        warn("no filter defined for current protocol_state (%s)", smtp_state_names[query->state]);
        return false;
    }
    if (context->context.current_filter != NULL) {
        filter = context->context.current_filter;
    } else {
        filter = array_ptr(mconfig->filters, mconfig->entry_points[query->state]);
    }
    context->context.current_filter = NULL;
    while (true) {
        bool  ok = false;
        const filter_hook_t *hook = filter_run(filter, query, &context->context);
        filter = next_filter(pcy, filter, query, hook, &ok);
        if (filter == NULL) {
            return ok;
        }
    }
}

static int policy_run(client_t *pcy, void* vconfig)
{
    const config_t *mconfig = vconfig;
    if (refresh) {
        array_add(busy, pcy);
        return 0;
    }

    query_context_t *context = client_data(pcy);
    query_t         *query   = &context->query;
    context->client = pcy;

    buffer_t *buf   = client_input_buffer(pcy);
    int search_offs = MAX(0, (int)(buf->len - 1));
    int nb          = client_read(pcy);
    const char *eoq;

    if (nb < 0) {
        if (errno == EAGAIN || errno == EINTR)
            return 0;
        UNIXERR("read");
        return -1;
    }
    if (nb == 0) {
        if (buf->len)
            err("unexpected end of data");
        return -1;
    }

    if (!(eoq = strstr(buf->data + search_offs, "\n\n"))) {
        return 0;
    }

    if (!query_parse(query, buf->data)) {
        return -1;
    }
    query->eoq = eoq + strlen("\n\n");

    /* The instance changed => reset the static context */
    if (query->instance == NULL || strcmp(context->context.instance, query->instance) != 0) {
        filter_context_clean(&context->context);
        m_strcat(context->context.instance, 64, query->instance);
    }
    client_io_none(pcy);
    return policy_process(pcy, mconfig) ? 0 : -1;
}

static void policy_async_handler(filter_context_t *context,
                                 const filter_hook_t *hook)
{
    bool ok = false;
    const filter_t *filter = context->current_filter;
    query_context_t *qctx  = context->data;
    query_t         *query = &qctx->query;
    client_t        *server = qctx->client;

    context->current_filter = next_filter(server, filter, query, hook, &ok);
    if (context->current_filter != NULL) {
        ok = policy_process(server, config);
    }
    if (!ok) {
        client_release(server);
    }
    if (refresh && filter_running == 0) {
        config_refresh(config);
    }
}

static int postlicyd_init(void)
{
    filter_async_handler_register(policy_async_handler);
    return 0;
}

static void postlicyd_shutdown(void)
{
    array_deep_wipe(busy, client_delete);
}
module_init(postlicyd_init);
module_exit(postlicyd_shutdown);

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

    if (!daemonize) {
        log_syslog = false;
    }

    if (argc - optind != 1) {
        usage();
        return EXIT_FAILURE;
    }

    info("%s v%s...", DAEMON_NAME, DAEMON_VERSION);

    if (pidfile_open(pidfile) < 0) {
        crit("unable to write pidfile %s", pidfile);
        return EXIT_FAILURE;
    }

    if (drop_privileges(RUNAS_USER, RUNAS_GROUP) < 0) {
        crit("unable to drop privileges");
        return EXIT_FAILURE;
    }

    config = config_read(argv[optind]);
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

    if (start_listener(config->port) == NULL) {
        return EXIT_FAILURE;
    } else {
        return server_loop(query_starter, query_stopper,
                           policy_run, config_refresh, config);
    }
}
