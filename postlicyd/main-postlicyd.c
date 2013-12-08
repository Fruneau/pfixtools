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

/*
 * Copyright © 2006-2007 Pierre Habouzit
 * Copyright © 2008 Florent Bruneau
 */

#include <getopt.h>

#include "buffer.h"
#include "common.h"

#include <srs2.h>

#include "policy_tokens.h"
#include "server.h"
#include "config.h"
#include "query.h"

#define DAEMON_NAME             "postlicyd"
#define DAEMON_VERSION          PFIXTOOLS_VERSION
#define DEFAULT_PORT            10000
#define DEFAULT_RUNAS_USER      NOBODY_USER
#define DEFAULT_RUNAS_GROUP     NOGROUP_GROUP

DECLARE_MAIN

typedef struct query_context_t {
    query_t query;
    filter_context_t context;
    client_t *client;
} query_context_t;

static struct {
    config_t *config;
    bool      refresh;
    PA(client_t) busy;
} postlicyd_g;
#define _G  postlicyd_g

static void *query_starter(listener_t *server)
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
    _G.refresh = true;
    if (filter_running_g > 0) {
        return true;
    }
    log_state = "refreshing ";
    notice("reloading configuration");
    bool ret = config_reload(mconfig);
    log_state = "";
    foreach (server, _G.busy) {
        client_io_ro(*server);
    }
    array_len(_G.busy) = 0;
    _G.refresh = false;
    return ret;
}

static void policy_answer(client_t *pcy, const char *message)
{
    query_context_t *context = client_data(pcy);
    const query_t *query = &context->query;
    buffer_t *buf = client_output_buffer(pcy);

    /* Write reply "action=ACTION [text]" */
    buffer_addstr(buf, "action=");
    if (!query_format_buffer(buf, message, query)) {
        buffer_addstr(buf, message);
    }
    if (_G.config->include_explanation) {
        const clstr_t *exp = &context->context.explanation;
        if (exp->len > 0) {
            buffer_addstr(buf, ": ");
            buffer_add(buf, exp->str, exp->len);
        }
    }
    buffer_addstr(buf, "\n\n");

    /* Finalize query. */
    buf = client_input_buffer(pcy);
    buffer_consume(buf, query->eoq - buf->data);
    client_io_rw(pcy);
}

static const filter_t *next_filter(client_t *pcy, const filter_t *filter,
                                   const query_t *query,
                                   const filter_hook_t *hook, bool *ok)
{
    char log_prefix[BUFSIZ];
    log_prefix[0] = '\0';

#define log_reply(Level, Msg, ...)                                           \
    if (log_level >= LOG_ ## Level) {                                        \
        if (log_prefix[0] == '\0') {                                         \
            query_format(log_prefix, BUFSIZ,                                 \
                         _G.config->log_format && _G.config->log_format[0] ? \
                         _G.config->log_format : DEFAULT_LOG_FORMAT, query); \
        }                                                                    \
        __log(LOG_ ## Level, "%s: " Msg, log_prefix, ##__VA_ARGS__);         \
    }

    if (hook != NULL) {
        query_context_t *context = client_data(pcy);
        if (hook->counter >= 0 && hook->counter < MAX_COUNTERS
            && hook->cost > 0) {
            context->context.counters[hook->counter] += hook->cost;
            log_reply(DEBUG, "added %d to counter %d (now %u)",
                      hook->cost, hook->counter,
                      context->context.counters[hook->counter]);
        }
        if (hook->warn != NULL) {
            query_format(log_prefix, BUFSIZ, hook->warn, query);
            warn("user warning for filter %s: %s", filter->name, log_prefix);
            log_prefix[0] = '\0';
        }
    }
    if (hook == NULL) {
        log_reply(WARNING, "aborted");
        *ok = false;
        return NULL;
    } else if (hook->async) {
        log_reply(DEBUG, "asynchronous filter from filter %s", filter->name);
        *ok = true;
        return NULL;
    } else if (hook->postfix) {
        log_reply(NOTICE, "answer %s from filter %s: \"%s\"",
                  htokens[hook->type], filter->name, hook->value);
        policy_answer(pcy, hook->value);
        *ok = true;
        return NULL;
    } else {
        log_reply(DEBUG, "answer %s from filter %s: next filter %s",
                  htokens[hook->type], filter->name,
                  (array_ptr(_G.config->filters, hook->filter_id))->name);
        return array_ptr(_G.config->filters, hook->filter_id);
    }
#undef log_reply
}

static bool policy_process(client_t *pcy, const config_t *mconfig)
{
    query_context_t *context = client_data(pcy);
    const query_t *query = &context->query;
    const filter_t *filter;
    if (mconfig->entry_points[query->state] == -1) {
        warn("no filter defined for current protocol_state (%s)",
             smtp_state_names_g[query->state].str);
        return false;
    }
    if (context->context.current_filter != NULL) {
        filter = context->context.current_filter;
    } else {
        filter = array_ptr(mconfig->filters,
                           mconfig->entry_points[query->state]);
    }
    context->context.current_filter = NULL;
    while (true) {
        bool  ok = false;
        const filter_hook_t *hook = filter_run(filter, query,
                                               &context->context);
        filter = next_filter(pcy, filter, query, hook, &ok);
        if (filter == NULL) {
            return ok;
        }
    }
}

static int policy_run(client_t *pcy, void* vconfig)
{
    const config_t *mconfig = vconfig;
    if (_G.refresh) {
        array_add(_G.busy, pcy);
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
    if (query->instance.str == NULL || query->instance.len == 0
        || strcmp(context->context.instance, query->instance.str) != 0) {
        filter_context_clean(&context->context);
        m_strcat(context->context.instance, 64, query->instance.str);
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
        ok = policy_process(server, _G.config);
    }
    if (!ok) {
        client_release(server);
    }
    if (_G.refresh && filter_running_g == 0) {
        config_refresh(_G.config);
    }
}

static int postlicyd_init(void)
{
    filter_async_handler_register(policy_async_handler);
    return 0;
}

static void postlicyd_shutdown(void)
{
    array_deep_wipe(_G.busy, client_delete);
}
module_init(postlicyd_init);
module_exit(postlicyd_shutdown);

/* administrivia {{{ */

static void usage(void)
{
    fputs("usage: "DAEMON_NAME" [options] config\n"
          "\n"
          "If neither -l or -L are specified and the configuration file also does not contain any port\n"
          "or socketfile directives, the default will be to listen on tcp port "STR(DEFAULT_PORT)".\n"
          "\n"
          "Options:\n"
          "    -l|--port <port>              port to listen to, overrides configuration\n"
          "    -L|--socketfile <file>        unix socket to listen to, overrides configuration\n"
          "    -c|--check-conf               only check configuration\n"
          COMMON_DAEMON_OPTION_HELP,
          stderr);
}

/* }}} */

int main(int argc, char *argv[])
{
    COMMON_DAEMON_OPTION_PARAMS;
    int port = DEFAULT_PORT;
    bool port_from_cli = false;
    const char *socketfile = NULL;
    bool check_conf = false;

    struct option longopts[] = {
        COMMON_DAEMON_OPTION_LIST,
        { "check-conf", no_argument, NULL, 'c' },
        { "port", required_argument, NULL, 'l' },
        { "socketfile", required_argument, NULL, 'L' },
        { NULL, 0, NULL, 0 }
    };

    for (int c = 0; (c = getopt_long(argc, argv,
                                     COMMON_DAEMON_OPTION_SHORTLIST "cl:L:",
                                     longopts, NULL)) >= 0;) {
        switch (c) {
          case 'l':
            port = atoi(optarg);
            port_from_cli = true;
            break;
          case 'L':
            socketfile = optarg;
            break;
          case 'c':
            check_conf = true;
            daemonize  = false;
            unsafe     = true;
            break;
          COMMON_DAEMON_OPTION_CASES
        }
    }

    if (argc - optind != 1) {
        usage();
        return EXIT_FAILURE;
    }

    // Sockaddr_un cannot store more than 107 characters (it is char[108])
    if (socketfile && strlen(socketfile) > 107) {
        fputs("The socketfile specified for -L cannot be more than 107 characters in length\n\n", stderr);
        usage();
        return EXIT_FAILURE;
    }

    if (check_conf) {
        // Just to make sure we read the config file as if we were run normally
        if (!unsafe) {
            if (drop_privileges(user, group) < 0) {
                crit("unable to drop privileges");
                return EXIT_FAILURE;
            }
        }
        return config_check(argv[optind]) ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    notice("%s v%s...", DAEMON_NAME, DAEMON_VERSION);

    // Fail on memory
    srs_set_malloc( xmalloc_unsigned, xrealloc_unsigned, free );

    if ( user == NULL )
        user = DEFAULT_RUNAS_USER;
    if ( group == NULL )
        user = DEFAULT_RUNAS_GROUP;

    if (pidfile_open(pidfile) < 0) {
        crit("unable to write pidfile %s", pidfile);
        return EXIT_FAILURE;
    }

    if (!unsafe) {
        if (drop_privileges(user, group) < 0) {
            crit("unable to drop privileges");
            return EXIT_FAILURE;
        }
    }

    _G.config = config_read(argv[optind]);
    if (_G.config == NULL) {
        return EXIT_FAILURE;
    }

    // If we specified socketfile on cmd line, override what's in config
    if (socketfile) {
        p_delete(&_G.config->socketfile);
        _G.config->socketfile = strdup(socketfile);
    }

    // If we specified port on cmd line, override what's in config if it's there
    // If it's not in config, set it anyway so it sets to default, but only if we didn't specify a socketfile
    if (port_from_cli || (!_G.config->port_present && !_G.config->socketfile)) {
        _G.config->port = port;
        _G.config->port_present = true;
    }

    if (daemonize && daemon_detach() < 0) {
        crit("unable to fork");
        return EXIT_FAILURE;
    }

    pidfile_refresh();

    if (_G.config->socketfile) {
        if (start_unix_listener(_G.config->socketfile) == NULL)
            return EXIT_FAILURE;
    }

    if (_G.config->port_present) {
        if (start_tcp_listener(_G.config->port) == NULL)
            return EXIT_FAILURE;
    }

    int ret = server_loop(query_starter, query_stopper, policy_run, config_refresh, _G.config);

    // Cleanup socket file
    if (_G.config->socketfile) {
        unlink(_G.config->socketfile);
    }

    return ret;
}

/* vim:set et sw=4 sts=4 sws=4: */
