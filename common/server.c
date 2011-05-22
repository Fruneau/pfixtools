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
 * Copyright © 2008 Florent Bruneau
 */

#include <ev.h>
#include "server.h"
#include "common.h"

typedef struct server_io_t {
    struct ev_io io;
    int fd;
} server_io_t;
#define server_of_io(s)  containerof(s, server_io_t, io);

struct listener_t {
    server_io_t io;
};
#define listener_of_io(l) ({                                                 \
        const server_io_t *__ser = server_of_io(l);                          \
        containerof(__ser, listener_t, io);                                  \
    })

struct client_t {
    server_io_t io;

    buffer_t ibuf;
    buffer_t obuf;

    run_client_f run;
    delete_client_f clear_data;
    void* data;
};
#define client_of_io(s)  ({                                                  \
        const server_io_t *__ser = server_of_io(s);                          \
        containerof(__ser, client_t, io);                                    \
    })


struct timeout_t {
    struct ev_timer timer;
    run_timeout_f run;
    void* data;
};
#define timeout_of_timer(t)  containerof(t, timeout_t, timer)

static struct {
    PA(listener_t)  listeners;
    PA(client_t)    client_pool;
    PA(timeout_t)   timeout_pool;

    struct ev_loop *loop;
    start_client_f  client_start;
    delete_client_f client_delete;
    run_client_f    client_run;
    refresh_f       config_refresh;
    void           *config;
} server_g;
#define _G  server_g

/* Server io structure methods.
 */

static inline void server_io_wipe(server_io_t *io)
{
    if (unlikely(_G.loop == NULL)) {
        return;
    }
    if (io->fd >= 0) {
        ev_io_stop(_G.loop, &io->io);
        close(io->fd);
        io->fd = -1;
    }
}


/* Client methods.
 */

/* 1 - managing clients */

static client_t *client_init(client_t *client)
{
    p_clear(client, 1);
    client->io.fd = -1;
    return client;
}
DO_NEW(client_t, client);

static void client_clear(client_t *server)
{
    server_io_wipe(&server->io);
    if (server->data && server->clear_data) {
        server->clear_data(&server->data);
    }
    server->obuf.len = 0;
    server->ibuf.len = 0;
    server->data = NULL;
    server->clear_data = NULL;
    server->run = NULL;
}

static void client_wipe(client_t *server)
{
    buffer_wipe(&server->ibuf);
    buffer_wipe(&server->obuf);
    client_clear(server);
}

void client_delete(client_t **client)
{
    if (*client) {
        client_wipe(*client);
        p_delete(client);
    }
}

static client_t *client_acquire(void)
{
    if (_G.client_pool.len != 0) {
        return array_pop_last(_G.client_pool);
    } else {
        return client_new();
    }
}

void client_release(client_t *server)
{
    client_clear(server);
    array_add(_G.client_pool, server);
}

/* 2 - Doing I/O */

void client_io_none(client_t *server)
{
    if (unlikely(_G.loop == NULL)) {
        return;
    }
    ev_io_stop(_G.loop, &server->io.io);
}

void client_io_rw(client_t *server)
{
    if (unlikely(_G.loop == NULL)) {
        return;
    }
    ev_io_stop(_G.loop, &server->io.io);
    ev_io_set(&server->io.io, server->io.fd, EV_READ | EV_WRITE);
    ev_io_start(_G.loop, &server->io.io);
}

void client_io_ro(client_t *server)
{
    if (unlikely(_G.loop == NULL)) {
        return;
    }
    ev_io_stop(_G.loop, &server->io.io);
    ev_io_set(&server->io.io, server->io.fd, EV_READ);
    ev_io_start(_G.loop, &server->io.io);
}

ssize_t client_read(client_t *client)
{
    return buffer_read(&client->ibuf, client->io.fd, -1);
}

buffer_t *client_input_buffer(client_t *client)
{
    return &client->ibuf;
}

buffer_t *client_output_buffer(client_t *client)
{
    return &client->obuf;
}

void *client_data(client_t *client)
{
    return client->data;
}


static void client_cb(EV_P_ struct ev_io *w, int events)
{
    client_t *server = client_of_io(w);

    if (events & EV_WRITE && server->obuf.len) {
        if (buffer_write(&server->obuf, server->io.fd) < 0) {
            client_release(server);
            return;
        }
        if (!server->obuf.len) {
            client_io_ro(server);
        }
    }

    if (events & EV_READ) {
        if (server->run(server, _G.config) < 0) {
            client_release(server);
            return;
        }
    }
}

client_t *client_register(int fd, run_client_f runner, void *data)
{
    if (fd < 0) {
        return NULL;
    }

    client_t *tmp   = client_acquire();
    tmp->io.fd      = fd;
    tmp->data       = data;
    tmp->run        = runner;
    tmp->clear_data = NULL;
    ev_io_init(&tmp->io.io, client_cb, tmp->io.fd, EV_READ);
    ev_io_start(_G.loop, &tmp->io.io);
    return tmp;
}


/* Listeners management.
 */

/* 1 - Allocation */

static listener_t *listener_init(listener_t *l)
{
    p_clear(l, 1);
    l->io.fd = -1;
    return l;
}
DO_NEW(listener_t, listener);

static inline void listener_wipe(listener_t *io)
{
    server_io_wipe(&io->io);
}
DO_DELETE(listener_t, listener);


/* 2 - Management */

static void listener_cb(EV_P_ struct ev_io *w, int events)
{
    listener_t *server = listener_of_io(w);
    client_t *tmp;
    void* data = NULL;
    int sock;

    sock = accept_nonblock(server->io.fd);
    if (sock < 0) {
        UNIXERR("accept");
        ev_unloop(EV_A_ EVUNLOOP_ALL);
        return;
    }

    if (_G.client_start) {
        data = _G.client_start(server);
        if (data == NULL) {
            close(sock);
            ev_unloop(EV_A_ EVUNLOOP_ALL);
            return;
        }
    }

    tmp             = client_acquire();
    tmp->io.fd      = sock;
    tmp->data       = data;
    tmp->run        = _G.client_run;
    tmp->clear_data = _G.client_delete;
    ev_io_init(&tmp->io.io, client_cb, tmp->io.fd, EV_READ);
    ev_io_start(_G.loop, &tmp->io.io);
}

listener_t *start_listener(int port)
{
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr   = { htonl(INADDR_LOOPBACK) },
    };
    listener_t *tmp;
    int sock;

    addr.sin_port = htons(port);
    sock = tcp_listen_nonblock((const struct sockaddr *)&addr, sizeof(addr));
    if (sock < 0) {
        return NULL;
    }

    tmp             = listener_new();
    tmp->io.fd      = sock;
    ev_io_init(&tmp->io.io, listener_cb, tmp->io.fd, EV_READ);
    ev_io_start(_G.loop, &tmp->io.io);
    array_add(_G.listeners, tmp);
    return tmp;
}



/* Timers
 */

DO_INIT(timeout_t, timeout);
DO_NEW(timeout_t, timeout);

static void timeout_wipe(timeout_t *timer)
{
    ev_timer_stop(_G.loop, &timer->timer);
}
DO_DELETE(timeout_t, timeout);


static void timeout_release(timeout_t *timer)
{
    timeout_wipe(timer);
    array_add(_G.timeout_pool, timer);
}

static void timeout_cb(EV_P_ struct ev_timer *w, int revents)
{
    timeout_t *timer = timeout_of_timer(w);
    run_timeout_f run = timer->run;
    void* data = timer->data;
    timeout_release(timer);

    if (run) {
        run(data);
    }
}

timeout_t *start_timer(int milliseconds, run_timeout_f runner, void *data)
{
    timeout_t *timer = NULL;
    float timeout = ((float)milliseconds) / 1000.;
    if (array_len(_G.timeout_pool) > 0) {
        timer = array_pop_last(_G.timeout_pool);
        ev_timer_set(&timer->timer, timeout, 0.);
    } else {
        timer = timeout_new();
        ev_timer_init(&timer->timer, timeout_cb, timeout, 0.);
    }
    timer->run = runner;
    timer->data = data;
    ev_timer_start(_G.loop, &timer->timer);
    return timer;
}

void timer_cancel(timeout_t *timer)
{
    timeout_release(timer);
}



/* Server runtime stuff.
 */

static int server_init(void)
{
    _G.loop = ev_default_loop(0);
    return 0;
}

static void server_shutdown(void)
{
    array_deep_wipe(_G.listeners, listener_delete);
    array_deep_wipe(_G.client_pool, client_delete);
    array_deep_wipe(_G.timeout_pool, timeout_delete);
    if (daemon_process) {
        ev_default_destroy();
        _G.loop = NULL;
    }
}
module_init(server_init);
module_exit(server_shutdown);


static void refresh_cb(EV_P_ struct ev_signal *w, int event)
{
    log_state = "refreshing ";
    if (!_G.config_refresh(_G.config)) {
        ev_unloop(EV_A_ EVUNLOOP_ALL);
        notice("failed");
    } else {
        notice("done");
    }
    log_state = "";
}

static void exit_cb(EV_P_ struct ev_signal *w, int event)
{
    ev_unloop(EV_A_ EVUNLOOP_ALL);
}

int server_loop(start_client_f starter, delete_client_f deleter,
                run_client_f runner, refresh_f refresh, void *config)
{
    struct ev_signal ev_sighup;
    struct ev_signal ev_sigint;
    struct ev_signal ev_sigterm;

    _G.client_start   = starter;
    _G.client_delete  = deleter;
    _G.client_run     = runner;
    _G.config_refresh = refresh;
    _G.config         = config;

    if (refresh != NULL) {
        ev_signal_init(&ev_sighup, refresh_cb, SIGHUP);
        ev_signal_start(_G.loop, &ev_sighup);
    }
    ev_signal_init(&ev_sigint, exit_cb, SIGINT);
    ev_signal_start(_G.loop, &ev_sigint);
    ev_signal_init(&ev_sigterm, exit_cb, SIGTERM);
    ev_signal_start(_G.loop, &ev_sigterm);

    log_state = "";
    notice("entering processing loop");
    ev_loop(_G.loop, 0);
    notice("exit requested");
    return EXIT_SUCCESS;
}

/* vim:set et sw=4 sts=4 sws=4: */
