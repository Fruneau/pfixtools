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
/*   Copyright (c) 2006-2009 the Authors                                      */
/*   see AUTHORS and source files for details                                 */
/******************************************************************************/

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

struct listener_t {
    server_io_t io;
};

struct client_t {
    server_io_t io;

    buffer_t ibuf;
    buffer_t obuf;

    run_client_t run;
    delete_client_t clear_data;
    void* data;
};


static PA(listener_t) listeners = ARRAY_INIT;
static PA(client_t) client_pool = ARRAY_INIT;

static struct ev_loop *gl_loop           = NULL;
static start_client_t  gl_client_start   = NULL;
static delete_client_t gl_client_delete  = NULL;
static run_client_t    gl_client_run     = NULL;
static refresh_t       gl_config_refresh = NULL;
static void           *gl_config         = NULL;


/* Server io structure methods.
 */

static inline void server_io_wipe(server_io_t *io)
{
    if (io->fd >= 0) {
        ev_io_stop(gl_loop, &io->io);
        close(io->fd);
        io->fd = -1;
    }
}


/* Client methods.
 */

/* 1 - managing clients */

static client_t* client_new(void)
{
    client_t* server = p_new(client_t, 1);
    server->io.fd  = -1;
    return server;
}

static void client_wipe(client_t *server)
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

void client_delete(client_t **server)
{
    if (*server) {
        buffer_wipe(&(*server)->ibuf);
        buffer_wipe(&(*server)->obuf);
        client_wipe(*server);
        p_delete(server);
    }
}

static client_t* client_acquire(void)
{
    if (client_pool.len != 0) {
        return array_pop_last(client_pool);
    } else {
        return client_new();
    }
}

void client_release(client_t *server)
{
    client_wipe(server);
    array_add(client_pool, server);
}

/* 2 - Doing I/O */

void client_io_none(client_t *server)
{
    ev_io_stop(gl_loop, &server->io.io);
}

void client_io_rw(client_t *server)
{
    ev_io_stop(gl_loop, &server->io.io);
    ev_io_set(&server->io.io, server->io.fd, EV_READ | EV_WRITE);
    ev_io_start(gl_loop, &server->io.io);
}

void client_io_ro(client_t *server)
{
    ev_io_stop(gl_loop, &server->io.io);
    ev_io_set(&server->io.io, server->io.fd, EV_READ);
    ev_io_start(gl_loop, &server->io.io);
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
    client_t *server = (client_t*)w;

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
        if (server->run(server, gl_config) < 0) {
            client_release(server);
            return;
        }
    }
}

client_t *client_register(int fd, run_client_t runner, void *data)
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
    ev_io_start(gl_loop, &tmp->io.io);
    return tmp;
}


/* Listeners management.
 */

/* 1 - Allocation */

static listener_t *listener_new(void)
{
    listener_t *io = p_new(listener_t, 1);
    io->io.fd = -1;
    return io;
}

static inline void listener_wipe(listener_t *io)
{
    server_io_wipe(&io->io);
}

static inline void listener_delete(listener_t **io)
{
    if (*io) {
        listener_wipe(*io);
        p_delete(io);
    }
}


/* 2 - Management */

static void listener_cb(EV_P_ struct ev_io *w, int events)
{
    listener_t *server = (listener_t*)w;
    client_t *tmp;
    void* data = NULL;
    int sock;

    sock = accept_nonblock(server->io.fd);
    if (sock < 0) {
        UNIXERR("accept");
        ev_unloop(EV_A_ EVUNLOOP_ALL);
        return;
    }

    if (gl_client_start) {
        data = gl_client_start(server);
        if (data == NULL) {
            close(sock);
            ev_unloop(EV_A_ EVUNLOOP_ALL);
            return;
        }
    }

    tmp             = client_acquire();
    tmp->io.fd      = sock;
    tmp->data       = data;
    tmp->run        = gl_client_run;
    tmp->clear_data = gl_client_delete;
    ev_io_init(&tmp->io.io, client_cb, tmp->io.fd, EV_READ);
    ev_io_start(gl_loop, &tmp->io.io);
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
    ev_io_start(gl_loop, &tmp->io.io);
    array_add(listeners, tmp);
    return tmp;
}




/* Server runtime stuff.
 */

static int server_init(void)
{
    gl_loop = ev_default_loop(0);
    return 0;
}

static void server_shutdown(void)
{
    array_deep_wipe(listeners, listener_delete);
    array_deep_wipe(client_pool, client_delete);
}
module_init(server_init);
module_exit(server_shutdown);


static void refresh_cb(EV_P_ struct ev_signal *w, int event)
{
    log_state = "refreshing ";
    if (!gl_config_refresh(gl_config)) {
        ev_unloop(EV_A_ EVUNLOOP_ALL);
        info("failed");
    } else {
        info("done");
    }
    log_state = "";
}

static void exit_cb(EV_P_ struct ev_signal *w, int event)
{
    ev_unloop(EV_A_ EVUNLOOP_ALL);
}

int server_loop(start_client_t starter, delete_client_t deleter,
                run_client_t runner, refresh_t refresh, void* config)
{
    struct ev_signal ev_sighup;
    struct ev_signal ev_sigint;
    struct ev_signal ev_sigterm;

    gl_client_start   = starter;
    gl_client_delete  = deleter;
    gl_client_run     = runner;
    gl_config_refresh = refresh;
    gl_config         = config;

    if (refresh != NULL) {
        ev_signal_init(&ev_sighup, refresh_cb, SIGHUP);
        ev_signal_start(gl_loop, &ev_sighup);
    }
    ev_signal_init(&ev_sigint, exit_cb, SIGINT);
    ev_signal_start(gl_loop, &ev_sigint);
    ev_signal_init(&ev_sigterm, exit_cb, SIGTERM);
    ev_signal_start(gl_loop, &ev_sigterm);

    log_state = "";
    info("entering processing loop");
    ev_loop(gl_loop, 0);
    info("exit requested");
    return EXIT_SUCCESS;
}

/* vim:set et sw=4 sts=4 sws=4: */
