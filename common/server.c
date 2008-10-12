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
 * Copyright © 2008 Florent Bruneau
 */

#include "server.h"
#include "common.h"

static PA(server_t) listeners   = ARRAY_INIT;
static PA(server_t) server_pool = ARRAY_INIT;

struct ev_loop *global_loop    = NULL;
static start_client_t  client_start   = NULL;
static delete_client_t client_delete  = NULL;
static run_client_t    client_run     = NULL;
static refresh_t       config_refresh = NULL;
static void           *config_ptr     = NULL;

static server_t* server_new(void)
{
    server_t* server = p_new(server_t, 1);
    server->fd  = -1;
    return server;
}

static void server_wipe(server_t *server)
{
    if (server->fd >= 0) {
        ev_io_stop(global_loop, &server->io);
        close(server->fd);
        server->fd = -1;
    }
    if (server->data && server->clear_data) {
        server->clear_data(&server->data);
    }
}

void server_delete(server_t **server)
{
    if (*server) {
        buffer_wipe(&(*server)->ibuf);
        buffer_wipe(&(*server)->obuf);
        server_wipe(*server);
        p_delete(server);
    }
}

static server_t* server_acquire(void)
{
    if (server_pool.len != 0) {
        return array_elt(server_pool, --server_pool.len);
    } else {
        return server_new();
    }
}

void server_release(server_t *server)
{
    server_wipe(server);
    array_add(server_pool, server);
}

static int server_init(void)
{
    global_loop = ev_default_loop(0);
    return 0;
}

static void server_shutdown(void)
{
    array_deep_wipe(listeners, server_delete);
    array_deep_wipe(server_pool, server_delete);
}
module_init(server_init);
module_exit(server_shutdown);

static void client_cb(EV_P_ struct ev_io *w, int events)
{
    server_t *server = (server_t*)w;

    debug("Entering client_cb for %p, %d (%d | %d)", w, events, EV_WRITE, EV_READ);

    if (events & EV_WRITE && server->obuf.len) {
        if (buffer_write(&server->obuf, server->fd) < 0) {
            server_release(server);
            return;
        }
        if (!server->obuf.len) {
            ev_io_set(&server->io, server->fd, EV_READ);
        }
    }

    if (events & EV_READ) {
        if (server->run(server, config_ptr) < 0) {
            server_release(server);
            return;
        }
    }
}

static int start_client(server_t *server, start_client_t starter,
                        run_client_t runner, delete_client_t deleter)
{
    server_t *tmp;
    void* data = NULL;
    int sock;

    sock = accept_nonblock(server->fd);
    if (sock < 0) {
        UNIXERR("accept");
        return -1;
    }

    if (starter) {
        data = starter(server);
        if (data == NULL) {
            close(sock);
            return -1;
        }
    }

    tmp             = server_acquire();
    tmp->fd         = sock;
    tmp->data       = data;
    tmp->run        = runner;
    tmp->clear_data = deleter;
    ev_io_init(&tmp->io, client_cb, tmp->fd, EV_READ);
    ev_io_start(global_loop, &tmp->io);
    return 0;
}

static void server_cb(EV_P_ struct ev_io *w, int events)
{
    server_t *server = (server_t*)w;
    if (start_client(server, client_start, client_run, client_delete) != 0) {
        ev_unloop(EV_A_ EVUNLOOP_ALL);
    }
}

int start_server(int port, start_listener_t starter, delete_client_t deleter)
{
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr   = { htonl(INADDR_LOOPBACK) },
    };
    server_t *tmp;
    void* data = NULL;
    int sock;

    addr.sin_port = htons(port);
    sock = tcp_listen_nonblock((const struct sockaddr *)&addr, sizeof(addr));
    if (sock < 0) {
        return -1;
    }

    if (starter) {
      data = starter();
      if (data == NULL) {
        close(sock);
        return -1;
      }
    }

    tmp             = server_acquire();
    tmp->fd         = sock;
    tmp->data       = data;
    tmp->run        = NULL;
    tmp->clear_data = deleter;
    ev_io_init(&tmp->io, server_cb, tmp->fd, EV_READ);
    ev_io_start(global_loop, &tmp->io);
    array_add(listeners, tmp);
    return 0;
}

server_t *server_register(int fd, run_client_t runner, void *data)
{
    if (fd < 0) {
        return NULL;
    }

    server_t *tmp   = server_acquire();
    tmp->fd         = fd;
    tmp->data       = data;
    tmp->run        = runner;
    tmp->clear_data = NULL;
    ev_io_init(&tmp->io, client_cb, tmp->fd, EV_READ);
    ev_io_start(global_loop, &tmp->io);
    return tmp;
}

static void refresh_cb(EV_P_ struct ev_signal *w, int event)
{
    if (!config_refresh(config_ptr)) {
        ev_unloop(EV_A_ EVUNLOOP_ALL);
    }
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

    client_start   = starter;
    client_delete  = deleter;
    client_run     = runner;
    config_refresh = refresh;
    config_ptr     = config;

    if (refresh != NULL) {
        ev_signal_init(&ev_sighup, refresh_cb, SIGHUP);
        ev_signal_start(global_loop, &ev_sighup);
    }
    ev_signal_init(&ev_sigint, exit_cb, SIGINT);
    ev_signal_start(global_loop, &ev_sigint);
    ev_signal_init(&ev_sigterm, exit_cb, SIGTERM);
    ev_signal_start(global_loop, &ev_sigterm);

    info("entering processing loop");
    ev_loop(global_loop, 0);
    info("exit requested");
    return EXIT_SUCCESS;
}
