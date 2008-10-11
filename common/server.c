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
#include "epoll.h"
#include "common.h"

static PA(server_t) listeners   = ARRAY_INIT;
static PA(server_t) server_pool = ARRAY_INIT;

static server_t* server_new(void)
{
    server_t* server = p_new(server_t, 1);
    server->fd  = -1;
    return server;
}

static void server_wipe(server_t *server)
{
    server->listener = false;
    if (server->fd >= 0) {
        epoll_unregister(server->fd);
        close(server->fd);
        server->fd = -1;
    }
    if (server->data && server->clear_data) {
        server->clear_data(&server->data);
    }
}

static void server_delete(server_t **server)
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

static void server_shutdown(void)
{
    printf("Server shutdown");
    array_deep_wipe(listeners, server_delete);
    array_deep_wipe(server_pool, server_delete);
}

module_exit(server_shutdown);

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
    tmp->listener   = true;
    tmp->data       = data;
    tmp->run        = NULL;
    tmp->clear_data = deleter;
    epoll_register(sock, EPOLLIN, tmp);
    array_add(listeners, tmp);
    return 0;
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
    tmp->listener   = false;
    tmp->fd         = sock;
    tmp->data       = data;
    tmp->run        = runner;
    tmp->clear_data = deleter;
    epoll_register(sock, EPOLLIN, tmp);
    return 0;
}

server_t *server_register(int fd, run_client_t runner, void *data)
{
    if (fd < 0) {
        return NULL;
    }

    server_t *tmp   = server_acquire();
    tmp->listener   = false;
    tmp->fd         = fd;
    tmp->data       = data;
    tmp->run        = runner;
    tmp->clear_data = NULL;
    epoll_register(fd, EPOLLIN, tmp);
    return tmp;
}

int server_loop(start_client_t starter, delete_client_t deleter,
                run_client_t runner, refresh_t refresh, void* config)
{
    info("entering processing loop");
    while (!sigint) {
        struct epoll_event evts[1024];
        int n;

        if (sighup && refresh) {
            sighup = false;
            info("refreshing...");
            if (!refresh(config)) {
                crit("error while refreshing configuration");
                return EXIT_FAILURE;
            }
            info("refresh done, processing loop restarts");
        }

        n = epoll_select(evts, countof(evts), -1);
        if (n < 0) {
            if (errno != EAGAIN && errno != EINTR) {
                UNIXERR("epoll_wait");
                return EXIT_FAILURE;
            }
            continue;
        }

        while (--n >= 0) {
            server_t *d = evts[n].data.ptr;

            if (d->listener) {
                (void)start_client(d, starter, runner, deleter);
                continue;
            }

            if ((evts[n].events & EPOLLOUT) && d->obuf.len) {
                if (buffer_write(&d->obuf, d->fd) < 0) {
                    server_release(d);
                    continue;
                }
                if (!d->obuf.len) {
                    epoll_modify(d->fd, EPOLLIN, d);
                }
            }

            if (evts[n].events & EPOLLIN) {
                if (d->run(d, config) < 0) {
                    server_release(d);
                }
                continue;
            }
        }
    }
    info("exit requested");
    return EXIT_SUCCESS;
}
