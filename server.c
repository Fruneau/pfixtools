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

static server_t* server_new(void)
{
    server_t* server = p_new(server_t, 1);
    server->fd = -1;
    return server;
}

static void server_delete(server_t **server)
{
    if (*server) {
        if ((*server)->fd >= 0) {
            close((*server)->fd);
        }
        if ((*server)->data && (*server)->clear_data) {
            (*server)->clear_data(&(*server)->data);
        }
        buffer_wipe(&(*server)->ibuf);
        buffer_wipe(&(*server)->obuf);
        p_delete(server);
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

    tmp             = server_new();
    tmp->fd         = sock;
    tmp->listener   = true;
    tmp->data       = data;
    tmp->clear_data = deleter;
    epoll_register(sock, EPOLLIN, tmp);
    return 0;
}

static int start_client(server_t *server, start_client_t starter,
                        delete_client_t deleter)
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

    tmp             = server_new();
    tmp->fd         = sock;
    tmp->data       = data;
    tmp->clear_data = deleter;
    epoll_register(sock, EPOLLIN, tmp);
    return 0;
}

int server_loop(start_client_t starter, delete_client_t deleter,
                run_client_t runner, void* config) {
    while (!sigint) {
        struct epoll_event evts[1024];
        int n;

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
                (void)start_client(d, starter, deleter);
                continue;
            }

            if (evts[n].events & EPOLLIN) {
                if (runner(d, config) < 0) {
                    server_delete(&d);
                    continue;
                }
            }

            if ((evts[n].events & EPOLLOUT) && d->obuf.len) {
                if (buffer_write(&d->obuf, d->fd) < 0) {
                    server_delete(&d);
                    continue;
                }
                if (!d->obuf.len) {
                    epoll_modify(d->fd, EPOLLIN, d);
                }
            }
        }
    }
    return EXIT_SUCCESS;
}
