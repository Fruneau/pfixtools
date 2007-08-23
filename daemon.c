/******************************************************************************/
/*          postlicyd: a postfix policy daemon with a lot of features         */
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
 * Copyright © 2007 Pierre Habouzit
 */

#include <sys/un.h>

#include "postlicyd.h"
#include "daemon.h"

int tcp_listen(const struct sockaddr *addr, socklen_t len)
{
    int sock;

    switch (addr->sa_family) {
      case AF_UNIX:
        unlink(((struct sockaddr_un *)addr)->sun_path);
        sock = socket(PF_UNIX, SOCK_STREAM, 0);
        break;
      case AF_INET:
        sock = socket(PF_INET, SOCK_STREAM, 0);
        break;
      case AF_INET6:
        sock = socket(PF_INET6, SOCK_STREAM, 0);
        break;
      default:
        errno = EINVAL;
        return -1;
    }

    if (sock < 0) {
        UNIXERR("socket");
        return -1;
    }

    if (addr->sa_family != AF_UNIX) {
        int v = 1;
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v)) < 0) {
            UNIXERR("setsockopt(SO_REUSEADDR)");
            close(sock);
            return -1;
        }
    }

    if (bind(sock, addr, len) < 0) {
        UNIXERR("bind");
        close(sock);
        return -1;
    }

    if (listen(sock, 0) < 0) {
        UNIXERR("bind");
        close(sock);
        return -1;
    }

    return sock;
}

