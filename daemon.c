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
 * Copyright © 2007 Pierre Habouzit
 */

#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <sys/un.h>

#include "common.h"

static int setnonblock(int sock)
{
    int res = fcntl(sock, F_GETFL);

    if (res < 0) {
        UNIXERR("fcntl");
        return -1;
    }

    if (fcntl(sock, F_SETFL, res | O_NONBLOCK) < 0) {
        UNIXERR("fcntl");
        return -1;
    }

    return 0;
}


int tcp_listen_nonblock(const struct sockaddr *addr, socklen_t len)
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

    if (setnonblock(sock)) {
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

int accept_nonblock(int fd)
{
    int sock = accept(fd, NULL, 0);

    if (sock < 0) {
        UNIXERR("accept");
        return -1;
    }

    if (setnonblock(sock)) {
        close(sock);
        return -1;
    }

    return sock;
}

int daemon_detach(void)
{
    pid_t pid;

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    open("/dev/null", O_RDWR);
    open("/dev/null", O_RDWR);
    open("/dev/null", O_RDWR);

    pid = fork();
    if (pid < 0)
        return -1;
    if (pid)
        exit(0);

    setsid();
    return 0;
}

int drop_privileges(const char *user, const char *group)
{
    if (!geteuid()) {
        struct passwd *pw;
        struct group *gr;

        if (group) {
            gr = getgrnam(group);
            if (!gr)
                return -1;
            setgid(gr->gr_gid);
        }

        pw = getpwnam(user);
        if (!pw)
            return -1;
        if (!group) {
            setgid(pw->pw_gid);
        }
        setuid(pw->pw_uid);
    }

    return 0;
}
