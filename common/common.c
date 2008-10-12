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
 * Copyright © 2008 Florent Bruneau
 */

#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <sys/un.h>

#include "common.h"

bool daemon_process  = true;
int  log_level       = LOG_INFO;
bool log_syslog      = false;

static FILE *pidfile = NULL;

void common_sighandler(int sig)
{
    switch (sig) {
      default:
        err("Killed (got signal %d)...", sig);
        exit(-1);
    }
}

int setnonblock(int sock)
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

int tcp_bind(const struct sockaddr *addr, socklen_t len)
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

    return sock;
}

int tcp_listen(const struct sockaddr *addr, socklen_t len)
{
    int sock = tcp_bind(addr, len);
    if (listen(sock, 0) < 0) {
        UNIXERR("bind");
        close(sock);
        return -1;
    }
    return sock;
}

int tcp_listen_nonblock(const struct sockaddr *addr, socklen_t len)
{
    int sock = tcp_bind(addr, len);
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

int xwrite(int fd, const char *s, size_t l)
{
    while (l > 0) {
        int nb = write(fd, s, l);
        if (nb < 0) {
            if (errno == EINTR || errno == EAGAIN)
                continue;
            return -1;
        }
        l -= nb;
    }
    return 0;
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
    if (pid < 0) {
        return -1;
    }
    if (pid) {
        daemon_process = false;
        exit(0);
    }

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

int pidfile_open(const char *name)
{
    if (name) {
        pidfile = fopen(name, "w");
        if (!pidfile)
            return -1;
        fprintf(pidfile, "%d\n", getpid());
        return fflush(pidfile);
    }
    return 0;
}

int pidfile_refresh(void)
{
    if (pidfile) {
        rewind(pidfile);
        ftruncate(fileno(pidfile), 0);
        fprintf(pidfile, "%d\n", getpid());
        return fflush(pidfile);
    }
    return 0;
}

static void pidfile_close(void)
{
    if (pidfile) {
        if (daemon_process) {
            rewind(pidfile);
            ftruncate(fileno(pidfile), 0);
        }
        fclose(pidfile);
        pidfile = NULL;
    }
}

int common_setup(const char* pidfilename, bool unsafe, const char* runas_user,
                 const char* runas_group, bool daemonize)
{
    if (pidfile_open(pidfilename) < 0) {
        crit("unable to write pidfile %s", pidfilename);
        return EXIT_FAILURE;
    }

    if (!unsafe && drop_privileges(runas_user, runas_group) < 0) {
        crit("unable to drop privileges");
        return EXIT_FAILURE;
    }

    if (daemonize && daemon_detach() < 0) {
        crit("unable to fork");
        return EXIT_FAILURE;
    }

    pidfile_refresh();
    return EXIT_SUCCESS;
}

extern initcall_t __madinit[];
extern exitcall_t __madexit[];

static void common_shutdown(void)
{
    if (daemon_process && log_syslog) {
        info("stopping...");
    }
    pidfile_close();
    for (int i = -1; __madexit[i]; i--) {
        (*__madexit[i])();
    }
}

static void __attribute__((__constructor__,__used__))
common_initialize(void)
{
    if (atexit(common_shutdown)) {
        fputs("Cannot hook my atexit function, quitting !\n", stderr);
        abort();
    }

    for (int i = 0; __madinit[i]; i++) {
        if ((*__madinit[i])()) {
            exit(EXIT_FAILURE);
        }
    }
}

