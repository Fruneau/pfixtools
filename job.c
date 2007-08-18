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

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <syslog.h>
#include <sysexits.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef EPOLLRDHUP
#  include <linux/poll.h>
#  ifdef POLLRDHUP
#    define EPOLLRDHUP POLLRDHUP
#  else
#    define EPOLLRDHUP 0
#  endif
#endif

#include "job.h"

static int epollfd = -1;
static bool sigint = false;

void job_delete(job_t **job)
{
    if (*job) {
        if ((*job)->stop) {
            (*job)->stop(*job);
        }
        if ((*job)->fd >= 0) {
            close((*job)->fd);
        }
        p_delete(job);
    }
}

static job_t *job_register_fd(job_t *job)
{
    struct epoll_event event = { .data.ptr = job, .events = EPOLLRDHUP };

    if (job->mode & (JOB_READ | JOB_LISTEN)) {
        event.events |= EPOLLIN;
    }

    if (job->mode & (JOB_WRITE | JOB_CONN)) {
        event.events |= EPOLLOUT;
    }

    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, job->fd, &event) < 0) {
        syslog(LOG_ERR, "epoll_ctl error: %m");
        job->error = true;
        job_delete(&job);
    }

    return job;
}

void job_update_mode(job_t *job, int mode)
{
    struct epoll_event event = { .data.ptr = job, .events = EPOLLRDHUP };

    if (job->mode == mode)
        return;

    job->mode = mode;
    if (job->mode & (JOB_READ | JOB_LISTEN)) {
        event.events |= EPOLLIN;
    }

    if (job->mode & (JOB_WRITE | JOB_CONN)) {
        event.events |= EPOLLOUT;
    }

    if (epoll_ctl(epollfd, EPOLL_CTL_MOD, job->fd, &event) < 0) {
        syslog(LOG_ERR, "epoll_ctl error: %m");
        job->error = true;
    }
}

job_t *job_accept(job_t *listener, int mode)
{
    int sock;
    job_t *res;

    if ((sock = accept(listener->fd, NULL, 0)) < 0) {
        syslog(LOG_ERR, "accept error: %m");
        return NULL;
    }

    if (fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) | O_NONBLOCK)) {
        syslog(LOG_ERR, "fcntl error: %m");
        return NULL;
    }

    res          = job_new();
    res->fd      = sock;
    res->mode    = mode;
    res->process = listener->process;
    res->stop    = listener->stop;
    return job_register_fd(res);
}

static void job_sighandler(int sig)
{
    static time_t lastintr = 0;
    time_t now = time(NULL);

    switch (sig) {
      case SIGINT:
        if (sigint) {
            if (now - lastintr >= 1)
                break;
        } else {
            lastintr = now;
            sigint   = true;
        }
        return;

      case SIGTERM:
        break;

      default:
        return;
    }

    syslog(LOG_ERR, "Killed...");
    exit(-1);
}

void job_initialize(void)
{
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT,  &job_sighandler);
    signal(SIGTERM, &job_sighandler);

    epollfd = epoll_create(128);
    if (epollfd < 0) {
        syslog(LOG_ERR, "epoll_create error: %m");
        exit(EX_OSERR);
    }
}

void job_loop(void)
{
    while (!sigint) {
        struct epoll_event events[FD_SETSIZE];
        int todo = epoll_wait(epollfd, events, countof(events), -1);

        if (todo < 0) {
            if (errno == EAGAIN || errno == EINTR)
                continue;
            syslog(LOG_ERR, "epoll_wait error: %m");
            exit(EX_OSERR);
        }

        while (todo) {
            job_t *job = events[--todo].data.ptr;

            assert (job->process);
            job->process(job);

            if (job->error || job->done) {
                job_delete(&job);
            }
        }
    }
}

void job_shutdown(void)
{
    if (epollfd >= 0) {
        close(epollfd);
        epollfd = -1;
    }
}
