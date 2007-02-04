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

#include <fcntl.h>
#include <stdbool.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
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

static int epollfd;

static void job_wipe(job_t *job)
{
    if (job->fd >= 0) {
        close(job->fd);
        job->fd = -1;
    }
}
DO_DELETE(job_t, job);

void job_release(job_t **job)
{
    if (*job) {
        if ((*job)->task && (*job)->task->stop) {
            (*job)->task->stop(*job);
        }
        job_delete(job);
    }
}

static job_t *job_register_fd(job_t *job)
{
    struct epoll_event event = { .data.ptr = job, .events = EPOLLRDHUP };

    if (job->state & JOB_READ || job->state & JOB_LISTEN) {
        event.events |= EPOLLIN;
    }

    if (job->state & JOB_WRITE || job->state & JOB_CONN) {
        event.events |= EPOLLIN;
    }

    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, job->fd, &event) < 0) {
        job->error = true;
        job_release(&job);
    }

    return job;
}

void job_update_events(job_t *job)
{
    struct epoll_event event = { .data.ptr = job, .events = EPOLLRDHUP };

    if (job->state & JOB_READ || job->state & JOB_LISTEN) {
        event.events |= EPOLLIN;
    }

    if (job->state & JOB_WRITE || job->state & JOB_CONN) {
        event.events |= EPOLLIN;
    }

    epoll_ctl(epollfd, EPOLL_CTL_MOD, job->fd, &event);
}

job_t *job_accept(job_t *listener, int state)
{
    int sock;
    job_t *res;

    if ((sock = accept(listener->fd, NULL, 0)) < 0) {
        return NULL;
    }

    if (fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) | O_NONBLOCK)) {
        return NULL;
    }

    res        = job_new();
    res->fd    = sock;
    res->state = state;
    res->task  = listener->task;
    return job_register_fd(res);
}
