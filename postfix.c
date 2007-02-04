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
 * Copyright © 2006-2007 Pierre Habouzit
 */

#include <errno.h>
#include <stdbool.h>
#include <unistd.h>

#include "job.h"
#include "postfix.h"

struct jpriv_t {
    buffer_t ibuf;
    buffer_t obuf;
};

void postfix_start(job_t *job, query_t *query)
{
}

void postfix_stop(job_t *job)
{
}

void postfix_process(job_t *job)
{
    if (job->state & JOB_LISTEN) {
        /* TODO check return code */
        job_accept(job, JOB_READ);
    }

    if (job->state & JOB_WRITE) {
        int nbwritten;

        nbwritten = write(job->fd, job->jdata->obuf.data, job->jdata->obuf.len);
        if (nbwritten < 0) {
            job->error = errno != EINTR && errno != EAGAIN;
            return;
        }

        buffer_consume(&job->jdata->obuf, nbwritten);
    }

    if (job->state & JOB_READ) {
        int nbread;

        nbread = buffer_read(&job->jdata->ibuf, job->fd, -1);
        if (nbread < 0) {
            job->error = errno != EINTR && errno != EAGAIN;
            return;
        }
        if (nbread == 0) {
            job->error = true;
            return;
        }

        if (!strstr(job->jdata->ibuf.data, "\r\n\r\n"))
            return;

        job->state &= ~JOB_READ;

        /* TODO: do the parse */
    }
}
