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
#include <syslog.h>
#include <unistd.h>

#include "job.h"
#include "postfix.h"
#include "buffer.h"

struct jpriv_t {
    buffer_t ibuf;
    buffer_t obuf;
};

jpriv_t *postfix_jpriv_init(jpriv_t *jp)
{
    buffer_init(&jp->ibuf);
    buffer_init(&jp->obuf);
    return jp;
}
void postfix_jpriv_wipe(jpriv_t *jp)
{
    buffer_wipe(&jp->ibuf);
    buffer_wipe(&jp->obuf);
}
DO_NEW(jpriv_t, postfix_jpriv);
DO_DELETE(jpriv_t, postfix_jpriv);


void postfix_start(job_t *listener)
{
    job_t *job;

    job = job_accept(listener, JOB_READ);
    if (!job)
        return;

    job->jdata = postfix_jpriv_new();
}

void postfix_stop(job_t *job)
{
    postfix_jpriv_delete(&job->jdata);
}

void postfix_process(job_t *job)
{
    int nb;

    switch (job->state) {
      case JOB_LISTEN:
        return postfix_start(job);

      case JOB_WRITE:
        nb = write(job->fd, job->jdata->obuf.data, job->jdata->obuf.len);
        if (nb < 0) {
            if ((job->error = errno != EINTR && errno != EAGAIN)) {
                syslog(LOG_ERR, "unexpected problem on the socket: %m");
            }
            return;
        }

        buffer_consume(&job->jdata->obuf, nb);
        if (job->jdata->obuf.len)
            return;

        job_update_state(job, JOB_READ);

        /* fall through */

      case JOB_READ:
        nb = buffer_read(&job->jdata->ibuf, job->fd, -1);
        if (nb < 0) {
            if ((job->error = errno != EINTR && errno != EAGAIN)) {
                syslog(LOG_ERR, "unexpected problem on the socket: %m");
            }
            return;
        }
        if (nb == 0) {
            syslog(LOG_ERR, "unexpected eof");
            job->error = true;
            return;
        }

        if (!strstr(job->jdata->ibuf.data, "\r\n\r\n"))
            return;

        /* TODO: do the parse */
        job_update_state(job, JOB_IDLE);
        return;

      default:
        job->error = true;
        return;
    }
}
