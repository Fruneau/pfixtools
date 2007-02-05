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

#ifndef POSTLICYD_JOB_H
#define POSTLICYD_JOB_H

#include "mem.h"

enum job_state {
    JOB_IDLE   = 0x00,
    JOB_READ   = 0x01,
    JOB_WRITE  = 0x02,
    JOB_RDWR   = 0x03,
    JOB_CONN   = 0x04,
    JOB_LISTEN = 0x08,
};

enum smtp_state {
    STATE_CONNECT,
    STATE_HELO, /* or EHLO */
    STATE_MAIL,
    STATE_RCPT,
    STATE_DATE,
    STATE_EOM,
    STATE_VRFY,
    STATE_ETRN,
};

typedef struct job_t   job_t;
typedef struct jpriv_t jpriv_t;

struct job_t {
    unsigned state : 6;
    unsigned done  : 1;
    unsigned error : 1;

    int fd;

    void (*process)(job_t *);
    void (*stop)(job_t *);

    jpriv_t *jdata;
};

static inline job_t *job_init(job_t *job) {
    p_clear(job, 1);
    job->fd = -1;
    return job;
}
DO_NEW(job_t, job);
void job_release(job_t **job);
void job_update_state(job_t *job, int state);
job_t *job_accept(job_t *listener, int state);

void job_initialize(void);
void job_loop(void);
void job_shutdown(void);

#endif
