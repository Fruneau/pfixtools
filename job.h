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

enum job_mode {
    JOB_IDLE   = 0x00,
    JOB_READ   = 0x01,
    JOB_WRITE  = 0x02,
    JOB_RDWR   = JOB_READ | JOB_WRITE,
    JOB_LISTEN = 0x04,
    JOB_CONN   = 0x08,
};

typedef struct jpriv_t jpriv_t;
typedef struct job_t {
    unsigned mode  :  6; /* 4 are enough, 2 used as padding */
    unsigned done  :  1;
    unsigned error :  1;
    unsigned state : 24;

    int fd;

    void (*process)(struct job_t *);
    void (*stop)(struct job_t *);

    jpriv_t *jdata;
} job_t;

static inline job_t *job_new(void) {
    job_t *job = p_new(job_t, 1);
    job->fd = -1;
    return job;
}
void job_delete(job_t **job);

void job_update_mode(job_t *job, int mode);
job_t *job_accept(job_t *listener, int mode);

void job_initialize(void);
void job_loop(void);
void job_shutdown(void);

#endif
