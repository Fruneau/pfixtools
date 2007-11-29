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

#include "threads.h"

static struct {
    pthread_spinlock_t spin;
    pthread_t *deads;
    int count, size;
} morgue;

struct thread_foo {
    void *(*fun)(int fd, void *);
    int fd;
    void *data;
};

void thread_register_dead(void *tid)
{
    pthread_spin_lock(&morgue.spin);
    if (morgue.count >= morgue.size) {
        p_allocgrow(&morgue.deads, morgue.count + 1, &morgue.size);
    }
    morgue.deads[morgue.count++] = (pthread_t)tid;
    pthread_spin_unlock(&morgue.spin);
}

static void *thread_wrapper(void *arg)
{
    struct thread_foo *foo = arg;
    void *res;
    pthread_cleanup_push(thread_register_dead, (void *)pthread_self());
    res = (*foo->fun)(foo->fd, foo->data);
    pthread_cleanup_pop(1);
    return res;
}

int thread_launch(void *(*f)(int, void *), int fd, void *data)
{
    struct thread_foo foo = { f, fd, data };
    pthread_t t;
    return pthread_create(&t, NULL, &thread_wrapper, &foo);
}

void threads_join(void)
{
    if (!morgue.count)
        return;

    pthread_spin_lock(&morgue.spin);
    while (morgue.count-- > 0) {
        pthread_join(morgue.deads[morgue.count], NULL);
    }
    pthread_spin_unlock(&morgue.spin);
}


static int threads_initialize(void)
{
    pthread_spin_init(&morgue.spin, PTHREAD_PROCESS_PRIVATE);
    return 0;
}

static void threads_shutdown(void)
{
    pthread_spin_destroy(&morgue.spin);
}

module_init(threads_initialize);
module_exit(threads_shutdown);
