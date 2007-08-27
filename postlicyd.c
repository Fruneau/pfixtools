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

#include <signal.h>
#include <time.h>
#include <getopt.h>

#include "common.h"

static sig_atomic_t cleanexit = false;
static sig_atomic_t sigint    = false;
static volatile int nbthreads = 0;

static void main_sighandler(int sig)
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

static void main_initialize(void)
{
    openlog("postlicyd", LOG_PID, LOG_MAIL);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT,  &main_sighandler);
    signal(SIGTERM, &main_sighandler);
    syslog(LOG_INFO, "Starting...");
}

void *job_run(void *_fd)
{
    int fd = (intptr_t)_fd;

    close(fd);
    return NULL;
}

static void main_loop(void)
{
    int sock = -1;

    while (!sigint) {
        int fd = accept(sock, NULL, 0);
        pthread_attr_t attr;
        pthread_t dummy;

        if (fd < 0) {
            if (errno != EINTR || errno != EAGAIN)
                UNIXERR("accept");
            continue;
        }

        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        pthread_create(&dummy, &attr, job_run, (void *)(intptr_t)fd);
        pthread_attr_destroy(&attr);
    }

    cleanexit = true;
    close(sock);
}

static void main_shutdown(void)
{
    syslog(LOG_INFO, cleanexit ? "Stopping..." : "Unclean exit...");
    closelog();
}

int main(void)
{
    if (atexit(main_shutdown)) {
        fputs("Cannot hook my atexit function, quitting !\n", stderr);
        return EXIT_FAILURE;
    }

    main_initialize();
    main_loop();
    main_shutdown();
    return EXIT_SUCCESS;
}
