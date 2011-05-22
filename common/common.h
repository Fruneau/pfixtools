/****************************************************************************/
/*          pfixtools: a collection of postfix related tools                */
/*          ~~~~~~~~~                                                       */
/*  ______________________________________________________________________  */
/*                                                                          */
/*  Redistribution and use in source and binary forms, with or without      */
/*  modification, are permitted provided that the following conditions      */
/*  are met:                                                                */
/*                                                                          */
/*  1. Redistributions of source code must retain the above copyright       */
/*     notice, this list of conditions and the following disclaimer.        */
/*  2. Redistributions in binary form must reproduce the above copyright    */
/*     notice, this list of conditions and the following disclaimer in      */
/*     the documentation and/or other materials provided with the           */
/*     distribution.                                                        */
/*  3. The names of its contributors may not be used to endorse or promote  */
/*     products derived from this software without specific prior written   */
/*     permission.                                                          */
/*                                                                          */
/*  THIS SOFTWARE IS PROVIDED BY THE CONTRIBUTORS ``AS IS'' AND ANY         */
/*  EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE       */
/*  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR      */
/*  PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE CONTRIBUTORS BE LIABLE   */
/*  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR            */
/*  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF    */
/*  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR         */
/*  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,   */
/*  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE    */
/*  OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,       */
/*  EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.                      */
/*                                                                          */
/*   Copyright (c) 2006-2011 the Authors                                    */
/*   see AUTHORS and source files for details                               */
/****************************************************************************/

/*
 * Copyright © 2007 Pierre Habouzit
 * Copyright © 2008 Florent Bruneau
 */

#ifndef PFIXTOOLS_COMMON_H
#define PFIXTOOLS_COMMON_H

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "mem.h"

#define PFIXTOOLS_VERSION "0.8"

#define __tostr(x)  #x
#define STR(x)      __tostr(x)

typedef int  (*initcall_f)(void);
typedef void (*exitcall_f)(void);

void common_register_exit(exitcall_f exitcall);
void common_init(void);

#define module_init(fn)                                                      \
    __attribute__((constructor,used))                                        \
    static void __init_wrapper__ ## fn (void) {                              \
        common_init();                                                       \
        if (fn() != 0) {                                                     \
            exit(-1);                                                        \
        }                                                                    \
    }
#define module_exit(fn)                                                      \
    __attribute__((constructor,used))                                        \
    static void __exit_wrapper ## fn(void) {                                 \
        common_init();                                                       \
        common_register_exit(fn);                                            \
    }

#define likely(expr)    __builtin_expect((expr) != 0, 1)
#define unlikely(expr)  __builtin_expect((expr) != 0, 0)

#define unused(expr)    { size_t t __attribute__((unused)) = expr; }

#define __level_name(L)                                                      \
    ((L) == LOG_DEBUG   ? "debug "                                           \
      : (L) == LOG_NOTICE  ? "notice"                                        \
      : (L) == LOG_INFO    ? "info  "                                        \
      : (L) == LOG_WARNING ? "warn  "                                        \
      : (L) == LOG_ERR     ? "error "                                        \
      : (L) == LOG_CRIT    ? "crit  "                                        \
      : (L) == LOG_ALERT   ? "alert "                                        \
      : "???   ")

#define __log(Level, Fmt, ...)                                               \
    if (log_level >= Level) {                                                \
        if (log_syslog) {                                                    \
            syslog(Level, "%s" Fmt, log_state, ##__VA_ARGS__);               \
        } else {                                                             \
            fprintf(stderr, "[%s] %s" Fmt "\n",                              \
                    __level_name(Level), log_state, ##__VA_ARGS__);          \
        }                                                                    \
    }

#define debug(Fmt, ...)  __log(LOG_DEBUG,   Fmt, ##__VA_ARGS__)
#define notice(Fmt, ...) __log(LOG_NOTICE,  Fmt, ##__VA_ARGS__)
#define info(Fmt, ...)   __log(LOG_INFO,    Fmt, ##__VA_ARGS__)
#define warn(Fmt, ...)   __log(LOG_WARNING, Fmt, ##__VA_ARGS__)
#define err(Fmt, ...)    __log(LOG_ERR,     Fmt, ##__VA_ARGS__)
#define crit(Fmt, ...)   __log(LOG_CRIT,    Fmt, ##__VA_ARGS__)
#define alert(Fmt, ...)  __log(LOG_ALERT,   Fmt, ##__VA_ARGS__)
#define emerg(Fmt, ...)  __log(LOG_ALERT,   Fmt, ##__VA_ARGS__)

#define UNIXERR(fun)     err("%s:%d:%s %s: %s", __FILE__, __LINE__, __func__,\
                             fun, strerror(errno))

extern bool         daemon_process;
extern int          log_level;
extern bool         log_syslog;
extern const char  *log_state;

void common_sighandler(int sig);

int setnonblock(int sock);
int tcp_bind(const struct sockaddr *addr, socklen_t len);
int tcp_listen(const struct sockaddr *addr, socklen_t len);
int tcp_listen_nonblock(const struct sockaddr *addr, socklen_t len);
int accept_nonblock(int fd);
int xwrite(int fd, const char *s, size_t l);

int daemon_detach(void);
int drop_privileges(const char *user, const char *group);

int pidfile_open(const char *name);
int pidfile_refresh(void);

int common_setup(const char* pidfile, bool unsafe, const char* runas_user,
                 const char* runas_group, bool daemonize);

static inline void common_startup(void)
{
    signal(SIGPIPE, SIG_IGN);
    signal(SIGSEGV, &common_sighandler);
}


#define DECLARE_MAIN                                                         \
    static int main_initialize(void)                                         \
    {                                                                        \
        log_syslog = true;                                                   \
        openlog(DAEMON_NAME, LOG_PID, LOG_MAIL);                             \
        common_startup();                                                    \
        return 0;                                                            \
    }                                                                        \
                                                                             \
    static void main_shutdown(void)                                          \
    {                                                                        \
        closelog();                                                          \
    }                                                                        \
                                                                             \
    module_init(main_initialize);                                            \
    module_exit(main_shutdown);

#define COMMON_OPTION_LIST                                                   \
    { "help", no_argument, NULL, 'h' },                                      \
    { "verbose", no_argument, NULL, 'v' }

#define COMMON_OPTION_SHORTLIST "hv"

#define COMMON_OPTION_CASES                                                  \
  case 'v':                                                                  \
    ++log_level;                                                             \
    break;                                                                   \
  default:                                                                   \
    usage();                                                                 \
    return EXIT_FAILURE;

#define COMMON_OPTION_HELP                                                   \
    "    -v|--verbose                  increase logging level\n"             \
    "    -h|--help                     show this help message\n"

#define COMMON_DAEMON_OPTION_LIST                                            \
    COMMON_OPTION_LIST,                                                      \
    { "unsafe", no_argument, NULL, 'u' },                                    \
    { "foreground", no_argument, NULL, 'f' },                                \
    { "pid-file", required_argument, NULL, 'p' }

#define COMMON_DAEMON_OPTION_SHORTLIST COMMON_OPTION_SHORTLIST "ufp:"

#define COMMON_DAEMON_OPTION_CASES                                           \
  case 'f':                                                                  \
    daemonize = false;                                                       \
    log_syslog = false;                                                      \
    break;                                                                   \
  case 'p':                                                                  \
    pidfile = optarg;                                                        \
    break;                                                                   \
  case 'u':                                                                  \
    unsafe = true;                                                           \
    break;                                                                   \
  COMMON_OPTION_CASES

#define COMMON_DAEMON_OPTION_PARAMS                                          \
    bool unsafe = false;                                                     \
    const char *pidfile = NULL;                                              \
    bool daemonize = true;

#define COMMON_DAEMON_OPTION_HELP                                            \
    "    -p|--pid-file <pidfile>       file to write our pid to\n"           \
    "    -u|--unsafe                   unsafe mode (don't drop privileges)\n"\
    "    -f|--foreground               stay in foreground\n"                 \
    COMMON_OPTION_HELP
#endif

/* vim:set et sw=4 sts=4 sws=4: */
