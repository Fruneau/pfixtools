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
/*  THIS SOFTWARE IS PROVIDED BY THE CONTRIBUTORS ``AS IS'' AND ANY EXPRESS   */
/*  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED         */
/*  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE    */
/*  DISCLAIMED.  IN NO EVENT SHALL THE CONTRIBUTORS BE LIABLE FOR ANY         */
/*  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL        */
/*  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS   */
/*  OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)     */
/*  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,       */
/*  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN  */
/*  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE           */
/*  POSSIBILITY OF SUCH DAMAGE.                                               */
/*                                                                            */
/*   Copyright (c) 2006-2010 the Authors                                      */
/*   see AUTHORS and source files for details                                 */
/******************************************************************************/

/*
 * Copyright © 2008 Florent Bruneau
 */

#ifndef PFIXTOOLS_SERVER_H
#define PFIXTOOLS_SERVER_H

#include "buffer.h"

typedef struct client_t client_t;
typedef struct timeout_t timeout_t;
typedef struct listener_t listener_t;
PARRAY(client_t)
PARRAY(timeout_t);
PARRAY(listener_t)

typedef void *(*start_listener_t)(void);
typedef void  (*delete_client_t)(void*);
typedef void *(*start_client_t)(listener_t*);
typedef int   (*run_client_t)(client_t*, void*);
typedef void  (*run_timeout_t)(void*);
typedef bool	(*refresh_t)(void*);


listener_t *start_listener(int port);

client_t *client_register(int fd, run_client_t runner, void *data);
void client_delete(client_t **client);
void client_release(client_t *client);

void client_io_none(client_t *client);
void client_io_rw(client_t *client);
void client_io_ro(client_t *client);

ssize_t client_read(client_t *client);
buffer_t *client_input_buffer(client_t *client);
buffer_t *client_output_buffer(client_t *client);
void *client_data(client_t *client);

timeout_t *start_timer(int milliseconds, run_timeout_t runner, void *data);
void timer_cancel(timeout_t* timer);


int server_loop(start_client_t starter, delete_client_t deleter,
                run_client_t runner, refresh_t refresh, void *config);

#endif

/* vim:set et sw=4 sts=4 sws=4: */
