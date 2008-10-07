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
 * Copyright © 2008 Florent Bruneau
 */

#ifndef PFIXTOOLS_SERVER_H
#define PFIXTOOLS_SERVER_H

#include "buffer.h"

typedef struct server_t server_t;
typedef int event_t;

#define INVALID_EVENT (-1)

typedef void *(*start_listener_t)(void);
typedef void  (*delete_client_t)(void*);
typedef void *(*start_client_t)(server_t*);
typedef int   (*run_client_t)(server_t*, void*);
typedef bool	(*refresh_t)(void*);
typedef bool  (*event_handler_t)(void* data, void* config);

struct server_t {
    unsigned listener : 1;
    unsigned event    : 1;

    int fd;
    int fd2;

    buffer_t ibuf;
    buffer_t obuf;

    delete_client_t clear_data;
    void* data;
};
ARRAY(server_t);

int start_server(int port, start_listener_t starter, delete_client_t deleter);

event_t event_register(void *data);
bool event_fire(event_t event);

int server_loop(start_client_t starter, delete_client_t deleter,
                run_client_t runner, event_handler_t handler,
                refresh_t refresh, void *config);

#endif
