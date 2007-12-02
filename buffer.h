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
 * Copyright © 2006-2007 Pierre Habouzit
 */

#ifndef PFIXTOOLS_BUFFER_H
#define PFIXTOOLS_BUFFER_H

#include "mem.h"
#include "str.h"

typedef struct buffer_t {
    char *data;
    ssize_t len;
    ssize_t size;
} buffer_t;

#define BUFFER_INIT {NULL, 0, 0}

DO_INIT(buffer_t, buffer);
static inline void buffer_wipe(buffer_t *buf) {
    p_delete(&buf->data);
}
DO_NEW(buffer_t, buffer);
DO_DELETE(buffer_t, buffer);

static inline void buffer_reset(buffer_t *buf) {
    buf->data[buf->len = 0] = '\0';
}

static inline char *buffer_unwrap(buffer_t **buf) {
    char *res = (*buf)->data;
    (*buf)->data = NULL;
    buffer_delete(buf);
    return res;
}


void buffer_resize(buffer_t *, ssize_t newsize);
static inline void buffer_ensure(buffer_t *buf, ssize_t extra) {
    assert (extra >= 0);
    if (buf->len + extra >= buf->size) {
        buffer_resize(buf, buf->len + extra);
    }
}
static inline void buffer_extend(buffer_t *buf, ssize_t extra) {
    buffer_ensure(buf, extra);
    buf->len += extra;
    buf->data[buf->len] = '\0';
}
static inline void buffer_extendch(buffer_t *buf, ssize_t extra, int c) {
    buffer_ensure(buf, extra);
    memset(buf->data + buf->len, c, extra);
    buf->len += extra;
    buf->data[buf->len] = '\0';
}


static inline void buffer_add(buffer_t *buf, const void *data, ssize_t len) {
    buffer_ensure(buf, len);
    memcpy(buf->data + buf->len, data, len);
    buf->len += len;
    buf->data[buf->len] = '\0';
}
static inline void buffer_addstr(buffer_t *buf, const char *s) {
    buffer_add(buf, s, m_strlen(s));
}
static inline void buffer_addbuf(buffer_t *buf, buffer_t *buf2) {
    buffer_add(buf, buf2->data, buf2->len);
}
static inline void buffer_addch(buffer_t *buf, int c) {
    buffer_extendch(buf, 1, c);
}

void buffer_consume(buffer_t *buf, ssize_t len);

ssize_t buffer_read(buffer_t *buf, int fd, ssize_t count);
ssize_t buffer_write(buffer_t *buf, int fd);

#endif /* PFIXTOOLS_BUFFER_H */
