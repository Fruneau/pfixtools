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
 * Copyright © 2006-2007 Pierre Habouzit
 */

#ifndef PFIXTOOLS_BUFFER_H
#define PFIXTOOLS_BUFFER_H

#include <stdarg.h>
#include "mem.h"
#include "str.h"
#include "array.h"

typedef A(char) buffer_t;

#define BUFFER_INIT ARRAY_INIT

DO_INIT(buffer_t, buffer);
static inline void buffer_wipe(buffer_t *buf) {
    p_delete(&buf->data);
}
DO_NEW(buffer_t, buffer);
DO_DELETE(buffer_t, buffer);

static inline void buffer_reset(buffer_t *buf) {
    if (buf->data) {
        buf->data[buf->len = 0] = '\0';
    }
    array_len(*buf) = 0;
}

static inline char *buffer_unwrap(buffer_t **buf) {
    char *res = (*buf)->data;
    (*buf)->data = NULL;
    buffer_delete(buf);
    return res;
}

static inline clstr_t buffer_tostr(buffer_t *buf) {
    clstr_t str = { buf->data, buf->len };
    return str;
}

#define buffer_resize(buffer, newsize)                                         \
  array_ensure_exact_capacity(*(buffer), (newsize) + 1)

static inline void buffer_ensure(buffer_t *buf, int extra) {
    assert (extra >= 0);
    if (buf->len + (uint32_t)extra >= buf->size) {
        buffer_resize(buf, buf->len + (uint32_t)extra);
    }
}
static inline void buffer_extend(buffer_t *buf, int extra) {
    buffer_ensure(buf, extra);
    buf->len += (uint32_t)extra;
    buf->data[buf->len] = '\0';
}
static inline void buffer_extendch(buffer_t *buf, int extra, int c) {
    buffer_ensure(buf, extra);
    xmemset(buf->data + buf->len, c, extra);
    buf->len += (uint32_t)extra;
    buf->data[buf->len] = '\0';
}


static inline void buffer_add(buffer_t *buf, const void *data, int len) {
    buffer_ensure(buf, len);
    xmemcpy(buf->data + buf->len, data, len);
    buf->len += (uint32_t)len;
    buf->data[buf->len] = '\0';
}
static inline void buffer_addstr(buffer_t *buf, const char *s) {
    buffer_add(buf, s, (int)m_strlen(s));
}
static inline void buffer_addbuf(buffer_t *buf, buffer_t *buf2) {
    buffer_add(buf, buf2->data, (int)buf2->len);
}
static inline void buffer_addch(buffer_t *buf, int c) {
    buffer_extendch(buf, 1, c);
}

__attribute__((format(printf,2,0)))
int buffer_addvf(buffer_t *, const char *fmt, va_list);

static inline __attribute__((format(printf,2,3)))
int buffer_addf(buffer_t *buf, const char *fmt, ...)
{
    int res;
    va_list args;
    va_start(args, fmt);
    res = buffer_addvf(buf, fmt, args);
    va_end(args);
    return res;
}

void buffer_consume(buffer_t *buf, int len);

int buffer_read(buffer_t *buf, int fd, int count);
int buffer_write(buffer_t *buf, int fd);

#endif /* PFIXTOOLS_BUFFER_H */

/* vim:set et sw=4 sts=4 sws=4: */
