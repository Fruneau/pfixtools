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
 * Copyright © 2006-2007 Pierre Habouzit
 */

#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#include "mem.h"
#include "buffer.h"

int buffer_addvf(buffer_t *buf, const char *fmt, va_list ap)
{
    int len, avail = buf->size - buf->len;
    va_list ap2;

    va_copy(ap2, ap);

    len = vsnprintf(buf->data + buf->len, (size_t)avail, fmt, ap);
    if (len >= avail) {
        buffer_resize(buf, buf->len + len);
        avail = buf->size - buf->len;
        len = vsnprintf(buf->data + buf->len, (size_t)avail, fmt, ap2);
    }
    buf->len += len;
    buf->data[buf->len] = '\0';
    va_end(ap2);
    return len;
}

void buffer_consume(buffer_t *buf, int len)
{
    if (len <= 0)
        return;

    if (len >= (int)buf->len) {
        buffer_reset(buf);
        return;
    }

    memmove(buf->data, buf->data + len, buf->len + 1 - len);
    buf->len -= len;
}

int buffer_read(buffer_t *buf, int fd, int count)
{
    int res;

    if (count < 0)
        count = BUFSIZ;

    buffer_ensure(buf, count);

    res = read(fd, buf->data + buf->len, (size_t)count);
    if (res < 0) {
        buf->data[buf->len] = '\0';
        return res;
    }

    buffer_extend(buf, res);
    return res;
}

int buffer_write(buffer_t *buf, int fd)
{
    int res = write(fd, buf->data, buf->len);
    if (res < 0) {
        return errno == EINTR || errno == EAGAIN ? 0 : -1;
    }
    buffer_consume(buf, res);
    return res;
}

/* vim:set et sw=4 sts=4 sws=4: */
