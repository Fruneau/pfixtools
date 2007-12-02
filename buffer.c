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

#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#include "buffer.h"

#define BUFSIZ_INCREMENT  256

void buffer_resize(buffer_t *buf, ssize_t newsize)
{
    if (newsize >= buf->size) {
        /* rounds newsize to the 1024 multiple just after newsize+1 */
        newsize = (newsize + BUFSIZ_INCREMENT) & ~(BUFSIZ_INCREMENT - 1);
        p_realloc(&buf->data, newsize);
    }
}

void buffer_consume(buffer_t *buf, ssize_t len) {
    if (len <= 0)
        return;

    if (len >= buf->len) {
        buffer_reset(buf);
        return;
    }

    memmove(buf->data, buf->data + len, buf->len + 1 - len);
    buf->len -= len;
}

ssize_t buffer_read(buffer_t *buf, int fd, ssize_t count)
{
    ssize_t res;

    if (count < 0)
        count = BUFSIZ;

    buffer_ensure(buf, count);

    res = read(fd, buf->data + buf->len, count);
    if (res < 0) {
        buf->data[buf->len] = '\0';
        return res;
    }

    buffer_extend(buf, res);
    return res;
}

ssize_t buffer_write(buffer_t *buf, int fd)
{
    ssize_t res = write(fd, buf->data, buf->len);
    if (res < 0) {
        return errno == EINTR || errno == EAGAIN ? 0 : -1;
    }
    buffer_consume(buf, res);
    return res;
}
