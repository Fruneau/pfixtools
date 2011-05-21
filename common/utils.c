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
 * Copyright © 2009 Florent Bruneau
 */

#include <arpa/inet.h>

#include "utils.h"
#include "str.h"

bool ip_parse_4(ip4_t *restrict ip, const char* restrict txt, ssize_t len)
{
    char str[BUFSIZ];
    if (len < 0) {
        len = m_strlen(txt);
    }
    if (m_strncpy(str, BUFSIZ, txt, len) > BUFSIZ) {
        return false;
    }
    if (inet_pton(AF_INET, str, ip) != 1) {
        return false;
    }
    *ip = ntohl(*ip);
    return true;
}

bool ip_parse_6(ip6_t ip, const char* restrict txt, ssize_t len)
{
    char str[BUFSIZ];
    if (len < 0) {
        len = m_strlen(txt);
    }
    if (m_strncpy(str, BUFSIZ, txt, len) > BUFSIZ) {
        return false;
    }
    if (inet_pton(AF_INET6, str, ip) != 1) {
        return false;
    }
    return true;
}

bool ip_print_4(buffer_t *buffer, ip4_t ip, bool display, bool reverse)
{
    unused(display);
    if (!reverse) {
        buffer_addf(buffer, "%d.%d.%d.%d",
                    (ip >> 24) & 0xff, (ip >> 16) & 0xff,
                    (ip >> 8) & 0xff, ip & 0xff);
    } else {
        buffer_addf(buffer, "%d.%d.%d.%d",
                    ip & 0xff, (ip >> 8) & 0xff,
                    (ip >> 16) & 0xff, (ip >> 24) & 0xff);
    }
    return true;
}

bool ip_print_6(buffer_t *buffer, const ip6_t ip, bool display, bool reverse)
{
    unused(display);
    if (!reverse) {
        buffer_addf(buffer, "%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x."
                    "%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x",
                    (ip[0] >> 4) & 0x0f, ip[0] & 0x0f,
                    (ip[1] >> 4) & 0x0f, ip[1] & 0x0f,
                    (ip[2] >> 4) & 0x0f, ip[2] & 0x0f,
                    (ip[3] >> 4) & 0x0f, ip[3] & 0x0f,
                    (ip[4] >> 4) & 0x0f, ip[4] & 0x0f,
                    (ip[5] >> 4) & 0x0f, ip[5] & 0x0f,
                    (ip[6] >> 4) & 0x0f, ip[6] & 0x0f,
                    (ip[7] >> 4) & 0x0f, ip[7] & 0x0f,
                    (ip[8] >> 4) & 0x0f, ip[8] & 0x0f,
                    (ip[9] >> 4) & 0x0f, ip[9] & 0x0f,
                    (ip[10] >> 4) & 0x0f, ip[10] & 0x0f,
                    (ip[11] >> 4) & 0x0f, ip[11] & 0x0f,
                    (ip[12] >> 4) & 0x0f, ip[12] & 0x0f,
                    (ip[13] >> 4) & 0x0f, ip[13] & 0x0f,
                    (ip[14] >> 4) & 0x0f, ip[14] & 0x0f,
                    (ip[15] >> 4) & 0x0f, ip[15] & 0x0f);
    } else {
        buffer_addf(buffer, "%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x."
                    "%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x",
                    ip[15] & 0x0f, (ip[15] >> 4) & 0x0f,
                    ip[14] & 0x0f, (ip[14] >> 4) & 0x0f,
                    ip[13] & 0x0f, (ip[13] >> 4) & 0x0f,
                    ip[12] & 0x0f, (ip[12] >> 4) & 0x0f,
                    ip[11] & 0x0f, (ip[11] >> 4) & 0x0f,
                    ip[10] & 0x0f, (ip[10] >> 4) & 0x0f,
                    ip[9] & 0x0f, (ip[9] >> 4) & 0x0f,
                    ip[8] & 0x0f, (ip[8] >> 4) & 0x0f,
                    ip[7] & 0x0f, (ip[7] >> 4) & 0x0f,
                    ip[6] & 0x0f, (ip[6] >> 4) & 0x0f,
                    ip[5] & 0x0f, (ip[5] >> 4) & 0x0f,
                    ip[4] & 0x0f, (ip[4] >> 4) & 0x0f,
                    ip[3] & 0x0f, (ip[3] >> 4) & 0x0f,
                    ip[2] & 0x0f, (ip[2] >> 4) & 0x0f,
                    ip[1] & 0x0f, (ip[1] >> 4) & 0x0f,
                    ip[0] & 0x0f, (ip[0] >> 4) & 0x0f);
    }
    return true;
}


/* vim:set et sw=4 sts=4 sws=4: */
