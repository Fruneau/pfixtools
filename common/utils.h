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

#ifndef PFIXTOOLS_UTILS_H
#define PFIXTOOLS_UTILS_H

#include "common.h"
#include "buffer.h"

typedef uint32_t ip4_t;

typedef uint8_t ip6_t[16];

typedef union ip_t {
    ip4_t v4;
    ip6_t v6;
} ip_t;

typedef uint8_t cidrlen_t;


/** Parse an IPv4 from a string.
 */
__attribute__((nonnull))
bool ip_parse_4(ip4_t* restrict ip, const char* restrict txt, ssize_t len);

/** Read an IPv4 from a buffer in network order.
 */
__attribute__((nonnull))
static inline ip4_t ip_read_4(const uint8_t* restrict data);

/** Compute the IPv4 network mask for the given CIDR length
 */
__attribute__((pure))
static ip4_t ip_mask_4(cidrlen_t cidr_len);

/** Compare two IPv4 with the given cidr mask len.
 */
static inline bool ip_compare_4(ip4_t ip1, ip4_t ip2, cidrlen_t cidr_len);

/** Print an IPv4 in the buffer.
 */
bool ip_print_4(buffer_t* buffer, ip4_t ip, bool display, bool reverse);


/** Parse an IPv6 from a string.
 */
__attribute__((nonnull))
bool ip_parse_6(ip6_t ip, const char* restrict txt, ssize_t len);

/** Compare two IPv6 with the given cird mask len.
 */
static inline bool ip_compare_6(const ip6_t ip1, const ip6_t ip2, cidrlen_t cidr_len);

/** Print an IPv6 in the buffer.
 */
bool ip_print_6(buffer_t* buffer, const ip6_t ip, bool display, bool reverse);


static inline ip4_t ip_mask_4(cidrlen_t cidr_len)
{
    if (likely(cidr_len > 0 && cidr_len <= 32)) {
        return (0xffffffff) << (32 - cidr_len);
    } else if (likely(cidr_len == 0)) {
        return 0;
    } else {
        return 0xffffffff;
    }
}

static inline bool ip_compare_4(ip4_t ip1, ip4_t ip2, cidrlen_t cidr_len)
{
    const ip4_t mask = ip_mask_4(cidr_len);
    return (ip1 & mask) == (ip2 & mask);
}

static inline bool ip_compare_6(const ip6_t ip1, const ip6_t ip2, cidrlen_t cidr_len)
{
    int bytes = cidr_len >> 3;
    int bits  = cidr_len & 7;
    if (bytes > 0) {
        if (memcmp(ip1, ip2, bytes) != 0) {
            return false;
        }
    }
    if (bits > 0) {
        return (ip1[bytes] >> (8 - bits)) == (ip2[bytes] >> (8 - bits));
    }
    return true;
}

static inline ip4_t ip_read_4(const uint8_t* restrict data) {
    return (data[0] << 24)
        | ((data[1]) << 16)
        | ((data[2]) << 8)
        | data[3];
}

#endif

/* vim:set et sw=4 sts=4 sws=4: */
