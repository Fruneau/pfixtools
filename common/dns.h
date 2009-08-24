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
/*   Copyright (c) 2006-2009 the Authors                                      */
/*   see AUTHORS and source files for details                                 */
/******************************************************************************/

/*
 * Copyright © 2008-2009 Florent Bruneau
 */

#ifndef PFIXTOOLS_DNS_H
#define PFIXTOOLS_DNS_H

#include <unbound.h>
#include "common.h"
#include "array.h"

typedef enum {
    DNS_ASYNC,
    DNS_ERROR,
    DNS_FOUND,
    DNS_NOTFOUND,
} dns_result_t;
ARRAY(dns_result_t);

typedef enum {
    DNS_RRT_A     = 1,
    DNS_RRT_NS    = 2,
    DNS_RRT_CNAME = 5,
    DNS_RRT_SOA   = 6,
    DNS_RRT_PTR   = 12,
    DNS_RRT_MX    = 15,
    DNS_RRT_TXT   = 16,
    DNS_RRT_AAAA  = 28,
    DNS_RRT_SRV   = 33,
    DNS_RRT_SPF   = 99
} dns_rrtype_t;

typedef enum {
    DNS_RRC_IN    = 1,
    DNS_RRC_CS    = 2,
    DNS_RRC_CH    = 3,
    DNS_RRC_HS    = 4,
} dns_rrclass_t;

typedef void (*dns_result_callback_t)(dns_result_t *result, void *data);

/** Run a DNS resolution for the given host with the given host and RRT
 */
__attribute__((nonnull(1,3,4)))
bool dns_resolve(const char *hostname, dns_rrtype_t type,
                 ub_callback_t callback, void *data);

/** Fetch the DNS record of the given type.
 */
__attribute__((nonnull(1,4)))
bool dns_check(const char *hostname, dns_rrtype_t type, dns_result_t *result,
               dns_result_callback_t callback, void *data);

/** Check the presence of the given IP in the given rbl.
 */
__attribute__((nonnull(1,3)))
bool dns_rbl_check(const char *rbl, uint32_t ip, dns_result_t *result,
                  dns_result_callback_t callback, void *data);

/** Check the presence of the given hostname in the given rhbl.
 */
__attribute__((nonnull(1,2,3)))
bool dns_rhbl_check(const char *rhbl, const char *hostname, dns_result_t *result,
                   dns_result_callback_t callback, void *data);

#endif

/* vim:set et sw=4 sts=4 sws=4: */
