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
 * Copyright © 2009 Florent Bruneau
 */

#ifndef PFIXTOOLS_SPF_H
#define PFIXTOOLS_SPF_H

#include "common.h"
#include "array.h"
#include "dns.h"

/** Opaque structure storing the context of a SPF lookup.
 */
typedef struct spf_t spf_t;
PARRAY(spf_t);

/** List of possible return values of a spf lookup.
 *
 * Details about this values can be found in RFC 4408, Section 2.5
 */
typedef enum {
    SPF_NONE,      /**< No record were published or no checkable sender domain
                        could be determined. You cannot be ascertain whether or
                        not the client host is authorized. */
    SPF_NEUTRAL,   /**< The domain owner has explicitly stated that he cannot
                        or does not want to assert whether the IP address is
                        authorized. This MUST be treated exactly like the SPF_NONE
                        result. */
    SPF_PASS,      /**< The client is authorized to inject mail with the given
                        identity. Further policy checks can proceed with confidence
                        in the legitimate use of the identity. */
    SPF_FAIL,      /**< This is an explicit statement that the client is not
                        authorized to use the domain in the given identity. You
                        can choose to mark the mail based on this or to reject
                        it outright. */
    SPF_SOFTFAIL,  /**< The domain believes the host is not authorized but is not willing
                        to make that strong of a statement. This result should
                        be treated as somewhere between SPF_FAIL and SPF_NEUTRAL. */
    SPF_TEMPERROR, /**< A transient error was encountered while performing the check.
                        You can choose to accept or temporarily reject the message. */
    SPF_PERMERROR, /**< An error condition that requires manual intervention to be resolved
                        has been encountered (e.g.: invalid SPF records, inclusion or redirection).
                        If the domain owner uses macros, this may be result of a checked
                        identity with an unexpected format. */
} spf_code_t;

/** Callback format to receive result of a SPF lookup.
 *
 * @param result The return value of the lookup.
 * @param exp The explanation in case of failure (if any).
 * @param arg The custom argument given to @ref spf_check.
 */
typedef void (*spf_result_t)(spf_code_t result, const char* exp, void *arg);

/** Starts a SPF lookup for the (ip, domain, sender) triplet.
 *
 * @param ip The ip of the SMTP client.
 * @param domain The domain to check. This can be either the HELO domain or the domain part
 *               of the MAIL FROM command. Not that if you want to check SPF for a specific
 *               transaction, MAIL FROM domain MUST be check while checking HELO domain
 *               is not mandatory (but recommended).
 * @param sender The MAIL FROM identity. If none is given, postmaster@HELO domain is used
 *               as a fallback.
 * @param helo HELO/EHLO domain.
 * @param cb A function to call back when a result is found.
 * @param no_spf_lookup If true, disable lookup of spf entries in SPF dns record (in this
 *                      case only entries in TXT dns records are selected). This avoid
 *                      a DNS lookup and can make resolution a bit faster since most
 *                      domains do not expose a SPF dns record.
 * @param arg A custom argument that will be passed to the result callback @p cb.
 * @return A pointer to an abstract spf context in case of success, NULL in case of error.
 */
spf_t* spf_check(const char *ip, const char *domain, const char *sender, const char* helo,
                 spf_result_t cb, bool no_spf_lookup, void* arg);

/** Cancel a SPF lookup.
 *
 * This function can be used to cancel a lookup between the call of spf_check and
 * the time the result is obtained. After a SPF lookup has been cancelled, you are
 * sure you'll never get the result, and the context becomes invalid.
 *
 * @param spf A pointer to a spf context returned by @ref spf_check.
 */
void spf_cancel(spf_t* spf);

#endif

/* vim:set et sw=4 sts=4 sws=4: */
