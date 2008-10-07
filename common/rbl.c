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

#include <netdb.h>
#include "rbl.h"

static inline rbl_result_t rbl_dns_check(const char *hostname)
{
    debug("looking up for %s", hostname);
    struct hostent *host = gethostbyname(hostname);
    if (host != NULL) {
        debug("host found");
        return RBL_FOUND;
    } else {
        if (h_errno == HOST_NOT_FOUND) {
            debug("host not found: %s", hostname);
            return RBL_NOTFOUND;
        }
        debug("dns error: %m");
        return RBL_ERROR;
    }
}

rbl_result_t rbl_check(const char *rbl, uint32_t ip)
{
    char host[257];
    int len;

    len = snprintf(host, 257, "%d.%d.%d.%d.%s.",
                   ip & 0xff, (ip >> 8) & 0xff, (ip >> 16) & 0xff, (ip >> 24) & 0xff,
                   rbl);
    if (len >= (int)sizeof(host))
        return RBL_ERROR;
    if (host[len - 2] == '.')
        host[len - 1] = '\0';
    return rbl_dns_check(host);
}

rbl_result_t rhbl_check(const char *rhbl, const char *hostname)
{
    char host[257];
    int len;

    len = snprintf(host, 257, "%s.%s.", hostname, rhbl);
    if (len >= (int)sizeof(host))
        return RBL_ERROR;
    if (host[len - 2] == '.')
        host[len - 1] = '\0';
    return rbl_dns_check(host);
}
