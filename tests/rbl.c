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
 * Copyright © 2007 Pierre Habouzit
 */

#define DEBUG(fmt, ...) \
    fprintf(stderr, "%s:%d:%s: "fmt"\n", \
            __FILE__, __LINE__, __func__, ##__VA_ARGS__)

#include <common/common.h>
#include <postlicyd/iplist.h>
#include <common/array.h>

int main(int argc, char *argv[])
{
    if (argc > 1) {
        rbldb_t *db = rbldb_create(argv[1], false);
        printf("loaded: %s, %d ips, %d o\n", argv[1], rbldb_stats(db),
               rbldb_stats(db) * 2 + 65536 * (int) sizeof(A(uint16_t)));

        time_t now = time(NULL);
        for (uint32_t i = 0 ; i < 1000000000 ; ++i) {
            rbldb_ipv4_lookup(db, (88 << 24) | (170 << 16) | (239 << 8) | (132));
        }
        printf("%ld request per second\n", 1000000000 / (time(NULL) - now));
        rbldb_delete(&db);
    }
    return 0;
}

/* vim:set et sw=4 sts=4 sws=4: */
