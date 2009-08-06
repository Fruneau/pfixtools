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
 * Copyright © 2008 Florent Bruneau
 */

#include <time.h>
#include <sys/time.h>
#include "file.h"
#include "array.h"
#include "regexp.h"

static regexp_t *create_regex_from_file(const char *file)
{
    A(char) buffer = ARRAY_INIT;
    file_map_t map;
    const char *p, *end;

    if (!file_map_open(&map, file, false)) {
        return NULL;
    }
    p   = map.map;
    end = map.end;
    while (end > p && end[-1] != '\n') {
        --end;
    }
    if (end != map.end) {
        warn("file %s miss a final \\n, ignoring last line", file);
    }

    array_append(buffer, "^(", 2);
    while (p < end && p != NULL && array_len(buffer) <= 32000) {
        const char *eol = (char *)memchr(p, '\n', end - p);
        if (eol == NULL) {
            eol = end;
        }
        if (eol - p > BUFSIZ) {
            p = eol - BUFSIZ;
        }
        if (array_len(buffer) > 2) {
            array_add(buffer, '|');
        }
        for (const char *s = p ; s < eol ; ++s) {
            if (*s == '.') {
                array_append(buffer, "\\.", 2);
            } else {
                array_add(buffer, *s);
            }
        }
        p = eol + 1;
    }
    array_append(buffer, ")$", 3);
    file_map_close(&map);

    regexp_t *re = regexp_new();
    if (!regexp_compile(re, array_start(buffer), false)) {
        array_wipe(buffer);
        regexp_delete(&re);
        return NULL;
    }
    array_wipe(buffer);
    return re;
}

static bool check_parse(const char *str, const char *prefix, const char *suffix,
                        const char *wildcard, bool cs) {
    buffer_t reprefix = ARRAY_INIT;
    buffer_t resuffix = ARRAY_INIT;
    buffer_t restr  = ARRAY_INIT;
    bool recs = false;
    bool res  = true;

    buffer_addch(&reprefix, '\0');
    buffer_addch(&resuffix, '\0');
    buffer_addch(&restr, '\0');

    if (regexp_parse(str, prefix ? &reprefix : NULL,
                     &restr,
                     suffix ? &resuffix : NULL,
                     &recs)) {
        printf("%s -> \"%s\" + /%s/ + \"%s\": ", str, reprefix.data, restr.data, resuffix.data);
        res = (cs == recs);
        if (prefix) {
            res = res && strcmp(reprefix.data, prefix) == 0;
        }
        if (suffix) {
            res = res && strcmp(resuffix.data, suffix) == 0;
        }
        res = res && strcmp(restr.data, wildcard) == 0;
    } else {
        printf("%s: ", str);
        res = false;
    }
    printf("%s\n", res ? "OK" : "FAILED");

    buffer_wipe(&reprefix);
    buffer_wipe(&resuffix);
    buffer_wipe(&restr);

    return res;
}

int main(int argc, char *argv[])
{
    /* Read prefixes and suffixes
     */
#define CHECK(str, prefix, suffix, content, cs)                                \
    if (!check_parse(str, prefix, suffix, content, cs)) {                      \
        return -1;                                                             \
    }
    CHECK("/^coucou/", "coucou", NULL, "^", true);
    CHECK("/^coucou\\.machin/", "coucou.machin", NULL, "^", true);
    CHECK("/^coucou.machin/", "coucou", NULL, "^.machin", true);
    CHECK("/^coucou\\.machin$/", "coucou.machin", NULL, "^$", true);

    CHECK("/coucou$/", "", "coucou", "$", true);
    CHECK("/coucou\\.machin$/", NULL, "coucou.machin", "$", true);
    CHECK("/coucou.machin$/", NULL, "machin", "coucou.$", true);
    CHECK("/coucou\\$/", NULL, "", "coucou\\$", true);
    CHECK("/\\\\$/", NULL, "\\", "$", true);
    CHECK("/\\\\\\$/", NULL, "", "\\\\\\$", true);
    CHECK("/\\\\\\\\$/i", NULL, "\\\\", "$", false);
    CHECK("/coucou.machin$/", NULL, NULL, "coucou.machin$", true);

    CHECK("/coucou\\/machin/", "", "", "coucou/machin", true);

    CHECK("/^s[cv]\\d+pub\\.verizon\\.net$/", NULL, "pub.verizon.net", "^s[cv]\\d+$", true);
    CHECK("/^mail\\d+\\.telekom\\.de$/", NULL, ".telekom.de", "^mail\\d+$", true);
    CHECK("/^mail\\d+\\.telekom\\.de$/", "mail", NULL, "^\\d+\\.telekom\\.de$", true);
    CHECK("/\\dmachin$/", NULL, "machin", "\\d$", true);

    /* Perf test
     */
    if (argc > 1) {
        regexp_t *re = create_regex_from_file(argv[1]);
        assert(re != NULL);
        if (argc > 2) {
            const uint32_t how_many = 100 * 1000;
            struct timeval start, end;
            double diff;

            gettimeofday(&start, NULL);
            static_str_t str = { argv[2], strlen(argv[2]) };
            for (uint32_t i = 0 ; i < how_many ; ++i) {
                regexp_match_str(re, &str);
            }
            gettimeofday(&end, NULL);
            diff = (end.tv_sec - start.tv_sec) + (double)(end.tv_usec - start.tv_usec) / 10e6;
            printf("%u lookups per second\n", (int)(how_many / diff));
        }
        regexp_delete(&re);
    }
    return 0;
}

/* vim:set et sw=4 sts=4 sws=4: */
