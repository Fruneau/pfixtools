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

#include "common.h"
#include "file.h"
#include "query.h"

static bool read_query(const char *base, const char *file, query_t *query,
                       char *buff)
{
    char path[FILENAME_MAX];
    snprintf(path, FILENAME_MAX, "%s%s", base, file);
    {
        file_map_t map;
        if (!file_map_open(&map, path, false)) {
            UNIXERR("open");
            return false;
        }
        if (map.end - map.map >= BUFSIZ) {
            err("File too large for a testcase: %s", path);
            file_map_close(&map);
            return false;
        }
        memcpy(buff, map.map, map.end - map.map);
        buff[map.end - map.map] = '\0';
        file_map_close(&map);
    }

    char *eoq = strstr(buff, "\n\n");
    if (eoq == NULL) {
        return false;
    }
    if (!query_parse(query, buff)) {
        err("Cannot parse query from file %s", path);
        return false;
    }
    return true;
}

int main(int argc, char *argv[])
{
    char basepath[FILENAME_MAX];
    char buff[BUFSIZ];
    char *p;

    p = strrchr(argv[0], '/');
    if (p == NULL) {
        p = argv[0];
    } else {
        ++p;
    }
    snprintf(basepath, FILENAME_MAX, "%.*sdata/", p - argv[0], argv[0]);

    query_t q;
    if (!read_query(basepath, "testcase_1", &q, buff)) {
        return EXIT_FAILURE;
    }

    static const char *format = "${sender} ${recipient} and ${client_name}[${client_address}] at ${protocol_state}";

    time_t now = time(0);

    char str[BUFSIZ];
    static const int iterations = 10000000;
    for (int i = 0 ; i < iterations ; ++i) {
        query_format(str, BUFSIZ, format, &q);
    }

    time_t ellapsed = time(0) - now;
    printf("Done %d iterations in %us (%d format per second)\n", iterations,
           (uint32_t)ellapsed, (int)(iterations / ellapsed));
    return 0;
}
