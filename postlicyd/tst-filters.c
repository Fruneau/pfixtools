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

#include "str.h"
#include "config.h"
#include "file.h"
#include <dirent.h>

#define DAEMON_NAME "tst-filters"

DECLARE_MAIN

static bool run_testcase(const config_t *config, const char *basepath,
                         const char *filename)
{
    char buff[BUFSIZ];
    char path[FILENAME_MAX];
    char *end;

    snprintf(path, FILENAME_MAX, "%s%s", basepath, filename);
    {
        file_map_t map;
        if (!file_map_open(&map, path, false)) {
            return false;
        }
        if (map.end - map.map >= BUFSIZ) {
            syslog(LOG_ERR, "File too large for a testcase: %s", path);
            return false;
        }
        memcpy(buff, map.map, map.end - map.map);
        end = buff + (map.end - map.map);
        *end = '\0';
        file_map_close(&map);
    }

    query_t query;
    const char *eol = strstr(buff, "\n\n") + 2;
    if (!query_parse(&query, buff)) {
        syslog(LOG_ERR, "Cannot parse query from file %s", path);
        return false;
    }

    bool ok = true;
    while (eol < end) {
        char *neol = memchr(eol, '\n', end - eol);
        if (neol == NULL) {
            neol = end;
        }
        *neol = '\0';
        char *sep = memchr(eol, '=', neol - eol);
        if (sep == NULL) {
            eol = neol + 1;
            syslog(LOG_ERR, "missing separator");
            continue;
        }
        *sep = '\0';

        int pos = filter_find_with_name(&config->filters, eol);
        if (pos == -1) {
            syslog(LOG_ERR, "Unknown filter %s", eol);
            eol = neol + 1;
            continue;
        }
        ++sep;
        filter_result_t result = hook_tokenize(sep, neol - sep);
        if (result == HTK_UNKNOWN) {
            syslog(LOG_ERR, "Unknown filter result %.*s", neol - sep, sep);
            eol = neol + 1;
            continue;
        }
        filter_t *filter = array_ptr(config->filters, pos);

        bool test = filter_test(filter, &query, result);
        printf("  filter %s: %s\n", filter->name, test ? "SUCCESS" : "FAILED");
        ok = ok && test;
        eol = neol + 1;
    }
    return ok;
}

int main(int argc, char *argv[])
{
    char basepath[FILENAME_MAX];
    char path[FILENAME_MAX];
    char *p;

    p = strrchr(argv[0], '/');
    if (p == NULL) {
        p = argv[0];
    } else {
        ++p;
    }

    snprintf(basepath, FILENAME_MAX, "%.*sdata/", p - argv[0], argv[0]);
    snprintf(path, FILENAME_MAX, "%s/test.conf", basepath);

    config_t *config = config_read(path);
    if (config == NULL) {
        return 1;
    }

    DIR *dir = opendir(basepath);
    if (dir == NULL) {
        UNIXERR("opendir");
        return 1;
    }

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (strncmp("testcase_", ent->d_name, 9) == 0) {
            printf("Running %s:\n", ent->d_name);
            printf("%s\n",
                   run_testcase(config, basepath, ent->d_name) ? "SUCCESS" : "FAILED");
        }
    }
    closedir(dir);

    return 0;
}
