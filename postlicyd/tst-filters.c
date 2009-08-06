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

#include "str.h"
#include "config.h"
#include "file.h"
#include <dirent.h>

static char *read_query(const char *basepath, const char *filename,
                        char *buff, char **end, query_t *q)
{
    char path[FILENAME_MAX];
    snprintf(path, FILENAME_MAX, "%s%s", basepath, filename);
    {
        file_map_t map;
        if (!file_map_open(&map, path, false)) {
            UNIXERR("open");
            return NULL;
        }
        if (map.end - map.map >= BUFSIZ) {
            err("File too large for a testcase: %s", path);
            file_map_close(&map);
            return NULL;
        }
        memcpy(buff, map.map, map.end - map.map);
        if (end != NULL) {
            *end = buff + (map.end - map.map);
            **end = '\0';
        } else {
            buff[map.end - map.map] = '\0';
        }
        file_map_close(&map);
    }

    char *eoq = strstr(buff, "\n\n");
    if (eoq == NULL) {
        return NULL;
    }
    if (!query_parse(q, buff)) {
        err("Cannot parse query from file %s", filename);
        return NULL;
    }
    return eoq + 2;
}

static bool run_testcase(const config_t *config, const char *basepath,
                         const char *filename)
{
    char buff[BUFSIZ];
    char *end;
    query_t query;
    const char *eol = read_query(basepath, filename, buff, &end, &query);
    if (eol == NULL) {
        return false;
    }

    bool ok = true;
    filter_context_t context;
    filter_context_prepare(&context, NULL);

    while (eol < end) {
        char *neol = memchr(eol, '\n', end - eol);
        if (neol == NULL) {
            neol = end;
        }
        *neol = '\0';
        char *sep = memchr(eol, '=', neol - eol);
        if (sep == NULL) {
            eol = neol + 1;
            err("missing separator");
            continue;
        }
        *sep = '\0';

        int pos = filter_find_with_name(&config->filters, eol);
        if (pos == -1) {
            err("Unknown filter %s", eol);
            eol = neol + 1;
            continue;
        }
        ++sep;
        filter_result_t result = hook_tokenize(sep, neol - sep);
        if (result == HTK_UNKNOWN) {
            err("Unknown filter result %.*s", (int) (neol - sep), sep);
            eol = neol + 1;
            continue;
        }
        filter_t *filter = array_ptr(config->filters, pos);

#define TEST(Name, Run)                                                        \
        do {                                                                   \
          bool __test = (Run);                                                 \
          printf("  test %s: %s\n", Name, __test ? "SUCCESS" : "FAILED");      \
          ok = ok && __test;                                                   \
        } while (0)
        TEST(filter->name, filter_test(filter, &query, &context, result));
        eol = neol + 1;

    }
    filter_context_wipe(&context);
    return ok;
}

static bool run_greylisttest(const config_t *config, const char *basepath)
{
    char buff_q1[BUFSIZ];
    char buff_q2[BUFSIZ];
    char buff_q3[BUFSIZ];
    query_t q1;
    query_t q2;
    query_t q3;
    bool ok = true;

    filter_t *greylist1;
//    filter_t *greylist2;

#define QUERY(Q)                                                               \
    if (read_query(basepath, "greylist_" STR(Q), buff_##Q, NULL, &Q) == NULL) {    \
        return false;                                                          \
    }
    QUERY(q1);
    QUERY(q2);
    QUERY(q3);
#undef QUERY

#define FILTER(F)                                                              \
    do {                                                                       \
      int __p = filter_find_with_name(&config->filters, STR(F));               \
      if (__p < 0) {                                                           \
          return false;                                                        \
      }                                                                        \
      F = array_ptr(config->filters, __p);                                     \
    } while (0)
    FILTER(greylist1);
//    FILTER(greylist2);
#undef FILTER

    filter_context_t context;
    filter_context_prepare(&context, NULL);

    /* Test greylist */
    TEST("greylisted", filter_test(greylist1, &q1, &context, HTK_GREYLIST));
    TEST("too_fast", filter_test(greylist1, &q1, &context, HTK_GREYLIST));
    sleep(5);
    TEST("too_slow", filter_test(greylist1, &q1, &context, HTK_GREYLIST));
    sleep(2);
    TEST("whitelisted", filter_test(greylist1, &q1, &context, HTK_WHITELIST));
    TEST("other_greylisted", filter_test(greylist1, &q2, &context, HTK_GREYLIST));
    TEST("auto_whitelisted", filter_test(greylist1, &q1, &context, HTK_WHITELIST));
    TEST("other_auto_whitelisted", filter_test(greylist1, &q2, &context, HTK_WHITELIST));
    TEST("greylisted", filter_test(greylist1, &q3, &context, HTK_GREYLIST));
    sleep(10);
    TEST("cleanup", filter_test(greylist1, &q1, &context, HTK_GREYLIST));

    filter_context_wipe(&context);
    return ok;
}

int main(int argc, char *argv[])
{
    char basepath[FILENAME_MAX];
    char path[FILENAME_MAX];
    char *p;

    common_startup();
    p = strrchr(argv[0], '/');
    if (p == NULL) {
        p = argv[0];
    } else {
        ++p;
    }
    snprintf(basepath, FILENAME_MAX, "%.*sdata/", (int) (p - argv[0]), argv[0]);

    /* Cleanup */
    {
#define RM(File)                                                               \
      snprintf(path, FILENAME_MAX, "%s/%s", basepath, File);                   \
      unlink(path);
      RM("test1_greylist.db");
      RM("test1_whitelist.db");
      RM("test2_greylist.db");
      RM("test2_whitelist.db");
#undef RM
    }

    snprintf(path, FILENAME_MAX, "%s/test.conf", basepath);

    config_t *config = config_read(path);
    if (config == NULL) {
        return 1;
    }


#define RUN(Name, Test, ...)                                                   \
    printf("Running %s:\n", Name);                                             \
    printf("%s\n", run_##Test(config, basepath, ##__VA_ARGS__) ? "SUCCESS"     \
                                                               : "FAILED");

    /* Test stateless filters */
    DIR *dir = opendir(basepath);
    if (dir == NULL) {
        UNIXERR("opendir");
        return 1;
    }
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (strncmp("testcase_", ent->d_name, 9) == 0) {
            RUN(ent->d_name, testcase, ent->d_name);
        }
    }
    closedir(dir);

    /* Test greylist */
    RUN("greylist", greylisttest);


#undef RUN
    return 0;
}

/* vim:set et sw=4 sts=4 sws=4: */
