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
#include "common.h"
#include "str.h"
#include "trie.h"
#include "file.h"

static trie_t *create_trie_from_file(const char *file)
{
    trie_t *db;
    file_map_t map;
    const char *p, *end;
    char line[BUFSIZ];

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

    db = trie_new();
    while (p < end && p != NULL) {
        const char *eol = (char *)memchr(p, '\n', end - p);
        if (eol == NULL) {
            eol = end;
        }
        if (eol - p > BUFSIZ) {
            p = eol - BUFSIZ;
        }
        int i = 0;
        if (*p != '#' && p != eol) {
#if 1
          for (const char *s = eol - 1 ; s >= p ; --s) {
              line[i++] = ascii_tolower(*s);
          }
#else
          memcpy(line, p, eol - p);
          i = eol - p;
#endif
          line[i] = '\0';
          trie_insert(db, line);
        }
        p = eol + 1;
    }
    file_map_close(&map);
    trie_compile(db, false);
    return db;
}


__attribute__((used))
static void check_trie_with_file(const trie_t *db, const char *file)
{
    file_map_t map;
    const char *p, *end;
    char line[BUFSIZ];

    if (!file_map_open(&map, file, false)) {
        return;
    }
    p   = map.map;
    end = map.end;
    while (end > p && end[-1] != '\n') {
        --end;
    }
    if (end != map.end) {
        warn("file %s miss a final \\n, ignoring last line", file);
    }

    while (p < end && p != NULL) {
        const char *eol = (char *)memchr(p, '\n', end - p);
        if (eol == NULL) {
            eol = end;
        }
        if (eol - p > BUFSIZ) {
            p = eol - BUFSIZ;
        }
        int i = 0;
        if (*p != '#' && p != eol) {
#if 1
          for (const char *s = eol - 1 ; s >= p ; --s) {
              line[i++] = ascii_tolower(*s);
          }
#else
          memcpy(line, p, eol - p);
          i = eol - p;
#endif
          line[i] = '\0';
          if (!trie_lookup(db, line)) {
            warn("'%s' not found in the trie", line);
          }
          strcat(line, "coucou");
          if (trie_lookup(db, line)) {
            warn("'%s' found in trie", line);
          }
          if (!trie_prefix(db, line)) {
            warn("'%s' has no prefix in trie", line);
          }
        }
        p = eol + 1;
    }
    file_map_close(&map);
}


static bool test_linear(const uint8_t *start, uint32_t len, uint8_t data) {
    const uint8_t *end = start + len;
    while (start < end) {
        const uint8_t val = *start;
        if (val == data) {
            return true;
        } else if (val > data) {
            return false;
        }
        ++start;
    }
    return false;
}

static bool test_dicho(const uint8_t *start, uint32_t len, uint8_t data) {
    const uint8_t *end = start + len;

    while (start < end) {
        const uint8_t *mid = start + ((end - start) >> 1);
        const uint8_t val = *mid;

        if (val == data) {
            return true;
        } else if (data < val) {
            end = mid;
        } else {
            start = mid + 1;
        }
    }
    return false;
}

__attribute__((used))
static void test_lookup(void) {
    bool set[64];
    uint8_t data[64];

    printf("size,dicho,linear\n");
    for (int i = 1 ; i < 64 ; ++i) {
        if (i > 32) {
            int selected = 64;
            memset(set, 1, 64 * sizeof(bool));
            while (selected > i) {
                int val = rand() % 64;
                if (set[val]) {
                    set[val] = false;
                    --selected;
                }
            }
        } else {
            int selected = 0;
            memset(set, 0, 64 * sizeof(bool));
            while (selected < i) {
                int val = rand() % 64;
                if (!set[val]) {
                    set[val] = true;
                    ++selected;
                }
            }
        }
        int pos = 0;
        for (int j = 0 ; j < 64 ; ++j) {
            if (set[j]) {
                data[pos] = j;
                ++pos;
            }
        }

        struct timeval start, end;
        double diff_dicho, diff_linear;
        const int iterations = 50000000;

        gettimeofday(&start, NULL);
        for (int k = 0 ; k < iterations ; ++k) {
            for (int j = 0 ; j < 64 ; ++j) {
                test_dicho(data, i, j);
            }
        }
        gettimeofday(&end, NULL);
        diff_dicho = ((end.tv_sec - start.tv_sec) * 10.0)
             + (double)(end.tv_usec - start.tv_usec) / 10e5;

        gettimeofday(&start, NULL);
        for (int k = 0 ; k < iterations ; ++k) {
            for (int j = 0 ; j < 64 ; ++j) {
                test_linear(data, i, j);
            }
        }
        gettimeofday(&end, NULL);
        diff_linear = ((end.tv_sec - start.tv_sec) * 10.0)
             + (double)(end.tv_usec - start.tv_usec) / 10e5;
        printf("%d,%d,%d\n", i, (int)diff_dicho, (int)diff_linear);
    }
}


int main(int argc, char *argv[])
{
    /* test_lookup(); */

    /* Trivial tests
     */
    trie_t *trie = trie_new();
    trie_insert(trie, "abcde123456789");
    trie_insert(trie, "abcde123654789");
    trie_insert(trie, "abcde123654789");
    trie_insert(trie, "abcdefghi");
    trie_insert(trie, "coucou");
    trie_insert(trie, "coucou chez vous");
    trie_insert(trie, "debout !");
    trie_compile(trie, false);
    trie_inspect(trie, true);

#define ASSERT_TRUE(str)                            \
    if (!trie_lookup(trie, str)) {                  \
        printf("\"%s\" not found in trie\n", str);  \
        return 1;                                   \
    }
#define ASSERT_FALSE(str)                           \
    if (trie_lookup(trie, str)) {                   \
        printf("\"%s\" found in trie\n", str);      \
        return 1;                                   \
    }
    ASSERT_FALSE("");
    ASSERT_FALSE("coucou ");
    ASSERT_FALSE("abcde123");
    ASSERT_FALSE("abcde");
    ASSERT_FALSE("coucou chez vous tous");
    ASSERT_TRUE("abcde123456789");
    ASSERT_TRUE("abcde123456789");
    ASSERT_TRUE("abcde123654789");
    ASSERT_TRUE("abcdefghi");
    ASSERT_TRUE("coucou");
    ASSERT_TRUE("coucou chez vous");
    ASSERT_TRUE("debout !");

    trie_delete(&trie);

    /* Perf test
     */
    if (argc > 1) {
        trie = create_trie_from_file(argv[1]);
        trie_inspect(trie, true);
        check_trie_with_file(trie, argv[1]);
        if (argc > 2) {
            const uint32_t how_many = 8 * 1000 * 1000;
            struct timeval start, end;
            double diff;

            gettimeofday(&start, NULL);
            for (uint32_t i = 0 ; i < how_many ; ++i) {
                trie_lookup(trie, argv[2]);
            }
            gettimeofday(&end, NULL);
            diff = (end.tv_sec - start.tv_sec) + (double)(end.tv_usec - start.tv_usec) / 10e6;
            printf("%u lookups per second\n", (int)(how_many / diff));

            trie_match_t match;
            gettimeofday(&start, NULL);
            for (uint32_t i = 0 ; i < how_many ; ++i) {
                trie_lookup_match(trie, argv[2], &match);
            }
            gettimeofday(&end, NULL);
            diff = (end.tv_sec - start.tv_sec) + (double)(end.tv_usec - start.tv_usec) / 10e6;
            printf("%u lookups per second\n", (int)(how_many / diff));

        }
        trie_delete(&trie);
    }
    return 0;
}
