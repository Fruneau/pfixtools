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
 * Copyright © 2007 Pierre Habouzit
 * Copyright © 2008 Florent Bruneau
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/mman.h>

#include "common.h"
#include "rbl.h"
#include "str.h"
#include "file.h"
#include "array.h"

#define IPv4_BITS        5
#define IPv4_PREFIX(ip)  ((uint32_t)(ip) >> IPv4_BITS)
#define IPv4_SUFFIX(ip)  ((uint32_t)(ip) & ((1 << IPv4_BITS) - 1))
#define NODE(db, i)      ((db)->tree + (i))
#ifndef DEBUG
#define DEBUG(...)
#endif

/* Implementation */

enum {
    BALANCED    = 0,
    LEFT_HEAVY  = 1,
    RIGHT_HEAVY = 2,
};

struct rbldb_t {
    A(uint32_t) ips;
    bool        locked;
};
ARRAY(rbldb_t)

static int get_o(const char *s, const char **out)
{
    int res = 0;

    if (*s < '0' || *s > '9')
        return -1;

    res = *s++ - '0';
    if (*s < '0' || *s > '9')
        goto ok;

    res = res * 10 + *s++ - '0';
    if (*s < '0' || *s > '9')
        goto ok;

    res = res * 10 + *s++ - '0';
    if (!(*s < '0' || *s > '9') || res < 100)
        return -1;

  ok:
    *out = s;
    return res;
}

static int parse_ipv4(const char *s, const char **out, uint32_t *ip)
{
    int o;

    o = get_o(s, &s);
    if ((o & ~0xff) || *s++ != '.')
        return -1;
    *ip = o << 24;

    o = get_o(s, &s);
    if ((o & ~0xff) || *s++ != '.')
        return -1;
    *ip |= o << 16;

    o = get_o(s, &s);
    if ((o & ~0xff) || *s++ != '.')
        return -1;
    *ip |= o << 8;

    o = get_o(s, &s);
    if (o & ~0xff)
        return -1;
    *ip |= o;

    *out = s;
    return 0;
}

rbldb_t *rbldb_create(const char *file, bool lock)
{
    rbldb_t *db;
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
        syslog(LOG_WARNING, "file %s miss a final \\n, ignoring last line",
               file);
    }

    db = p_new(rbldb_t, 1);
    while (p < end) {
        uint32_t ip;

        while (*p == ' ' || *p == '\t' || *p == '\r')
            p++;

        if (parse_ipv4(p, &p, &ip) < 0) {
            p = (char *)memchr(p, '\n', end - p) + 1;
        } else {
            array_add(db->ips, ip);
        }
    }
    file_map_close(&map);

    /* Lookup may perform serveral I/O, so avoid swap.
     */
    array_adjust(db->ips);
    db->locked = lock && array_lock(db->ips);
    if (lock && !db->locked) {
        UNIXERR("mlock");
    }

    if (db->ips.len) {
#       define QSORT_TYPE uint32_t
#       define QSORT_BASE db->ips.data
#       define QSORT_NELT db->ips.len
#       define QSORT_LT(a,b) *a < *b
#       include "qsort.c"
    }

    syslog(LOG_INFO, "rbl %s loaded, %d IPs", file, db->ips.len);
    return db;
}

static void rbldb_wipe(rbldb_t *db)
{
    if (db->locked) {
      array_unlock(db->ips);
    }
    array_wipe(db->ips);
}

void rbldb_delete(rbldb_t **db)
{
    if (*db) {
        rbldb_wipe(*db);
        p_delete(&(*db));
    }
}

uint32_t rbldb_stats(const rbldb_t *rbl)
{
    return rbl->ips.len;
}

bool rbldb_ipv4_lookup(const rbldb_t *db, uint32_t ip)
{
    int l = 0, r = db->ips.len;

    while (l < r) {
        int i = (r + l) / 2;

        if (array_elt(db->ips, i) == ip)
            return true;

        if (ip < array_elt(db->ips, i)) {
            r = i;
        } else {
            l = i + 1;
        }
    }
    return false;
}


/* postlicyd filter declaration */

#include "filter.h"

typedef struct rbl_filter_t {
    PA(rbldb_t) rbls;
    A(int)      weights;

    int32_t     hard_threshold;
    int32_t     soft_threshold;
} rbl_filter_t;

static rbl_filter_t *rbl_filter_new(void)
{
    return p_new(rbl_filter_t, 1);
}

static void rbl_filter_delete(rbl_filter_t **rbl)
{
    if (*rbl) {
        array_deep_wipe((*rbl)->rbls, rbldb_delete);
        array_wipe((*rbl)->weights);
        p_delete(rbl);
    }
}


static bool rbl_filter_constructor(filter_t *filter)
{
    rbl_filter_t *data = rbl_filter_new();

#define PARSE_CHECK(Expr, Str, ...)                                            \
    if (!(Expr)) {                                                             \
        syslog(LOG_ERR, Str, ##__VA_ARGS__);                                   \
        rbl_filter_delete(&data);                                              \
        return false;                                                          \
    }

    foreach (filter_param_t *param, filter->params) {
        switch (param->type) {
          /* file parameter is:
           *  [no]lock:weight:filename
           *  valid options are:
           *    - lock:   memlock the database in memory.
           *    - nolock: don't memlock the database in memory [default].
           *    - \d+:    a number describing the weight to give to the match
           *              the given list [mandatory]
           *  the file pointed by filename MUST be a valid ip list issued from
           *  the rsync (or equivalent) service of a (r)bl.
           */
          case ATK_FILE: {
            bool lock = false;
            int  weight = 0;
            rbldb_t *rbl = NULL;
            const char *current = param->value;
            const char *p = m_strchrnul(param->value, ':');
            char *next = NULL;
            for (int i = 0 ; i < 3 ; ++i) {
                PARSE_CHECK(i == 2 || *p,
                            "file parameter must contains a locking state "
                            "and a weight option");
                switch (i) {
                  case 0:
                    if ((p - current) == 4 && strncmp(current, "lock", 4) == 0) {
                        lock = true;
                    } else if ((p - current) == 6
                               && strncmp(current, "nolock", 6) == 0) {
                        lock = false;
                    } else {
                        PARSE_CHECK(false, "illegal locking state %.*s",
                                    p - current, current);
                    }
                    break;

                  case 1:
                    weight = strtol(current, &next, 10);
                    PARSE_CHECK(next == p && weight >= 0 && weight <= 1024,
                                "illegal weight value %.*s",
                                (p - current), current);
                    break;

                  case 2:
                    rbl = rbldb_create(current, lock);
                    PARSE_CHECK(rbl != NULL,
                                "cannot load rbl db from %s", current);
                    array_add(data->rbls, rbl);
                    array_add(data->weights, weight);
                    break;
                }
                current = p + 1;
                p = m_strchrnul(current, ':');
            }
          } break;

          /* hard_threshold parameter is an integer.
           *  If the matching score is greater than this threshold,
           *  the hook "hard_match" is called.
           * hard_threshold = 0 means, that all matches are hard matches.
           * default is 0;
           */
          case ATK_HARD_THRESHOLD: {
            char *next;
            data->hard_threshold = strtol(param->value, &next, 10);
            PARSE_CHECK(!*next, "invalid threshold value %s", param->value);
          } break;

          /* soft_threshold parameter is an integer.
           *  if the matching score is greater than this threshold
           *  and smaller or equal than the hard_threshold, the hook "soft_match"
           *  is called.
           * default is 0;
           */
          case ATK_SOFT_THRESHOLD: {
            char *next;
            data->soft_threshold = strtol(param->value, &next, 10);
            PARSE_CHECK(!*next, "invalid threshold value %s", param->value);
          } break;

          default: break;
        }
    }}

    PARSE_CHECK(data->rbls.len, 
                "no file parameter in the filter %s", filter->name);
    filter->data = data;
    return true;
}

static void rbl_filter_destructor(filter_t *filter)
{
    rbl_filter_t *data = filter->data;
    rbl_filter_delete(&data);
    filter->data = data;
}

static filter_result_t rbl_filter(const filter_t *filter, const query_t *query)
{
    uint32_t ip;
    int32_t sum = 0;
    const char *end = NULL;
    const rbl_filter_t *data = filter->data;

    if (parse_ipv4(query->client_address, &end, &ip) != 0) {
        syslog(LOG_WARNING, "invalid client address: %s, expected ipv4",
               query->client_address);
        return HTK_ERROR;
    }
    for (int i = 0 ; i < data->rbls.len ; ++i) {
        const rbldb_t *rbl = array_elt(data->rbls, i);
        int weight   = array_elt(data->weights, i);
        if (rbldb_ipv4_lookup(rbl, ip)) {
            sum += weight;
        }
    }
    if (sum > data->hard_threshold) {
        return HTK_HARD_MATCH;
    } else if (sum > data->soft_threshold) {
        return HTK_SOFT_MATCH;
    } else {
        return HTK_FAIL;
    }
}

static int rbl_init(void)
{
    filter_type_t type =  filter_register("rbl", rbl_filter_constructor,
                                          rbl_filter_destructor, rbl_filter);
    /* Hooks.
     */
    (void)filter_hook_register(type, "abort");
    (void)filter_hook_register(type, "error");
    (void)filter_hook_register(type, "fail");
    (void)filter_hook_register(type, "hard_match");
    (void)filter_hook_register(type, "soft_match");

    /* Parameters.
     */
    (void)filter_param_register(type, "file");
    (void)filter_param_register(type, "hard_threshold");
    (void)filter_param_register(type, "soft_threshold");
    return 0;
}
module_init(rbl_init);
