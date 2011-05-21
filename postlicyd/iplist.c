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
/*   Copyright (c) 2006-2010 the Authors                                      */
/*   see AUTHORS and source files for details                                 */
/******************************************************************************/

/*
 * Copyright © 2007 Pierre Habouzit
 * Copyright © 2008 Florent Bruneau
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/mman.h>

#include "common.h"
#include "iplist.h"
#include "str.h"
#include "file.h"
#include "array.h"
#include "resources.h"
#include "dns.h"

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
    char        *filename;
    A(uint16_t) *ips;
};
ARRAY(rbldb_t)

typedef struct rbldb_resource_t {
    time_t mtime;
    off_t  size;
    A(uint16_t) ips[1 << 16];
} rbldb_resource_t;

static void rbldb_resource_wipe(rbldb_resource_t *res)
{
    for (int i = 0 ; i < 1 << 16 ; ++i) {
        array_wipe(res->ips[i]);
    }
    p_delete(&res);
}

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
    uint32_t ips = 0;
    time_t now = time(0);

    if (!file_map_open(&map, file, false)) {
        return NULL;
    }

    rbldb_resource_t *res = resource_get("iplist", file);
    if (res == NULL) {
        res = p_new(rbldb_resource_t, 1);
        resource_set("iplist", file, res, (resource_destructor_t)rbldb_resource_wipe);
    }

    db = p_new(rbldb_t, 1);
    db->filename = m_strdup(file);
    db->ips = res->ips;
    if (map.st.st_size == res->size && map.st.st_mtime == res->mtime) {
        notice("%s loaded: already up-to-date", file);
        file_map_close(&map);
        return db;
    }
    res->size  = map.st.st_size;
    res->mtime = map.st.st_mtime;

    p   = map.map;
    end = map.end;
    while (end > p && end[-1] != '\n') {
        --end;
    }
    if (end != map.end) {
        warn("%s: final \\n missing, ignoring last line", file);
    }

    /* Initialize the length of array (can be reused).
     */
    for (int i = 0 ; i < 1 << 16 ; ++i) {
        array_unlock(res->ips[i]);
        array_len(res->ips[i]) = 0;
    }

    while (p < end) {
        uint32_t ip;

        while (*p == ' ' || *p == '\t' || *p == '\r')
            p++;

        if (parse_ipv4(p, &p, &ip) < 0) {
            p = (char *)memchr(p, '\n', end - p) + 1;
        } else {
            array_add(res->ips[ip >> 16], ip & 0xffff);
            ++ips;
        }
    }
    file_map_close(&map);

    /* Lookup may perform serveral I/O, so avoid swap.
     */
    for (int i = 0 ; i < 1 << 16 ; ++i) {
        array_adjust(res->ips[i]);
        if (lock && !array_lock(res->ips[i])) {
            UNIXERR("mlock");
        }
        if (res->ips[i].len) {
#       define QSORT_TYPE uint16_t
#       define QSORT_BASE res->ips[i].data
#       define QSORT_NELT res->ips[i].len
#       define QSORT_LT(a,b) *a < *b
#       include "qsort.c"
        }
    }

    notice("%s loaded: done in %us, %u IPs", file, (uint32_t)(time(0) - now), ips);
    return db;
}

static void rbldb_wipe(rbldb_t *db)
{
    resource_release("iplist", db->filename);
    p_delete(&db->filename);
    db->ips = NULL;
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
    uint32_t ips = 0;
    for (int i = 0 ; i < 1 << 16 ; ++i) {
        ips += array_len(rbl->ips[i]);
    }
    return ips;
}

bool rbldb_ipv4_lookup(const rbldb_t *db, uint32_t ip)
{
    const uint16_t hip = ip >> 16;
    const uint16_t lip = ip & 0xffff;
    int l = 0, r = db->ips[hip].len;

    while (l < r) {
        int i = (r + l) / 2;

        if (array_elt(db->ips[hip], i) == lip)
            return true;

        if (lip < array_elt(db->ips[hip], i)) {
            r = i;
        } else {
            l = i + 1;
        }
    }
    return false;
}


/* postlicyd filter declaration */

#include "filter.h"

typedef struct iplist_filter_t {
    PA(rbldb_t) rbls;
    A(int)      weights;
    A(char)     hosts;
    A(int)      host_offsets;
    A(int)      host_weights;

    int32_t     hard_threshold;
    int32_t     soft_threshold;
} iplist_filter_t;

typedef struct iplist_async_data_t {
    A(dns_result_t) results;
    int awaited;
    uint32_t sum;
    bool error;
} iplist_async_data_t;

static iplist_filter_t *iplist_filter_new(void)
{
    return p_new(iplist_filter_t, 1);
}

static void iplist_filter_delete(iplist_filter_t **rbl)
{
    if (*rbl) {
        array_deep_wipe((*rbl)->rbls, rbldb_delete);
        array_wipe((*rbl)->weights);
        array_wipe((*rbl)->hosts);
        array_wipe((*rbl)->host_offsets);
        array_wipe((*rbl)->host_weights);
        p_delete(rbl);
    }
}


static bool iplist_filter_constructor(filter_t *filter)
{
    iplist_filter_t *data = iplist_filter_new();

#define PARSE_CHECK(Expr, Str, ...)                                            \
    if (!(Expr)) {                                                             \
        err(Str, ##__VA_ARGS__);                                               \
        iplist_filter_delete(&data);                                           \
        return false;                                                          \
    }

    data->hard_threshold = 1;
    data->soft_threshold = 1;
    foreach (param, filter->params) {
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
          case ATK_FILE: case ATK_RBLDNS: {
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
                                    (int)(p - current), current);
                    }
                    break;

                  case 1:
                    weight = strtol(current, &next, 10);
                    PARSE_CHECK(next == p && weight >= 0 && weight <= 1024,
                                "illegal weight value %.*s",
                                (int)(p - current), current);
                    break;

                  case 2:
                    rbl = rbldb_create(current, lock);
                    PARSE_CHECK(rbl != NULL,
                                "cannot load rbl db from %s", current);
                    array_add(data->rbls, rbl);
                    array_add(data->weights, weight);
                    break;
                }
                if (i != 2) {
                    current = p + 1;
                    p = m_strchrnul(current, ':');
                }
            }
          } break;

          /* dns parameter.
           *  weight:hostname.
           * define a RBL to use through DNS resolution.
           */
          case ATK_DNS: {
            int  weight = 0;
            const char *current = param->value;
            const char *p = m_strchrnul(param->value, ':');
            char *next = NULL;
            for (int i = 0 ; i < 2 ; ++i) {
                PARSE_CHECK(i == 1 || *p,
                            "host parameter must contains a weight option");
                switch (i) {
                  case 0:
                    weight = strtol(current, &next, 10);
                    PARSE_CHECK(next == p && weight >= 0 && weight <= 1024,
                                "illegal weight value %.*s",
                                (int)(p - current), current);
                    break;

                  case 1:
                    array_add(data->host_offsets, array_len(data->hosts));
                    array_append(data->hosts, current, strlen(current) + 1);
                    array_add(data->host_weights, weight);
                    break;
                }
                if (i != 1) {
                    current = p + 1;
                    p = m_strchrnul(current, ':');
                }
            }
          } break;

          /* hard_threshold parameter is an integer.
           *  If the matching score is greater or equal than this threshold,
           *  the hook "hard_match" is called.
           * hard_threshold = 1 means, that all matches are hard matches.
           * default is 1;
           */
          FILTER_PARAM_PARSE_INT(HARD_THRESHOLD, data->hard_threshold);

          /* soft_threshold parameter is an integer.
           *  if the matching score is greater or equal than this threshold
           *  and smaller or equal than the hard_threshold, the hook "soft_match"
           *  is called.
           * default is 1;
           */
          FILTER_PARAM_PARSE_INT(SOFT_THRESHOLD, data->soft_threshold);

          default: break;
        }
    }

    PARSE_CHECK(data->rbls.len || data->host_offsets.len,
                "no file parameter in the filter %s", filter->name);
    filter->data = data;
    return true;
}

static void iplist_filter_destructor(filter_t *filter)
{
    iplist_filter_t *data = filter->data;
    iplist_filter_delete(&data);
    filter->data = data;
}

static void iplist_filter_async(dns_result_t *result, void *arg)
{
    filter_context_t   *context = arg;
    const filter_t      *filter = context->current_filter;
    const iplist_filter_t *data = filter->data;
    iplist_async_data_t  *async = filter_context(filter, context);


    if (*result != DNS_ERROR) {
        async->error = false;
    }
    --async->awaited;

    debug("got asynchronous request result for filter %s, rbl %d, still awaiting %d answers",
          filter->name, (int)(result - array_ptr(async->results, 0)), async->awaited);

    if (async->awaited == 0) {
        filter_result_t res = HTK_FAIL;
        if (async->error) {
            res = HTK_ERROR;
        } else {
            for (uint32_t i = 0 ; i < array_len(data->host_offsets) ; ++i) {
                int weight = array_elt(data->host_weights, i);

                switch (array_elt(async->results, i)) {
                  case DNS_ASYNC:
                    crit("no more awaited answer but result is ASYNC");
                    abort();
                  case DNS_FOUND:
                    async->sum += weight;
                    break;
                  default:
                    break;
                }
            }
            if (async->sum >= (uint32_t)data->hard_threshold) {
                res = HTK_HARD_MATCH;
            } else if (async->sum >= (uint32_t)data->soft_threshold) {
                res = HTK_SOFT_MATCH;
            }
        }
        debug("answering to filter %s", filter->name);
        filter_post_async_result(context, res);
    }
}

static filter_result_t iplist_filter(const filter_t *filter, const query_t *query,
                                     filter_context_t *context)
{
    uint32_t ip;
    int32_t sum = 0;
    const char *end = NULL;
    const iplist_filter_t *data = filter->data;
    bool  error = true;

    if (query->client_address.str == NULL) {
        warn("client address is missing, cannot run iplist");
        return HTK_ERROR;
    }

    if (parse_ipv4(query->client_address.str, &end, &ip) != 0) {
        if (strchr(query->client_address.str, ':')) {
            /* iplist only works on IPv4 */
            return HTK_FAIL;
        }
        warn("invalid client address: %s, expected ipv4",
             query->client_address.str);
        return HTK_ERROR;
    }
    for (uint32_t i = 0 ; i < data->rbls.len ; ++i) {
        const rbldb_t *rbl = array_elt(data->rbls, i);
        int weight   = array_elt(data->weights, i);
        if (rbldb_ipv4_lookup(rbl, ip)) {
            sum += weight;
            if (sum >= data->hard_threshold) {
                return HTK_HARD_MATCH;
            }
        }
        error = false;
    }
    if (array_len(data->host_offsets) > 0) {
        iplist_async_data_t *async = filter_context(filter, context);
        array_ensure_exact_capacity(async->results, array_len(data->host_offsets));
        async->sum = sum;
        async->awaited = 0;
        for (uint32_t i = 0 ; i < data->host_offsets.len ; ++i) {
            const char *rbl = array_ptr(data->hosts, array_elt(data->host_offsets, i));
            if (dns_rbl_check(rbl, ip, array_ptr(async->results, i),
                             iplist_filter_async, context)) {
                error = false;
                ++async->awaited;
            }
        }
        debug("filter %s awaiting %d asynchronous queries", filter->name, async->awaited);
        async->error = error;
        return HTK_ASYNC;
    }
    if (error) {
        err("filter %s: all the rbl returned an error", filter->name);
        return HTK_ERROR;
    }
    if (sum >= data->hard_threshold) {
        return HTK_HARD_MATCH;
    } else if (sum >= data->soft_threshold) {
        return HTK_SOFT_MATCH;
    } else {
        return HTK_FAIL;
    }
}

static void *iplist_context_constructor(void)
{
    return p_new(iplist_async_data_t, 1);
}

static void iplist_context_destructor(void *data)
{
    iplist_async_data_t *ctx = data;
    array_wipe(ctx->results);
    p_delete(&ctx);
}

filter_constructor(iplist)
{
    filter_type_t filter_type =  filter_register("iplist", iplist_filter_constructor,
                                                 iplist_filter_destructor, iplist_filter,
                                                 iplist_context_constructor,
                                                 iplist_context_destructor);
    /* Hooks.
     */
    (void)filter_hook_register(filter_type, "error");
    (void)filter_hook_register(filter_type, "fail");
    (void)filter_hook_register(filter_type, "hard_match");
    (void)filter_hook_register(filter_type, "soft_match");
    (void)filter_hook_register(filter_type, "async");

    filter_hook_forward_register(filter_type, HTK_SOFT_MATCH, HTK_HARD_MATCH);
    filter_hook_forward_register(filter_type, HTK_ERROR, HTK_FAIL);

    /* Parameters.
     */
    (void)filter_param_register(filter_type, "file");
    (void)filter_param_register(filter_type, "rbldns");
    (void)filter_param_register(filter_type, "dns");
    (void)filter_param_register(filter_type, "hard_threshold");
    (void)filter_param_register(filter_type, "soft_threshold");
    return 0;
}

/* vim:set et sw=4 sts=4 sws=4: */
