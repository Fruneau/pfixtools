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
 */

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "common.h"
#include "rbl.h"
#include "str.h"

#define IPv4_BITS        5
#define IPv4_PREFIX(ip)  ((uint32_t)(ip) >> IPv4_BITS)
#define IPv4_SUFFIX(ip)  ((uint32_t)(ip) & ((1 << IPv4_BITS) - 1))
#define NODE(db, i)      ((db)->tree + (i))
#ifndef DEBUG
#define DEBUG(...)
#endif

enum {
    BALANCED    = 0,
    LEFT_HEAVY  = 1,
    RIGHT_HEAVY = 2,
};

struct rbldb_t {
    uint32_t len, size;
    uint32_t *ips;
    bool     locked;
};

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
    const char *map, *p, *end;
    struct stat st;
    int fd;

    fd = open(file, O_RDONLY, 0000);
    if (fd < 0) {
        UNIXERR("open");
        return NULL;
    }

    if (fstat(fd, &st) < 0) {
        UNIXERR("fstat");
        close(fd);
        return NULL;
    }

    p = map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        UNIXERR("mmap");
        close(fd);
        return NULL;
    }
    close(fd);

    end = map + st.st_size;
    while (end > map && end[-1] != '\n') {
        --end;
    }
    if (end != map + st.st_size) {
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
            if (db->len >= db->size) {
                db->size += 64 * 1024;
                p_realloc(&db->ips, db->size);
            }
            db->ips[db->len++] = ip;
        }
    }
    munmap((void*)map, st.st_size);

    /* Lookup may perform serveral I/O, so avoid swap.
     */
    db->locked = lock && mlock(db->ips, db->len * sizeof(*(db->ips))) == 0;

    if (db->len) {
#       define QSORT_TYPE uint32_t
#       define QSORT_BASE db->ips
#       define QSORT_NELT db->len
#       define QSORT_LT(a,b) *a < *b
#       include "qsort.c"
    }

    syslog(LOG_INFO, "rbl %s loaded, %d IPs", file, db->len);
    return db;
}

void rbldb_delete(rbldb_t **db)
{
    if (*db) {
        if ((*db)->locked) {
            (void)munlock((*db)->ips, (*db)->len * sizeof(*(*db)->ips));
        }
        p_delete(&(*db)->ips);
        p_delete(&(*db));
    }
}

uint32_t rbldb_stats(rbldb_t *rbl)
{
    return rbl->len;
}

bool rbldb_ipv4_lookup(rbldb_t *db, uint32_t ip)
{
    int l = 0, r = db->len;

    while (l < r) {
        int i = (r + 1) / 2;

        if (db->ips[i] == ip)
            return true;

        if (ip < db->ips[i]) {
            r = i;
        } else {
            l = i + 1;
        }
    }
    return false;
}
