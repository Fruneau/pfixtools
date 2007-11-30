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

#include <tcbdb.h>

#include "common.h"
#include "greylist.h"
#include "str.h"

static struct {
    bool do_awl;
    bool lookup_by_host;

    int awl_limit;
    int delay;
    int window;

    TCBDB *awl_db, *obj_db;
} cfg;

struct awl_entry {
    int32_t count;
    time_t  last;
};

struct obj_entry {
    time_t first;
    time_t last;
};

int greylist_initialize(const char *directory, const char *prefix)
{
    char path[PATH_MAX];

    if (cfg.do_awl) {
        snprintf(path, sizeof(path), "%s/%swhitelist.db", directory, prefix);
        cfg.awl_db = tcbdbnew();
        if (!tcbdbopen(cfg.awl_db, path, BDBOWRITER | BDBOCREAT)) {
            tcbdbdel(cfg.awl_db);
            cfg.awl_db = NULL;
        }
        return -1;
    }

    snprintf(path, sizeof(path), "%s/%sgreylist.db", directory, prefix);
    cfg.obj_db = tcbdbnew();
    if (!tcbdbopen(cfg.obj_db, path, BDBOWRITER | BDBOCREAT)) {
        tcbdbdel(cfg.obj_db);
        cfg.obj_db = NULL;
        if (cfg.awl_db) {
            tcbdbdel(cfg.awl_db);
            cfg.awl_db = NULL;
        }
        return -1;
    }

    return 0;
}

static void greylist_shutdown(void)
{
    if (cfg.awl_db) {
        tcbdbsync(cfg.awl_db);
        tcbdbdel(cfg.awl_db);
        cfg.awl_db = NULL;
    }
    if (cfg.obj_db) {
        tcbdbsync(cfg.obj_db);
        tcbdbdel(cfg.obj_db);
        cfg.obj_db = NULL;
    }
}
module_exit(greylist_shutdown);

const char *sender_normalize(const char *sender, char *buf, int len)
{
    const char *at = strchr(sender, '@');
    int rpos = 0, wpos = 0, userlen;

    if (!at)
        return sender;

    /* strip extension used for VERP or alike */
    userlen = ((char *)memchr(sender, '+', at - sender) ?: at) - sender;

    while (rpos < userlen) {
        int count = 0;

        while (isdigit(sender[rpos + count]) && rpos + count < userlen)
            count++;
        if (count && !isalnum(sender[rpos + count])) {
            /* replace \<\d+\> with '#' */
            wpos += m_strputc(buf + wpos, len - wpos, '#');
            rpos += count;
            count = 0;
        }
        while (isalnum(sender[rpos + count]) && rpos + count < userlen)
            count++;
        while (!isalnum(sender[rpos + count]) && rpos + count < userlen)
            count++;
        wpos += m_strncpy(buf + wpos, len - wpos, sender + rpos, count);
        rpos += count;
    }

    wpos += m_strputc(buf + wpos, len - wpos, '#');
    wpos += m_strcpy(buf + wpos, len - wpos, at + 1);
    return buf;
}

static const char *
c_net(const char *c_addr, const char *c_name, char *cnet, int cnetlen)
{
    char ip2[4], ip3[4];
    const char *dot, *p;

    if (cfg.lookup_by_host)
        return c_addr;

    if (!(dot = strchr(c_addr, '.')))
        return c_addr;
    if (!(dot = strchr(dot + 1, '.')))
        return c_addr;

    p = ++dot;
    if (!(dot = strchr(dot, '.')) || dot - p > 3)
        return c_addr;
    m_strncpy(ip2, sizeof(ip2), p, dot - p);

    p = ++dot;
    if (!(dot = strchr(dot, '.')) || dot - p > 3)
        return c_addr;
    m_strncpy(ip3, sizeof(ip3), p, dot - p);

    /* skip if contains the last two ip numbers in the hostname,
       we assume it's a pool of dialup of a provider */
    if (strstr(c_name, ip2) && strstr(c_name, ip3))
        return c_addr;

    m_strncpy(cnet, cnetlen, c_addr, dot - c_addr);
    return cnet;
}

bool try_greylist(const char *sender, const char *c_addr,
                  const char *c_name, const char *rcpt)
{
    char sbuf[BUFSIZ], cnet[64], key[BUFSIZ];
    const void *res;

    time_t now = time(NULL);
    struct obj_entry oent = { now, now };
    struct awl_entry aent = { 0, 0 };

    int len, klen, c_addrlen = strlen(c_addr);


    if (cfg.do_awl) {
        res = tcbdbget3(cfg.awl_db, c_addr, c_addrlen, &len);
        if (res && len == sizeof(aent)) {
            memcpy(&aent, res, len);
        }
        if (aent.count > cfg.awl_limit) {
            if (now < aent.last + 3600)
                goto incr_aent;
            return true;
        }
    }

    klen = snprintf(key, sizeof(key), "%s/%s/%s",
                    c_net(c_addr, c_name, cnet, sizeof(cnet)),
                    sender_normalize(sender, sbuf, sizeof(sbuf)), rcpt);
    klen = MIN(klen, ssizeof(key) - 1);

    res = tcbdbget3(cfg.obj_db, key, klen, &len);
    if (res && len == sizeof(oent)) {
        memcpy(&oent, res, len);
    }

    if (oent.last - oent.first < cfg.delay && now - oent.first > cfg.window) {
        oent.first = now;
    }
    oent.last = now;
    tcbdbput(cfg.obj_db, key, klen, &oent, sizeof(oent));
    if (oent.first + cfg.delay < now) {
        if (cfg.do_awl) {
          incr_aent:
            aent.count++;
            aent.last = now;
            tcbdbput(cfg.awl_db, c_addr, c_addrlen, &aent, sizeof(aent));
        }
        return true;
    }
    return false;
}
