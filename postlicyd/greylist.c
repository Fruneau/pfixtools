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
#include "str.h"


typedef struct greylist_config_t {
    unsigned lookup_by_host : 1;
    int delay;
    int retry_window;
    int client_awl;

    TCBDB *awl_db;
    TCBDB *obj_db;
} greylist_config_t;

#define GREYLIST_INIT { .lookup_by_host = false,       \
                        .delay = 300,                  \
                        .retry_window = 2 * 24 * 2600, \
                        .client_awl = 5,               \
                        .awl_db = NULL,                \
                        .obj_db = NULL }

struct awl_entry {
    int32_t count;
    time_t  last;
};

struct obj_entry {
    time_t first;
    time_t last;
};


static bool greylist_initialize(greylist_config_t *config,
                                const char *directory, const char *prefix)
{
    char path[PATH_MAX];

    if (config->client_awl) {
        snprintf(path, sizeof(path), "%s/%swhitelist.db", directory, prefix);
        config->awl_db = tcbdbnew();
        if (!tcbdbopen(config->awl_db, path, BDBOWRITER | BDBOCREAT)) {
            tcbdbdel(config->awl_db);
            config->awl_db = NULL;
        }
        return false;
    }

    snprintf(path, sizeof(path), "%s/%sgreylist.db", directory, prefix);
    config->obj_db = tcbdbnew();
    if (!tcbdbopen(config->obj_db, path, BDBOWRITER | BDBOCREAT)) {
        tcbdbdel(config->obj_db);
        config->obj_db = NULL;
        if (config->awl_db) {
            tcbdbdel(config->awl_db);
            config->awl_db = NULL;
        }
        return false;
    }

    return true;
}

static void greylist_shutdown(greylist_config_t *config)
{
    if (config->awl_db) {
        tcbdbsync(config->awl_db);
        tcbdbdel(config->awl_db);
        config->awl_db = NULL;
    }
    if (config->obj_db) {
        tcbdbsync(config->obj_db);
        tcbdbdel(config->obj_db);
        config->obj_db = NULL;
    }
}

static const char *sender_normalize(const char *sender, char *buf, int len)
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

static const char *c_net(const greylist_config_t *config,
                         const char *c_addr, const char *c_name,
                         char *cnet, int cnetlen)
{
    char ip2[4], ip3[4];
    const char *dot, *p;

    if (config->lookup_by_host)
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

static bool try_greylist(const greylist_config_t *config,
                         const char *sender, const char *c_addr,
                         const char *c_name, const char *rcpt)
{
#define INCR_AWL                                              \
    aent.count++;                                             \
    aent.last = now;                                          \
    tcbdbput(config->awl_db, c_addr, c_addrlen, &aent,        \
             sizeof(aent));

    char sbuf[BUFSIZ], cnet[64], key[BUFSIZ];
    const void *res;

    time_t now = time(NULL);
    struct obj_entry oent = { now, now };
    struct awl_entry aent = { 0, 0 };

    int len, klen, c_addrlen = strlen(c_addr);

    /* Auto whitelist clients.
     */
    if (config->client_awl) {
        res = tcbdbget3(config->awl_db, c_addr, c_addrlen, &len);
        if (res && len == sizeof(aent)) {
            memcpy(&aent, res, len);
        }

        /* Whitelist if count is enough.
         */
        if (aent.count > config->client_awl) {
            if (now < aent.last + 3600) {
                INCR_AWL
            }

            /* OK.
             */
            return true;
        }
    }

    /* Lookup.
     */
    klen = snprintf(key, sizeof(key), "%s/%s/%s",
                    c_net(config, c_addr, c_name, cnet, sizeof(cnet)),
                    sender_normalize(sender, sbuf, sizeof(sbuf)), rcpt);
    klen = MIN(klen, ssizeof(key) - 1);

    res = tcbdbget3(config->obj_db, key, klen, &len);
    if (res && len == sizeof(oent)) {
        memcpy(&oent, res, len);
    }

    /* Discard stored first-seen if it is the first retrial and
     * it is beyong the retry window.
     */
    if (oent.last - oent.first < config->delay
        &&  now - oent.first > config->retry_window) {
        oent.first = now;
    }

    /* Update.
     */
    oent.last = now;
    tcbdbput(config->obj_db, key, klen, &oent, sizeof(oent));

    /* Auto whitelist clients:
     *  algorithm:
     *    - on successful entry in the greylist db of a triplet:
     *        - client not whitelisted yet ? -> increase count
     *                                       -> withelist if count > limit
     *        - client whitelisted already ? -> update last-seen timestamp.
     */
    if (oent.first + config->delay < now) {
        if (config->client_awl) {
            INCR_AWL
        }

        /* OK
         */
        return true;
    }

    /* DUNNO
     */
    return false;
}


/* postlicyd filter declaration */

#include "filter.h"

static greylist_config_t *greylist_config_new(void)
{
    const greylist_config_t g = GREYLIST_INIT;
    greylist_config_t *config = p_new(greylist_config_t, 1);
    *config = g;
    return config;
}

static void greylist_config_delete(greylist_config_t **config)
{
    if (*config) {
        greylist_shutdown(*config);
        p_delete(config);
    }
}

static bool greylist_filter_constructor(filter_t *filter)
{
    const char* path   = NULL;
    const char* prefix = NULL;
    greylist_config_t *config = greylist_config_new();

#define PARSE_CHECK(Expr, Str, ...)                                            \
    if (!(Expr)) {                                                             \
        syslog(LOG_ERR, Str, ##__VA_ARGS__);                                   \
        greylist_config_delete(&config);                                       \
        return false;                                                          \
    }

    foreach (filter_param_t *param, filter->params) {
        switch (param->type) {
          case ATK_PATH:
            path = param->value;
            break;

          case ATK_PREFIX:
            prefix = param->value;
            break;

          case ATK_LOOKUP_BY_HOST:
            config->lookup_by_host = (atoi(param->value) != 0);
            break;

          case ATK_RETRY_WINDOW:
            config->retry_window = atoi(param->value);
            break;

          case ATK_CLIENT_AWL:
            config->client_awl = atoi(param->value);
            break;

          default: break;
        }
    }}

    PARSE_CHECK(path, "path to greylist db not given");
    PARSE_CHECK(greylist_initialize(config, path, prefix ? prefix : ""),
                "can not load greylist database");

    filter->data = config;
    return true;
}

static void greylist_filter_destructor(filter_t *filter)
{
    greylist_config_t *data = filter->data;
    greylist_config_delete(&data);
    filter->data = data;
}

static filter_result_t greylist_filter(const filter_t *filter,
                                       const query_t *query)
{
    const greylist_config_t *config = filter->data;
    return try_greylist(config, query->sender, query->client_address,
                        query->client_name, query->recipient) ?
           HTK_MATCH : HTK_FAIL;
}

static int greylist_init(void)
{
    filter_type_t type =  filter_register("greylist", greylist_filter_constructor,
                                          greylist_filter_destructor,
                                          greylist_filter);
    /* Hooks.
     */
    (void)filter_hook_register(type, "error");
    (void)filter_hook_register(type, "fail");
    (void)filter_hook_register(type, "match");

    /* Parameters.
     */
    (void)filter_param_register(type, "lookup_by_host");
    (void)filter_param_register(type, "delay");
    (void)filter_param_register(type, "retry_window");
    (void)filter_param_register(type, "client_awl");
    (void)filter_param_register(type, "path");
    (void)filter_param_register(type, "prefix");
    return 0;
}
module_init(greylist_init)
