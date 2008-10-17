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
    int max_age;

    TCBDB *awl_db;
    TCBDB *obj_db;
} greylist_config_t;

#define GREYLIST_INIT { .lookup_by_host = false,       \
                        .delay = 300,                  \
                        .retry_window = 2 * 24 * 3600, \
                        .client_awl = 5,               \
                        .max_age = 35 * 3600,          \
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

static inline bool greylist_check_awlentry(const greylist_config_t *config,
                                           struct awl_entry *aent, time_t now)
{
    return !(config->max_age > 0 && now - aent->last > config->max_age);
}

static inline bool greylist_check_object(const greylist_config_t *config,
                                         const struct obj_entry *oent, time_t now)
{
    return !((config->max_age > 0 && now - oent->last > config->max_age)
             || (oent->last - oent->first < config->delay
                 && now - oent->last > config->retry_window));
}

typedef bool (*db_entry_checker_t)(const greylist_config_t *, const void *, time_t);

static TCBDB *greylist_db_get(const greylist_config_t *config,
                              const char *path, bool cleanup,
                              size_t entry_len, db_entry_checker_t check)
{
    TCBDB *awl_db, *tmp_db;
    time_t now = time(NULL);

    /* Rebuild a new database after removing too old entries.
     */
    if (cleanup && config->max_age > 0) {
        uint32_t old_count = 0;
        uint32_t new_count = 0;
        bool replace = false;
        bool trashable = false;
        char tmppath[PATH_MAX];
        snprintf(tmppath, PATH_MAX, "%s.tmp", path);

        info("database cleanup started");
        awl_db = tcbdbnew();
        if (tcbdbopen(awl_db, path, BDBOREADER)) {
            tmp_db = tcbdbnew();
            if (tcbdbopen(tmp_db, tmppath, BDBOWRITER | BDBOCREAT | BDBOTRUNC)) {
                BDBCUR *cur = tcbdbcurnew(awl_db);
                TCXSTR *key, *value;

                key = tcxstrnew();
                value = tcxstrnew();
                if (tcbdbcurfirst(cur)) {
                    replace = true;
                    do {
                        tcxstrclear(key);
                        tcxstrclear(value);
                        (void)tcbdbcurrec(cur, key, value);

                        if ((size_t)tcxstrsize(value) == entry_len
                            && check(config, tcxstrptr(value), now)) {
                            tcbdbput(tmp_db, tcxstrptr(key), tcxstrsize(key),
                                     tcxstrptr(value), entry_len);
                            ++new_count;
                        }
                        ++old_count;
                    } while (tcbdbcurnext(cur));
                }
                tcxstrdel(key);
                tcxstrdel(value);
                tcbdbcurdel(cur);
                tcbdbsync(tmp_db);
            } else {
                warn("cannot run database cleanup: can't open destination database: %s",
                     tcbdberrmsg(tcbdbecode(awl_db)));
            }
            tcbdbdel(tmp_db);
        } else {
            int ecode = tcbdbecode(awl_db);
            warn("can not open database: %s", tcbdberrmsg(ecode));
            trashable = ecode != TCENOPERM && ecode != TCEOPEN && ecode != TCENOFILE && ecode != TCESUCCESS;
        }
        tcbdbdel(awl_db);

        /** Cleanup successful, replace the old database with the new one.
         */
        if (trashable) {
            info("database cleanup finished: database was corrupted, create a new one");
            unlink(path);
        } else if (replace) {
            info("database cleanup finished: before %u entries, after %d entries",
                   old_count, new_count);
            unlink(path);
            if (rename(tmppath, path) != 0) {
                UNIXERR("rename");
                return NULL;
            }
        } else {
            unlink(tmppath);
            info("database cleanup finished: nothing to do, %u entries", new_count);
        }
    }

    /* Effectively open the database.
     */
    awl_db = tcbdbnew();
    if (!tcbdbopen(awl_db, path, BDBOWRITER | BDBOCREAT)) {
        err("can not open database: %s", tcbdberrmsg(tcbdbecode(awl_db)));
        tcbdbdel(awl_db);
        return NULL;
    }
    return awl_db;
}


static bool greylist_initialize(greylist_config_t *config,
                                const char *directory, const char *prefix)
{
    char path[PATH_MAX];

    if (config->client_awl) {
        snprintf(path, sizeof(path), "%s/%swhitelist.db", directory, prefix);
        info("loading auto-whitelist database");
        config->awl_db = greylist_db_get(config, path, true,
                                         sizeof(struct awl_entry),
                                         (db_entry_checker_t)(greylist_check_awlentry));
        if (config->awl_db == NULL) {
            return false;
        }
    }

    snprintf(path, sizeof(path), "%s/%sgreylist.db", directory, prefix);
    info("loading greylist database");
    config->obj_db = greylist_db_get(config, path, true,
                                     sizeof(struct obj_entry),
                                     (db_entry_checker_t)(greylist_check_object));
    if (config->obj_db == NULL) {
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
    debug("whitelist entry for %.*s updated, count %d",       \
          c_addrlen, c_addr, aent.count);                     \
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
            debug("client %.*s has a whitelist entry, count is %d",
                  c_addrlen, c_addr, aent.count);
        }

        if (!greylist_check_awlentry(config, &aent, now)) {
            aent.count = 0;
            aent.last  = 0;
            debug("client %.*s whitelist entry too old",
                  c_addrlen, c_addr);
        }

        /* Whitelist if count is enough.
         */
        if (aent.count >= config->client_awl) {
            debug("client %.*s whitelisted", c_addrlen, c_addr);
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
        debug("found a greylist entry for %.*s", klen, key);
    }

    /* Discard stored first-seen if it is the first retrial and
     * it is beyong the retry window and too old entries.
     */
    if (!greylist_check_object(config, &oent, now)) {
        oent.first = now;
        debug("invalid retry for %.*s: %s", klen, key,
              (config->max_age > 0 && now - oent.last > config->max_age) ?
                  "too old entry"
                : (oent.last - oent.first < config->delay ?
                  "retry too early" : "retry too late" ));
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
        debug("valid retry for %.*s", klen, key);
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
        err(Str, ##__VA_ARGS__);                                               \
        greylist_config_delete(&config);                                       \
        return false;                                                          \
    }

    foreach (filter_param_t *param, filter->params) {
        switch (param->type) {
          FILTER_PARAM_PARSE_STRING(PATH,   path);
          FILTER_PARAM_PARSE_STRING(PREFIX, prefix);
          FILTER_PARAM_PARSE_BOOLEAN(LOOKUP_BY_HOST, config->lookup_by_host);
          FILTER_PARAM_PARSE_INT(RETRY_WINDOW, config->retry_window);
          FILTER_PARAM_PARSE_INT(CLIENT_AWL,   config->client_awl);
          FILTER_PARAM_PARSE_INT(DELAY,        config->delay);
          FILTER_PARAM_PARSE_INT(MAX_AGE,      config->max_age);

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
                                       const query_t *query,
                                       filter_context_t *context)
{
    const greylist_config_t *config = filter->data;
    if (query->state != SMTP_RCPT) {
        warn("greylisting only works as smtpd_recipient_restrictions");
        return HTK_ABORT;
    }

    return try_greylist(config, query->sender, query->client_address,
                        query->client_name, query->recipient) ?
           HTK_WHITELIST : HTK_GREYLIST;
}

static int greylist_init(void)
{
    filter_type_t type =  filter_register("greylist", greylist_filter_constructor,
                                          greylist_filter_destructor,
                                          greylist_filter, NULL, NULL);
    /* Hooks.
     */
    (void)filter_hook_register(type, "abort");
    (void)filter_hook_register(type, "error");
    (void)filter_hook_register(type, "greylist");
    (void)filter_hook_register(type, "whitelist");

    /* Parameters.
     */
    (void)filter_param_register(type, "lookup_by_host");
    (void)filter_param_register(type, "delay");
    (void)filter_param_register(type, "retry_window");
    (void)filter_param_register(type, "client_awl");
    (void)filter_param_register(type, "max_age");
    (void)filter_param_register(type, "path");
    (void)filter_param_register(type, "prefix");
    return 0;
}
module_init(greylist_init)
