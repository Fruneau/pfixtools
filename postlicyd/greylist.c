/****************************************************************************/
/*          pfixtools: a collection of postfix related tools                */
/*          ~~~~~~~~~                                                       */
/*  ______________________________________________________________________  */
/*                                                                          */
/*  Redistribution and use in source and binary forms, with or without      */
/*  modification, are permitted provided that the following conditions      */
/*  are met:                                                                */
/*                                                                          */
/*  1. Redistributions of source code must retain the above copyright       */
/*     notice, this list of conditions and the following disclaimer.        */
/*  2. Redistributions in binary form must reproduce the above copyright    */
/*     notice, this list of conditions and the following disclaimer in      */
/*     the documentation and/or other materials provided with the           */
/*     distribution.                                                        */
/*  3. The names of its contributors may not be used to endorse or promote  */
/*     products derived from this software without specific prior written   */
/*     permission.                                                          */
/*                                                                          */
/*  THIS SOFTWARE IS PROVIDED BY THE CONTRIBUTORS ``AS IS'' AND ANY         */
/*  EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE       */
/*  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR      */
/*  PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE CONTRIBUTORS BE LIABLE   */
/*  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR            */
/*  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF    */
/*  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR         */
/*  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,   */
/*  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE    */
/*  OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,       */
/*  EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.                      */
/*                                                                          */
/*   Copyright (c) 2006-2011 the Authors                                    */
/*   see AUTHORS and source files for details                               */
/****************************************************************************/

/*
 * Copyright © 2007 Pierre Habouzit
 * Copyright © 2008-2009 Florent Bruneau
 */

#include "filter.h"
#include "common.h"
#include "str.h"
#include "db.h"

typedef struct greylist_config_t {
    unsigned lookup_by_host : 1;
    unsigned no_sender      : 1;
    unsigned no_recipient   : 1;
    unsigned normalize_sender: 1;
    int delay;
    int retry_window;
    int client_awl;
    int max_age;
    int cleanup_period;

    db_t *awl;
    db_t *obj;
} greylist_config_t;

#define GREYLIST_INIT { .lookup_by_host = false,       \
                        .no_sender = false,            \
                        .no_recipient = false,         \
                        .normalize_sender = true,      \
                        .delay = 300,                  \
                        .retry_window = 2 * 24 * 3600, \
                        .client_awl = 5,               \
                        .max_age = 35 * 3600,          \
                        .cleanup_period = 86400,       \
                        .awl = NULL,                   \
                        .obj = NULL }

struct awl_entry {
    int32_t count;
    time_t  last;
};

struct obj_entry {
    time_t first;
    time_t last;
};

static inline bool greylist_check_objentry(const greylist_config_t *config,
                                           const struct obj_entry* oent,
                                           time_t now)
{
    return !((config->max_age > 0 && now - oent->last > config->max_age)
             || (oent->last - oent->first < config->delay
                 && now - oent->last > config->retry_window));
}

static bool greylist_db_check_objentry(const void *entry, size_t entry_len,
                                    time_t now, void *data)
{
    return entry_len == sizeof(struct obj_entry)
        && greylist_check_objentry(data, entry, now);
}

static inline bool greylist_check_awlentry(const greylist_config_t *config,
                                           const struct awl_entry *aent,
                                           time_t now)
{
    return !(config->max_age > 0 && now - aent->last > config->max_age);
}

static bool greylist_db_check_awlentry(const void* entry, size_t entry_len,
                                       time_t now, void* data)
{
    return entry_len == sizeof(struct awl_entry)
        && greylist_check_awlentry(data, entry, now);
}

static bool greylist_db_need_cleanup(time_t last_update, time_t now,
                                     void* data)
{
    const greylist_config_t *config = data;
    return now - last_update >= config->cleanup_period;
}

static bool greylist_db_load(greylist_config_t *config,
                             const char *directory, const char *prefix)
{
    char path[PATH_MAX];

    if (config->client_awl) {
        snprintf(path, sizeof(path), "%s/%swhitelist.db", directory, prefix);
        config->awl = db_load("greylist", path, config->max_age > 0,
                              greylist_db_need_cleanup,
                              greylist_db_check_awlentry, config);
        if (config->awl == NULL) {
            return false;
        }
    }

    snprintf(path, sizeof(path), "%s/%sgreylist.db", directory, prefix);
    config->obj = db_load("greylist", path, config->max_age > 0,
                          greylist_db_need_cleanup,
                          greylist_db_check_objentry, config);
    if (config->obj == NULL) {
        if (config->awl) {
            db_release(config->awl);
            config->awl = NULL;
        }
        return false;
    }
    return true;
}

static
bool try_greylist(const greylist_config_t *config, const query_t *query)
{
#define INCR_AWL                                                             \
    aent.count++;                                                            \
    aent.last = now;                                                         \
    debug("whitelist entry for %.*s updated, count %d",                      \
          (int)c_addr->len, c_addr->str, aent.count);                        \
    db_put(config->awl, c_addr->str, c_addr->len, &aent, sizeof(aent));

    char key[BUFSIZ];

    time_t now = time(NULL);
    struct obj_entry oent = { now, now };
    struct awl_entry aent = { 0, 0 };
    const clstr_t *c_addr = &query->client_address;

    size_t klen;

    /* Auto whitelist clients.
     */
    if (config->client_awl) {
        if (db_get_len(config->awl, c_addr->str, c_addr->len,
                       &aent, sizeof(aent))) {
            debug("client %.*s has a whitelist entry, count is %d",
                  (int)c_addr->len, c_addr->str, aent.count);
        }

        if (!greylist_check_awlentry(config, &aent, now)) {
            aent.count = 0;
            aent.last  = 0;
            debug("client %.*s whitelist entry too old",
                  (int)c_addr->len, c_addr->str);
        }

        /* Whitelist if count is enough.
         */
        if (aent.count >= config->client_awl) {
            debug("client %.*s whitelisted", (int)c_addr->len, c_addr->str);
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
    const clstr_t *cnet = query_field_for_id(query,
                                             config->lookup_by_host ?
                                             PTK_CLIENT_ADDRESS :
                                             PTK_NORMALIZED_CLIENT);
    const clstr_t *sender = NULL;
    if (!config->no_sender) {
        sender = query_field_for_id(query,
                                    config->normalize_sender ?
                                    PTK_NORMALIZED_SENDER :
                                    PTK_SENDER);
    }
    klen = snprintf(key, sizeof(key), "%s/%s/%s", cnet->str,
                    config->no_sender ? "" : sender->str,
                    config->no_recipient ? "" : query->recipient.str);
    klen = MIN(klen, ssizeof(key) - 1);

    if (db_get_len(config->obj, key, klen, &oent, sizeof(oent))) {
        debug("found a greylist entry for %.*s", (int)klen, key);
    }

    /* Discard stored first-seen if it is the first retrial and
     * it is beyong the retry window and too old entries.
     */
    if (!greylist_check_objentry(config, &oent, now)) {
        oent.first = now;
        debug("invalid retry for %.*s: %s", (int)klen, key,
              (config->max_age > 0 && now - oent.last > config->max_age) ?
                  "too old entry"
                : (oent.last - oent.first < config->delay ?
                  "retry too early" : "retry too late"));
    }

    /* Update.
     */
    oent.last = now;
    db_put(config->obj, key, klen, &oent, sizeof(oent));

    /* Auto whitelist clients:
     *  algorithm:
     *    - on successful entry in the greylist db of a triplet:
     *        - client not whitelisted yet ? -> increase count
     *                                       -> withelist if count > limit
     *        - client whitelisted already ? -> update last-seen timestamp.
     */
    if (oent.first + config->delay < now) {
        debug("valid retry for %.*s", (int)klen, key);
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

static greylist_config_t *greylist_config_init(greylist_config_t *config)
{
    *config = (greylist_config_t)GREYLIST_INIT;
    return config;
}
DO_NEW(greylist_config_t, greylist_config);

static void greylist_config_wipe(greylist_config_t *config)
{
    if (config->awl) {
        db_release(config->awl);
        config->awl = NULL;
    }
    if (config->obj) {
        db_release(config->obj);
        config->obj = NULL;
    }
}
DO_DELETE(greylist_config_t, greylist_config);

static bool greylist_filter_constructor(filter_t *filter)
{
    const char* path   = NULL;
    const char* prefix = NULL;
    greylist_config_t *config = greylist_config_new();

#define PARSE_CHECK(Expr, Str, ...)                                          \
    if (!(Expr)) {                                                           \
        err(Str, ##__VA_ARGS__);                                             \
        greylist_config_delete(&config);                                     \
        return false;                                                        \
    }

    foreach (param, filter->params) {
        switch (param->type) {
          FILTER_PARAM_PARSE_STRING(PATH,   path, false);
          FILTER_PARAM_PARSE_STRING(PREFIX, prefix, false);
          FILTER_PARAM_PARSE_BOOLEAN(LOOKUP_BY_HOST, config->lookup_by_host);
          FILTER_PARAM_PARSE_BOOLEAN(NO_SENDER, config->no_sender);
          FILTER_PARAM_PARSE_BOOLEAN(NO_RECIPIENT, config->no_recipient);
          FILTER_PARAM_PARSE_BOOLEAN(NORMALIZE_SENDER,
                                     config->normalize_sender);
          FILTER_PARAM_PARSE_INT(RETRY_WINDOW, config->retry_window);
          FILTER_PARAM_PARSE_INT(CLIENT_AWL,   config->client_awl);
          FILTER_PARAM_PARSE_INT(DELAY,        config->delay);
          FILTER_PARAM_PARSE_INT(MAX_AGE,      config->max_age);
          FILTER_PARAM_PARSE_INT(CLEANUP_PERIOD, config->cleanup_period);

          default: break;
        }
    }

    PARSE_CHECK(path, "path to greylist db not given");
    PARSE_CHECK(greylist_db_load(config, path, prefix ? prefix : ""),
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
    if (!config->no_recipient && query->state != SMTP_RCPT) {
        warn("greylisting on recipient only works "
             "as smtpd_recipient_restrictions");
        return HTK_ABORT;
    }
    if (!config->no_sender && query->state < SMTP_MAIL) {
        warn("greylisting on sender must be performed after (or at) MAIL TO");
        return HTK_ABORT;
    }

    return try_greylist(config, query) ? HTK_WHITELIST : HTK_GREYLIST;
}

filter_constructor(greylist)
{
    filter_type_t type
        = filter_register("greylist", greylist_filter_constructor,
                          greylist_filter_destructor,
                          greylist_filter, NULL, NULL);
    /* Hooks.
     */
    (void)filter_hook_register(type, "abort");
    (void)filter_hook_register(type, "greylist");
    (void)filter_hook_register(type, "whitelist");

    /* Parameters.
     */
    (void)filter_param_register(type, "lookup_by_host");
    (void)filter_param_register(type, "normalize_sender");
    (void)filter_param_register(type, "no_sender");
    (void)filter_param_register(type, "no_recipient");
    (void)filter_param_register(type, "delay");
    (void)filter_param_register(type, "retry_window");
    (void)filter_param_register(type, "client_awl");
    (void)filter_param_register(type, "max_age");
    (void)filter_param_register(type, "cleanup_period");
    (void)filter_param_register(type, "path");
    (void)filter_param_register(type, "prefix");
    return 0;
}

/* vim:set et sw=4 sts=4 sws=4: */
