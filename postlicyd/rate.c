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
 * Copyright © 2009 Florent Bruneau
 */

#include "filter.h"
#include "db.h"

#define RATE_MAX_SLOTS 128

typedef struct rate_config_t {
    char *key_format;
    int delay;
    int soft_threshold;
    int hard_threshold;
    int cleanup_period;

    db_t *db;
} rate_config_t;

#define RATE_CONFIG_INIT { .key_format     = NULL,                           \
                           .delay          = 0,                              \
                           .soft_threshold = 1,                              \
                           .hard_threshold = 1,                              \
                           .cleanup_period = 86400,                          \
                           .db             = NULL }

struct rate_entry_t {
    time_t ts;
    uint32_t delay;
    unsigned last_total         : 24;
    unsigned active_entries     : 8;
    uint16_t entries[RATE_MAX_SLOTS];
};

static rate_config_t *rate_config_init(rate_config_t *config)
{
    *config = (rate_config_t)RATE_CONFIG_INIT;
    return config;
}
DO_NEW(rate_config_t, rate_config);

static void rate_config_wipe(rate_config_t *config)
{
    p_delete(&config->key_format);
    db_release(config->db);
    config->db = NULL;
}
DO_DELETE(rate_config_t, rate_config);

static bool rate_db_need_cleanup(time_t last_cleanup, time_t now, void *data)
{
    rate_config_t *config = data;
    return (now - last_cleanup) >= config->cleanup_period;
}

static bool rate_db_check_entry(const void *entry, size_t entry_len,
                                time_t now, void *data)
{
    const size_t len = offsetof(struct rate_entry_t, entries);
    rate_config_t *config = data;
    const struct rate_entry_t *rate = entry;
    if (entry_len < len) {
        return false;
    }
    return (int)rate->delay == config->delay
        && rate->ts + 2 * (int)rate->delay > now
        && entry_len == len + 2 * rate->active_entries;
}

static bool rate_db_load(rate_config_t *config, const char *directory,
                         const char *prefix)
{
    char path[PATH_MAX];

    snprintf(path, sizeof(path), "%s/%srate.db", directory, prefix);
    config->db = db_load("rate", path, true, rate_db_need_cleanup,
                         rate_db_check_entry, config);
    return config->db != NULL;
}

static bool rate_filter_constructor(filter_t *filter)
{
    const char *path = NULL;
    const char *prefix = NULL;
    rate_config_t *config = rate_config_new();

#define PARSE_CHECK(Expr, Str, ...)                                          \
    if (!(Expr)) {                                                           \
        err(Str, ##__VA_ARGS__);                                             \
        rate_config_delete(&config);                                         \
        return false;                                                        \
    }

    foreach (param, filter->params) {
        switch (param->type) {
          FILTER_PARAM_PARSE_STRING(PATH, path, false);
          FILTER_PARAM_PARSE_STRING(PREFIX, prefix, false);
          FILTER_PARAM_PARSE_STRING(KEY, config->key_format, true);
          FILTER_PARAM_PARSE_INT(DELAY, config->delay);
          FILTER_PARAM_PARSE_INT(SOFT_THRESHOLD, config->soft_threshold);
          FILTER_PARAM_PARSE_INT(HARD_THRESHOLD, config->hard_threshold);
          FILTER_PARAM_PARSE_INT(CLEANUP_PERIOD, config->cleanup_period);

          default: break;
        }
    }

    PARSE_CHECK(config->key_format != NULL
                && query_format_check(config->key_format),
                "invalid key for rate filter");
    PARSE_CHECK(rate_db_load(config, path, prefix == NULL ? "" : prefix),
                "can not load rate database");
    PARSE_CHECK(config->delay > 0, "invalid delay");

    filter->data = config;
    return true;
}

static void rate_filter_destructor(filter_t *filter)
{
    rate_config_t *config = filter->data;
    rate_config_delete(&config);
    filter->data = NULL;
}

static inline int rate_slot_for_delay(int t, int delay, bool up)
{
    if (t >= delay || t < 0) {
        return -1;
    }
    if (delay < RATE_MAX_SLOTS) {
        return t;
    }
    if (up) {
        return ((t * RATE_MAX_SLOTS) + delay - 1) / delay;
    } else {
        return (t * RATE_MAX_SLOTS) / delay;
    }
}

static inline int rate_delay_for_slot(int slot, int delay)
{
    if (slot >= RATE_MAX_SLOTS || slot < 0) {
        return -1;
    }
    if (delay < RATE_MAX_SLOTS) {
        return slot;
    }
    return (delay * slot) / RATE_MAX_SLOTS;
}

static filter_result_t rate_filter(const filter_t *filter,
                                   const query_t *query,
                                   filter_context_t *context)
{
    static size_t entry_header_len = offsetof(struct rate_entry_t, entries);
    char key[BUFSIZ];
    const rate_config_t *config = filter->data;
    time_t now = time(NULL);
    size_t key_len, entry_len;
    struct rate_entry_t entry;
    p_clear(&entry, 1);

    key_len = query_format(key, sizeof(key), config->key_format, query);
    if (key_len >= BUFSIZ) {
        key_len = BUFSIZ - 1;
    }
    const void *data = db_get(config->db, key, key_len, &entry_len);
    if (rate_db_check_entry(data, entry_len, now, (void*)config)) {
        memcpy(&entry, data, entry_len);
        debug("rate entry found for \"%s\"", key);
        if (entry.active_entries == 0) {
            entry.active_entries = 1;
            entry.entries[0] = 1;
        }
    }
    entry.delay = config->delay;

    uint32_t last_total = entry.last_total;
    time_t   new_start = now - config->delay + 1;
    int      total = 1;
    int      start_slot;

    if (new_start <= entry.ts) {
        start_slot = 0;
    } else {
        start_slot = rate_slot_for_delay(new_start - entry.ts,
                                         config->delay, true);
    }

    if (start_slot < 0) {
        debug("rate entry obsolete, initialize a new one");
        entry.ts = now;
        entry.active_entries = 1;
        entry.entries[0] = 1;
        last_total = 0;
    } else {
        bool found_active = false;

        for (int i = start_slot ; i < entry.active_entries ; i++) {
            if (!found_active && entry.entries[i] != 0) {
                start_slot = i;
                found_active = true;
            }
            total += entry.entries[i];
        }

        debug("analysis gives: active_entries=%d, first_slot=%d (%d) hits=%d",
              entry.active_entries, start_slot, found_active, total);

        if (!found_active) {
            entry.ts = now;
            entry.active_entries = 1;
            entry.entries[0] = 1;
        } else {
            if (start_slot > 0) {
                entry.ts += rate_delay_for_slot(start_slot, config->delay);
                entry.active_entries -= start_slot;
                memmove(entry.entries, &entry.entries[start_slot],
                        2 * entry.active_entries);
            }

            int current_slot = rate_slot_for_delay(now - entry.ts,
                                                   entry.delay, false);
            debug("rate current entry belongs to slot %d", current_slot);
            assert(current_slot < RATE_MAX_SLOTS);
            assert(current_slot >= 0);
            if (current_slot >= entry.active_entries) {
                p_clear(&entry.entries[entry.active_entries],
                        current_slot - entry.active_entries);
                entry.entries[current_slot] = 1;
                entry.active_entries = current_slot + 1;
            } else {
                assert(current_slot == entry.active_entries - 1);
                if (entry.entries[current_slot] == UINT16_MAX) {
                    warn("rate storage capacity for a single slot reached");
                } else {
                    ++entry.entries[current_slot];
                }
            }
        }
    }
    entry.last_total = total;
    if (entry.active_entries == 1 && entry.entries[0] == 1) {
        entry.active_entries = 0;
    }
    db_put(config->db, key, key_len, &entry,
           entry_header_len + 2 * entry.active_entries);

    if (total >= config->hard_threshold) {
        if (last_total < (uint32_t)config->hard_threshold) {
            return HTK_HARD_MATCH_START;
        }
        return HTK_HARD_MATCH;
    } else if (total >= config->soft_threshold) {
        if (last_total < (uint32_t)config->soft_threshold) {
            return HTK_SOFT_MATCH_START;
        }
        return HTK_SOFT_MATCH;
    } else {
        return HTK_FAIL;
    }
}

filter_constructor(rate)
{
    filter_type_t type = filter_register("rate", rate_filter_constructor,
                                         rate_filter_destructor,
                                         rate_filter, NULL, NULL);

    /* Hooks
     */
    (void)filter_hook_register(type, "fail");
    (void)filter_hook_register(type, "soft_match");
    (void)filter_hook_register(type, "soft_match_start");
    (void)filter_hook_register(type, "hard_match");
    (void)filter_hook_register(type, "hard_match_start");

    filter_hook_forward_register(type, HTK_SOFT_MATCH_START, HTK_SOFT_MATCH);
    filter_hook_forward_register(type, HTK_HARD_MATCH_START, HTK_HARD_MATCH);
    filter_hook_forward_register(type, HTK_SOFT_MATCH, HTK_HARD_MATCH);

    /* Parameters
     */
    (void)filter_param_register(type, "key");
    (void)filter_param_register(type, "path");
    (void)filter_param_register(type, "prefix");
    (void)filter_param_register(type, "delay");
    (void)filter_param_register(type, "soft_threshold");
    (void)filter_param_register(type, "hard_threshold");
    (void)filter_param_register(type, "cleanup_period");
    return 0;
}

/* vim:set et sw=4 sts=4 sws=4: */
