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
 * Copyright © 2008 Florent Bruneau
 */

#include "filter.h"
#include "trie.h"
#include "file.h"
#include "str.h"
#include "rbl.h"
#include "policy_tokens.h"

typedef struct strlist_config_t {
    PA(trie_t) tries;
    A(int)     weights;
    A(bool)    reverses;
    A(bool)    partiales;

    A(char)     hosts;
    A(int)      host_offsets;
    A(int)      host_weights;

    int soft_threshold;
    int hard_threshold;

    unsigned is_email         :1;
    unsigned is_hostname      :1;

    unsigned match_sender     :1;
    unsigned match_recipient  :1;

    unsigned match_helo       :1;
    unsigned match_client     :1;
    unsigned match_reverse    :1;
} strlist_config_t;

typedef struct strlist_async_data_t {
    A(rbl_result_t) results;
    int awaited;
    uint32_t sum;
    bool error;
} strlist_async_data_t;

static filter_type_t filter_type = FTK_UNKNOWN;


static strlist_config_t *strlist_config_new(void)
{
    return p_new(strlist_config_t, 1);
}

static void strlist_config_delete(strlist_config_t **config)
{
    if (*config) {
        array_deep_wipe((*config)->tries, trie_delete);
        array_wipe((*config)->weights);
        array_wipe((*config)->reverses);
        array_wipe((*config)->partiales);
        array_wipe((*config)->hosts);
        array_wipe((*config)->host_offsets);
        array_wipe((*config)->host_weights);
        p_delete(config);
    }
}

static inline void strlist_copy(char *dest, const char *str, ssize_t str_len,
                                bool reverse)
{
    if (str_len > 0) {
        if (reverse) {
            for (const char *src = str + str_len - 1 ; src >= str ; --src) {
                *dest = ascii_tolower(*src);
                ++dest;
            }
        } else {
            for (int i = 0 ; i < str_len ; ++i) {
                *dest = ascii_tolower(str[i]);
                ++dest;
            }
        }
    }
    *dest = '\0';
}


static trie_t *strlist_create(const char *file, bool reverse, bool lock)
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
        warn("file %s miss a final \\n, ignoring last line",
             file);
    }

    db = trie_new();
    while (p < end && p != NULL) {
        const char *eol = (char *)memchr(p, '\n', end - p);
        if (eol == NULL) {
            eol = end;
        }
        if (eol - p >= BUFSIZ) {
            err("unreasonnable long line");
            file_map_close(&map);
            trie_delete(&db);
            return NULL;
        }
        if (*p != '#') {
            const char *eos = eol;
            while (p < eos && isspace(*p)) {
                ++p;
            }
            while (p < eos && isspace(eos[-1])) {
                --eos;
            }
            if (p < eos) {
                strlist_copy(line, p, eos - p, reverse);
                trie_insert(db, line);
            }
        }
        p = eol + 1;
    }
    file_map_close(&map);
    trie_compile(db, lock);
    return db;
}

static bool strlist_create_from_rhbl(const char *file, bool lock,
                                     trie_t **phosts, trie_t **pdomains)
{
    trie_t *hosts, *domains;
    uint32_t host_count, domain_count;
    file_map_t map;
    const char *p, *end;
    char line[BUFSIZ];

    if (!file_map_open(&map, file, false)) {
        return false;
    }
    p   = map.map;
    end = map.end;
    while (end > p && end[-1] != '\n') {
        --end;
    }
    if (end != map.end) {
        warn("file %s miss a final \\n, ignoring last line",
             file);
    }

    hosts = trie_new();
    host_count = 0;
    domains = trie_new();
    domain_count = 0;
    while (p < end && p != NULL) {
        const char *eol = (char *)memchr(p, '\n', end - p);
        if (eol == NULL) {
            eol = end;
        }
        if (eol - p >= BUFSIZ) {
            err("unreasonnable long line");
            file_map_close(&map);
            trie_delete(&hosts);
            trie_delete(&domains);
            return false;
        }
        if (*p != '#') {
            const char *eos = eol;
            while (p < eos && isspace(*p)) {
                ++p;
            }
            while (p < eos && isspace(eos[-1])) {
                --eos;
            }
            if (p < eos) {
                if (isalnum(*p)) {
                    strlist_copy(line, p, eos - p, true);
                    trie_insert(hosts, line);
                    ++host_count;
                } else if (*p == '*') {
                    ++p;
                    strlist_copy(line, p, eos - p, true);
                    trie_insert(domains, line);
                    ++domain_count;
                }
            }
        }
        p = eol + 1;
    }
    file_map_close(&map);
    if (host_count > 0) {
        trie_compile(hosts, lock);
        *phosts = hosts;
    } else {
        trie_delete(&hosts);
        *phosts = NULL;
    }
    if (domain_count > 0) {
        trie_compile(domains, lock);
        *pdomains = domains;
    } else {
        trie_delete(&domains);
        *pdomains = NULL;
    }
    return hosts != NULL || domains != NULL;

}


static bool strlist_filter_constructor(filter_t *filter)
{
    strlist_config_t *config = strlist_config_new();

#define PARSE_CHECK(Expr, Str, ...)                                            \
    if (!(Expr)) {                                                             \
        err(Str, ##__VA_ARGS__);                                               \
        strlist_config_delete(&config);                                        \
        return false;                                                          \
    }

    config->hard_threshold = 1;
    config->soft_threshold = 1;
    foreach (filter_param_t *param, filter->params) {
        switch (param->type) {
          /* file parameter is:
           *  [no]lock:(partial-)(prefix|suffix):weight:filename
           *  valid options are:
           *    - lock:   memlock the database in memory.
           *    - nolock: don't memlock the database in memory.
           *    - prefix: perform "prefix" compression on storage.
           *    - suffix  perform "suffix" compression on storage.
           *    - \d+:    a number describing the weight to give to the match
           *              the given list [mandatory]
           *  the file pointed by filename MUST be a valid string list (one string per
           *  line, empty lines and lines beginning with a '#' are ignored).
           */
          case ATK_FILE: {
            bool lock = false;
            int  weight = 0;
            bool reverse = false;
            bool partial = false;
            trie_t *trie = NULL;
            const char *current = param->value;
            const char *p = m_strchrnul(param->value, ':');
            char *next = NULL;
            for (int i = 0 ; i < 4 ; ++i) {
                PARSE_CHECK(i == 3 || *p,
                            "file parameter must contains a locking state "
                            "and a weight option");
                switch (i) {
                  case 0:
                    if ((p - current) == 4 && strncmp(current, "lock", 4) == 0) {
                        lock = true;
                    } else if ((p - current) == 6 && strncmp(current, "nolock", 6) == 0) {
                        lock = false;
                    } else {
                        PARSE_CHECK(false, "illegal locking state %.*s",
                                    (int)(p - current), current);
                    }
                    break;

                  case 1:
                    if (p - current > (ssize_t)strlen("partial-") 
                        && strncmp(current, "partial-", strlen("partial-")) == 0) {
                        partial = true;
                        current += strlen("partial-");
                    }
                    if ((p - current) == 6 && strncmp(current, "suffix", 6) == 0) {
                        reverse = true;
                    } else if ((p - current) == 6 && strncmp(current, "prefix", 6) == 0) {
                        reverse = false;
                    } else {
                        PARSE_CHECK(false, "illegal character order value %.*s",
                                    (int)(p - current), current);
                    }
                    break;

                  case 2:
                    weight = strtol(current, &next, 10);
                    PARSE_CHECK(next == p && weight >= 0 && weight <= 1024,
                                "illegal weight value %.*s",
                                (int)(p - current), current);
                    break;

                  case 3:
                    trie = strlist_create(current, reverse, lock);
                    PARSE_CHECK(trie != NULL,
                                "cannot load string list from %s", current);
                    array_add(config->tries, trie);
                    array_add(config->weights, weight);
                    array_add(config->reverses, reverse);
                    array_add(config->partiales, partial);
                    break;
                }
                if (i != 3) {
                    current = p + 1;
                    p = m_strchrnul(current, ':');
                }
            }
          } break;

          /* rbldns parameter is:
           *  [no]lock::weight:filename
           *  valid options are:
           *    - lock:   memlock the database in memory.
           *    - nolock: don't memlock the database in memory.
           *    - \d+:    a number describing the weight to give to the match
           *              the given list [mandatory]
           *  directly import a file issued from a rhbl in rbldns format.
           */
          case ATK_RBLDNS: {
            bool lock = false;
            int  weight = 0;
            trie_t *trie_hosts   = NULL;
            trie_t *trie_domains = NULL;
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
                    } else if ((p - current) == 6 && strncmp(current, "nolock", 6) == 0) {
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
                    PARSE_CHECK(strlist_create_from_rhbl(current, lock,
                                                         &trie_hosts, &trie_domains),
                                "cannot load string list from rhbl %s", current);
                    if (trie_hosts != NULL) {
                        array_add(config->tries, trie_hosts);
                        array_add(config->weights, weight);
                        array_add(config->reverses, true);
                        array_add(config->partiales, false);
                    }
                    if (trie_domains != NULL) {
                        array_add(config->tries, trie_domains);
                        array_add(config->weights, weight);
                        array_add(config->reverses, true);
                        array_add(config->partiales, true);
                    }
                    config->is_hostname = true;
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
                    array_add(config->host_offsets, array_len(config->hosts));
                    array_append(config->hosts, current, strlen(current) + 1);
                    array_add(config->host_weights, weight);
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
          FILTER_PARAM_PARSE_INT(HARD_THRESHOLD, config->hard_threshold);

          /* soft_threshold parameter is an integer.
           *  if the matching score is greater or equal than this threshold
           *  and smaller or equal than the hard_threshold, the hook "soft_match"
           *  is called.
           * default is 1;
           */
          FILTER_PARAM_PARSE_INT(SOFT_THRESHOLD, config->soft_threshold);

          /* fields to match againes:
           *  fields = field_name(,field_name)*
           *  field_names are
           *    - hostname: helo_name,client_name,reverse_client_name
           *    - email: sender,recipient
           */
          case ATK_FIELDS: {
            const char *current = param->value;
            const char *p = m_strchrnul(param->value, ',');
            do {
                postlicyd_token tok = policy_tokenize(current, p - current);
                switch (tok) {
#define           CASE(Up, Low, Type)                                          \
                  case PTK_ ## Up:                                             \
                    config->match_ ## Low = true;                              \
                    config->is_ ## Type = true;                                \
                    break
                  CASE(HELO_NAME, helo, hostname);
                  CASE(CLIENT_NAME, client, hostname);
                  CASE(REVERSE_CLIENT_NAME, reverse, hostname);
                  CASE(SENDER_DOMAIN, sender, hostname);
                  CASE(RECIPIENT_DOMAIN, recipient, hostname);
                  CASE(SENDER, sender, email);
                  CASE(RECIPIENT, recipient, email);
#undef CASE
                  default:
                    PARSE_CHECK(false, "unknown field %.*s", (int)(p - current), current);
                    break;
                }
                if (!*p) {
                    break;
                }
                current = p + 1;
                p = m_strchrnul(current, ',');
            } while (true);
          } break;

          default: break;
        }
    }}

    PARSE_CHECK(config->is_email != config->is_hostname,
                "matched field MUST be emails XOR hostnames");
    PARSE_CHECK(config->tries.len || config->host_offsets.len,
                "no file parameter in the filter %s", filter->name);
    filter->data = config;
    return true;
}

static void strlist_filter_destructor(filter_t *filter)
{
    strlist_config_t *config = filter->data;
    strlist_config_delete(&config);
    filter->data = config;
}

static void strlist_filter_async(rbl_result_t *result, void *arg)
{
    filter_context_t   *context = arg;
    const filter_t      *filter = context->current_filter;
    const strlist_config_t *data = filter->data;
    strlist_async_data_t  *async = context->contexts[filter_type];

    if (*result != RBL_ERROR) {
        async->error = false;
    }
    --async->awaited;

    debug("got asynchronous request result for filter %s, rbl %d, still awaiting %d answers",
          filter->name, result - array_ptr(async->results, 0), async->awaited);

    if (async->awaited == 0) {
        filter_result_t res = HTK_FAIL;
        if (async->error) {
            res = HTK_ERROR;
        } else {
            uint32_t j = 0;
#define DO_SUM(Field)                                                          \
        if (data->match_ ## Field) {                                           \
            for (uint32_t i = 0 ; i < array_len(data->host_offsets) ; ++i) {   \
                int weight = array_elt(data->host_weights, i);                 \
                                                                               \
                switch (array_elt(async->results, j)) {                        \
                  case RBL_ASYNC:                                              \
                    crit("no more awaited answer but result is ASYNC");        \
                    abort();                                                   \
                  case RBL_FOUND:                                              \
                    async->sum += weight;                                      \
                    break;                                                     \
                  default:                                                     \
                    break;                                                     \
                }                                                              \
                ++j;                                                           \
            }                                                                  \
        }
            DO_SUM(helo);
            DO_SUM(client);
            DO_SUM(reverse);
            DO_SUM(recipient);
            DO_SUM(sender);
#undef DO_SUM
            debug("score is %d", async->sum);
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


static filter_result_t strlist_filter(const filter_t *filter, const query_t *query,
                                      filter_context_t *context)
{
    char reverse[BUFSIZ];
    char normal[BUFSIZ];
    const strlist_config_t *config = filter->data;
    strlist_async_data_t *async = context->contexts[filter_type];
    int result_pos = 0;
    async->sum = 0;
    async->error = true;
    array_ensure_exact_capacity(async->results, (config->match_client
                                + config->match_sender + config->match_helo
                                + config->match_recipient + config->match_reverse)
                                * array_len(config->host_offsets));
    async->awaited = 0;


    if (config->is_email && 
        ((config->match_sender && query->state < SMTP_MAIL)
        || (config->match_recipient && query->state != SMTP_RCPT))) {
        warn("trying to match an email against a field that is not "
             "available in current protocol state");
        return HTK_ABORT;
    } else if (config->is_hostname && config->match_helo && query->state < SMTP_HELO) {
        warn("trying to match hostname against helo before helo is received");
        return HTK_ABORT;
    }
#define LOOKUP(Flag, Field)                                                    \
    if (config->match_ ## Flag) {                                              \
        const int len = m_strlen(query->Field);                                \
        strlist_copy(normal, query->Field, len, false);                        \
        strlist_copy(reverse, query->Field, len, true);                        \
        for (uint32_t i = 0 ; i < config->tries.len ; ++i) {                   \
            const int weight   = array_elt(config->weights, i);                \
            const trie_t *trie = array_elt(config->tries, i);                  \
            const bool rev     = array_elt(config->reverses, i);               \
            const bool part    = array_elt(config->partiales, i);              \
            if ((!part && trie_lookup(trie, rev ? reverse : normal))           \
                || (part && trie_prefix(trie, rev ? reverse : normal))) {      \
                async->sum += weight;                                          \
                if (async->sum >= (uint32_t)config->hard_threshold) {          \
                    return HTK_HARD_MATCH;                                     \
                }                                                              \
            }                                                                  \
            async->error = false;                                              \
        }                                                                      \
    }
#define DNS(Flag, Field)                                                       \
    if (config->match_ ## Flag) {                                              \
        const int len = m_strlen(query->Field);                                \
        strlist_copy(normal, query->Field, len, false);                        \
        for (uint32_t i = 0 ; len > 0 && i < config->host_offsets.len ; ++i) { \
            const char *rbl = array_ptr(config->hosts,                         \
                                        array_elt(config->host_offsets, i));   \
            if (rhbl_check(normal, rbl, array_ptr(async->results, result_pos), \
                           strlist_filter_async, context)) {                   \
                async->error = false;                                          \
                ++async->awaited;                                              \
            }                                                                  \
            ++result_pos;                                                      \
        }                                                                      \
    }

    if (config->is_email) {
        LOOKUP(sender, sender);
        LOOKUP(recipient, recipient);
        DNS(sender, sender);
        DNS(recipient, recipient);
    } else if (config->is_hostname) {
        LOOKUP(helo, helo_name);
        LOOKUP(client, client_name);
        LOOKUP(reverse, reverse_client_name);
        LOOKUP(recipient, recipient_domain);
        LOOKUP(sender, sender_domain);
        DNS(helo, helo_name);
        DNS(client, client_name);
        DNS(reverse, reverse_client_name);
        DNS(recipient, recipient_domain);
        DNS(sender, sender_domain);
    }
#undef  DNS
#undef  LOOKUP
    if (async->awaited > 0) {
        return HTK_ASYNC;
    }
    if (async->error) {
        err("filter %s: all the rbls returned an error", filter->name);
        return HTK_ERROR;
    }
    if (async->sum >= (uint32_t)config->hard_threshold) {
        return HTK_HARD_MATCH;
    } else if (async->sum >= (uint32_t)config->soft_threshold) {
        return HTK_SOFT_MATCH;
    } else {
        return HTK_FAIL;
    }
}

static void *strlist_context_constructor(void)
{
    return p_new(strlist_async_data_t, 1);
}

static void strlist_context_destructor(void *data)
{
    strlist_async_data_t *ctx = data;
    array_wipe(ctx->results);
    p_delete(&ctx);
}

static int strlist_init(void)
{
    filter_type =  filter_register("strlist", strlist_filter_constructor,
                                   strlist_filter_destructor, strlist_filter,
                                   strlist_context_constructor,
                                   strlist_context_destructor);
    /* Hooks.
     */
    (void)filter_hook_register(filter_type, "abort");
    (void)filter_hook_register(filter_type, "error");
    (void)filter_hook_register(filter_type, "fail");
    (void)filter_hook_register(filter_type, "hard_match");
    (void)filter_hook_register(filter_type, "soft_match");

    /* Parameters.
     */
    (void)filter_param_register(filter_type, "file");
    (void)filter_param_register(filter_type, "rbldns");
    (void)filter_param_register(filter_type, "dns");
    (void)filter_param_register(filter_type, "hard_threshold");
    (void)filter_param_register(filter_type, "soft_threshold");
    (void)filter_param_register(filter_type, "fields");
    return 0;
}
module_init(strlist_init);
