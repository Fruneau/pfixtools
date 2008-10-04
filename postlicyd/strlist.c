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
#include "policy_tokens.h"

typedef struct strlist_config_t {
    PA(trie_t) tries;
    A(int)     weights;
    A(bool)    reverses;
    A(bool)    partiales;

    int soft_threshold;
    int hard_threshold;

    unsigned is_email         :1;
    unsigned match_sender     :1;
    unsigned match_recipient  :1;

    unsigned is_hostname      :1;
    unsigned match_helo       :1;
    unsigned match_client     :1;
    unsigned match_reverse    :1;
} strlist_config_t;


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
           *  [no]lock:(prefix|suffix):weight:filename
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
                                    p - current, current);
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
                                    p - current, current);
                    }
                    break;

                  case 2:
                    weight = strtol(current, &next, 10);
                    PARSE_CHECK(next == p && weight >= 0 && weight <= 1024,
                                "illegal weight value %.*s",
                                (p - current), current);
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
                  CASE(SENDER, sender, email);
                  CASE(RECIPIENT, recipient, email);
#undef CASE
                  default:
                    PARSE_CHECK(false, "unknown field %.*s", p - current, current);
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
    PARSE_CHECK(config->tries.len,
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

static filter_result_t strlist_filter(const filter_t *filter, const query_t *query)
{
    char reverse[BUFSIZ];
    char normal[BUFSIZ];
    const strlist_config_t *config = filter->data;
    int sum = 0;
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
                sum += weight;                                                 \
                if (sum >= config->hard_threshold) {                           \
                    return HTK_HARD_MATCH;                                     \
                }                                                              \
            }                                                                  \
        }                                                                      \
    }
    if (config->is_email) {
        LOOKUP(sender, sender);
        LOOKUP(recipient, recipient);
    } else if (config->is_hostname) {
        LOOKUP(helo, helo_name);
        LOOKUP(client, client_name);
        LOOKUP(reverse, reverse_client_name);
    }
#undef  LOOKUP
    if (sum >= config->hard_threshold) {
        return HTK_HARD_MATCH;
    } else if (sum >= config->soft_threshold) {
        return HTK_SOFT_MATCH;
    } else {
        return HTK_FAIL;
    }
}

static int strlist_init(void)
{
    filter_type_t type =  filter_register("strlist", strlist_filter_constructor,
                                          strlist_filter_destructor, strlist_filter);
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
    (void)filter_param_register(type, "fields");
    return 0;
}
module_init(strlist_init);
