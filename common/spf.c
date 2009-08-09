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
/*   Copyright (c) 2006-2009 the Authors                                      */
/*   see AUTHORS and source files for details                                 */
/******************************************************************************/

/*
 * Copyright © 2008-2009 Florent Bruneau
 */

#include <ctype.h>

#include "spf.h"
#include "spf_tokens.h"


typedef struct spf_rule_t {
    spf_code_t qualifier;
    spf_ruleid_t rule;
    char* content;
} spf_rule_t;
ARRAY(spf_rule_t);

struct spf_t {
    unsigned txt_received : 1;
    unsigned txt_inerror  : 1;
    unsigned spf_received : 1;
    unsigned spf_inerror  : 1;
    unsigned canceled     : 1;

    const char* ip;
    const char* domain;
    const char* sender;

    char *record;
    A(spf_rule_t) rules;
    uint8_t current_rule;

    uint8_t queries;
    spf_result_t exit;
    void* data;
};

static PA(spf_t) spf_pool = ARRAY_INIT;

static spf_t* spf_new(void)
{
    return p_new(spf_t, 1);
}

static void spf_wipe(spf_t* spf)
{
    p_delete(&spf->record);
    p_clear(spf, 1);
}

static void spf_delete(spf_t **spf)
{
    if (*spf) {
        spf_wipe(*spf);
        p_delete(spf);
    }
}

static spf_t* spf_acquire(void)
{
    if (array_len(spf_pool)) {
        return array_pop_last(spf_pool);
    }
    return spf_new();
}

static void spf_module_exit(void)
{
    array_deep_wipe(spf_pool, spf_delete);
}
module_exit(spf_module_exit);

static bool spf_release(spf_t* spf, bool decrement)
{
    if (decrement) {
        --spf->queries;
    }
    if (spf->canceled && spf->queries == 0) {
        spf_wipe(spf);
        array_add(spf_pool, spf);
        return true;
    }
    return false;
}

static bool spf_query(spf_t* spf, const char* query, dns_rrtype_t rtype, ub_callback_t cb)
{
    if (dns_resolve(query, rtype, cb, spf)) {
        ++spf->queries;
        return true;
    }
    return false;
}

static void spf_exit(spf_t* spf, spf_code_t code)
{
    if (spf->exit) {
        spf->exit(code, NULL, spf->data);
    }
    spf_cancel(spf);
}

static void spf_next(spf_t* spf)
{
    while (true) {
        ++spf->current_rule;
        if (spf->current_rule >= array_len(spf->rules)) {
            spf_exit(spf, SPF_NEUTRAL);
            return;
        }
        spf_rule_t* rule = array_ptr(spf->rules, spf->current_rule);
        switch (rule->rule) {
          case SPF_RULE_ALL:
            spf_exit(spf, rule->qualifier);
            return;

          case SPF_RULE_UNKNOWN:
            break;

          default:
            break;
        }
    }
}

static spf_code_t spf_qualifier(const char** str)
{
    switch (**str) {
      case '+':
        ++(*str);
        return SPF_PASS;
      case '-':
        ++(*str);
        return SPF_FAIL;
      case '~':
        ++(*str);
        return SPF_SOFTFAIL;
      case '?':
        ++(*str);
        return SPF_NEUTRAL;
      default:
        return SPF_NEUTRAL;
    }
}

static bool spf_check_cidrlength(const char* pos, const char* end)
{
#define READ_NEXT(CanBeEnd)                                                    \
    ++pos;                                                                     \
    if (pos == end) {                                                          \
        return CanBeEnd;                                                       \
    }

    if (*pos != '/') {
        return false;
    }
    READ_NEXT(false);
    if (*pos != '/') {
        if (!isdigit(*pos)) {
            return false;
        }
        READ_NEXT(true);
        while (pos < end) {
            if (*pos == '/') {
                break;
            }
            if (!isdigit(*pos) && *pos != '/') {
                return false;
            }
            READ_NEXT(true);
        }
        assert(*pos == '/');
    }
    READ_NEXT(false);
    do {
        if (!isdigit(*pos)) {
            return false;
        }
        READ_NEXT(true);
    } while (true);

#undef READ_NEXT
}

static bool spf_check_domainspec(const char* pos, const char* end, bool with_cidr_length, bool allow_empty)
{
#define READ_NEXT                                                              \
    ++pos;                                                                     \
    if (pos == end) {                                                          \
        return can_be_end;                                                     \
    }

    bool can_be_end = allow_empty;
    while (pos < end) {
        can_be_end = false;

        /* cidr length parsing */
        if (*pos == '/') {
            if (!with_cidr_length || !can_be_end) {
                return false;
            }
            return spf_check_cidrlength(pos, end);

        /* final dot */
        } else if (*pos == '.') {
            bool has_dash = false;
            bool has_alpha = false;
            can_be_end = true;
            READ_NEXT;
            if (!isalnum(*pos)) {
                continue;
            }
            while (pos < end) {
                if (*pos == '-') {
                    has_dash = true;
                    can_be_end = false;
                } else if (isalpha(*pos)) {
                    has_alpha = true;
                    can_be_end = true;
                } else if (isdigit(*pos)) {
                    can_be_end = (has_dash || has_alpha);
                } else if (*pos == '.') {
                    has_dash = false;
                    has_alpha = false;
                    if (!can_be_end) {
                        return false;
                    }
                    can_be_end = true;
                } else {
                    --pos;
                    break;
                }
                READ_NEXT;
            }

        /* macro expand */
        } else if (*pos == '%') {
            READ_NEXT;
            if (*pos == '%' || *pos == '_' || *pos == '-') {
                can_be_end = true;
            } else if (*pos == '{') {
                READ_NEXT;
                if (*pos != 's' && *pos != 'l' && *pos != 'o' && *pos != 'd'
                    && *pos != 'i' && *pos != 'p' && *pos != 'h' && *pos != 'c'
                    && *pos != 'r' && *pos != 't') {
                    return false;
                }
                READ_NEXT;
                while (isdigit(*pos)) {
                    READ_NEXT;
                }
                if (*pos == 'r') {
                    READ_NEXT;
                }
                while (*pos == '.' || *pos == '-' || *pos == '+' || *pos == ','
                       || *pos == '/' || *pos == '_' || *pos == '=') {
                    READ_NEXT;
                }
                if (*pos != '}') {
                    return false;
                }
                can_be_end = true;

            /* Other caracters */
            } else if (*pos < 0x21 || *pos > 0x7e) {
                return false;
            }
        }
        READ_NEXT;
    }
    return can_be_end;

#undef READ_NEXT
}

static bool spf_parse(spf_t* spf) {
    const char* pos = spf->record + 6;
    do {
        while (*pos == ' ') {
            ++pos;
        }
        if (*pos == '\0') {
            return true;
        }
        const char* rule_start = pos;
        const char* name_end = NULL;
        while (*pos != ' ' && *pos != '\0') {
            if (name_end == NULL && (*pos == ':' || *pos == '=')) {
                name_end = pos;
            }
            ++pos;
        }
        if (name_end == NULL) {
            name_end = pos;
        }
        bool is_mechanism = (*name_end == '\0' || *name_end == ' ' || *name_end == ':');
        spf_code_t qual = SPF_NEUTRAL;
        if (is_mechanism) {
            qual = spf_qualifier(&rule_start);
        }
        if (name_end - rule_start == 0) {
            return false;
        }
        spf_ruleid_t id = spf_rule_tokenize(rule_start, name_end - rule_start);
        if (is_mechanism) {
            switch (id) {
              case SPF_RULE_ALL:
                if (*name_end == ':') {
                    return false;
                }
                break;

              case SPF_RULE_INCLUDE:
              case SPF_RULE_EXISTS:
                if (*name_end != ':') {
                    return false;
                }
                if (!spf_check_domainspec(name_end + 1, pos, false, false)) {
                    return false;
                }
                break;

              case SPF_RULE_A:
              case SPF_RULE_MX:
                if (!spf_check_domainspec(name_end + 1, pos, true, true)) {
                    return false;
                }
                break;

              case SPF_RULE_PTR:
                if (!spf_check_domainspec(name_end + 1, pos, false, true)) {
                    return false;
                }
                break;

              case SPF_RULE_IP4:
              case SPF_RULE_IP6:
                break;

              default:
                return false;
            }
        } else {
            if (*name_end != '=') {
                return false;
            }
            switch (id) {
              case SPF_RULE_REDIRECT:
              case SPF_RULE_EXPLANATION:
                if (!spf_check_domainspec(name_end + 1, pos, false, true)) {
                    return false;
                }
                break;

              case SPF_RULE_UNKNOWN: {
                const char* p = rule_start;
                if (!isalpha(*p)) {
                    return false;
                }
                ++p;
                while (p < name_end) {
                    if (!isalnum(*p) && *p != '-' && *p != '_' && *p != '.') {
                        return false;
                    }
                    ++p;
                }
              } break;

              default:
                return false;
            }
        }

        info("rule found: %.*s -> %s", (int)(name_end - rule_start), rule_start,
                                       id != SPF_RULE_UNKNOWN ? spftokens[id] : "unknown");
        spf_rule_t rule;
        rule.qualifier = qual;
        rule.rule = id;
        rule.content = NULL;
        array_add(spf->rules, rule);
    } while (true);
    return true;
}

static void spf_line_callback(void *arg, int err, struct ub_result* result)
{
    spf_t* spf = arg;
    info("Coucou %d", result->qtype);
    if (spf_release(spf, true)) {
        info("processing already finished");
        return;
    }
    if (spf->record != NULL) {
        info("record already found");
        return;
    }
    if (result->qtype == DNS_RRT_SPF) {
        spf->spf_received = true;
        spf->spf_inerror  = (result->rcode != 0 && result->rcode != 3);
    }
    if (result->qtype == DNS_RRT_TXT) {
        spf->txt_received = true;
        spf->txt_inerror  = (result->rcode != 0 && result->rcode != 3);
    }
    if (result->rcode == 0) {
        int i = 0;
        while (result->data[i] != NULL) {
            const char* str = result->data[i] + 1;
            const int len   = result->len[i] - 1;
            assert(len == result->data[i][0]);
            if (len < 6) {
                info("record too short to be a spf record");
            } else {
                if (strncmp(str, "v=spf1", 6) != 0) {
                    info("not a spf record: \"%.*s\"", len, str);
                } else if (len == 6 || str[6] == ' ') {
                    info("spf record: \"%.*s\"", len, str);
                    if (spf->record != NULL) {
                        info("too many spf records");
                        spf_exit(spf, SPF_PERMERROR);
                        return;
                    }
                    spf->record = p_dupstr(str, len);
                } else {
                    info("version is ok, but not finished by a space: \"%.*s\"", len, str);
                }
            }
            ++i;
        }
    }
    if (spf->txt_inerror && spf->spf_inerror) {
        spf_exit(spf, SPF_TEMPERROR);
    } else if (spf->spf_received && spf->txt_received && spf->record == NULL) {
        spf_exit(spf, SPF_NONE);
    } else if (spf->record != NULL) {
        if (!spf_parse(spf)) {
            spf_exit(spf, SPF_PERMERROR);
        } else {
            spf_next(spf);
        }
    }
}

spf_t* spf_check(const char *ip, const char *domain, const char *sender, spf_result_t resultcb, void *data)
{
    spf_t* spf = spf_acquire();
    spf->ip = ip;
    spf->domain = domain;
    spf->sender = sender;
    spf->exit = resultcb;
    spf->data = data;
    spf_query(spf, domain, DNS_RRT_SPF, spf_line_callback);
    spf_query(spf, domain, DNS_RRT_TXT, spf_line_callback);
    if (spf->queries == 0) {
        spf_delete(&spf);
        return NULL;
    } else {
        return spf;
    }
}

void spf_cancel(spf_t* spf)
{
    spf->canceled = true;
    spf_release(spf, false);
}

/* vim:set et sw=4 sts=4 sws=4: */
