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
 * Copyright © 2009 Florent Bruneau
 */

#include <ctype.h>
#include <arpa/inet.h>

#include "spf.h"
#include "spf_tokens.h"
#include "buffer.h"

#define SPF_MAX_RECUSION 15

typedef struct spf_rule_t {
    spf_code_t qualifier;
    spf_ruleid_t rule;
    buffer_t content;
} spf_rule_t;
ARRAY(spf_rule_t);
#define SPF_RULE_INIT { 0, 0, ARRAY_INIT }

struct spf_t {
    unsigned txt_received : 1;
    unsigned txt_inerror  : 1;
    unsigned txt_toomany  : 1;
    unsigned spf_received : 1;
    unsigned spf_inerror  : 1;
    unsigned spf_nolookup : 1;
    unsigned canceled     : 1;
    unsigned is_ip6       : 1;

    uint32_t ip4;
    uint8_t ip6[16];
    buffer_t ip;
    buffer_t domain;
    buffer_t sender;
    buffer_t helo;

    buffer_t record;
    A(spf_rule_t) rules;
    uint8_t current_rule;
    int8_t redirect;

    int cidr4;
    int cidr6;
    buffer_t domainspec;

    int recursions;
    struct spf_t* subquery;

    uint8_t a_resolutions;
    bool a_dnserror;

    uint8_t queries;
    spf_result_t exit;
    void* data;
};

static PA(spf_t) spf_pool = ARRAY_INIT;
static A(spf_rule_t) spf_rule_pool = ARRAY_INIT;

static buffer_t expand_buffer = ARRAY_INIT;
static buffer_t query_buffer = ARRAY_INIT;
static buffer_t dns_buffer = ARRAY_INIT;

static spf_t* spf_new(void)
{
    return p_new(spf_t, 1);
}

static void spf_rule_wipe(spf_rule_t* rule)
{
    array_wipe(rule->content);
}

static void spf_wipe(spf_t* spf)
{
    array_append(spf_rule_pool, array_start(spf->rules), array_len(spf->rules));
    array_wipe(spf->rules);
    array_wipe(spf->domain);
    array_wipe(spf->ip);
    array_wipe(spf->sender);
    array_wipe(spf->helo);
    array_wipe(spf->record);
    array_wipe(spf->domainspec);
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
    array_deep_wipe(spf_rule_pool, spf_rule_wipe);
    buffer_wipe(&expand_buffer);
    buffer_wipe(&query_buffer);
    buffer_wipe(&dns_buffer);
}
module_exit(spf_module_exit);

static bool spf_release(spf_t* spf, bool decrement)
{
    if (decrement) {
        --spf->queries;
    }
    if (spf->canceled && spf->queries == 0) {
        array_append(spf_rule_pool, array_start(spf->rules), array_len(spf->rules));
        array_len(spf->rules) = 0;
        array_len(spf->domain) = 0;
        array_len(spf->ip) = 0;
        array_len(spf->sender) = 0;
        array_len(spf->record) = 0;
        array_len(spf->helo) = 0;
        array_len(spf->domainspec) = 0;
        array_add(spf_pool, spf);
        return true;
    }
    return false;
}

static bool spf_validate_domain(const char* domain) {
    int label_count = 0;
    int label_length = 0;
    const char* pos = domain;
    while (*pos != '\0') {
        if (*pos == '.') {
            if (label_length == 0) {
                debug("spf: invalid domain name \"%s\": contains a non-terminal zero-length label", domain);
                return false;
            }
            label_length = 0;
        } else if (!isalnum(*pos) && *pos != '-' && *pos != '_') {
            debug("spf: invalid domain name \"%s\": contains illegal character '%c'", domain, *pos);
            return false;
        } else {
            if (label_length == 0) {
                ++label_count;
            }
            ++label_length;
            if (label_length > 63) {
                debug("spf: invalid domain name \"%s\": contains a too long label", domain);
                return false;
            }
        }
        ++pos;
    }
    return label_count > 1;
}

static bool spf_query(spf_t* spf, const char* query, dns_rrtype_t rtype, ub_callback_t cb)
{
    array_len(query_buffer) = 0;
    buffer_addstr(&query_buffer, query);
    if (array_last(query_buffer) != '.') {
        buffer_addch(&query_buffer, '.');
    }
    debug("spf (depth=%d): performing query of type %d for %s", spf->recursions, rtype, query);
    if (dns_resolve(array_start(query_buffer), rtype, cb, spf)) {
        if (rtype == DNS_RRT_A || rtype == DNS_RRT_AAAA) {
            ++spf->a_resolutions;
        }
        ++spf->queries;
        return true;
    }
    return false;
}

static void spf_exit(spf_t* spf, spf_code_t code)
{
    if (log_level >= LOG_NOTICE) {
        const char* str = NULL;
        switch (code) {
          case SPF_NONE: str = "NONE"; break;
          case SPF_NEUTRAL: str = "NEUTRAL"; break;
          case SPF_PASS: str = "PASS"; break;
          case SPF_FAIL: str = "FAIL"; break;
          case SPF_SOFTFAIL: str = "SOFTFAIL"; break;
          case SPF_TEMPERROR: str = "TEMPERROR"; break;
          case SPF_PERMERROR: str = "PERMERROR"; break;
        }
        notice("spf (depth=%d): result for query is %s", spf->recursions, str);
    }
    if (spf->exit) {
        spf->exit(code, NULL, spf->data);
    }
    spf_cancel(spf);
}

static bool spf_expand_pattern(spf_t* spf, buffer_t* buffer, char identifier, int parts, bool reverse,
                               const char* delimiters, int delimiters_count) {
    static_str_t sections[256];
    static_str_t* pos = sections;
    switch (identifier) {
      case 's':
        pos->str = array_start(spf->sender);
        pos->len = array_len(spf->sender);
        break;
      case 'l':
        pos->str = array_start(spf->sender);
        pos->len = strchr(pos->str, '@') - pos->str;
        break;
      case 'o':
        pos->str = strchr(pos->str, '@') + 1;
        pos->len = m_strlen(pos->str);
        break;
      case 'd':
        pos->str = array_start(spf->domain);
        pos->len = array_len(spf->domain);
        break;
      case 'i':
        pos->str = array_start(spf->ip);
        pos->len = array_len(spf->ip);
        break;
      case 'p':
        warn("Macrostring expansion for 'p' not yet supported");
        pos->str = "unknown";
        pos->len = m_strlen(pos->str);
        break;
      case 'v':
        pos->str = spf->is_ip6 ? "ip6" : "in_addr";
        pos->len = m_strlen(pos->str);
        break;
      case 'h':
        pos->str = array_start(spf->helo);
        pos->len = array_len(spf->helo);
        break;
      default:
        return false;
    }
    const char* c = pos->str;
    const char* end = pos->str + pos->len;
    const char* delim_end = delimiters + delimiters_count;
    pos->len = 0;
    while (c < end) {
        const char* delim = delimiters;
        bool is_delim = false;
        while (delim < delim_end) {
            if (*c == *delim) {
                ++pos;
                is_delim = true;
                pos->str = c + 1;
                pos->len = 0;
                break;
            }
            ++delim;
        }
        if (!is_delim) {
            ++(pos->len);
        }
        ++c;
    }
    if (parts > pos - sections + 1) {
        parts = pos - sections + 1;
    }
    int i = 0;
    for (i = 0 ; i < parts ; ++i) {
        if (i != 0) {
            buffer_addch(buffer, '.');
        }
        if (reverse) {
            buffer_add(buffer, sections[i].str, sections[i].len);
        } else {
            buffer_add(buffer, pos[-i].str, pos[-i].len);
        }
    }
    return true;
}

static const char* spf_expand(spf_t* spf, const char* macrostring, int* cidr4, int* cidr6, bool expand)
{
    bool getCidr = false;
    if (cidr4 != NULL) {
        getCidr = true;
        *cidr4 = 32;
    }
    if (cidr6 != NULL) {
        getCidr = true;
        *cidr6 = 128;
    }
    if (macrostring == NULL) {
        macrostring = "";
    }
    const char* cidrStart = m_strchrnul(macrostring, '/');
    if (*cidrStart != '\0' && !getCidr) {
        debug("spf (depth=%d): cidr length found, but no cidr requested on %s", spf->recursions, macrostring);
        return NULL;
    }
    array_len(expand_buffer) = 0;
    if (expand) {
        while (macrostring < cidrStart) {
            const char* next_format = strchr(macrostring, '%');
            if (next_format == NULL || next_format >= cidrStart) {
                next_format = cidrStart;
            }
            buffer_add(&expand_buffer, macrostring, next_format - macrostring);
            macrostring = next_format;
            if (macrostring < cidrStart) {
                ++macrostring;
                switch (*macrostring) {
                  case '%':
                    buffer_addch(&expand_buffer, '%');
                    break;
                  case '_':
                    buffer_addch(&expand_buffer, ' ');
                    break;
                  case '-':
                    buffer_addstr(&expand_buffer, "%20");
                    break;
                  case '{': {
                    ++macrostring;
                    next_format = strchr(macrostring, '}');
                    if (next_format == NULL || next_format >= cidrStart) {
                        debug("spf (depth=%d): unmatched %%{ in macro \"%s\"", spf->recursions, macrostring);
                        return NULL;
                    }
                    char* end;
                    char entity = *macrostring;
                    int parts = 256;
                    bool reverse = false;
                    const char* delimiters = ".";
                    int delimiters_count = 1;
                    ++macrostring;
                    if (isdigit(*macrostring)) {
                        parts = strtol(macrostring, &end, 10);
                        if (parts < 0) {
                            debug("spf (depth=%d): invalid number of parts (%d) in macro  \"%s\"", spf->recursions, parts, macrostring);
                            return NULL;
                        }
                        macrostring = end;
                    }
                    if (*macrostring == 'r') {
                        reverse = true;
                        ++macrostring;
                    }
                    if (macrostring < next_format) {
                        delimiters = macrostring;
                        delimiters_count = next_format - delimiters;
                    }
                    if (!spf_expand_pattern(spf, &expand_buffer, entity, parts, reverse,
                                            delimiters, delimiters_count)) {
                        debug("spf (depth=%d): invalid macro %c in \"%s\"", spf->recursions, entity, macrostring);
                        return NULL;
                    }
                    macrostring = next_format;
                  } break;
                }
                ++macrostring;
            }
        }
    } else {
        buffer_add(&expand_buffer, macrostring, cidrStart - macrostring);
    }
    if (*cidrStart != '\0') {
        char* end;
        ++cidrStart;
        if (*cidrStart == '/') {
            if (cidr4 == NULL || cidr6 == NULL) {
                debug("spf (depth=%d): invalid cidr4 length in macrostring \"%s\"", spf->recursions, macrostring);
                return NULL;
            }
            ++cidrStart;
            *cidr6 = strtol(cidrStart, &end, 10);
            if (end == cidrStart || *end != '\0' || *cidr6 < 0 || *cidr6 > 128) {
                debug("spf (depth=%d): invalid cidr6 length in macrostring \"%s\"", spf->recursions, macrostring);
                return NULL;
            }
        } else {
            int count = strtol(cidrStart, &end, 10);
            if (end == cidrStart) {
                debug("spf (depth=%d): invalid cidr length in macrostring \"%s\"", spf->recursions, macrostring);
                return NULL;
            }
            cidrStart = end;
            if (cidr4 != NULL) {
                if (count < 0 || count > 32) {
                    debug("spf (depth=%d): invalid cidr4 length in macrostring \"%s\"", spf->recursions, macrostring);
                    return NULL;
                }
                *cidr4 = count;
                if (*cidrStart == '/') {
                    ++cidrStart;
                    if (cidr6 == NULL || *cidrStart != '/') {
                        debug("spf (depth=%d): invalid cidr6 length in macrostring \"%s\"", spf->recursions, macrostring);
                        return NULL;
                    }
                    ++cidrStart;
                    *cidr6 = strtol(cidrStart, &end, 10);
                    if (end == cidrStart || *end != '\0' || *cidr6 < 0 || *cidr6 > 128) {
                        debug("spf (depth=%d): invalid cidr6 length in macrostring \"%s\"", spf->recursions, macrostring);
                        return NULL;
                    }
                }
            } else {
                if (count < 0 || count > 128 || *cidrStart != '\0') {
                    debug("spf (depth=%d): invalid cidr6 length in macrostring \"%s\"", spf->recursions, macrostring);
                    return NULL;
                }
                *cidr6 = count;
            }
        }
    }
    if (cidr4 != NULL) {
        if (cidr6 != NULL) {
            debug("spf (depth=%d): macro \"%s\" parsed: \"%s\" with cidr4=%d cidr6=%d", spf->recursions,
                  macrostring, array_start(expand_buffer), *cidr4, *cidr6);
        } else {
            debug("spf (depth=%d): macro \"%s\" parsed: \"%s\" with cidr4=%d", spf->recursions,
                  macrostring, array_start(expand_buffer), *cidr4);
        }
    } else if (cidr6 != NULL) {
        debug("spf (depth=%d): macro \"%s\" parsed: \"%s\" with cidr6=%d", spf->recursions,
              macrostring, array_start(expand_buffer), *cidr6);
    } else {
        debug("spf (depth=%d): macro \"%s\" parsed: \"%s\"", spf->recursions, macrostring, array_start(expand_buffer));
    }
    return array_start(expand_buffer);
}


/* Rule processing
 */
static void spf_include_exit(spf_code_t result, const char* exp, void* arg);
static void spf_redirect_exit(spf_code_t result, const char* exp, void* arg);
static void spf_a_receive(void* arg, int err, struct ub_result* result);
static void spf_aaaa_receive(void* arg, int err, struct ub_result* result);
static void spf_mx_receive(void* arg, int err, struct ub_result* result);
static void spf_exists_receive(void* arg, int err, struct ub_result* result);
static void spf_ptr_receive(void* arg, int err, struct ub_result* result);

static bool spf_subquery(spf_t* spf, const char* domain, spf_result_t cb)
{
    if (spf->recursions >= SPF_MAX_RECUSION) {
        return false;
    } else {
        spf_code_t code;
        spf->subquery = spf_check(array_start(spf->ip), domain,
                                  array_start(spf->sender), array_start(spf->helo),
                                  cb, spf->spf_nolookup, spf, &code);
        if (spf->subquery == NULL) {
            return false;
        }
        spf->subquery->recursions = spf->recursions + 1;
        return true;
    }
}

static bool parse_ip4(uint32_t* result, const char* txt)
{
    if (inet_pton(AF_INET, txt, result) != 1) {
        return false;
    }
    *result = ntohl(*result);
    return true;
}

static bool parse_ip6(uint8_t* result, const char* txt)
{
    if (inet_pton(AF_INET6, txt, result) != 1) {
        return false;
    }
    return true;
}

static bool spf_checkip4(spf_t* spf, uint32_t ip, int cidr)
{
    uint32_t mask = 0xffffffff;
    if (spf->is_ip6) {
        return false;
    }
    if (cidr < 0) {
        cidr = 32;
    }
    mask <<= 32 - cidr;
    return (spf->ip4 & mask) == (ip & mask);
}

static bool spf_checkip6(spf_t* spf, const uint8_t* ip, int cidr)
{
    if (!spf->is_ip6) {
        return false;
    }
    if (cidr < 0) {
        cidr = 128;
    }
    int bytes = cidr >> 3;
    int bits  = cidr & 7;
    if (bytes > 0) {
        if (memcmp(spf->ip6, ip, bytes) != 0) {
            return false;
        }
    }
    if (bits > 0) {
        if ((spf->ip6[bytes] >> (8 - bits)) != (ip[bytes] >> (8 - bits))) {
            return false;
        }
    }
    return true;
}

static void spf_match(spf_t* spf)
{
    spf_exit(spf, array_elt(spf->rules, spf->current_rule).qualifier);
}

static void spf_next(spf_t* spf, bool start)
{
    while (true) {
        if (!start) {
            ++spf->current_rule;
        }
        start = false;
        spf->a_dnserror = false;
        if (spf->current_rule >= array_len(spf->rules)) {
            if (spf->redirect >= 0) {
                debug("spf (debug=%d): reached the end of spf record, running redirect", spf->recursions);
                spf_rule_t* rule = array_ptr(spf->rules, spf->redirect);
                const char* domain = spf_expand(spf, array_start(rule->content), NULL, NULL, true);
                if (domain == NULL) {
                    spf_exit(spf, SPF_PERMERROR);
                    return;
                }
                ++domain;
                if (!spf_validate_domain(domain)) {
                    spf_exit(spf, SPF_PERMERROR);
                    return;
                }
                if (!spf_subquery(spf, domain, spf_redirect_exit)) {
                    warn("spf: maximum recursion depth exceeded, error");
                    spf_exit(spf, SPF_PERMERROR);
                }
                return;
            } else {
                debug("spf (depth=%d): reached the end of spf record", spf->recursions);
                spf_exit(spf, SPF_NEUTRAL);
                return;
            }
        }
        spf->cidr4 = 32;
        spf->cidr6 = 128;
        spf_rule_t* rule = array_ptr(spf->rules, spf->current_rule);
        notice("spf (depth=%d): processing rule %s: %s", spf->recursions,
              rule->rule == SPF_RULE_UNKNOWN ? "unknown" : spftokens[rule->rule],
              array_len(rule->content) == 0 ? "(empty)" : array_start(rule->content));
        switch (rule->rule) {
          case SPF_RULE_ALL:
            spf_exit(spf, rule->qualifier);
            return;

          case SPF_RULE_INCLUDE: {
            const char* domain = spf_expand(spf, array_start(rule->content), NULL, NULL, true);
            if (domain == NULL) {
                spf_exit(spf, SPF_PERMERROR);
                return;
            }
            ++domain;
            if (!spf_validate_domain(domain)) {
                spf_exit(spf, SPF_PERMERROR);
                return;
            }
            if (!spf_subquery(spf, domain, spf_include_exit)) {
                warn("spf: maximum recursion depth exceeded, error");
                spf_exit(spf, SPF_PERMERROR);
            }
            return;
          } break;

          case SPF_RULE_REDIRECT:
            spf->redirect = spf->current_rule;
            break;

          case SPF_RULE_MX:
          case SPF_RULE_A: {
            const char* domain = NULL;
            if (array_start(rule->content) != 0) {
                domain = spf_expand(spf, array_start(rule->content), &spf->cidr4, &spf->cidr6, true);
                if (domain == NULL) {
                    spf_exit(spf, SPF_PERMERROR);
                    return;
                }
                if (*domain != ':') {
                    domain = array_start(spf->domain);
                } else {
                    ++domain;
                }
                if (!spf_validate_domain(domain)) {
                    spf_exit(spf, SPF_PERMERROR);
                    return;
                }
            } else {
                domain = array_start(spf->domain);
            }
            if (rule->rule == SPF_RULE_MX) {
                if (!spf_query(spf, domain, DNS_RRT_MX, spf_mx_receive)) {
                    spf_exit(spf, SPF_TEMPERROR);
                }
            } else {
                if (!spf_query(spf, domain, spf->is_ip6 ? DNS_RRT_AAAA : DNS_RRT_A,
                                            spf->is_ip6 ? spf_aaaa_receive : spf_a_receive)) {
                    spf_exit(spf, SPF_TEMPERROR);
                }
            }
            return;
          } break;

          case SPF_RULE_IP4: {
            const char* ip = spf_expand(spf, array_start(rule->content), &spf->cidr4, NULL, false);
            uint32_t val;
            if (ip == NULL || !parse_ip4(&val, ip + 1)) {
                spf_exit(spf, SPF_PERMERROR);
                return;
            }
            if (spf_checkip4(spf, val, spf->cidr4)) {
                spf_match(spf);
                return;
            }
          } break;

          case SPF_RULE_IP6: {
            const char* ip = spf_expand(spf, array_start(rule->content), NULL, &spf->cidr6, false);
            uint8_t val[16];
            if (ip == NULL || !parse_ip6(val, ip + 1)) {
                spf_exit(spf, SPF_PERMERROR);
                return;
            }
            if (spf_checkip6(spf, val, spf->cidr6)) {
                spf_match(spf);
                return;
            }
          } break;

          case SPF_RULE_EXISTS: {
            const char* domain = spf_expand(spf, array_start(rule->content), NULL, NULL, true);
            if (domain == NULL) {
                spf_exit(spf, SPF_PERMERROR);
                return;
            }
            ++domain;
            if (!spf_validate_domain(domain)) {
                spf_exit(spf, SPF_PERMERROR);
                return;
            }
            spf_query(spf, domain, DNS_RRT_A, spf_exists_receive);
            return;
          } break;

          case SPF_RULE_PTR: {
            const char* domain = NULL;
            if (array_len(rule->content) == 0) {
                domain = spf_expand(spf, array_start(rule->content), NULL, NULL, true);
                if (domain == NULL) {
                    spf_exit(spf, SPF_PERMERROR);
                    return;
                }
                ++domain;
                if (!spf_validate_domain(domain)) {
                    spf_exit(spf, SPF_PERMERROR);
                    return;
                }
            } else {
                domain = array_start(spf->domain);
            }
            array_len(spf->domainspec) = 0;
            buffer_addstr(&spf->domainspec, domain);
            if (array_last(spf->domainspec) != '.') {
                buffer_addch(&spf->domainspec, '.');
            }
            array_len(dns_buffer) = 0;
            if (!spf->is_ip6) {
                buffer_addf(&dns_buffer, "%d.%d.%d.%d.in-addr.arpa.",
                            spf->ip4 & 0xff, (spf->ip4 >> 8) & 0xff,
                            (spf->ip4 >> 16) & 0xff, (spf->ip4 >> 24) & 0xff);
            } else {
                buffer_addf(&dns_buffer, "%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x."
                                         "%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.ip6.arpa.",
                            spf->ip6[15] & 0x0f, (spf->ip6[15] >> 4) & 0x0f,
                            spf->ip6[14] & 0x0f, (spf->ip6[14] >> 4) & 0x0f,
                            spf->ip6[13] & 0x0f, (spf->ip6[13] >> 4) & 0x0f,
                            spf->ip6[12] & 0x0f, (spf->ip6[12] >> 4) & 0x0f,
                            spf->ip6[11] & 0x0f, (spf->ip6[11] >> 4) & 0x0f,
                            spf->ip6[10] & 0x0f, (spf->ip6[10] >> 4) & 0x0f,
                            spf->ip6[9] & 0x0f, (spf->ip6[9] >> 4) & 0x0f,
                            spf->ip6[8] & 0x0f, (spf->ip6[8] >> 4) & 0x0f,
                            spf->ip6[7] & 0x0f, (spf->ip6[7] >> 4) & 0x0f,
                            spf->ip6[6] & 0x0f, (spf->ip6[6] >> 4) & 0x0f,
                            spf->ip6[5] & 0x0f, (spf->ip6[5] >> 4) & 0x0f,
                            spf->ip6[4] & 0x0f, (spf->ip6[4] >> 4) & 0x0f,
                            spf->ip6[3] & 0x0f, (spf->ip6[3] >> 4) & 0x0f,
                            spf->ip6[2] & 0x0f, (spf->ip6[2] >> 4) & 0x0f,
                            spf->ip6[1] & 0x0f, (spf->ip6[1] >> 4) & 0x0f,
                            spf->ip6[0] & 0x0f, (spf->ip6[0] >> 4) & 0x0f);
            }
            spf_query(spf, array_start(dns_buffer), DNS_RRT_PTR, spf_ptr_receive);
            return;
          } break;

          case SPF_RULE_UNKNOWN:
            break;

          default:
            break;
        }
    }
}

/* A Mechanism
 */
static void spf_aaaa_receive(void* arg, int err, struct ub_result* result)
{
    spf_t* spf = arg;
    int i;
    --spf->a_resolutions;
    if (spf_release(spf, true)) {
        debug("spf (depth=%d): AAAA received but processing already finished", spf->recursions);
        return;
    }
    if (err != 0 && err != 3) {
        debug("spf (depth=%d): DNS error on AAAA query for %s", spf->recursions, result->qname);
        spf->a_dnserror = true;
        if (spf->a_resolutions == 0) {
            spf_exit(spf, SPF_TEMPERROR);
        }
        return;
    }
    debug("spf (depth=%d): AAAA answer received for %s", spf->recursions, result->qname);
    if (err == 0) {
        for (i = 0 ; result->data[i] != NULL ; ++i) {
            if (spf_checkip6(spf, (uint8_t*)result->data[i], spf->cidr6)) {
                debug("spf (depth=%d): IPv6 matches with cidr=%d for query on %s", spf->recursions, spf->cidr6, result->qname);
                spf_match(spf);
                return;
            }
        }
    }
    if (spf->a_resolutions == 0) {
        if (spf->a_dnserror) {
            spf_exit(spf, SPF_TEMPERROR);
        } else {
            spf_next(spf, false);
        }
    }
}

static void spf_a_receive(void* arg, int err, struct ub_result* result)
{
    spf_t* spf = arg;
    int i;
    --spf->a_resolutions;
    if (spf_release(spf, true)) {
        debug("spf (depth=%d): A received but processing already finished", spf->recursions);
        return;
    }
    if (err != 0 && err != 3) {
        debug("spf (depth=%d): DNS error on A query for %s", spf->recursions, result->qname);
        spf->a_dnserror = true;
        if (spf->a_resolutions == 0) {
            spf_exit(spf, SPF_TEMPERROR);
        }
        return;
    }
    debug("spf (depth=%d): A answer received for %s", spf->recursions, result->qname);
    if (err == 0) {
        for (i = 0 ; result->data[i] != NULL ; ++i) {
            uint32_t ip = (((uint8_t)result->data[i][0]) << 24)
                        | (((uint8_t)result->data[i][1]) << 16)
                        | (((uint8_t)result->data[i][2]) << 8)
                        | (((uint8_t)result->data[i][3]));
            if (spf_checkip4(spf, ip, spf->cidr4)) {
                debug("spf (depth=%d): IPv4 (%d.%d.%d.%d) matches with cidr=%d for query on %s", spf->recursions,
                      result->data[i][0], result->data[i][1], result->data[i][2], result->data[i][3],
                      spf->cidr4, result->qname);
                spf_match(spf);
                return;
            } else {
                debug("spf (depth=%d): IPv4 (%d.%d.%d.%d) does not match with cidr=%d for query on %s", spf->recursions,
                      result->data[i][0], result->data[i][1], result->data[i][2], result->data[i][3],
                      spf->cidr4, result->qname);
            }
        }
    }
    if (spf->a_resolutions == 0) {
        if (spf->a_dnserror) {
            spf_exit(spf, SPF_TEMPERROR);
        } else {
            spf_next(spf, false);
        }
    }
}

/* MX Mechanism
 */
static void spf_mx_receive(void* arg, int err, struct ub_result* result)
{
    spf_t* spf = arg;
    int i;
    if (spf_release(spf, true)) {
        debug("spf (depth=%d): MX received but processing already finished", spf->recursions);
        return;
    }
    if (err != 0 && err != 3) {
        debug("spf (depth=%d): DNS error on query for MX entry for %s", spf->recursions, result->qname);
        spf_exit(spf, SPF_TEMPERROR);
        return;
    }
    debug("spf (depth=%d): MX entry received for %s", spf->recursions, result->qname);
    if (err == 0) {
        for (i = 0 ; result->data[i] != NULL ; ++i) {
            const char* pos = result->data[i] + 2;
            array_len(dns_buffer) = 0;
            if (i >= 10) {
                notice("spf (depth=%d): too many MX entries for %s", spf->recursions, result->qname);
                break;
            }
            while (*pos != '\0') {
                uint8_t count = *pos;
                ++pos;
                buffer_add(&dns_buffer, pos, count);
                buffer_addch(&dns_buffer, '.');
                pos += count;
            }
            spf_query(spf, array_start(dns_buffer), spf->is_ip6 ? DNS_RRT_AAAA : DNS_RRT_A,
                                                    spf->is_ip6 ? spf_aaaa_receive : spf_a_receive);
        }
    }
    if (spf->a_resolutions == 0) {
        notice("spf (depth=%d): no MX entry for %s", spf->recursions, result->qname);
        spf_next(spf, false);
    }
}

/* EXISTS Mechanism
 */
static void spf_exists_receive(void* arg, int err, struct ub_result* result)
{
    spf_t* spf = arg;
    if (spf_release(spf, true)) {
        debug("spf (depth=%d): A received but processing already finished", spf->recursions);
        return;
    }
    if (err != 0 && err != 3) {
        debug("spf (depth=%d): DNS error on A query for existence for %s", spf->recursions, result->qname);
        spf_exit(spf, SPF_TEMPERROR);
        return;
    }
    debug("spf (depth=%d): existence query received for %s", spf->recursions, result->qname);
    if (err == 0) {
        spf_match(spf);
    } else {
        spf_next(spf, false);
    }
}

/* PTR Mechanism
 */
static void spf_ptr_a_receive(void* arg, int err, struct ub_result* result)
{
    spf_t* spf = arg;
    --spf->a_resolutions;
    if (spf_release(spf, true)) {
        debug("spf (depth=%d): A received but processing already finished", spf->recursions);
        return;
    }
    if (err != 0 && err != 3) {
        debug("spf (depth=%d): DNS error for A query on %s", spf->recursions, result->qname);
        spf->a_dnserror = true;
        if (spf->a_resolutions == 0) {
            spf_exit(spf, SPF_TEMPERROR);
        }
        return;
    }
    debug("spf (depth=%d): A entry received following PTR request for %s", spf->recursions, result->qname);
    if (err == 0) {
        int i;
        for (i = 0 ; result->data[i] != NULL ; ++i) {
            bool match = false;
            if (spf->is_ip6) {
                assert(result->qtype == DNS_RRT_AAAA);
                if (memcmp(result->data[i], spf->ip6, 16) == 0) {
                    match = true;
                }
            } else {
                assert(result->qtype == DNS_RRT_A);
                uint32_t ip = (((uint8_t)result->data[i][0]) << 24)
                            | (((uint8_t)result->data[i][1]) << 16)
                            | (((uint8_t)result->data[i][2]) << 8)
                            | (((uint8_t)result->data[i][3]));
                match = (ip == spf->ip4);
            }
            if (match) {
                notice("spf (depth=%d): PTR validated by domain %s", spf->recursions, result->qname);
                spf_match(spf);
                return;
            }
        }
    }
    if (spf->a_resolutions == 0) {
        if (spf->a_dnserror) {
            spf_exit(spf, SPF_TEMPERROR);
        } else {
            spf_next(spf, false);
        }
    }
}

static void spf_ptr_receive(void* arg, int err, struct ub_result* result)
{
    spf_t* spf = arg;
    if (spf_release(spf, true)) {
        debug("spf (depth=%d): PTR received but processing already finished", spf->recursions);
        return;
    }
    if (err != 0 && err != 3) {
        debug("spf (depth=%d): DNS error for PTR query on %s", spf->recursions, result->qname);
        spf_exit(spf, SPF_TEMPERROR);
        return;
    }
    debug("spf (depth=%d): PTR entry received for query %s", spf->recursions, result->qname);
    if (err == 0) {
        int i;
        for (i = 0 ; result->data[i] != NULL ; ++i) {
            const char* pos = result->data[i];
            array_len(dns_buffer) = 0;
            if (spf->a_resolutions >= 10) {
                notice("spf (depth=%d): too many PTR entries for %s", spf->recursions, result->qname);
                break;
            }
            while (*pos != '\0') {
                uint8_t count = *pos;
                ++pos;
                buffer_add(&dns_buffer, pos, count);
                buffer_addch(&dns_buffer, '.');
                pos += count;
            }

            ssize_t diff = array_len(dns_buffer) - array_len(spf->domainspec);
            bool match = false;
            if (diff == 0) {
                if (strcasecmp(array_start(spf->domainspec), array_start(dns_buffer)) == 0) {
                    debug("spf (depth=%d): PTR potential entry found for domain %s", spf->recursions, array_start(dns_buffer));
                    match = true;
                }
            } else if (diff > 0 && array_elt(dns_buffer, diff - 1) == '.') {
                if (strcasecmp(array_start(spf->domainspec), array_ptr(dns_buffer, diff)) == 0) {
                    debug("spf (depth=%d): PTR potential entry found for subdomain %s", spf->recursions, array_start(dns_buffer));
                    match = true;
                }
            }
            if (match) {
                spf_query(spf, array_start(dns_buffer), spf->is_ip6 ? DNS_RRT_AAAA : DNS_RRT_A, spf_ptr_a_receive);
            }
        }
    }
    if (spf->a_resolutions == 0) {
        spf_next(spf, false);
    }
}

/* INCLUDE Mechanism
 */
static void spf_include_exit(spf_code_t result, const char* exp, void* arg)
{
    spf_t* spf = arg;
    spf->subquery = NULL;
    switch (result) {
      case SPF_PASS:
        debug("spf (depth=%d): include matched", spf->recursions);
        spf_match(spf);
        return;

      case SPF_FAIL:
      case SPF_SOFTFAIL:
      case SPF_NEUTRAL:
        spf_next(spf, false);
        return;

      case SPF_TEMPERROR:
        spf_exit(spf, SPF_TEMPERROR);
        return;

      case SPF_PERMERROR:
      case SPF_NONE:
      default:
        spf_exit(spf, SPF_PERMERROR);
        return;
    }
}

/* REDIRECT Modifier
 */
static void spf_redirect_exit(spf_code_t result, const char* exp, void* arg)
{
    spf_t* spf = arg;
    spf->subquery = NULL;
    if (result == SPF_NONE) {
        spf_exit(spf, SPF_PERMERROR);
    } else {
        debug("spf (depth=%d): redirect matched", spf->recursions);
        spf_exit(spf, result);
    }
}


/*  Parsing   */

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
        return SPF_PASS;
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

static bool spf_check_domainspec(const char* pos, const char* end,
                                 bool with_cidr_length, bool allow_empty)
{
#define READ_NEXT                                                              \
    ++pos;                                                                     \
    if (pos == end) {                                                          \
        return can_be_end;                                                     \
    }

    bool can_be_end = allow_empty;
    if (pos >= end) {
        return can_be_end;
    }
    if (*pos == ':' || *pos == '=') {
        can_be_end = false;
        READ_NEXT;
    }
    while (pos < end) {
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
                if (*pos == '-' && has_alpha) {
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
            can_be_end = false;
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
        } else {
            can_be_end = false;
        }
        READ_NEXT;
    }
    return can_be_end;

#undef READ_NEXT
}

static bool spf_parse(spf_t* spf) {
    const char* pos = array_start(spf->record);
    const char* end = pos + array_len(spf->record);
    pos += 6;
    do {
        while (*pos == ' ') {
            ++pos;
        }
        if (*pos == '\0') {
            return true;
        }
        const char* rule_start = pos;
        const char* name_end = NULL;
        while (*pos != ' ' && pos < end) {
            if (name_end == NULL && (*pos == ':' || *pos == '=' || *pos == '/')) {
                name_end = pos;
            }
            ++pos;
        }
        if (name_end == NULL) {
            name_end = pos;
        }
        bool is_mechanism = (name_end == end || *name_end == ' ' || *name_end == ':' || *name_end == '/');
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
                if (*name_end == ':' || *name_end == '/') {
                    return false;
                }
                break;

              case SPF_RULE_INCLUDE:
              case SPF_RULE_EXISTS:
                if (*name_end != ':') {
                    return false;
                }
                if (!spf_check_domainspec(name_end, pos, false, false)) {
                    return false;
                }
                break;

              case SPF_RULE_A:
              case SPF_RULE_MX:
                if (!spf_check_domainspec(name_end, pos, true, true)) {
                    return false;
                }
                break;

              case SPF_RULE_PTR:
                if (!spf_check_domainspec(name_end, pos, false, true)) {
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
                if (!spf_check_domainspec(name_end, pos, false, true)) {
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

        spf_rule_t rule = SPF_RULE_INIT;
        if (array_len(spf_rule_pool) > 0) {
            rule = array_pop_last(spf_rule_pool);
        }
        rule.qualifier = qual;
        rule.rule = id;
        array_len(rule.content) = 0;
        if (name_end != pos) {
            buffer_add(&rule.content, name_end, pos - name_end);
        }
        array_add(spf->rules, rule);
    } while (true);
    return true;
}

static void spf_line_callback(void *arg, int err, struct ub_result* result)
{
    spf_t* spf = arg;
    if (spf_release(spf, true)) {
        debug("spf (depth=%d): %s for %s received but processing already finished", spf->recursions,
              result->qtype == DNS_RRT_TXT ? "TXT" : "SPF", result->qname);
        return;
    }
    if (array_len(spf->record) != 0 && spf->spf_received) {
        debug("spf (depth=%d): record already found for %s", spf->recursions, result->qname);
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
    debug("spf (depth=%d): %s for %s received", spf->recursions,
          result->qtype == DNS_RRT_TXT ? "TXT" : "SPF", result->qname);
    if (result->rcode == 0) {
        int i = 0;
        bool is_mine = false;
        for (i = 0 ; result->data[i] != NULL ; ++i) {
            /* Parse field: (RFC 1035)
             * TXT-DATA: One or more <character-string>
             * <character-string> is a single
             * length octet followed by that number of characters.  <character-string>
             * is treated as binary information, and can be up to 256 characters in
             * length (including the length octet).
             */
            const char* pos = result->data[i];
            const char* const end = pos + result->len[i];
            array_len(expand_buffer) = 0;
            while (pos < end) {
                const int len = *pos;
                buffer_add(&expand_buffer, pos + 1, len);
                pos += len + 1;
            }

            /* Looking for spf fields. (RFC 4408)
             *  record           = version terms *SP
             *  version          = "v=spf1"
             *
             *  1. Records that do not begin with a version section of exactly
             *     "v=spf1" are discarded.  Note that the version section is
             *     terminated either by an SP character or the end of the record.  A
             *     record with a version section of "v=spf10" does not match and
             *     must  be discarded.
             */
            const char* str = array_start(expand_buffer);
            const int len   = array_len(expand_buffer);
            if (len < 6) {
                debug("spf (depth=%d): entry too short to be a spf record", spf->recursions);
            } else {
                if (strncasecmp(str, "v=spf1", 6) != 0) {
                    debug("spf (depth=%d): not a record: \"%.*s\"", spf->recursions, len, str);
                } else if (len == 6 || str[6] == ' ') {
                    debug("spf (depth=%d): record found: \"%.*s\"", spf->recursions, len, str);
                    /* After the above steps, there should be exactly one record remaining
                     * and evaluation can proceed.  If there are two or more records
                     * remaining, then check_host() exits immediately with the result of
                     * "PermError".
                     */
                    if (array_len(spf->record) != 0) {
                        if (is_mine || result->qtype != DNS_RRT_SPF) {
                            if (spf->spf_received) {
                                notice("spf (depth=%d): too many records", spf->recursions);
                                spf_exit(spf, SPF_PERMERROR);
                                return;
                            } else {
                                spf->txt_toomany = true;
                                array_len(spf->record) = 0;
                                return;
                            }
                        } else {
                            /* 2. If any record of type SPF are in the set, then all records
                             *    of type TXT are discarded
                             */
                            array_len(spf->record) = 0;
                        }
                    }
                    buffer_add(&spf->record, str, len);
                    is_mine = true;
                } else {
                    debug("spf (depth=%d): invalid record, version is ok, but not finished by a space: \"%.*s\"", spf->recursions, len, str);
                }
            }
        }
    }
    if (!spf->spf_received) {
        return;
    }
    if (spf->txt_inerror && spf->spf_inerror) {
        spf_exit(spf, SPF_TEMPERROR);
    } else if (spf->spf_received && spf->txt_received && array_len(spf->record) == 0) {
        /* No record found
         *
         * If no matching records are returned, an SPF client MUST assume that
         * the domain makes no SPF declarations.  SPF processing MUST stop and
         * return "None".
         */
        if (spf->txt_toomany) {
            notice("spf (depth=%d): too many records", spf->recursions);
        } else {
            notice("spf (depth=%d): no record found", spf->recursions);
        }
        spf_exit(spf, spf->txt_toomany ? SPF_PERMERROR : SPF_NONE);
    } else if (array_len(spf->record) != 0) {
        /* Parse record and start processing (RFC 4408)
         *
         * After one SPF record has been selected, the check_host() function
         * parses and interprets it to find a result for the current test.  If
         * there are any syntax errors, check_host() returns immediately with
         * the result "PermError".
         */
        if (!spf_parse(spf)) {
            notice("spf (depth=%d): cannot parse spf entry: \"%s\"", spf->recursions, array_start(spf->record));
            spf_exit(spf, SPF_PERMERROR);
        } else {
            notice("spf (depth=%d): record selected: \"%s\"", spf->recursions, array_start(spf->record));
            spf_next(spf, true);
        }
    }
}


spf_t* spf_check(const char *ip, const char *domain, const char *sender, const char* helo,
                 spf_result_t resultcb, bool no_spf_lookup, void *data, spf_code_t* code)
{
    notice("spf: new SPF lookup of (%s, %s, %s)", ip, domain, sender);
    spf_t* spf = spf_acquire();
    spf->txt_received = false;
    spf->txt_inerror  = false;
    spf->txt_toomany  = false;
    spf->spf_received = false;
    spf->spf_inerror  = false;
    spf->spf_nolookup = false;
    spf->canceled = false;
    spf->is_ip6   = false;
    spf->queries  = 0;
    spf->a_resolutions = 0;
    spf->a_dnserror = 0;
    spf->recursions = 0;
    spf->redirect = -1;
    spf->current_rule = 0;

    buffer_addstr(&spf->ip, ip);
    if (!parse_ip4(&spf->ip4, ip)) {
        if (!parse_ip6(spf->ip6, ip)) {
            *code = SPF_NONE;
            err("spf: invalid ip: %s", ip);
            spf_release(spf, false);
            return NULL;
        }
        spf->is_ip6 = true;

        /* Find IP4 mapped on IP6 */
        uint8_t mapped4to6[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
        if (memcmp(mapped4to6, spf->ip6, 12) == 0) {
            memcpy(&spf->ip4, spf->ip6 + 12, 4);
            spf->ip4 = ntohl(spf->ip4);
            spf->is_ip6 = false;
        }
    } else if (!parse_ip6(spf->ip6, ip)) {
        spf->is_ip6 = false;
    }
    spf->spf_received = spf->spf_nolookup = spf->spf_inerror = no_spf_lookup;
    buffer_addstr(&spf->domain, domain);
    buffer_addstr(&spf->sender, sender);
    buffer_addstr(&spf->helo, helo);
    const char* sender_domain = strchr(array_start(spf->sender), '@');
    if (sender_domain == array_start(spf->sender)) {
        array_len(spf->sender) = 0;
        buffer_addstr(&spf->sender, "postmaster");
        buffer_addstr(&spf->sender, sender);
        sender_domain = strchr(array_start(spf->sender), '@');
    }
    if (sender_domain == NULL
        || !spf_validate_domain(array_start(spf->domain))
        || !spf_validate_domain(sender_domain + 1)) {
        *code = SPF_NONE;
        err("spf: malformed query");
        spf_release(spf, false);
        return NULL;
    }
    spf->exit = resultcb;
    spf->data = data;
    if (!spf->spf_nolookup) {
        spf_query(spf, domain, DNS_RRT_SPF, spf_line_callback);
    }
    spf_query(spf, domain, DNS_RRT_TXT, spf_line_callback);
    if (spf->queries == 0) {
        *code = SPF_TEMPERROR;
        spf_release(spf, false);
        return NULL;
    } else {
        return spf;
    }
}

void spf_cancel(spf_t* spf)
{
    if (spf->subquery != NULL) {
        spf_cancel(spf->subquery);
        spf->subquery = NULL;
    }
    spf->canceled = true;
    spf_release(spf, false);
}

/* vim:set et sw=4 sts=4 sws=4: */
