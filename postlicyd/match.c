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
 * Copyright © 2008 Florent Bruneau
 */

#include "filter.h"
#include "str.h"
#include "regexp.h"
#include "policy_tokens.h"

enum condition_t {
    MATCH_UNKNOWN  = 0,
    MATCH_EQUAL,
    MATCH_DIFFER,
    MATCH_CONTAINS,
    MATCH_CONTAINED,
    MATCH_EMPTY,
    MATCH_MATCH,
    MATCH_DONTMATCH,

    MATCH_NUMBER
};

typedef struct match_condition_t {
    postlicyd_token field;
    bool case_sensitive;
    enum condition_t condition;

    union {
      static_str_t value;
      regexp_t     regexp;
    } data;
} match_condition_t;
ARRAY(match_condition_t)
#define CONDITION_INIT { PTK_UNKNOWN, false, MATCH_UNKNOWN, { .value = { NULL, 0 } } }

struct match_operator_t {
    const static_str_t short_name;
    const static_str_t long_name;
    enum condition_t condition;
    bool             cs;
};

static const struct match_operator_t operators[] = {
    { {"=i", 2}, {"EQUALS_i", 8},    MATCH_EQUAL,     false },
    { {"==", 2}, {"EQUALS", 6},      MATCH_EQUAL,     true },
    { {"!i", 2}, {"DIFFERS_i", 9},   MATCH_DIFFER,    false },
    { {"!=", 2}, {"DIFFERS", 7},     MATCH_DIFFER,    true },
    { {">i", 2}, {"CONTAINS_i", 10},  MATCH_CONTAINS,  false },
    { {">=", 2}, {"CONTAINS", 8},    MATCH_CONTAINS,  true },
    { {"<i", 2}, {"CONTAINED_i", 11}, MATCH_CONTAINED, false },
    { {"<=", 2}, {"CONTAINED", 9},   MATCH_CONTAINED, true },
    { {"#=", 2}, {"EMPTY", 5},       MATCH_EMPTY,     true },
    { {"#i", 2}, {"NOTEMPTY", 8},    MATCH_EMPTY,     false },
    { {"=~", 2}, {"MATCH", 5},       MATCH_MATCH,     false },
    { {"!~", 2}, {"DONTMATCH", 9},   MATCH_DONTMATCH, false },
    { {NULL, 0}, {NULL, 0}, MATCH_UNKNOWN, false }
};

static const char *condition_names[] = {
    "unknown",
    "equals to",
    "differs from",
    "contains",
    "is contained",
    "is empty",
    "matches",
    "does not match"
};

typedef struct match_config_t {
    A(match_condition_t) conditions;
    bool match_all;
} match_config_t;

static buffer_t match_buffer = BUFFER_INIT;

static match_config_t *match_config_new(void)
{
    return p_new(match_config_t, 1);
}

static inline void match_condition_wipe(match_condition_t *condition)
{
    if (condition->condition == MATCH_MATCH || condition->condition == MATCH_DONTMATCH) {
        regexp_wipe(&condition->data.regexp);
    } else {
        char *str = (char*)condition->data.value.str;
        p_delete(&str);
        condition->data.value.str = NULL;
        condition->data.value.len = 0;
    }
}

static void match_config_delete(match_config_t **config)
{
    if (*config) {
        array_deep_wipe((*config)->conditions, match_condition_wipe);
        p_delete(config);
    }
}

static bool match_filter_constructor(filter_t *filter)
{
    match_config_t *config = match_config_new();
    buffer_t regexp = ARRAY_INIT;

#define PARSE_CHECK(Expr, Str, ...)                                            \
    if (!(Expr)) {                                                             \
        err(Str, ##__VA_ARGS__);                                               \
        match_config_delete(&config);                                          \
        buffer_wipe(&regexp);                                                  \
        return false;                                                          \
    }

    foreach (filter_param_t *param, filter->params) {
        switch (param->type) {
          FILTER_PARAM_PARSE_BOOLEAN(MATCH_ALL, config->match_all);

          /* condition parameter is:
           *  field_name OPERATOR value.
           *  valid operators are:
           *    == field_name is strictly equal to
           *    =i field_name is case insensitively equal to
           *    != field_name is not equal to
           *    !i field_name is not case insensitively equal to
           *    >= field_name contains
           *    >i field_name contains case insensitively
           *    <= field_name is contained
           *    <i field_name is contained case insensitively
           *    #= field_name is empty or not set
           *    #i field_name is not empty
           *    =~ /regexp/i? match regexp
           *    !~ /regexp/i? does not match regexp
           */
          case ATK_CONDITION: {
            match_condition_t condition = CONDITION_INIT;
            const char *p = skipspaces(param->value);
            const char *n = p + 1;
            PARSE_CHECK(isalnum(*p), "invalid field name");
            for (n = p + 1 ; *n && (isalnum(*n) || *n == '_') ; ++n);
            condition.field = policy_tokenize(p, n - p);
            PARSE_CHECK(condition.field >= PTK_HELO_NAME
                        && condition.field < PTK_SMTPD_ACCESS_POLICY,
                        "invalid field name %.*s", (int)(n - p), p);
            p = skipspaces(n);

            condition.condition = MATCH_UNKNOWN;
            const struct match_operator_t *op = operators;
            while (condition.condition == MATCH_UNKNOWN && op->condition != MATCH_UNKNOWN) {
                if (strncmp(p, op->short_name.str, op->short_name.len) == 0) {
                    condition.condition = op->condition;
                    condition.case_sensitive = op->cs;
                    p += op->short_name.len;
                    break;
                } else if (strncmp(p, op->long_name.str, op->long_name.len) == 0) {
                    condition.condition = op->condition;
                    condition.case_sensitive = op->cs;
                    p += op->long_name.len;
                    break;
                }
                ++op;
            }
            PARSE_CHECK((*p == '\0' || isspace(*p)) && condition.condition != MATCH_UNKNOWN,
                        "invalid operator");
            p = skipspaces(p);
            switch (condition.condition) {
              case MATCH_EMPTY:
                break;

              case MATCH_MATCH:
              case MATCH_DONTMATCH: {
                PARSE_CHECK(*p, "no value defined to check the condition");
                const char * const end = param->value + param->value_len;
                static_str_t reg = { p, end - p };
                buffer_addstr(&regexp, "");
                PARSE_CHECK(regexp_parse_str(&reg, NULL, &regexp, NULL, &condition.case_sensitive),
                            "invalid regexp");
                reg.str = regexp.data;
                reg.len = regexp.len;
                PARSE_CHECK(regexp_compile_str(&condition.data.regexp, &reg, condition.case_sensitive),
                            "cannot compile regexp %.*s", (int)(end - p), p);
              } break;

              default:
                PARSE_CHECK(*p, "no value defined to check the condition");
                condition.data.value.len = param->value_len - (p - param->value);
                condition.data.value.str = p_dupstr(p, condition.data.value.len);
                PARSE_CHECK(query_format_check(condition.data.value.str),
                            "invalid condition right hand expression \"%s\"", condition.data.value.str);
                break;
            }
            array_add(config->conditions, condition);
          } break;

          default: break;
        }
    }}

    PARSE_CHECK(config->conditions.len > 0,
                "no condition defined");
    filter->data = config;
    buffer_wipe(&regexp);
    return true;
}

static void match_filter_destructor(filter_t *filter)
{
    match_config_t *config = filter->data;
    match_config_delete(&config);
    filter->data = config;
}

static inline bool match_condition(const match_condition_t *cond, const query_t *query)
{
    const static_str_t *field = query_field_for_id(query, cond->field);
    if (cond->condition != MATCH_EMPTY && cond->condition != MATCH_MATCH
        && cond->condition != MATCH_DONTMATCH) {
        buffer_reset(&match_buffer);
        query_format_buffer(&match_buffer, cond->data.value.str, query);
    }
    debug("running condition: \"%s\" %s %s\"%s\"",
          field->str, condition_names[cond->condition],
          cond->case_sensitive ? "" : "(alternative) ",
          cond->condition != MATCH_MATCH && cond->condition != MATCH_DONTMATCH 
              && cond->data.value.str ? match_buffer.data : "(none)");
    switch (cond->condition) {
      case MATCH_EQUAL:
      case MATCH_DIFFER:
        if (field == NULL || field->str == NULL) {
            return cond->condition != MATCH_DIFFER;
        }
        if (cond->case_sensitive) {
            return !!((strcmp(field->str, match_buffer.data) == 0)
                      ^ (cond->condition == MATCH_DIFFER));
        } else {
            return !!((ascii_strcasecmp(field->str, match_buffer.data) == 0)
                      ^ (cond->condition == MATCH_DIFFER));
        }
        break;

      case MATCH_CONTAINS:
        if (field == NULL || field->str == NULL) {
            return false;
        }
        if (cond->case_sensitive) {
            return strstr(field->str, match_buffer.data);
        } else {
            return m_stristrn(field->str, match_buffer.data, match_buffer.len);
        }
        break;

      case MATCH_CONTAINED:
        if (field == NULL || field->str == NULL) {
            return false;
        }
        if (cond->case_sensitive) {
            return strstr(match_buffer.data, field->str);
        } else {
            return m_stristr(match_buffer.data, field->str);
        }
        break;

      case MATCH_EMPTY:
        return !!((field == NULL || field->len == 0) ^ (!cond->case_sensitive));

      case MATCH_MATCH:
        if (field == NULL || field->str == NULL) {
            return false;
        }
        return regexp_match_str(&cond->data.regexp, field);

      case MATCH_DONTMATCH:
        if (field == NULL || field->str == NULL) {
            return false;
        }
        return !regexp_match_str(&cond->data.regexp, field);

      default:
        assert(false && "invalid condition type");
    }
    return true;
}

static filter_result_t match_filter(const filter_t *filter, const query_t *query,
                                    filter_context_t *context)
{
    const match_config_t *config = filter->data;
    foreach (const match_condition_t *condition, config->conditions) {
        bool r = match_condition(condition, query);
        if (!r && config->match_all) {
            debug("condition failed, match_all failed");
            return HTK_FAIL;
        } else if (r && !(config->match_all)) {
            debug("condition succeed, not-match_all succeed");
            return HTK_MATCH;
        }
    }}
    if (config->match_all) {
        debug("all conditions matched, match_all succeed");
        return HTK_MATCH;
    } else {
        debug("no condition matched, not-match_all failed");
        return HTK_FAIL;
    }
}

static int match_init(void)
{
    filter_type_t type =  filter_register("match", match_filter_constructor,
                                          match_filter_destructor, match_filter,
                                          NULL, NULL);
    /* Hooks.
     */
    (void)filter_hook_register(type, "abort");
    (void)filter_hook_register(type, "error");
    (void)filter_hook_register(type, "match");
    (void)filter_hook_register(type, "fail");

    /* Parameters.
     */
    (void)filter_param_register(type, "match_all");
    (void)filter_param_register(type, "condition");
    return 0;
}
module_init(match_init);

static void match_exit(void)
{
    buffer_wipe(&match_buffer);
}
module_exit(match_exit);
