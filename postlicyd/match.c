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
#include "str.h"
#include "policy_tokens.h"

typedef struct match_condition_t {
    postlicyd_token field;
    bool case_sensitive;
    enum {
        MATCH_UNKNOWN  = 0,
        MATCH_EQUAL,
        MATCH_DIFFER,
        MATCH_CONTAINS,
        MATCH_CONTAINED,
        MATCH_EMPTY,
    } condition;

    char *value;
    ssize_t value_len;
} match_condition_t;
ARRAY(match_condition_t)

#define CONDITION_INIT { PTK_UNKNOWN, false, MATCH_UNKNOWN, NULL, 0 }

typedef struct match_config_t {
    A(match_condition_t) conditions;
    bool match_all;
} match_config_t;

static match_config_t *match_config_new(void)
{
    return p_new(match_config_t, 1);
}

static inline void match_condition_wipe(match_condition_t *condition)
{
    p_delete(&condition->value);
    condition->value_len = 0;
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

#define PARSE_CHECK(Expr, Str, ...)                                            \
    if (!(Expr)) {                                                             \
        syslog(LOG_ERR, Str, ##__VA_ARGS__);                                   \
        match_config_delete(&config);                                        \
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
           */
          case ATK_CONDITION: {
#define     IS_OP_START(N)                                                        \
              ((N) == '=' || (N) == '!' || (N) == '>' || (N) == '<' || (N) == '#')
#define     IS_OP_END(N)                                                          \
              ((N) == '=' || (N) == 'i')
            match_condition_t condition = CONDITION_INIT;
            const char *p = m_strnextsp(param->value);
            const char *n = p + 1;
            PARSE_CHECK(isalnum(*p), "invalid field name");
            for (n = p + 1 ; *n && (isalnum(*n) || *n == '_') ; ++n);
            PARSE_CHECK(*n &&
                        (isspace(*n) || IS_OP_START(*n)),
                        "invalid condition, expected operator after field name");
            condition.field = policy_tokenize(p, n - p);
            PARSE_CHECK(condition.field >= PTK_HELO_NAME
                        && condition.field < PTK_SMTPD_ACCESS_POLICY,
                        "invalid field name %.*s", n - p, p);
            p = m_strnextsp(n);
            n = p + 1;
            PARSE_CHECK(IS_OP_START(*p) && IS_OP_END(*n),
                        "invalid operator %2s", p);
            switch (*p) {
#define       CASE_OP(C, Value)                                                         \
              case C:                                                                   \
                condition.condition = MATCH_ ## Value;                                  \
                PARSE_CHECK(*n == '=' || *n == 'i', "invalid operator modifier %c", *n);\
                condition.case_sensitive = !!(*n == '=');                               \
                break;
              CASE_OP('=', EQUAL);
              CASE_OP('!', DIFFER);
              CASE_OP('>', CONTAINS);
              CASE_OP('<', CONTAINED);
              CASE_OP('1', EMPTY);
#undef        CASE_OP
            }
            PARSE_CHECK(condition.condition != MATCH_UNKNOWN,
                        "invalid operator");
            if (condition.condition != MATCH_EMPTY) {
                p = m_strnextsp(n + 1);
                PARSE_CHECK(*p, "no value defined to check the condition");
                condition.value_len = param->value_len - (p - param->value);
                condition.value     = p_dupstr(p, condition.value_len);
            }
            array_add(config->conditions, condition);
          } break;

          default: break;
        }
    }}

    PARSE_CHECK(config->conditions.len > 0,
                "no condition defined");
    filter->data = config;
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
//    const char *field = NULL;
    return true;
}

static filter_result_t match_filter(const filter_t *filter, const query_t *query)
{
    const match_config_t *config = filter->data;
    foreach (const match_condition_t *condition, config->conditions) {
        bool r = match_condition(condition, query);
        if (!r && config->match_all) {
            return HTK_FALSE;
        } else if (r && !(config->match_all)) {
            return HTK_TRUE;
        }
    }}
    if (config->match_all) {
        return HTK_TRUE;
    } else {
        return HTK_FALSE;
    }
}

static int match_init(void)
{
    filter_type_t type =  filter_register("match", match_filter_constructor,
                                          match_filter_destructor, match_filter);
    /* Hooks.
     */
    (void)filter_hook_register(type, "abort");
    (void)filter_hook_register(type, "error");
    (void)filter_hook_register(type, "true");
    (void)filter_hook_register(type, "false");

    /* Parameters.
     */
    (void)filter_param_register(type, "match_all");
    (void)filter_param_register(type, "condition");
    return 0;
}
module_init(match_init);
