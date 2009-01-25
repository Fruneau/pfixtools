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
/*   Copyright (c) 2006-2008 the Authors                                      */
/*   see AUTHORS and source files for details                                 */
/******************************************************************************/

/*
 * Copyright © 2009 Florent Bruneau
 */

#include "regexp.h"

regexp_t *regexp_new(void)
{
    return p_new(regexp_t, 1);
}

void regexp_wipe(regexp_t *re)
{
    pcre_free(re->re);
    pcre_free(re->extra);
}

void regexp_delete(regexp_t **re)
{
    if (*re) {
        regexp_wipe(*re);
        p_delete(re);
    }
}

bool regexp_compile(regexp_t *re, const char *str, bool cs)
{
    const char *error = NULL;
    int erroffset = 0;

    int flags = (cs ? 0 : PCRE_CASELESS);

    debug("compiling regexp: %s", str);
    re->re = pcre_compile(str, flags, &error, &erroffset, NULL);
    if (re->re == NULL) {
        err("cannot compile regexp: %s (at %d)", error, erroffset);
        return false;
    }
    re->extra = pcre_study(re->re, 0, &error);
    if (re->extra == NULL && error != NULL) {
        warn("regexp inspection failed: %s", error);
    }
    return true;
}

bool regexp_compile_str(regexp_t* re, const static_str_t *str, bool cs)
{
    if (str->str[str->len + 1] == '\0') {
        return regexp_compile(re, str->str, cs);
    } else {
        // TODO: Use a buffer to avoid stupid allocations
        char *cpy = p_dupstr(str->str, str->len);
        bool ok = regexp_compile(re, cpy, cs);
        p_delete(&cpy);
        return ok;
    }
}

bool regexp_match_str(const regexp_t *re, const static_str_t *str)
{
    return 0 == pcre_exec(re->re, re->extra, str->str, str->len, 0, 0, NULL, 0);
}

bool regexp_match(const regexp_t *re, const char *str)
{
    static_str_t s = { str, m_strlen(str) };
    return regexp_match_str(re, &s);
}

/** Returns true if the character has a special meaning in regexp when non escaped.
 */
static inline bool is_wildcard(const char c) {
    return c == '.' || c == '$' || c == '^'
        || c == '?' || c == '+' || c == '*' || c == '|'
        || c == '(' || c == ')' || c == '[' || c == ']' || c == '{' || c == '}';
}

/** Returns true if the character affects the previous character behaviour in a regexp
 * when non escaped.
 */
static inline bool is_modifier(const char c) {
    return c == '?' || c == '+' || c == '*' || c == '{';
}

/** Returns true if the character has a special in regexp when espaced.
 */
static inline bool is_special(const char c) {
    return c == 'x' || c == '0'
        || c == 'd' || c == 'D' || c == 'h' || c == 'H'
        || c == 's' || c == 'S' || c == 'v' || c == 'V'
        || c == 'w' || c == 'W' || c == 'b' || c == 'B';
}

/** Return true if the character is a valid regexp delimiter.
 */
static inline bool is_valid_delimiter(const char c) {
    return !isspace(c) && !isalnum(c) && isascii(c) && !is_wildcard(c);
}

bool regexp_parse_str(const static_str_t *str, buffer_t *prefix,
                      buffer_t *re, buffer_t *suffix, bool *cs) {
    if (str == NULL || re == NULL || str->len < 2) {
        err("Invalid argument");
        return false;
    }

    const char *p   = str->str;
    const char *end = str->str + str->len;
    char delim = *(p++);
    if (!is_valid_delimiter(delim)) {
        err("Invalid delimiter %c", delim);
        return false;
    }

    buffer_reset(re);
    /* Read literal prefix */
    if (prefix != NULL) {
        buffer_reset(prefix);
        if (*p == '^') {
            buffer_addch(re, '^');
            ++p;
            while (p < end - 1 && !is_wildcard(*p) && *p != delim) {
                if (*p == '\\') {
                    ++p;
                    if (is_special(*p)) {
                        --p;
                        break;
                    }
                }
                buffer_addch(prefix, *p);
                ++p;
            }
            if (p >= end) {
                err("Reached the end of the regexp");
                return false;
            }
            if (is_modifier(*p)) {
                --prefix->len;
                prefix->data[prefix->len] = '\0';
            }
        }
    }

    /* Read the regexp */
    while (p < end && *p != delim) {
        if (*p == '\\') {
            ++p;
            if (p == end) {
                err("Read the end of the regexp");
                return false;
            }
            if (*p != delim) {
                buffer_addch(re, '\\');
            }
        }
        buffer_addch(re, *p);
        ++p;
    }
    if (p == end) {
        err("Reached the end of the regexp");
        return false;
    }
    if (*p != delim) {
        err("Invalid end of regexp, found %c while expecting %c", *p, delim);
        return false;
    }

    /* Read the modifiers (if any) */
    ++p;
    if (cs) {
        *cs = true;
    }
    if (p < end) {
        if (*p != 'i') {
            err("Invalid regexp modifier %c", *p);
            return false;
        }
        if (cs) {
            *cs = false;
        }
    }

    /* Extract literal suffix (if any) */
    if (suffix != NULL) {
        suffix->len = 0;
        if (re->len > 0 && array_last(*re) == '$') {
            int pos = re->len - 2;
            int bs  = 0;
            while (pos >= 0 && array_elt(*re, pos) == '\\') {
                --pos;
                ++bs;
            }
            if ((bs & 1) == 1) {
                /* The termination $ is escaped, it is not a termination, so, no suffix */
                return true;
            }
            bs = 0;
            while (pos >= 0) {
                const char c = array_elt(*re, pos);
                bs = 0;
                if (is_wildcard(c) || is_special(c)) {
                    --pos;
                    while (pos >= 0 && array_elt(*re, pos) == '\\') {
                        --pos;
                        ++bs;
                    }
                    if (is_wildcard(c)) {
                        if ((bs & 1) == 0) {
                            /* Character not escaped, break, wildcard found */
                            ++pos;
                            break;
                        }
                    } else {
                        if ((bs & 1) == 1) {
                            /* Special sequence */
                            ++pos;
                            break;
                        }
                    }
                } else {
                    --pos;
                }
            }
            if (pos != 0 || bs != 0) {
                pos += bs + 1;
            }
            bs = pos;
            while (pos < (int)re->len - 1) {
                char c = array_elt(*re, pos);
                if (c == '\\') {
                    ++pos;
                    c = array_elt(*re, pos);
                }
                buffer_addch(suffix, c);
                ++pos;
            }
            if (pos == (int)re->len) {
                return false;
            }
            re->len = bs;
            buffer_addch(re, '$');
        }
    }
    return true;
}

bool regexp_parse(const char *str, buffer_t *prefix, buffer_t *re, buffer_t *suffix, bool *cs) {
    static_str_t s = { str, m_strlen(str) };
    return regexp_parse_str(&s, prefix, re, suffix, cs);
}
