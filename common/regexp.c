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

bool regexp_compile(regexp_t *re, const char *str, bool cs, bool utf8)
{
    const char *error = NULL;
    int erroffset = 0;

    int flags = (cs ? 0 : PCRE_CASELESS) | (utf8 ? PCRE_UTF8 : 0);

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

bool regexp_compile_str(regexp_t* re, const static_str_t *str, bool cs, bool utf8)
{
    if (str->str[str->len + 1] == '\0') {
        return regexp_compile(re, str->str, cs, utf8);
    } else {
        // TODO: Use a buffer to avoid stupid allocations
        char *cpy = p_dupstr(str->str, str->len);
        bool ok = regexp_compile(re, cpy, cs, utf8);
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

