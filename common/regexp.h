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
/*   Copyright (c) 2006-2010 the Authors                                      */
/*   see AUTHORS and source files for details                                 */
/******************************************************************************/

/*
 * Copyright © 2009 Florent Bruneau
 */

#ifndef PFIXTOOLS_REGEXP_H
#define PFIXTOOLS_REGEXP_H

#include <pcre.h>
#include "str.h"
#include "array.h"
#include "buffer.h"

struct regexp_t {
    pcre *re;
    pcre_extra *extra;
};

typedef struct regexp_t regexp_t;
ARRAY(regexp_t);

regexp_t *regexp_new(void);
void regexp_wipe(regexp_t *re);
void regexp_delete(regexp_t **re);

/** Compile a regexp and fill the @c re structure.
 */
__attribute__((nonnull))
bool regexp_compile_str(regexp_t *re, const static_str_t *str, bool cs);

/** Compile a regexp and fill the @c re structure.
 */
__attribute__((nonnull))
bool regexp_compile(regexp_t *re, const char *str, bool cs);

/** Match the given string against the regexp.
 */
__attribute__((nonnull))
bool regexp_match_str(const regexp_t *re, const static_str_t *str);

/** Match the given string against the regexp.
 */
__attribute__((nonnull))
bool regexp_match(const regexp_t *re, const char *str);

/** Parse a string and extract the regexp.
 * The string format must bee /regexp/modifier
 *  * the delimiter can be any character.
 *  * supported modifiers are i (case insensitive)
 *  * if prefix is not NULL, the parser will try to find a prefix string in the regexp
 *    with no wildcard (e.g /^myprefix(.*)/)
 *  * if suffix is not NULL, the parser will try to find a suffix string in the regexp
 *    with no wildcard (e.g /(.*)mysuffix$/)
 */
__attribute__((nonnull(1,3)))
bool regexp_parse_str(const static_str_t *str, buffer_t *prefix, buffer_t *re,
                      buffer_t *suffix, bool *cs);


__attribute__((nonnull(1,3)))
bool regexp_parse(const char *str, buffer_t *prefix, buffer_t *re, buffer_t *suffix, bool *cs);

#endif

/* vim:set et sw=4 sts=4 sws=4: */
