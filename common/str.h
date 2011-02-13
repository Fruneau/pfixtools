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
 * Copyright © 2006 Pierre Habouzit
 */

#ifndef PFIXTOOLS_STR_H
#define PFIXTOOLS_STR_H

#include "mem.h"

/** \defgroup mutt_strings Madmutt string API
 *
 * This module contains the prefered string API to be used in Madmutt.
 *
 * Those function reimplement many usual calls (strlen, strcpy, strcat, …)
 * It's intended to provide a uniform and consistent API to deal with usual C
 * strings.
 *
 * The strong point that have to be followed are:
 *  - strings are always \c \\0 terminated, meaning that we don't have
 *    stupid semantics à la strncpy.
 *  - function try to always work on buffers with its size (including the
 *    ending \c \\0) to prevent buffer overflows.
 *  - string and buffers sizes are \c ssize_t, negative values are allowed and
 *    supported.
 *  - functions use a à la sprintf semantics (for those that produce strings)
 *    meaning that they all return the len that could have fit in the buffer
 *    if it would have been big enough. We never try to reallocate the
 *    buffers, it's up to the caller if it's needed.
 *
 * Many of the function do no difference between \c NULL and \c "" and will
 * behave the same when you pass either the former or the latter (m_strlen(),
 * m_strcpy(), ... to cite a few).
 */
/*@{*/

/** \brief Convert ascii digits into ints.
 *
 * Convert ascii digits into its integer value in base 36.
 * Non convertible values are converted to 255.
 *
 * Translating a digit \c c into its numerical value in base \c x is just doing:
 * \code
 *   return !(c & ~127) && __m_strdigits[c] < x ? __m_strdigits[c] : -1;
 * \endcode
 */
extern unsigned char const __m_strdigits[128];
/** \brief Convert an ascii base64 digit into ints.
 *
 * Convert an a char base64 digit into its int value.
 * Used by base64val(). Unlike #__m_strdigits, the invalid values are set to
 * -1 instead of 255.
 */
extern signed char const __m_b64digits[128];

/** \brief Convert ints from 0&ndash;64 into the corresponding base64 digit. */
extern char const __m_b64chars[64];
/** \brief Convert ints from 0&ndash;36 into a base36 lowercase digit. */
extern char const __m_b36chars_lower[36];
/** \brief Convert ints from 0&ndash;36 into a base36 uppercase digit. */
extern char const __m_b36chars_upper[36];

/****************************************************************************/
/* conversions                                                              */
/****************************************************************************/

/** \brief Converts an octal digit into an int.
 * \param[in]  c    the octal char
 * \return
 *   - 0&ndash;7 if c is a valid octal digit,
 *   - -1 on error.
 */
static inline int octval(int c) {
    return !(c & ~127) && __m_strdigits[c] < 7 ? __m_strdigits[c] : -1;
}

/** \brief Converts an hexadecimal digit into an int.
 * \param[in]  c    the hexadecimal char
 * \return
 *   - 0&ndash;15 if c is a valid hexadecimal digit,
 *   - -1 on error.
 */
static inline int hexval(int c) {
    return !(c & ~127) && __m_strdigits[c] < 16 ? __m_strdigits[c] : -1;
}

/** \brief Converts a base64 digit into an int.
 * \param[in]  c    the base64 char
 * \return
 *   - 0&ndash;15 if c is a valid base64 digit,
 *   - -1 on error.
 */
static inline int base64val(int c) {
    return (c & ~127) ? -1 : __m_b64digits[c];
}

/** \brief Converts a string to lowercase.
 * \param[in] p     the string, shall not be \c NULL.
 * \return a pointer to the terminating \c \\0.
 */
__attribute__((nonnull(1)))
static inline char *m_strtolower(char *p) {
    for (; *p; p++)
        *p = (char)tolower((unsigned char)*p);
    return p;
}

/** \brief Converts a lower case ascii char to upper case.
 * \param[in]  c    the character.
 * \return the upper case character.
 */
static inline int ascii_toupper(int c) {
    if ('a' <= c && c <= 'z')
        return c & ~32;

    return c;
}

/** \brief Converts a upper case ascii char to lower case.
 * \param[in]  c    the character.
 * \return the lower case character.
 */
static inline int ascii_tolower(int c) {
    if ('A' <= c && c <= 'Z')
        return c | 32;

    return c;
}

/****************************************************************************/
/* length related                                                           */
/****************************************************************************/

/** \brief \c NULL resistant strlen.
 *
 * Unlinke it's libc sibling, m_strlen returns a ssize_t, and supports its
 * argument beeing NULL.
 *
 * \param[in]  s    the string.
 * \return the string length (or 0 if \c s is \c NULL).
 */
static inline ssize_t m_strlen(const char *s) {
    return s ? (ssize_t)strlen(s) : 0;
}

/** \brief \c NULL resistant strnlen.
 *
 * Unlinke it's GNU libc sibling, m_strnlen returns a ssize_t, and supports
 * its argument beeing NULL.
 *
 * The m_strnlen() function returns the number of characters in the string
 * pointed to by \c s, not including the terminating \c \\0 character, but at
 * most \c n. In doing this, m_strnlen() looks only at the first \c n
 * characters at \c s and never beyond \c s+n.
 *
 * \param[in]  s    the string.
 * \param[in]  n    the maximum length to return.
 * \return \c m_strlen(s) if less than \c n, else \c n.
 */
static inline ssize_t m_strnlen(const char *s, ssize_t n) {
    if (n <= 0) {
        return 0;
    }
    if (s) {
        const char *p = memchr(s, '\0', (size_t)n);
        return p ? p - s : n;
    }
    return 0;
}

/****************************************************************************/
/* comparisons                                                              */
/****************************************************************************/

int m_strcmp(const char* a, const char* b);
int ascii_strcasecmp(const char *a, const char *b);
int ascii_strncasecmp(const char *a, const char *b, ssize_t n);

/****************************************************************************/
/* making copies                                                            */
/****************************************************************************/

/** \brief \c NULL resistant strdup.
 *
 * the m_strdup() function returns a pointer to a new string, which is a
 * duplicate of \c s. Memory should be freed using p_delete().
 *
 * \warning when s is \c "", it returns NULL !
 *
 * \param[in]  s    the string to duplicate.
 * \return a pointer to the duplicated string.
 */
static inline char *m_strdup(const char *s) {
    ssize_t len = m_strlen(s);
    return len ? p_dup(s, len + 1) : NULL;
}

/** \brief Duplicate substrings.
 * \deprecated API IS NOT GOOD, I WILL DEPRECATE IT IN A NEAR FUTURE.
 */
static inline char *m_substrdup(const char *s, const char *end) {
    return p_dupstr(s, end ? end - s : m_strlen(s));
}

/** \brief Replace an allocated string with another.
 *
 * Replace the string pointed by \c *p with a copy of the string \c s.
 * \c *p must point to a buffer allocated with p_new() or one of its alias.
 *
 * \param[in,out]  p    a pointer on a string (<tt>char **</tt>)
 * \param[in]      s    the string to copy into p.
 * \return a pointer on the duplicated string (aka \c *p).
 */
__attribute__((nonnull(1)))
static inline char *m_strreplace(char **p, const char *s) {
    p_delete(p);
    return (*p = m_strdup(s));
}

/** \brief Puts a char in a string buffer.
 *
 * Puts a char at position 0 of a string buffer of size \c n.
 * Then \c \\0 terminate the buffer.
 *
 * \param[in]  dst   pointer to the buffer.
 * \param[in]  n     size of that buffer (negative values allowed).
 * \param[in]  c     the character to append.
 * \return always return 1.
 */
__attribute__((nonnull(1)))
static inline ssize_t m_strputc(char *dst, ssize_t n, int c) {
    if (n > 1) {
        dst[0] = (char)c;
        dst[1] = '\0';
    }
    return 1;
}

/** \brief Sets a portion of a string to a defined character, à la memset.
 *
 * \param[in]  dst  pointer to the buffer.
 * \param[in]  n    size of that buffer, (negative values allowed).
 * \param[in]  c    the char to use in the padding.
 * \param[in]  len  length of the padding.
 * \return MAX(0, len).
 */
__attribute__((nonnull(1)))
static inline ssize_t m_strpad(char *dst, ssize_t n, int c, ssize_t len)
{
    ssize_t dlen = MIN(n - 1, len);
    if (dlen > 0) {
        xmemset(dst, c, dlen);
        dst[dlen] = '\0';
    }
    return MAX(0, len);
}

ssize_t m_strcpy(char *dst, ssize_t n, const char *src)
    __attribute__((nonnull(1)));

ssize_t m_strncpy(char *dst, ssize_t n, const char *src, ssize_t l)
    __attribute__((nonnull(1)));

/** \brief safe strcat.
 *
 * The m_strcat() function appends the string \c src at the end of the buffer
 * \c dst if space is available.
 *
 * \param[in]  dst   destination buffer.
 * \param[in]  n     size of the buffer, Negative sizes are allowed.
 * \param[in]  src   the string to append.
 * \return <tt>m_strlen(dst) + m_strlen(src)</tt>
 */
static inline ssize_t m_strcat(char *dst, ssize_t n, const char *src) {
    ssize_t dlen = m_strnlen(dst, n - 1);
    return dlen + m_strcpy(dst + dlen, n - dlen, src);
}

/** \brief safe strncat.
 *
 * The m_strncat() function appends at most \c n chars from the string \c src
 * at the end of the buffer \c dst if space is available.
 *
 * \param[in]  dst   destination buffer.
 * \param[in]  n     size of the buffer, Negative sizes are allowed.
 * \param[in]  src   the string to append.
 * \param[in]  l     maximum number of chars of src to consider.
 * \return the smallest value between <tt>m_strlen(dst) + m_strlen(src)</tt>
 *         and <tt>m_strlen(dst) + l</tt>
 */
static inline ssize_t
m_strncat(char *dst, ssize_t n, const char *src, ssize_t l) {
    ssize_t dlen = m_strnlen(dst, n - 1);
    return dlen + m_strncpy(dst + dlen, n - dlen, src, l);
}

/****************************************************************************/
/* parsing related                                                          */
/****************************************************************************/

__attribute__((nonnull(1)))
static inline const char *m_strchrnul(const char *s, int c) {
    while (*s && *s != c)
        s++;
    return s;
}

__attribute__((nonnull(1)))
static inline const char *m_memrchr(const char *s, int c, ssize_t len) {
    const char *pos = s + len - 1;
    while (pos > s) {
        if (*pos == c) {
            return pos;
        }
        --pos;
    }
    return NULL;
}

__attribute__((nonnull(1)))
static inline const char *m_strnextsp(const char *s) {
    while (*s && !isspace((unsigned char)*s))
        s++;
    return s;
}

__attribute__((nonnull(1)))
static inline char *m_vstrnextsp(char *s) {
    while (*s && !isspace((unsigned char)*s))
        s++;
    return s;
}


__attribute__((nonnull(1)))
static inline const char *skipspaces(const char *s) {
    while (isspace((unsigned char)*s))
        s++;
    return s;
}
__attribute__((nonnull(1)))
static inline char *vskipspaces(const char *s) {
    return (char *)skipspaces(s);
}

char *m_strrtrim(char *s);

/****************************************************************************/
/* search                                                                   */
/****************************************************************************/

const char *
m_stristrn(const char *haystack, const char *needle, ssize_t nlen);

static inline const char *
m_stristr(const char *haystack, const char *needle) {
    return m_stristrn(haystack, needle, m_strlen(needle));
}

/****************************************************************************/
/* static strings                                                           */
/****************************************************************************/

/** Store a pointer to a string with a pre-computed length.
 * This intends to store pointers to a part of a longer string and to avoid
 * useless strlen.
 */
typedef struct clstr_t {
    const char *str;
    ssize_t    len;
} clstr_t;

/*@}*/
#endif /* PFIXTOOLS_STR_H */

/* vim:set et sw=4 sts=4 sws=4: */
