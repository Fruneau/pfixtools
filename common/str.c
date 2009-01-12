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
 * Copyright © 2006 Pierre Habouzit
 */

/** \addtogroup mutt_strings */
/*@{*/

/** \file str.c
 * \brief Madmutt string API module implementation.
 * \author Pierre Habouzit <madcoder@debian.org>
 */

#include "str.h"

#ifndef __doxygen_skip__
#define XX 255
unsigned char const __m_strdigits[128] = {
    XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX,
    XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX,
    XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX,
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, XX, XX, XX, XX, XX, XX,
    XX, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
    25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, XX, XX, XX, XX, XX,
    XX, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
    25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, XX, XX, XX, XX, XX,
};
#undef XX

#define XX -1
signed char const __m_b64digits[128] = {
    XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX,
    XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX,
    XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, 62, XX, XX, XX, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, XX, XX, XX, XX, XX, XX,
    XX,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, XX, XX, XX, XX, XX,
    XX, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, XX, XX, XX, XX, XX
};
#undef XX

char const __m_b64chars[64] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
    'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',
    'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
    't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', '+', '/'
};

char const __m_b36chars_lower[36] = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
    'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
    'u', 'v', 'w', 'x', 'y', 'z'
};

char const __m_b36chars_upper[36] = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
    'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
    'U', 'V', 'W', 'X', 'Y', 'Z'
};
#endif

/** \brief safe strcpy.
 *
 * Copies at most <tt>n-1</tt> characters from \c src into \c dst, always
 * adding a final \c \\0 in \c dst.
 *
 * \param[in]  dst      destination buffer.
 * \param[in]  n        size of the buffer. Negative sizes are allowed.
 * \param[in]  src      source string.
 *
 * \return \c src \e length. If this value is \>= \c n then the copy was
 *         truncated.
 */
ssize_t m_strcpy(char *dst, ssize_t n, const char *src)
{
    ssize_t len = m_strlen(src);

    if (n > 0) {
        ssize_t dlen = MIN(n - 1, len);
        memcpy(dst, src, dlen);
        dst[dlen] = '\0';
    }

    return len;
}

/** \brief safe limited strcpy.
 *
 * Copies at most min(<tt>n-1</tt>, \c l) characters from \c src into \c dst,
 * always adding a final \c \\0 in \c dst.
 *
 * \param[in]  dst      destination buffer.
 * \param[in]  n        size of the buffer. Negative sizes are allowed.
 * \param[in]  src      source string.
 * \param[in]  l        maximum number of chars to copy.
 *
 * \return minimum of  \c src \e length and \c l.
 */
ssize_t m_strncpy(char *dst, ssize_t n, const char *src, ssize_t l)
{
    ssize_t len = m_strnlen(src, l);

    if (n > 0) {
        ssize_t dlen = MIN(n - 1, len);
        memcpy(dst, src, dlen);
        dst[dlen] = '\0';
    }

    return len;
}

char *m_strrtrim(char *s)
{
    ssize_t len = m_strlen(s);

    while (len > 1 && isspace((unsigned char)s[len - 1]))
        s[--len] = '\0';

    return s + len;
}

const char *m_stristrn(const char *haystack, const char *needle, ssize_t nlen)
{
    int nc;

    if (!nlen)
        return haystack;

    nc = tolower(*needle);
    for (;;) {
        int c = tolower(*haystack);

        if (c != nc) {
            if (c == '\0')
                return NULL;
        } else {
            ssize_t i;

            /* compare the rest of needle */
            for (i = 1;; i++) {
                if (i == nlen)
                    return haystack;
                if (c == '\0')
                    return NULL;
                c = tolower(haystack[i]);
                if (c != tolower(needle[i]))
                    break;
            }
        }

        haystack++;
    }
}

/** \brief \c NULL resistant strcasecmp.
 * \param[in]  a     the first string.
 * \param[in]  b     the second string.
 * \return <tt>strcasecmp(a, b)</tt>, and treats \c NULL strings like \c ""
 *         ones, as if we were in the C locale.
 */
int ascii_strcasecmp(const char *a, const char *b)
{
    if (a == b)
        return 0;
    if (!a)
        return -1;
    if (!b)
        return 1;

    while (*a || *b) {
        int i;
        if ((i = ascii_tolower(*a++) - ascii_tolower(*b++)))
            return i;
    }

    return 0;
}

/** \brief \c NULL resistant strncasecmp.
 * \param[in]  a     the first string.
 * \param[in]  b     the second string.
 * \param[in]  n     the number of maximum chars to compare.
 * \return <tt>strncasecmp(a, b)</tt>, and treats \c NULL strings like \c ""
 *         ones, as if we were in the C locale.
 */
int ascii_strncasecmp(const char *a, const char *b, ssize_t n)
{
    if (a == b)
        return 0;
    if (!a)
        return -1;
    if (!b)
        return 1;

    while ((*a || *b) && n > 0) {
        int i;
        if ((i = ascii_tolower(*a++) - ascii_tolower(*b++)))
            return i;
        n--;
    }

    return 0;
}

/*@}*/
