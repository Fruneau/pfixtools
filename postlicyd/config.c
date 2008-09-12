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

#include "file.h"
#include "filter.h"
#include "config.h"

struct config_t {
    filter_t *filters;
    int filters_len;
    int filters_size;

    int entry_point;
};

static inline config_t *config_new(void)
{
    config_t *config = p_new(config_t, 1);
    config->entry_point = -1;
    return config;
}

void config_delete(config_t **config)
{
    if (*config) {
        for (int i = 0 ; i < (*config)->filters_len ; ++i) {
            filter_wipe((*config)->filters + i);
        }
        p_delete(&(*config)->filters);
    }
}

config_t *config_read(const char *file)
{
    config_t *config;
    //filter_t *filter = NULL;
    file_map_t map;
    const char *p;
    int line = 0;

    char key[BUFSIZ];
    char value[BUFSIZ];
    ssize_t key_len, value_len;

    if (!file_map_open(&map, file, false)) {
        return false;
    }

    config = config_new();
    p = map.map;

#define READ_ERROR(Fmt, ...)                                                   \
    syslog(LOG_ERR, "config file %s:%d: " Fmt, file, line, ##__VA_ARGS__)
#define ADD_IN_BUFFER(Buffer, Len, Char)                                       \
    if ((Len) >= BUFSIZ - 1) {                                                 \
        READ_ERROR("unreasonnable long line");                                 \
        goto error;                                                            \
    }                                                                          \
    (Buffer)[(Len)++] = (Char);                                                \
    (Buffer)[(Len)]   = '\0';

#define READ_NEXT(OnEOF)                                                       \
    if (++p >= map.end) {                                                      \
        OnEOF;                                                                 \
    }
#define READ_BLANK(OnEOF)                                                      \
    while (isblank(*p)) {                                                      \
        if (*p == '\n') {                                                      \
            ++line;                                                            \
        }                                                                      \
        READ_NEXT(OnEOF);                                                      \
    }
#define READ_TOKEN(Name, Buffer, Len)                                          \
    do {                                                                       \
        (Len) = 0;                                                             \
        (Buffer)[0] = '\0';                                                    \
        if (!isalpha(*p)) {                                                    \
            READ_ERROR("invalid %s, unexpected character '%c'", Name, *p);     \
            goto error;                                                        \
        }                                                                      \
        do {                                                                   \
            ADD_IN_BUFFER(Buffer, Len, *p);                                    \
            if ((Len) >= BUFSIZ - 1) {                                         \
                READ_ERROR("unreasonnable long token");                        \
                goto error;                                                    \
            }                                                                  \
            (Buffer)[(Len)++] = *p;                                            \
            READ_NEXT(goto badeof)                                             \
        } while (isalnum(*p) || *p == '_');                                    \
    } while (0)
#define READ_STRING(Name, Buffer, Len, OnEOF)                                  \
    do {                                                                       \
        (Len) = 0;                                                             \
        (Buffer)[0] = '\0';                                                    \
        if (*p == '"') {                                                       \
            bool escaped = false;                                              \
            while (*p == '"') {                                                \
                READ_NEXT(goto badeof);                                        \
                while (true) {                                                 \
                    if (*p == '\n') {                                          \
                        READ_ERROR("string must not contain EOL");             \
                        goto error;                                            \
                    } else if (escaped) {                                      \
                        ADD_IN_BUFFER(Buffer, Len, *p);                        \
                        escaped = false;                                       \
                    } else if (*p == '\\') {                                   \
                        escaped = true;                                        \
                    } else if (*p == '"') {                                    \
                        READ_NEXT(goto badeof);                                \
                        break;                                                 \
                    } else {                                                   \
                        ADD_IN_BUFFER(Buffer, Len, *p);                        \
                    }                                                          \
                    READ_NEXT(goto badeof);                                    \
                }                                                              \
                READ_BLANK(goto badeof);                                       \
            }                                                                  \
            if (*p != ';') {                                                   \
                READ_ERROR("%s must end with a ';'", Name);                    \
                goto error;                                                    \
            }                                                                  \
        } else {                                                               \
            bool escaped = false;                                              \
            READ_NEXT(goto badeof);                                            \
            while (*p != ';' && isascii(*p) && isprint(*p)) {                  \
                if (escaped) {                                                 \
                    if (*p == '\r' || *p == '\n') {                            \
                        READ_BLANK(goto badeof);                               \
                    } else {                                                   \
                        ADD_IN_BUFFER(Buffer, Len, '\\');                      \
                    }                                                          \
                    escaped = false;                                           \
                }                                                              \
                if (*p == '\\') {                                              \
                    escaped = true;                                            \
                } else if (*p == '\r' || *p == '\n') {                         \
                    READ_ERROR("%s must not contain EOL", Name);               \
                } else {                                                       \
                    ADD_IN_BUFFER(Buffer, Len, *p);                            \
                }                                                              \
                READ_NEXT(goto badeof);                                        \
            }                                                                  \
            if (escaped) {                                                     \
                ADD_IN_BUFFER(Buffer, Len, '\\');                              \
            }                                                                  \
        }                                                                      \
        READ_NEXT(OnEOF)                                                       \
    } while(0)


read_section:
    if (p >= map.end) {
        goto ok;
    }

    value[0] = key[0] = '\0';
    value_len = key_len = 0;

    READ_BLANK(goto ok);
    READ_TOKEN("section name", key, key_len);
    READ_BLANK(goto badeof);
    switch (*p) {
      case '=':
        READ_NEXT(goto badeof)
        goto read_param_value;
      case '{':
        READ_NEXT(goto badeof)
        goto read_filter;
      default:
        READ_ERROR("invalid character '%c', expected '=' or '{'", *p);
        goto error;
    }

read_param_value:
    READ_BLANK(goto badeof);
    READ_STRING("parameter value", value, value_len, ;);
    /* TODO: Insert parameter in the configuration.
     */
    goto read_section;

read_filter:
    /* TODO: Create a filter with the given name.
     */
    READ_BLANK(goto badeof);
    while (*p != '}') {
        READ_TOKEN("filter parameter name", key, key_len);
        READ_BLANK(goto badeof);
        READ_STRING("filter parameter value", value, value_len, goto badeof);
        /* TODO: Insert parameter in the filter.
         */
    }
    /* TODO: Check the filter.
     */
    goto read_section;

ok:
    return config;

badeof:
    syslog(LOG_ERR, "Unexpected end of file");

error:
    config_delete(&config);
    return NULL;
}
