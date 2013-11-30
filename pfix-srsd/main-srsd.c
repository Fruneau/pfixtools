/****************************************************************************/
/*          pfixtools: a collection of postfix related tools                */
/*          ~~~~~~~~~                                                       */
/*  ______________________________________________________________________  */
/*                                                                          */
/*  Redistribution and use in source and binary forms, with or without      */
/*  modification, are permitted provided that the following conditions      */
/*  are met:                                                                */
/*                                                                          */
/*  1. Redistributions of source code must retain the above copyright       */
/*     notice, this list of conditions and the following disclaimer.        */
/*  2. Redistributions in binary form must reproduce the above copyright    */
/*     notice, this list of conditions and the following disclaimer in      */
/*     the documentation and/or other materials provided with the           */
/*     distribution.                                                        */
/*  3. The names of its contributors may not be used to endorse or promote  */
/*     products derived from this software without specific prior written   */
/*     permission.                                                          */
/*                                                                          */
/*  THIS SOFTWARE IS PROVIDED BY THE CONTRIBUTORS ``AS IS'' AND ANY         */
/*  EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE       */
/*  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR      */
/*  PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE CONTRIBUTORS BE LIABLE   */
/*  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR            */
/*  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF    */
/*  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR         */
/*  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,   */
/*  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE    */
/*  OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,       */
/*  EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.                      */
/*                                                                          */
/*   Copyright (c) 2006-2011 the Authors                                    */
/*   see AUTHORS and source files for details                               */
/****************************************************************************/

/*
 * Copyright © 2005-2007 Pierre Habouzit
 * Copyright © 2008 Florent Bruneau
 */

#include <getopt.h>

#include "common.h"

#include <srs2.h>

#include "mem.h"
#include "buffer.h"
#include "server.h"

#define DAEMON_NAME             "pfix-srsd"
#define DAEMON_VERSION          PFIXTOOLS_VERSION
#define DEFAULT_ENCODER_PORT    10001
#define DEFAULT_DECODER_PORT    10002
#define DEFAULT_RUNAS_USER      NOBODY_USER
#define DEFAULT_RUNAS_GROUP     NOGROUP_GROUP
#define SOCKETMAP_MAX_QUERY     10000

#define SOCKETMAP_STATE_LENGTH  0
#define SOCKETMAP_STATE_NAME    1
#define SOCKETMAP_STATE_ADDRESS 2

#define SOCKETMAP_NAME_ENCODER  0
#define SOCKETMAP_NAME_DECODER  1

DECLARE_MAIN

typedef struct srs_config_t {
    srs_t *srs;
    const char* domain;
    size_t domainlen;
    unsigned ignore_ext : 1;
    char separator;
} srs_config_t;

typedef struct srs_context_t {
    listener_t *server;
    size_t addrlen;
    int state;
    int name;
} srs_context_t;

/* Server {{{1
 */

static struct {
    listener_t *decoder_ptr;
    listener_t *encoder_ptr;

    bool socketmap;

    srs_config_t config;
} pfixsrsd_g;
#define _G  pfixsrsd_g


static void *srsd_starter_socketmap(listener_t *server)
{
    srs_context_t *context;
    context = p_new(srs_context_t, 1);
    context->server = server;
    return context;
}

static void srsd_stopper_socketmap(void *data)
{
    srs_context_t **context = data;
    if (*context) {
        p_delete(context);
    }
}

static void *srsd_starter_tcp(listener_t *server)
{
    return server;
}

/* Processing {{{1
 */

static char *urldecode(char *s, char *end)
{
    char *p = s;

    while (*p) {
        if (*p == '%' && end - p >= 3) {
            int h = (hexval(p[1]) << 4) | hexval(p[2]);

            if (h >= 0) {
                *s++ = h;
                p += 3;
                continue;
            }
        }

        *s++ = *p++;
    }
    *s = '\0';
    return s;
}

static void buffer_addurlencoded(buffer_t *buf, const char *p)
{
    static int hexdigit[16] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };

    while (*p) {
        if (*p == '%' || !isprint(*p) || isspace(*p)) {
            buffer_addch(buf, '%');
            buffer_addch(buf, hexdigit[(unsigned char)*p >> 4]);
            buffer_addch(buf, hexdigit[(*p) & 0x0f]);
        } else {
            buffer_addch(buf, *p);
        }
        p++;
    }
}

static int netstring_calc_length(size_t num, const char *str, va_list args)
{
    size_t len = strlen(str), i;
    for (i = 1; i < num; i++) {
        len += strlen(va_arg(args, char *));
    }
    return len;
}

static void netstring_encode_and_send(buffer_t *buf, size_t len, size_t num, const char *str, va_list args)
{
    buffer_addf(buf, "%zu:%s", len, str);
    for (size_t i = 1; i < num; i++) {
        buffer_addstr(buf, va_arg(args, char *));
    }
    buffer_addch(buf, ',');
}

static void netstring_send(buffer_t *buf, size_t num, const char *str, ...)
{
    size_t len;
    va_list args;

    va_start(args, str);
    len = netstring_calc_length(num, str, args);
    va_end(args);

    va_start(args, str);
    netstring_encode_and_send(buf, len, num, str, args);
    va_end(args);
}

static int netstring_send_limit(buffer_t *buf, size_t limit, size_t num, const char *str, ...)
{
    size_t len;
    va_list args;

    va_start(args, str);
    len = netstring_calc_length(num, str, args);
    va_end(args);
    if (len > limit)
        return -1;

    va_start(args, str);
    netstring_encode_and_send(buf, len, num, str, args);
    va_end(args);

    return 0;
}

static int process_srs_socketmap(client_t *srsd, void* vconfig)
{
    srs_config_t *config = vconfig;
    buffer_t *ibuf = client_input_buffer(srsd);
    buffer_t *obuf = client_output_buffer(srsd);
    srs_context_t *context = client_data(srsd);
    int res = client_read(srsd);

    if ((res < 0 && errno != EINTR && errno != EAGAIN) || res == 0)
        return -1;

    while (ibuf->len) {
        char *co, *p;

        switch (context->state) {
          default:
          case SOCKETMAP_STATE_LENGTH:
            // Netstring messages are of the form <length>:<string>,
            co = strchr(ibuf->data, ':');
            if (!co) {
                if (ibuf->len > BUFSIZ) {
                    err("invalid netstring received: missing length terminator");
                    return -1;
                }
                goto skipend;
            } else if (co == ibuf->data) {
                err("invalid netstring received: no length provided");
                return -1;
            }

            context->addrlen = 0;
            for (p = ibuf->data; *p >= '0' && *p <= '9'; p++) {
                context->addrlen *= 10;
                context->addrlen += *p - 0x30;
                if ( context->addrlen >= SOCKETMAP_MAX_QUERY ) {
                    break;
                }
            }

            if (p != co) {
                err("invalid netstring received: invalid length digit '%c'", *p);
                return -1;
            }

            if (context->addrlen > SOCKETMAP_MAX_QUERY) {
                err("invalid netstring received: length %zu is invalid - (max is "STR(SOCKETMAP_MAX_QUERY)")", context->addrlen);
                return -1;
            }

            context->state = SOCKETMAP_STATE_NAME;

            buffer_consume(ibuf, co - ibuf->data + 1);
            break;
          case SOCKETMAP_STATE_NAME:
            if (ibuf->len > context->addrlen) {
                if (ibuf->data[context->addrlen] != ',') {
                    err("invalid netstring received: missing netstring terminator");
                    return -1;
                }
            }

            // The message sent by postfix contains a table name followed by a space
            // This table name will tell us whether to encode or decode
            co = strchr(ibuf->data, ' ');
            if (!co) {
                if (ibuf->len > context->addrlen) {
                    warn("invalid request received: missing socketmap name terminator");
                    netstring_send(obuf, 1, "PERM Invalid request");
                    goto skip;
                }
                goto skipend;
            } else if (co == ibuf->data) {
                warn("invalid request received: no socketmap name provided");
                netstring_send(obuf, 1, "PERM Invalid request");
                goto skip;
            }

            size_t len = co - ibuf->data;
            if (len > context->addrlen) {
                warn("invalid request received: missing socketmap name terminator");
                netstring_send(obuf, 1, "PERM Invalid request");
                goto skip;
            }

            // Slightly dirty since we modify the buffer
            ibuf->data[len] = 0;

            if (strcmp(ibuf->data, "srsencoder") == 0) {
                context->name = SOCKETMAP_NAME_ENCODER;
            } else if (strcmp(ibuf->data, "srsdecoder") == 0) {
                context->name = SOCKETMAP_NAME_DECODER;
            } else {
                warn("invalid socketmap name received: %s", ibuf->data);
                netstring_send(obuf, 1, "PERM Invalid request");
                goto skip;
            }

            context->state = SOCKETMAP_STATE_ADDRESS;
            context->addrlen -= len + 1;

            buffer_consume(ibuf, len + 1);
            break;
          case SOCKETMAP_STATE_ADDRESS:
            // Waiting for the full netstring to arrive, terminated by comma
            if (ibuf->len < context->addrlen + 1) {
                goto skipend;
            }

            if (ibuf->data[context->addrlen] != ',') {
                err("invalid netstring received: missing netstring terminator");
                return -1;
            }

            if (context->addrlen == 0) {
                warn("empty request received");
                netstring_send(obuf, 1, "NOTFOUND ");
                goto skip;
            }

            // Slightly dirty since we modify the buffer, but it properly terminates the address in place with no copying necessary
            ibuf->data[context->addrlen] = 0;

            char *buf;
            int err;

            if (context->name == SOCKETMAP_NAME_DECODER) {
                if (config->ignore_ext) {
                    size_t dlen = config->domainlen;

                    if (context->addrlen <= dlen || ibuf->data[context->addrlen - 1 - dlen] != '@' ||
                        memcmp(ibuf->data + context->addrlen - dlen, config->domain, dlen))
                    {
                        netstring_send(obuf, 2, "OK ", ibuf->data);
                        goto skip;
                    }
                }
                err = srs_reverse_alloc(config->srs, &buf, ibuf->data);
            } else {
                err = srs_forward_alloc(config->srs, &buf, ibuf->data, config->domain);
            }

            if (err == SRS_SUCCESS) {
                if (netstring_send_limit(obuf, SOCKETMAP_MAX_QUERY, 2, "OK ", buf) != 0) {
                    netstring_send(obuf, 1, "PERM The SRS response would exceed the maximum socketmap response length");
                }
                free( buf );
            } else {
                switch (SRS_ERROR_TYPE(err)) {
                  case SRS_ERRTYPE_CONFIG:
                    netstring_send(obuf, 2, "PERM ", srs_strerror(err));
                    break;
                  default:
                    netstring_send(obuf, 2, "NOTFOUND ", srs_strerror(err));
                    break;
                }
            }

          skip:
            context->state = SOCKETMAP_STATE_LENGTH;
            buffer_consume(ibuf, context->addrlen + 1);
            break;
        }

    }

  skipend:
    if (obuf->len) {
        client_io_rw(srsd);
    }

    return 0;
}

static int process_srs_tcp(client_t *srsd, void* vconfig)
{
    srs_config_t *config = vconfig;
    buffer_t *ibuf = client_input_buffer(srsd);
    buffer_t *obuf = client_output_buffer(srsd);
    bool decoder = (client_data(srsd) == _G.decoder_ptr);
    int res = client_read(srsd);

    if ((res < 0 && errno != EINTR && errno != EAGAIN) || res == 0)
        return -1;

    while (ibuf->len > 4) {
        char buf[BUFSIZ], *p, *q, *nl;
        int err;

        nl = strchr(ibuf->data + 4, '\n');
        if (!nl) {
            if (ibuf->len > BUFSIZ) {
                err("unreasonnable amount of data without a \\n");
                return -1;
            }
            if (obuf->len) {
                client_io_rw(srsd);
            }
            return 0;
        }

        if (strncmp("get ", ibuf->data, 4)) {
            err("bad request, not starting with \"get \"");
            return -1;
        }

        for (p = ibuf->data + 4; p < nl && isspace(*p); p++);
        for (q = nl++; q >= p && isspace(*q); *q-- = '\0');

        if (p == q) {
            buffer_addstr(obuf, "400 empty request ???\n");
            warn("empty request");
            goto skip;
        }

        q = urldecode(p, q);

        if (decoder) {
            if (config->ignore_ext) {
                int dlen = config->domainlen;

                if (q - p <= dlen || q[-1 - dlen] != '@' ||
                    memcmp(q - dlen, config->domain, dlen))
                {
                    buffer_addstr(obuf, "200 ");
                    buffer_add(obuf, p, q - p);
                    buffer_addch(obuf, '\n');
                    goto skip;
                }
            }
            err = srs_reverse(config->srs, buf, ssizeof(buf), p);
        } else {
            err = srs_forward(config->srs, buf, ssizeof(buf), p,
                              config->domain);
        }

        if (err == SRS_SUCCESS) {
            buffer_addstr(obuf, "200 ");
            buffer_addurlencoded(obuf, buf);
        } else {
            switch (SRS_ERROR_TYPE(err)) {
              case SRS_ERRTYPE_CONFIG:
                buffer_addstr(obuf, "400 ");
                break;
              default:
                buffer_addstr(obuf, "500 ");
                break;
            }
            buffer_addstr(obuf, srs_strerror(err));
        }
        buffer_addch(obuf, '\n');

      skip:
        buffer_consume(ibuf, nl - ibuf->data);
    }
    if (obuf->len) {
        client_io_rw(srsd);
    }
    return 0;
}

/* config {{{1
 */


/** overload srs_free since the lib is not properly maintained.
 */
inline void srs_free(srs_t *srs)
{
    int  i;
    for (i = 0; i < srs->numsecrets; i++) {
        memset(srs->secrets[i], 0, strlen(srs->secrets[i]));
        free(srs->secrets[i]);
        srs->secrets[i] = '\0';
    }
    if (srs->secrets) {
        free(srs->secrets);
    }
    free(srs);
}

static void config_shutdown(void)
{
    if (_G.config.srs) {
        srs_free(_G.config.srs);
        _G.config.srs = NULL;
    }
}

module_exit(config_shutdown);

static srs_t *srs_read_secrets(const char *sfile)
{
    srs_t *srs;
    char buf[BUFSIZ];
    FILE *f;
    int lineno = 0;

    f = fopen(sfile, "r");
    if (!f) {
        UNIXERR("fopen");
        return NULL;
    }

    srs = srs_new();

    while (fgets(buf, sizeof(buf), f)) {
        int n = strlen(buf);

        ++lineno;
        if (n == sizeof(buf) - 1 && buf[n - 1] != '\n') {
            crit("%s:%d: line too long", sfile, lineno);
            goto error;
        }
        m_strrtrim(buf);
        srs_add_secret(srs, skipspaces(buf));
    }

    if (!lineno) {
        crit("%s: empty file, no secrets", sfile);
        goto error;
    }

    fclose(f);
    return srs;

  error:
    fclose(f);
    srs_free(srs);
    return NULL;
}

/* administrivia {{{1
 */

static void usage(void)
{
    fputs("usage: "DAEMON_NAME" [options] domain secrets\n"
          "\n"
          "Options:\n"
          "    -P|--protocol tcp|socketmap   the postfix lookup table protocol to use, default is tcp\n"
          "    -s|--separator <sep>          change the character used as srs separator (+, - or =), default is =\n"
          "    -I|--ignore-outside           do not touch mails outside of \"domain\" in decoding mode\n"
          COMMON_DAEMON_OPTION_HELP
          "\n"
          "Options for tcp protocol:\n"
          "    -e|--encoding <port>          tcp port to listen to for encoding requests, default is "STR(DEFAULT_ENCODER_PORT)"\n"
          "    -d|--decoding <port>          tcp port to listen to for decoding requests, default is "STR(DEFAULT_DECODER_PORT)"\n"
          "\n"
          "Options for socketmap protocol:\n"
          "    -l|--port <port>              tcp port to listen to for requests\n"
          "    -L|--socketfile <file>        unix socket to listen to for requests\n"
          "    When neither port or socketfile are specified, the socketmap default is port "STR(DEFAULT_ENCODER_PORT)".\n"
          "    The socketmap protocol provides two socketmap names, 'srsencoder' and 'srsdecoder'. Use these\n"
          "    in your postfix configuration file to state what action needs to be performed.\n",
          stderr);
}

/* }}}
 */

int main(int argc, char *argv[])
{
    COMMON_DAEMON_OPTION_PARAMS;
    int port_enc = DEFAULT_ENCODER_PORT;
    int port_dec = DEFAULT_DECODER_PORT;
    int port = DEFAULT_ENCODER_PORT;
    bool port_enc_set = false;
    bool port_dec_set = false;
    bool port_set = false;
    const char *socketfile = NULL;

    struct option longopts[] = {
        COMMON_DAEMON_OPTION_LIST,
        { "protocol", required_argument, NULL, 'P' },
        { "separator", required_argument, NULL, 's' },
        { "ignore-outside", no_argument, NULL, 'I' },
        { "encoding", required_argument, NULL, 'e' },
        { "decoding", required_argument, NULL, 'd' },
        { "port", required_argument, NULL, 'l' },
        { "socketfile", required_argument, NULL, 'L' },
        { NULL, 0, NULL, 0 }
    };

    for (int c = 0; (c = getopt_long(argc, argv,
                                     COMMON_DAEMON_OPTION_SHORTLIST "P:s:Ie:d:l:L:",
                                     longopts, NULL)) >= 0;) {
        switch (c) {
          case 'P':
            if (strcmp(optarg, "tcp") == 0) {
                _G.socketmap = false;
            } else if (strcmp(optarg, "socketmap") == 0) {
                _G.socketmap = true;
            } else {
                usage();
                return EXIT_FAILURE;
            }
            break;
          case 'e':
            port_enc = atoi(optarg);
            port_enc_set = true;
            break;
          case 'd':
            port_dec = atoi(optarg);
            port_dec_set = true;
            break;
          case 'l':
            port = atoi(optarg);
            port_set = true;
            break;
          case 'L':
            socketfile = optarg;
            break;
          case 'I':
            _G.config.ignore_ext = true;
            break;
          case 's':
            if (m_strlen(optarg) != 1) {
                usage();
                return EXIT_FAILURE;
            }
            _G.config.separator = *optarg;
            if (_G.config.separator != '+' && _G.config.separator != '-'
                && _G.config.separator != '=') {
                usage();
                return EXIT_FAILURE;
            }
            break;
          COMMON_DAEMON_OPTION_CASES
        }
    }

    // If protocol is tcp we can't use -l or -L
    if (!_G.socketmap && (port_set || socketfile)) {
        usage();
        return EXIT_FAILURE;
    }

    if (_G.socketmap) {

        // Likewise, if protocol is socketmap we can't use -e or -d
        if (port_enc_set || port_dec_set) {
            usage();
            return EXIT_FAILURE;
        }

        // If neither -l or -L are specified, use default of just the port
        if (!port_set && !socketfile) {
            port_set = true;
        }

    }

    // Sockaddr_un cannot store more than 107 characters (it is char[108])
    if (socketfile && strlen(socketfile) > 107) {
        fputs("The socketfile specified for -L cannot be more than 107 characters in length\n\n", stderr);
        usage();
        return EXIT_FAILURE;
    }

    if (argc - optind != 2) {
        usage();
        return EXIT_FAILURE;
    }

    notice("%s v%s...", DAEMON_NAME, DAEMON_VERSION);

    // Fail on memory
    srs_set_malloc( xmalloc_unsigned, xrealloc_unsigned, free );

    _G.config.domain = argv[optind];
    _G.config.domainlen = strlen(_G.config.domain);
    _G.config.srs = srs_read_secrets(argv[optind + 1]);
    if (_G.config.srs == NULL) {
        return EXIT_FAILURE;
    }
    if (_G.config.separator != '\0'
        && srs_set_separator(_G.config.srs, _G.config.separator)
            == SRS_ESEPARATORINVALID) {
        return EXIT_FAILURE;
    }

    if (user == NULL)
        user = DEFAULT_RUNAS_USER;
    if (group == NULL)
        user = DEFAULT_RUNAS_GROUP;

    if (common_setup(pidfile, unsafe, user, group, daemonize) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    if (_G.socketmap) {

        if (socketfile && start_unix_listener(socketfile) == NULL)
            return EXIT_FAILURE;

        if (port_set && start_tcp_listener(port) == NULL)
            return EXIT_FAILURE;

    } else {

        if ((_G.encoder_ptr = start_tcp_listener(port_enc)) == NULL)
            return EXIT_FAILURE;

        if ((_G.decoder_ptr = start_tcp_listener(port_dec)) == NULL)
            return EXIT_FAILURE;

    }

    int ret;

    if (_G.socketmap) {
        // socketmap protocol
        ret = server_loop(srsd_starter_socketmap, srsd_stopper_socketmap, process_srs_socketmap, NULL, &_G.config);
    } else {
        // tcp protocol
        ret = server_loop(srsd_starter_tcp, NULL, process_srs_tcp, NULL, &_G.config);
    }

    // Cleanup socket file
    if (_G.socketmap) {
        if (socketfile) {
            unlink(socketfile);
        }
    }

    return ret;
}

/* vim:set et sw=4 sts=4 sws=4: */
