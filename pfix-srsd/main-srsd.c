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
 * Copyright © 2005-2007 Pierre Habouzit
 * Copyright © 2008 Florent Bruneau
 */

#include "common.h"

#include <srs2.h>

#include "mem.h"
#include "buffer.h"
#include "server.h"

#define DAEMON_NAME             "pfix-srsd"
#define DAEMON_VERSION          "0.1"
#define DEFAULT_ENCODER_PORT    10001
#define DEFAULT_DECODER_PORT    10002
#define RUNAS_USER              "nobody"
#define RUNAS_GROUP             "nogroup"

DECLARE_MAIN

typedef struct srs_config_t {
    srs_t* srs;
    const char* domain;
} srs_config_t;


/* Server {{{1
 */

static listener_t *decoder_ptr = NULL;
static listener_t *encoder_ptr = NULL;

static void *srsd_starter(listener_t *server)
{
    return server;
}


/* Processing {{{1
 */

void urldecode(char *s, char *end)
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
    *s++ = '\0';
}

int process_srs(client_t *srsd, void* vconfig)
{
    srs_config_t* config = vconfig;
    buffer_t *ibuf = client_input_buffer(srsd);
    buffer_t *obuf = client_output_buffer(srsd);
    bool decoder = (client_data(srsd) == decoder_ptr);
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
            buffer_addstr(&*obuf, "400 empty request ???\n");
            warn("empty request");
            goto skip;
        }

        urldecode(p, q);

        if (decoder) {
            err = srs_reverse(config->srs, buf, ssizeof(buf), p);
        } else {
            err = srs_forward(config->srs, buf, ssizeof(buf), p, config->domain);
        }

        if (err == 0) {
            buffer_addstr(&*obuf, "200 ");
            buffer_addstr(&*obuf, buf);
        } else {
            switch (SRS_ERROR_TYPE(err)) {
              case SRS_ERRTYPE_SRS:
              case SRS_ERRTYPE_SYNTAX:
                buffer_addstr(&*obuf, "500 ");
                break;
              default:
                buffer_addstr(&*obuf, "400 ");
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

static srs_config_t config = {
    .srs = NULL,
    .domain = NULL
};

/** overload srs_free since the lib is not properly maintained.
 */
inline void srs_free(srs_t* srs)
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
    if (config.srs) {
        srs_free(config.srs);
        config.srs = NULL;
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

void usage(void)
{
    fputs("usage: "DAEMON_NAME" [options] domain secrets\n"
          "\n"
          "Options:\n"
          "    -e <port>    port to listen to for encoding requests\n"
          "                 (default: "STR(DEFAULT_ENCODER_PORT)")\n"
          "    -d <port>    port to listen to for decoding requests\n"
          "                 (default: "STR(DEFAULT_DECODER_PORT)")\n"
          "    -p <pidfile> file to write our pid to\n"
          "    -u           unsafe mode: don't drop privilegies\n"
          "    -f           stay in foreground\n"
         , stderr);
}

/* }}}
 */

int main(int argc, char *argv[])
{
    bool unsafe  = false;
    bool daemonize = true;
    int port_enc = DEFAULT_ENCODER_PORT;
    int port_dec = DEFAULT_DECODER_PORT;
    const char *pidfile = NULL;

    for (int c = 0; (c = getopt(argc, argv, "hfu" "e:d:p:")) >= 0; ) {
        switch (c) {
          case 'e':
            port_enc = atoi(optarg);
            break;
          case 'f':
            daemonize = false;
            break;
          case 'd':
            port_dec = atoi(optarg);
            break;
          case 'p':
            pidfile = optarg;
            break;
          case 'u':
            unsafe = true;
            break;
          default:
            usage();
            return EXIT_FAILURE;
        }
    }

    if (!daemonize) {
        log_syslog = false;
    }

    if (argc - optind != 2) {
        usage();
        return EXIT_FAILURE;
    }

    info("starting %s v%s...", DAEMON_NAME, DAEMON_VERSION);

    config.domain = argv[optind];
    config.srs = srs_read_secrets(argv[optind + 1]);
    if (!config.srs
        || common_setup(pidfile, unsafe, RUNAS_USER, RUNAS_GROUP,
                        daemonize) != EXIT_SUCCESS
        || (encoder_ptr = start_listener(port_enc)) == NULL
        || (decoder_ptr = start_listener(port_dec)) == NULL) {
        return EXIT_FAILURE;
    }
    return server_loop(srsd_starter, NULL, process_srs, NULL, &config);
}
