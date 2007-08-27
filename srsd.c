/******************************************************************************/
/*          postlicyd: a postfix policy daemon with a lot of features         */
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
 */

#include <fcntl.h>
#include <sys/stat.h>

#include <srs2.h>

#include "common.h"
#include "mem.h"

#define MAX_SIZE 0x10000

static char **read_sfile(char *sfile)
{
    int fd  = -1;
    int pos = 0;
    int nb  = 0;
    int len = 0;

    char  *buf = NULL;
    char **res = NULL;

    struct stat stat_buf;

    if (stat(sfile, &stat_buf)) {
        perror("stat");
        exit(1);
    }

    if (stat_buf.st_size > MAX_SIZE) {
        fprintf(stderr, "the secret file is too big\n");
        exit(1);
    }

    buf = (char *)malloc(stat_buf.st_size+1);
    buf[stat_buf.st_size] = 0;

    if ((fd = open(sfile, O_RDONLY)) < 0) {
        perror("open");
        exit (1);
    }

    for (;;) {
        if ((nb = read(fd, &(buf[pos]), stat_buf.st_size)) < 0) {
            if (errno == EINTR)
                continue;
            perror("read");
            exit(1);
        }
        pos += nb;
        if (nb == 0 || pos == stat_buf.st_size) {
            close(fd);
            fd = -1;
            break;
        }
    }

    for (nb = pos = 0; pos < stat_buf.st_size ; pos++) {
        if (buf[pos] == '\n') {
            nb++;
            buf[pos] = 0;
        }
    }

    res = p_new(char*, nb + 2);

    nb = pos = 0;
    while (pos < stat_buf.st_size) {
        len = strlen(&(buf[pos]));
        if (len) {
            res[nb++] = &(buf[pos]);
        }
        pos += len+1;
    }

    return res;
}


static char *encode(char *secret, char *sender, char *alias)
{
    int    err = 0;
    char  *res = NULL;
    srs_t *srs = srs_new();

    srs_add_secret(srs, secret);
    err = srs_forward_alloc(srs, &res, sender, alias);

    if (res == NULL) {
        fprintf(stderr, "%s\n", srs_strerror(err));
        exit (1);
    }

    return res;
}

static char *decode(char *secret, char *secrets[], char *sender)
{
    int    err = 0;
    char  *res = NULL;
    srs_t *srs = srs_new();

    if (secret) {
        srs_add_secret(srs, secret);
    }

    for (; secrets && secrets[err] != 0; err++) {
        srs_add_secret(srs, secrets[err]);
    }

    err = srs_reverse_alloc(srs, &res, sender);

    if (res == NULL) {
        fprintf(stderr, "%s\n", srs_strerror(err));
        exit(1);
    }

    return res;
}

static void help(void)
{
    puts(
            "Usage: srs-c [ -r | -d domain ] [ -s secret | -f sfile ] -e sender\n"
            "Perform an SRS encoding / decoding\n"
            "\n"
            "    -r          perform an SRS decoding\n"
            "    -d domain   use that domain (required for encoding)\n"
            "\n"
            "    -s secret   secret used in the encoding (sfile required if omitted)\n"
            "    -f sfile    secret file for decoding.  the first line is taken if -s omitted\n"
            "\n"
            "    -e sender   the sender address we want to encode/decode\n"
          );
    exit (1);
}

int main(int argc, char *argv[])
{
    char *buf    = NULL;
    char *domain = NULL;
    char *sender = NULL;
    char *secret = NULL;
    char *sfile  = NULL;

    int    opt   = 0;
    bool   rev   = false;
    char **secr  = NULL;

    while ((opt = getopt(argc, argv, "d:e:s:f:r")) != -1) {
        switch (opt) {
            case 'd': domain = optarg;  break;
            case 'e': sender = optarg;  break;
            case 'f': sfile  = optarg;  break;
            case 'r': rev    = true;    break;
            case 's': secret = optarg;  break;
        }
    }

    if (!sender || !(secret||sfile) || !(rev||domain)) {
        help ();
    }

    if (sfile) {
        secr = read_sfile(sfile);
        if (!secret && (!secr || !secr[0])) {
            fprintf(stderr, "No secret given, and secret file is empty\n");
            exit (1);
        }
    }

    if (rev) {
        buf = decode(secret, secr, sender);
    } else {
        buf = encode((secret ? secret : secr[0]), sender, domain);
    }

    puts(buf);
    return 0;
}
