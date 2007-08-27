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

static srs_t *srs = NULL;

static int read_sfile(const char *sfile)
{
    FILE *f;
    char buf[BUFSIZ];
    srs_t *newsrs;

    f = fopen(sfile, "r");
    if (!f) {
        UNIXERR("fopen");
        return -1;
    }

    newsrs = srs_new();

    while (fgets(buf, sizeof(buf), f)) {
        int n = strlen(buf);

        if (buf[n - 1] != '\n')
            goto error;
        while (n > 0 && isspace((unsigned char)buf[n - 1]))
            buf[--n] = '\0';
        if (n > 0)
            srs_add_secret(newsrs, buf);
    }
    fclose(f);

    if (srs) {
        srs_free(srs);
    }
    srs = newsrs;
    return 0;

  error:
    fclose(f);
    srs_free(newsrs);
    return -1;
}

static void help(void)
{
    puts(
            "Usage: srs-c [ -r | -d domain ] -f sfile -e sender\n"
            "Perform an SRS encoding / decoding\n"
            "\n"
            "    -r          perform an SRS decoding\n"
            "    -d domain   use that domain (required for encoding)\n"
            "\n"
            "    -f sfile    secret file for decoding.  the first line is taken if -s omitted\n"
            "\n"
            "    -e sender   the sender address we want to encode/decode\n"
          );
    exit(1);
}

int main(int argc, char *argv[])
{
    char *res    = NULL;
    char *domain = NULL;
    char *sender = NULL;
    char *sfile  = NULL;

    int    opt   = 0;
    bool   rev   = false;
    int    err   = 0;

    while ((opt = getopt(argc, argv, "d:e:f:r")) != -1) {
        switch (opt) {
            case 'd': domain = optarg;  break;
            case 'e': sender = optarg;  break;
            case 'f': sfile  = optarg;  break;
            case 'r': rev    = true;    break;
        }
    }

    if (!sender || !sfile || !(rev||domain)) {
        help();
    }

    if (read_sfile(sfile) < 0)
        return -1;

    if (rev) {
        err = srs_reverse_alloc(srs, &res, sender);
    } else {
        err = srs_forward_alloc(srs, &res, sender, domain);
    }

    if (res == NULL) {
        fprintf(stderr, "%s\n", srs_strerror(err));
        return -1;
    }
    puts(res);
    return 0;
}
