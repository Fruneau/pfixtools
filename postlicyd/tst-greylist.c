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
 * Copyright © 2008 Florent Bruneau
 */

#include <tcbdb.h>

#include "common.h"
#include "str.h"


struct awl_entry {
    int32_t count;
    time_t  last;
};

union obj {
  struct {
    unsigned a:8;
    unsigned b:8;
    unsigned c:8;
    unsigned d:8;
    unsigned e:8;
    unsigned f:8;
    unsigned g:8;
    unsigned h:8;
  } b;

  struct {
    unsigned a:32;
    unsigned b:32;
  } w;

  uint64_t l;
};

__attribute__((used))
static void fill_tree(TCBDB *db)
{
    char key[BUFSIZ];
    union obj val;
    ssize_t key_len;

    struct awl_entry entry = { 0, 0 };

    for (uint32_t i = 0 ; i < 1000000 ; ++i) {
        val.w.a = random();
        val.w.b = random();
        key_len = snprintf(key, BUFSIZ, "%u.%u.%u.%u.%u.%u.%u.%u",
                           val.b.a, val.b.b, val.b.c, val.b.d,
                           val.b.e, val.b.f, val.b.g, val.b.h);
        tcbdbput(db, key, key_len, &entry, sizeof(entry));
        if (i && i % 10000 == 0) {
            info("%u inserted... sill %u to go", i, 1000000 - i);
        }
    }
    tcbdbsync(db);
}

static void enumerate_tree(TCBDB *src, TCBDB *dest)
{
    BDBCUR *cur = tcbdbcurnew(src);
    TCXSTR *key, *value;
    uint32_t new_count = 0;

    key = tcxstrnew();
    value = tcxstrnew();
    if (tcbdbcurfirst(cur)) {
        do {
            tcxstrclear(key);
            tcxstrclear(value);
            (void)tcbdbcurrec(cur, key, value);

            tcbdbput(dest, tcxstrptr(key), tcxstrsize(key),
                      tcxstrptr(value), sizeof(struct awl_entry));
            ++new_count;
            if (new_count % 10000 == 0) {
                info("%u enumerated... strill %u to go", new_count, 1000000 - new_count);
            }
        } while (tcbdbcurnext(cur));
    }
    tcxstrdel(key);
    tcxstrdel(value);
    tcbdbcurdel(cur);
    tcbdbsync(dest);
}

int main(void)
{
    TCBDB *db;
    TCBDB *tmp;
    common_startup();

    info("Fill the database with 1.000.000 of random entries");
    db = tcbdbnew();
    if (!tcbdbopen(db, "/tmp/test_greylist_perf", BDBOWRITER | BDBOCREAT | BDBOTRUNC)) {
        err("can not open database: %s", tcbdberrmsg(tcbdbecode(db)));
        tcbdbdel(db);
        return -1;
    }

    fill_tree(db);
    info("Done");
    tcbdbclose(db);
    tcbdbdel(db);

    info("Enumerate the database in a new one");
    tmp = tcbdbnew();
    if (!tcbdbopen(tmp, "/tmp/test_greylist_perf.tmp",
                   BDBOWRITER | BDBOCREAT | BDBOTRUNC)) {
        err("can not open database: %s", tcbdberrmsg(tcbdbecode(tmp)));
        tcbdbdel(tmp);
        return -1;
    }
    db = tcbdbnew();
    if (!tcbdbopen(db, "/tmp/test_greylist_perf", BDBOREADER)) {
        err("can not open database: %s", tcbdberrmsg(tcbdbecode(db)));
        tcbdbdel(db);
        tcbdbdel(tmp);
        return -1;
    }

    enumerate_tree(db, tmp);
    info("done");
    tcbdbclose(db);
    tcbdbdel(db);
    tcbdbclose(tmp);
    tcbdbdel(tmp);

    return 0;
}
