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

#include <tcbdb.h>

#include "db.h"
#include "str.h"
#include "resources.h"

static const clstr_t static_cleanup = { "@@cleanup@@", 11 };

struct db_t {
    unsigned can_expire : 1;

    char *ns;
    char *filename;
    TCBDB **db;

    db_checker_t need_cleanup;
    db_entry_checker_t entry_check;
    void *config;
};

typedef struct db_resource_t {
    TCBDB *db;
} db_resource_t;

static db_t *db_new(void)
{
    return p_new(db_t, 1);
}

static void db_delete(db_t **db)
{
    if (*db) {
        p_delete(&(*db)->ns);
        p_delete(&(*db)->filename);
        p_delete(db);
    }
}

static void db_resource_wipe(db_resource_t *res)
{
    if (res->db) {
        tcbdbsync(res->db);
        tcbdbdel(res->db);
    }
    p_delete(&res);
}

static bool db_need_cleanup(const db_t *db, TCBDB* tcdb)
{
    int len = 0;
    time_t now = time(NULL);
    const time_t *last_cleanup = tcbdbget3(tcdb, static_cleanup.str, static_cleanup.len, &len);
    if (last_cleanup == NULL) {
        debug("No last cleanup time");
    }
    return last_cleanup == NULL
        || len != sizeof(*last_cleanup)
        || db->need_cleanup(*last_cleanup, now, db->config);
}

static TCBDB** db_resource_acquire(const db_t *db)
{
    TCBDB *awl_db, *tmp_db;
    time_t now = time(NULL);

    db_resource_t *res = resource_get(db->ns, db->filename);
    if (res == NULL) {
        res = p_new(db_resource_t, 1);
        resource_set(db->ns, db->filename, res, (resource_destructor_t)db_resource_wipe);
    }

    /* Open the database and check if cleanup is needed
     */
    awl_db = res->db;
    res->db = NULL;
    if (awl_db == NULL) {
        awl_db = tcbdbnew();
        if (!tcbdbopen(awl_db, db->filename, BDBOWRITER | BDBOCREAT)) {
            err("can not open database: %s", tcbdberrmsg(tcbdbecode(awl_db)));
            tcbdbdel(awl_db);
            resource_release(db->ns, db->filename);
            return NULL;
        }
    }
    if (!db->can_expire || !db_need_cleanup(db, awl_db)) {
        notice("%s loaded: no cleanup needed", db->filename);
        res->db = awl_db;
        return &res->db;
    } else {
        tcbdbsync(awl_db);
        tcbdbdel(awl_db);
    }

    /* Rebuild a new database after removing too old entries.
     */
    if (db->can_expire) {
        uint32_t old_count = 0;
        uint32_t new_count = 0;
        bool replace = false;
        bool trashable = false;
        char tmppath[PATH_MAX];
        snprintf(tmppath, PATH_MAX, "%s.tmp", db->filename);

        awl_db = tcbdbnew();
        if (tcbdbopen(awl_db, db->filename, BDBOREADER)) {
            tmp_db = tcbdbnew();
            if (tcbdbopen(tmp_db, tmppath, BDBOWRITER | BDBOCREAT | BDBOTRUNC)) {
                BDBCUR *cur = tcbdbcurnew(awl_db);
                TCXSTR *key, *value;

                key = tcxstrnew();
                value = tcxstrnew();
                if (tcbdbcurfirst(cur)) {
                    replace = true;
                    do {
                        tcxstrclear(key);
                        tcxstrclear(value);
                        (void)tcbdbcurrec(cur, key, value);

                        if (db->entry_check(tcxstrptr(value), (size_t)tcxstrsize(value), now, db->config)) {
                            tcbdbput(tmp_db, tcxstrptr(key), tcxstrsize(key),
                                     tcxstrptr(value), tcxstrsize(value));
                            ++new_count;
                        }
                        ++old_count;
                    } while (tcbdbcurnext(cur));
                    tcbdbput(tmp_db, static_cleanup.str, static_cleanup.len, &now, sizeof(now));
                }
                tcxstrdel(key);
                tcxstrdel(value);
                tcbdbcurdel(cur);
                tcbdbsync(tmp_db);
            } else {
                warn("cannot run database cleanup: can't open destination database: %s",
                     tcbdberrmsg(tcbdbecode(awl_db)));
            }
            tcbdbdel(tmp_db);
        } else {
            int ecode = tcbdbecode(awl_db);
            warn("can not open database: %s", tcbdberrmsg(ecode));
            trashable = ecode != TCENOPERM && ecode != TCEOPEN && ecode != TCENOFILE && ecode != TCESUCCESS;
        }
        tcbdbdel(awl_db);

        /** Cleanup successful, replace the old database with the new one.
         */
        if (trashable) {
            notice("%s cleanup: database was corrupted, create a new one", db->filename);
            unlink(db->filename);
        } else if (replace) {
            notice("%s cleanup: done in %us, before %u, after %u entries",
                   db->filename, (uint32_t)(time(0) - now), old_count, new_count);
            unlink(db->filename);
            if (rename(tmppath, db->filename) != 0) {
                UNIXERR("rename");
                resource_release(db->ns, db->filename);
                return NULL;
            }
        } else {
            unlink(tmppath);
            notice("%s cleanup: done in %us, nothing to do, %u entries",
                   db->filename, (uint32_t)(time(0) - now), old_count);
        }
    }

    /* Effectively open the database.
     */
    res->db = NULL;
    awl_db = tcbdbnew();
    if (!tcbdbopen(awl_db, db->filename, BDBOWRITER | BDBOCREAT)) {
        err("can not open database: %s", tcbdberrmsg(tcbdbecode(awl_db)));
        tcbdbdel(awl_db);
        resource_release(db->ns, db->filename);
        return NULL;
    }

    notice("%s loaded", db->filename);
    res->db = awl_db;
    return &res->db;
}

db_t *db_load(const char* ns, const char* path, bool can_expire,
              db_checker_t need_cleanup, db_entry_checker_t entry_check, void *config)
{
    db_t *db = db_new();
    db->can_expire = can_expire;
    db->need_cleanup = need_cleanup;
    db->entry_check = entry_check;
    db->config = config;
    db->ns = m_strdup(ns);
    db->filename = m_strdup(path);
    db->db = db_resource_acquire(db);
    if (db->db == NULL) {
        db_delete(&db);
    }
    return db;
}

bool db_release(db_t *db)
{
    resource_release(db->ns, db->filename);
    db_delete(&db);
    return true;
}

const void* db_get(const db_t *db, const void* key, size_t key_len, size_t *entry_len)
{
    int len = 0;
    const void* data = tcbdbget3(*db->db, key, key_len, &len);
    *entry_len = len;
    return data;
}

bool db_get_len(const db_t *db, const void* key, size_t key_len, void* entry, size_t entry_len)
{
    int len = 0;
    const void* data = tcbdbget3(*db->db, key, key_len, &len);
    if (len != (int)entry_len || data == NULL) {
        return false;
    } else {
        memcpy(entry, data, entry_len);
        return true;
    }
}

bool db_put(const db_t *db, const void* key, size_t key_len, const void* entry, size_t entry_len)
{
    tcbdbput(*db->db, key, key_len, entry, entry_len);
    return true;
}

/* vim:set et sw=4 sts=4 sws=4: */
