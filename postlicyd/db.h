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
 * Copyright © 2009 Florent Bruneau
 */

#ifndef PFIXTOOLS_DB_H
#define PFIXTOOLS_DB_H

typedef struct db_t db_t;
typedef bool (*db_entry_checker_f)(const void* entry, size_t entry_len,
                                   time_t now, void* config);
typedef bool (*db_checker_f)(time_t last_cleanup, time_t now, void* config);

/** Load the database at the given path.
 * @param ns The resource namespace.
 * @param path The path to the database on-disk storage.
 * @param can_expire true if the entries of the database can expire.
 * @param need_cleanup A callback that check if the database requires cleanup.
 * @param entry_check A callback that check if an entry of the database is
 * obsolete.
 * @param config A pointer to a user data.
 * @return a db object or NULL if an error occured.
 */
db_t *db_load(const char* ns, const char* path, bool can_expire,
              db_checker_f need_cleanup, db_entry_checker_f entry_check,
              void* config);

/** Release and invalidate a db object.
 */
bool db_release(db_t *db);

/** Get an entry in a db.
 *
 * The pointer returned by this function is owned by the database handler,
 * you must not free it. If the key cannot be found in the databse, this
 * functions returns NULL.
 */
const void* db_get(const db_t *db, const void* key, size_t key_len,
                   size_t *entry_len);

/** Get an entry and ensure it has the correct size.
 *
 * The data is copied in the @p entry buffer. If the key is not found in the
 * database or if the entry does not have the length @p entry_len, this
 * function returrns false.
 */
bool db_get_len(const db_t *db, const void* key, size_t key_len,
                void* entry, size_t entry_len);

/** Add or replace the value associated to the given key in the database.
 */
bool db_put(const db_t *db, const void* key, size_t key_len,
            const void* entry, size_t entry_len);

#endif

/* vim:set et sw=4 sts=4 sws=4: */
