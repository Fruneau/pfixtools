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

#ifndef PFIXTOOLS_TRIE_H
#define PFIXTOOLS_TRIE_H

#include "common.h"
#include "array.h"

typedef struct trie_t trie_t;
PARRAY(trie_t)

trie_t *trie_new(void);
void trie_delete(trie_t **trie);

/** Add a string in the trie.
 * \ref trie_compile.
 */
__attribute__((nonnull(1,2)))
void trie_insert(trie_t *trie, const char *key);

/** Compile the trie.
 * A trie must be compiled before lookup is possible. Compiling the trie
 * consists in building the tree.
 *
 * \param memlock if true, the trie is locked into the RAM (mlock).
 *
 * Usage of a trie:
 *   trie_insert(trie, ...);
 *   trie_insert(trie, ...);
 *   ...
 *   trie_insert(trie, ...);
 *
 *   trie_compile(trie, lock);
 *
 *   trie_lookup(trie, ...);
 *   trie_lookup(trie, ...);
 */
__attribute__((nonnull(1)))
void trie_compile(trie_t *trie, bool memlock);

/** Lock the trie into memory.
 * \ref trie_unlock
 */
__attribute__((nonnull(1)))
void trie_lock(trie_t *trie);

/** Unlock the trie.
 * \ref trie_lock
 */
__attribute__((nonnull(1)))
void trie_unlock(trie_t *trie);

/** Check if the trie contains \p key.
 */
__attribute__((nonnull(1,2)))
bool trie_lookup(const trie_t *trie, const char *key);

/** Check if the trie contains a prefix of \p key.
 */
__attribute__((nonnull(1,2)))
bool trie_prefix(const trie_t *trie, const char *key);

/** Show the content of the trie and computes statistics.
 */
__attribute__((nonnull(1)))
void trie_inspect(const trie_t *trie, bool show_content);

#endif
