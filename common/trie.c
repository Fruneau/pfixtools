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

#include "str.h"
#include "trie.h"

typedef struct trie_entry_t trie_entry_t;

struct trie_entry_t {
    char *c;
    int  c_len;
    bool c_own;

    int* children;
    int children_len;
    int children_size;

    bool locked;
};

struct trie_t {
    trie_entry_t* entries;
    int entries_len;
    int entries_size;

    bool locked;
};

trie_t *trie_new()
{
    return p_new(trie_t, 1);
}

void trie_delete(trie_t **trie)
{
    if (*trie) {
        for (int i = 0 ; i < (*trie)->entries_len ; ++i) {
            trie_entry_t *entry = &(*trie)->entries[i];
            if (entry->c_own) {
                p_delete(&entry->c);
            } else {
                entry->c = NULL;
            }
            p_delete(&(entry->children));
        }
        p_delete(&(*trie)->entries);
        p_delete(trie);
    }
}

/** Check that the given entry is a prefix for the given key.
 */
static inline bool trie_entry_c_match(const trie_entry_t* entry,
                                      const char *key, int *pos)
{
    int i = 0;
    for (i = 0 ; i < entry->c_len ; ++i) {
        if (key[i] != entry->c[i]) {
            if (pos) {
                *pos = i;
            }
            return false;
        }
    }
    if (pos) {
        *pos = i;
    }
    return true;
}

/** Lookup for a child of entry matching the given entry at the given pos.
 * Only the first character of the children is taken into account in the
 * lookup. The current entry is assumed to match the key.
 */
static inline trie_entry_t* trie_entry_child(const trie_t *trie,
                                             const trie_entry_t* entry,
                                             const char *key)
{
    int start = 0;
    int end   = entry->children_len;
    const char c = *key;

    while (start < end) {
        int mid = (start + end) / 2;
        trie_entry_t* child = &trie->entries[entry->children[mid]];

        if (child->c_len) {
            if (child->c[0] == c) {
                return child;
            }
            if (c < child->c[0]) {
                end = mid;
            } else {
                start = mid + 1;
            }
        } else {
            abort();
        }
    }
    return NULL;
}

static inline void trie_grow(trie_t *trie, int delta)
{
    int next_size = trie->entries_size;
    if (next_size > trie->entries_len + delta) {
        return;
    }
    do {
        next_size = p_alloc_nr(next_size);
    } while (trie->entries_len + delta > next_size);
    p_allocgrow(&trie->entries, next_size, &trie->entries_size);
}

static inline int trie_entry_new(trie_t *trie)
{
    memset(trie->entries + trie->entries_len, 0, sizeof(trie_entry_t));
    return trie->entries_len++;
}

static inline int trie_add_leaf(trie_t *trie, const char *key)
{
    trie_entry_t *entry;
    entry = &trie->entries[trie_entry_new(trie)];
    entry->c     = strdup(key); /* don't use m_strdup
                                   since m_strdup("") == NULL */
    entry->c_len = m_strlen(key) + 1;
    entry->c_own = true;
    return trie->entries_len - 1;
}

static inline void trie_entry_insert_child(trie_t *trie, trie_entry_t *entry,
                                           int pchild)
{
    const char c = trie->entries[pchild].c[0];
    int start = 0;
    int end   = entry->children_len;

    p_allocgrow(&entry->children, entry->children_len + 1, &entry->children_size);
    while (start < end) {
        int mid = (start + end) / 2;
        trie_entry_t* child = &trie->entries[entry->children[mid]];

        if (child->c_len) {
            if (child->c[0] == c) {
                abort();
            }
            if (c < child->c[0]) {
                end = mid;
            } else {
                start = mid + 1;
            }
        } else {
            abort();
        }
    }
    memmove(entry->children + start + 1,
            entry->children + start,
            sizeof(int) * (entry->children_len - start));
    entry->children[start] = pchild;
    ++entry->children_len;
}

static inline void trie_entry_split(trie_t *trie, trie_entry_t *entry, int pos)
{
    trie_entry_t *child;
    child    = &trie->entries[trie_entry_new(trie)];
    if (pos == 0) {
        child->c     = entry->c;
        child->c_len = entry->c_len;
        child->c_own = entry->c_own;
        entry->c     = NULL;
        entry->c_len = 0;
        entry->c_own = false;
    } else {
        child->c     = entry->c + pos;
        child->c_len = entry->c_len - pos;
        child->c_own = false;
        entry->c_len = pos;
    }
    child->children      = entry->children;
    child->children_len  = entry->children_len;
    child->children_size = entry->children_size;
    entry->children      = NULL;
    entry->children_len  = 0;
    entry->children_size = 0;
    trie_entry_insert_child(trie, entry, trie->entries_len - 1);
}

void trie_insert(trie_t *trie, const char* key)
{
    trie_grow(trie, 2);
    if (trie->entries_len == 0) {
        (void)trie_add_leaf(trie, key);
    } else {
        trie_entry_t *current = trie->entries;
        while (true) {
            int pos = 0;
            if (trie_entry_c_match(current, key, &pos)) {
                if (current->c_len && current->c[current->c_len - 1] == '\0') {
                    return;
                }
                trie_entry_t *next = NULL;
                key += pos;
                next = trie_entry_child(trie, current, key);
                if (next == NULL) {
                    trie_entry_insert_child(trie, current,
                                            trie_add_leaf(trie, key));
                    return;
                } else {
                    current = next;
                }
            } else {
                trie_entry_split(trie, current, pos);
                trie_entry_insert_child(trie, current,
                                        trie_add_leaf(trie, key + pos));
                return;
            }
        }
    }
}

bool trie_lookup(const trie_t *trie, const char *key)
{
    if (trie->entries_len == 0) {
        return false;
    } else {
        trie_entry_t *current = trie->entries;
        while (true) {
            int pos = 0;
            if (trie_entry_c_match(current, key, &pos)) {
                if (current->c_len && current->c[current->c_len - 1] == '\0') {
                    return true;
                }
                key += pos;
                current = trie_entry_child(trie, current, key);
                if (current == NULL) {
                    return false;
                }
            } else {
                return false;
            }
        }
    }
}


/* Debug {{{1
 */

static inline void trie_entry_inspect(const trie_t *trie,
                                      const trie_entry_t *entry, int level)
{
    for (int i = 0 ; i < level ; ++i) {
        fputs("  ", stdout);
    }
    if (entry->c == NULL) {
        fputs("(nil)", stdout);
    } else {
        for (int i = 0 ; i < entry->c_len ; ++i) {
            if (entry->c[i]) {
                printf("%c ", entry->c[i]);
            } else {
                fputs("\\0 ", stdout);
            }
        }
    }
    fputs("\n", stdout);
    for (int i = 0 ; i < entry->children_len ; ++i) {
        trie_entry_inspect(trie, &trie->entries[entry->children[i]], level + 1);
    }
}

void trie_inspect(const trie_t *trie)
{
    trie_entry_inspect(trie, trie->entries, 0);
}
