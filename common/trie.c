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

#include <sys/mman.h>

#include "array.h"
#include "str.h"
#include "trie.h"

typedef struct trie_entry_t trie_entry_t;

struct trie_entry_t {
    int32_t  c_offset;
    int32_t  c_len;

    int32_t children_offset;
    int32_t children_len;
};
#define TRIE_ENTRY_INIT { 0, 0, 0, 0 }
ARRAY(trie_entry_t)

struct trie_t {
    A(trie_entry_t) entries;
    A(char)         c;
    A(char)         keys;
    A(int)          keys_offset;

    bool locked;
};

trie_t *trie_new(void)
{
    return p_new(trie_t, 1);
}

static inline void trie_cleanup_build_data(trie_t *trie)
{
    array_wipe(trie->keys);
    array_wipe(trie->keys_offset);
}

void trie_delete(trie_t **trie)
{
    if (*trie) {
        trie_cleanup_build_data(*trie);
        trie_unlock(*trie);
        array_wipe((*trie)->entries);
        array_wipe((*trie)->c);
        p_delete(trie);
    }
}

/** Check that the given entry is a prefix for the given key.
 */
static inline bool trie_entry_c_match(const trie_t *trie,
                                      const trie_entry_t *entry,
                                      const char *key, int *pos)
{
    const char *c = array_ptr(trie->c, entry->c_offset);
    int i = 0;
    for (i = 0 ; i < entry->c_len ; ++i) {
        if (key[i] != c[i]) {
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

static inline bool trie_entry_match(const trie_t *trie,
                                    const trie_entry_t *entry, const char *key)
{
    return !!(strcmp(array_ptr(trie->c, entry->c_offset), key) == 0);
}

static inline bool trie_entry_is_leaf(const trie_entry_t *entry)
{
    return entry->children_len == 0;
}

/** Lookup for a child of entry matching the given entry at the given pos.
 * Only the first character of the children is taken into account in the
 * lookup. The current entry is assumed to match the key.
 */
static inline trie_entry_t* trie_entry_child(const trie_t *trie,
                                             const trie_entry_t* entry,
                                             const char *key)
{
    int start = entry->children_offset;
    int end   = start + entry->children_len;
    const char c = *key;

    while (start < end) {
        int mid = (start + end) / 2;
        trie_entry_t* child = array_ptr(trie->entries, mid);
        const char c2 = array_elt(trie->c, child->c_offset);

        if (child->c_len) {
            if (c2 == c) {
                return child;
            }
            if (c < c2) {
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

static inline int trie_entry_new(trie_t *trie)
{
    const trie_entry_t e = TRIE_ENTRY_INIT;
    array_add(trie->entries, e);
    return trie->entries.len;
}

static inline int trie_add_leaf(trie_t *trie, const char *key)
{
    trie_entry_t *entry;
    int len = m_strlen(key) + 1;
    entry = array_ptr(trie->entries, trie_entry_new(trie));
    entry->c_offset = trie->c.len;
    entry->c_len    = len;
    array_append(trie->c, key, len);
    return trie->entries.len - 1;
}

static inline void trie_entry_insert_child(trie_t *trie, trie_entry_t *entry,
                                           int pchild)
{
    if (entry->children_len == 0) {
        entry->children_offset = pchild;
        entry->children_len    = 1;
    } else {
        if (entry->children_offset + entry->children_len != pchild) {
            printf("Inserting child %d while offset is %d[%d]\n",
                   pchild, entry->children_offset, entry->children_len);
            abort();
        }
        ++entry->children_len;
    }
}

static inline void trie_entry_split(trie_t *trie, trie_entry_t *entry, int pos)
{
    trie_entry_t *child;
    child    = array_ptr(trie->entries, trie_entry_new(trie));
    if (pos == 0) {
        child->c_offset = entry->c_offset;
        child->c_len    = entry->c_len;
        entry->c_offset = 0;
        entry->c_len    = 0;
    } else {
        child->c_offset = entry->c_offset + pos;
        child->c_len    = entry->c_len - pos;
        entry->c_len    = pos;
    }
    child->children_offset = entry->children_offset;
    child->children_len    = entry->children_len;
    entry->children_offset = trie->entries.len - 1;
    entry->children_len    = 1;
}

void trie_insert(trie_t *trie, const char* key)
{
    assert(trie->entries.len == 0 && "Trie already compiled");

    int len = m_strlen(key) + 1;
    array_add(trie->keys_offset, trie->keys.len);
    array_append(trie->keys, key, len);
}


static inline void trie_compile_aux(trie_t *trie, int id,
                                    int first_key, int last_key, int offset,
                                    int initial_diff)
{
    int forks[256];
    int fork_pos = 0;
    char current = '\0';

    for (int off_diff = initial_diff ; fork_pos == 0 ; ++off_diff, ++offset) {
        current = array_elt(trie->keys, array_elt(trie->keys_offset, first_key) + offset);
        for (int i = first_key + 1 ; i < last_key ; ++i) {
            const char *str = array_ptr(trie->keys, array_elt(trie->keys_offset, i));
            const char c = str[offset];
            if (c != current) {
                array_ensure_capacity_delta(trie->entries, 2);
                if (fork_pos == 0) {
                    trie_entry_split(trie, array_ptr(trie->entries, id), off_diff);
                }
                trie_entry_insert_child(trie, array_ptr(trie->entries, id),
                                        trie_add_leaf(trie, str + offset));
                forks[fork_pos++] = i;
                current = c;
            }
        }
        if (fork_pos == 0 && current == '\0') {
            return;
        }
    }
    forks[fork_pos] = last_key;

    const int children_len = array_elt(trie->entries, id).children_len;
    for (int i = 0 ; i < children_len ; ++i) {
        int child = array_elt(trie->entries, id).children_offset + i;
        if (forks[i] - 1 > first_key) {
            trie_compile_aux(trie, child, first_key, forks[i], offset, 1);
        }
        first_key = forks[i];
    }
}

void trie_compile(trie_t *trie, bool memlock)
{
    assert(trie->entries.len == 0 && "Trie already compiled");
    assert(trie->keys.len != 0 && "Trying to compile an empty trie");
    {
#       define QSORT_TYPE int
#       define QSORT_BASE trie->keys_offset.data
#       define QSORT_NELT trie->keys_offset.len
#       define QSORT_LT(a,b) strcmp(trie->keys.data + *a, trie->keys.data + *b) < 0
#       include "qsort.c"
    }

    array_ensure_capacity(trie->entries, trie->keys.len);
    trie_compile_aux(trie, trie_add_leaf(trie, trie->keys.data),
                     0, trie->keys_offset.len, 0, 0);
    trie_cleanup_build_data(trie);
    array_adjust(trie->entries);
    array_adjust(trie->c);
    if (memlock) {
        trie_lock(trie);
    }
}

bool trie_lookup(const trie_t *trie, const char *key)
{
    assert(trie->keys.len == 0L && "Can't lookup: trie not compiled");
    if (trie->entries.len == 0) {
        return false;
    } else {
        trie_entry_t *current = array_ptr(trie->entries, 0);
        while (true) {
            int pos = 0;
            if (trie_entry_is_leaf(current)) {
                return trie_entry_match(trie, current, key);
            } else if (trie_entry_c_match(trie, current, key, &pos)) {
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

void trie_lock(trie_t *trie)
{
    if (trie->locked) {
        return;
    }
    if (mlock(trie->entries.data, sizeof(trie_entry_t) * trie->entries.len) != 0) {
        UNIXERR("mlock");
        return;
    }
    if (mlock(trie->c.data, trie->c.len) != 0) {
        UNIXERR("mlock");
        munlock(trie->entries.data, sizeof(trie_entry_t) * trie->entries.len);
        return;
    }
    trie->locked = true;
}

void trie_unlock(trie_t *trie)
{
    if (!trie->locked) {
        return;
    }
    munlock(trie->entries.data, sizeof(trie_entry_t) * trie->entries.len);
    munlock(trie->c.data, trie->c.len);
    trie->locked = false;
}

/* Debug {{{1
 */

static inline void trie_entry_inspect(const trie_t *trie, bool show_content,
                                      const trie_entry_t *entry, int level)
{
    static int max_depth = 0;
    static int leaves    = 0;
    static int depth_sum = 0;

    if (trie_entry_is_leaf(entry)) {
        if (level > max_depth) {
            max_depth = level;
        }
        ++leaves;
        depth_sum += level;
    }
    if (show_content) {
        for (int i = 0 ; i < level ; ++i) {
            fputs("  ", stdout);
        }
        if (entry->c_len == 0) {
            fputs("(nil)", stdout);
        } else {
            const char *c = array_ptr(trie->c, entry->c_offset);
            printf("(%d) ", entry->c_len);
            for (int i = 0 ; i < entry->c_len ; ++i) {
                if (c[i]) {
                    printf("%c ", c[i]);
                } else {
                    fputs("\\0 ", stdout);
                }
            }
        }
        fputs("\n", stdout);
    }
    for (int i = entry->children_offset ;
          i < entry->children_offset + entry->children_len ; ++i) {
        trie_entry_inspect(trie, show_content, array_ptr(trie->entries, i), level + 1);
    }
    if (level == 0) {
        printf("Average char per node: %d\n", trie->c.len / trie->entries.len);
        printf("Number of nodes: %d\n", trie->entries.len);
        printf("Number of leaves: %d\n", leaves);
        printf("Max depth: %d\n", max_depth);
        printf("Average leaf depth: %d\n", depth_sum / leaves);
        printf("Memory used: %d\n", (trie->entries.size * sizeof(trie_entry_t))
                                  + (trie->c.size) + sizeof(trie_t));
    }
}

void trie_inspect(const trie_t *trie, bool show_content)
{
    trie_entry_inspect(trie, show_content, trie->entries.data, 0);
}
