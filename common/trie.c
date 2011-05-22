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
 * Copyright © 2008-2009 Florent Bruneau
 */

#include "array.h"
#include "str.h"
#include "trie.h"

typedef struct trie_entry_t trie_entry_t;

struct trie_entry_t {
    uint32_t c_offset;
    uint32_t children_offset;
    int32_t  regexp_offset;

    uint16_t c_len;
    uint16_t children_len;
};
#define TRIE_ENTRY_INIT { 0, 0, -1, 0, 0 }
ARRAY(trie_entry_t)
#define str(trie, entry)  array_ptr((trie)->c, (entry)->c_offset)
#define rex(trie, entry)  (entry)->regexp_offset < 0 ? NULL                  \
                          : array_ptr((trie)->regexps, (entry)->regexp_offset)

typedef struct trie_key_t {
    int offset;
    int regexp;
} trie_key_t;
ARRAY(trie_key_t)
#define key(trie, id) array_ptr((trie)->keys,                                \
                                array_elt((trie)->keys_offset, (id)).offset)
#define rek(trie, id) (array_elt((trie)->keys_offset, (id)).regexp)

struct trie_t {
    A(trie_entry_t) entries;
    A(char)         c;
    A(regexp_t)     regexps;

    /* Build stuff */
    A(char)         keys;
    A(trie_key_t)   keys_offset;

    bool locked;
};

DO_INIT(trie_t, trie)
trie_t *trie_new(void)
{
    return trie_init(p_new(trie_t, 1));
}

static inline void trie_wipe_build_data(trie_t *trie)
{
    array_wipe(trie->keys);
    array_wipe(trie->keys_offset);
}

static inline void trie_wipe(trie_t *trie)
{
    trie_wipe_build_data(trie);
    trie_unlock(trie);
    array_wipe(trie->entries);
    array_wipe(trie->c);
    array_deep_wipe(trie->regexps, regexp_wipe);
}
void trie_delete(trie_t **trie)
{
    if (*trie) {
        trie_wipe(*trie);
        p_delete(trie);
    }
}

/** Check that the given entry is a prefix for the given key.
 */
static inline bool trie_entry_c_match(const trie_t *trie,
                                      const trie_entry_t *entry,
                                      const char *key)
{
    const char *c = str(trie, entry);
    int i = 0;
    for (i = 0 ; i < entry->c_len ; ++i) {
        if (key[i] != c[i]) {
            return false;
        }
    }
    return true;
}

static inline bool trie_entry_match(const trie_t *trie,
                                    const trie_entry_t *entry,
                                    const char *key)
{
    return !!(strcmp(str(trie, entry), key) == 0);
}

static inline bool trie_entry_prefix(const trie_t *trie,
                                     const trie_entry_t *entry,
                                     const char *key)
{
    int len = entry->c_len;
    if (len > 0 && str(trie, entry)[len - 1] == '\0') {
        --len;
    }
    return !!(strncmp(str(trie, entry), key, (size_t)len) == 0);
}

static inline bool trie_entry_is_leaf(const trie_entry_t *entry)
{
    return entry->children_len == 0;
}

/** Lookup for a child of entry matching the given entry at the given pos.
 * Only the first character of the children is taken into account in the
 * lookup. The current entry is assumed to match the key.
 */
static inline const trie_entry_t *trie_entry_child(const trie_t *trie,
                                                   const trie_entry_t *entry,
                                                   const char c)
{
    uint32_t start = entry->children_offset;
    uint32_t end   = start + entry->children_len;

    while (start < end) {
        uint32_t mid = (start + end) >> 1;
        const trie_entry_t *child = array_ptr(trie->entries, mid);
        const char c2 = str(trie, child)[0];

        if (c2 == c) {
            return child;
        }
        if (c < c2) {
            end = mid;
        } else {
            start = mid + 1;
        }
    }
    return NULL;
}

static inline uint32_t trie_entry_new(trie_t *trie)
{
    const trie_entry_t e = TRIE_ENTRY_INIT;
    array_add(trie->entries, e);
    return trie->entries.len - 1;
}

static inline uint32_t trie_add_leaf(trie_t *trie, const char *key,
                                     int regexp)
{
    trie_entry_t *entry;
    int len = m_strlen(key) + 1;
    int id  = trie_entry_new(trie);
    entry = array_ptr(trie->entries, id);
    entry->c_offset = trie->c.len;
    entry->c_len    = len;
    entry->regexp_offset = regexp;
#ifdef CHECK_INTEGRITY
    for (int i = 0 ; i < len - 1 ; ++i) {
        if (key[i] == '\0') {
            printf("Found a '\\0' in the string of the leaf\n");
            abort();
        }
    }
    if (key[len - 1] != '\0') {
      printf("Key does not end with a '\\0'");
      abort();
    }
#endif
    array_append(trie->c, key, len);
    return trie->entries.len - 1;
}

static inline void trie_entry_insert_child(trie_t *trie, uint32_t id,
                                           uint32_t pchild)
{
    trie_entry_t *entry = array_ptr(trie->entries, id);
    if (entry->children_len == 0) {
        entry->children_offset = pchild;
        entry->children_len    = 1;
    } else {
        if ((uint32_t)(entry->children_offset + entry->children_len)
            != pchild) {
            printf("Inserting child %d while offset is %d[%d]\n",
                   pchild, entry->children_offset, entry->children_len);
            abort();
        }
        ++entry->children_len;
    }
}

static inline void trie_entry_split(trie_t *trie, uint32_t id, uint16_t pos)
{
    trie_entry_t *child;
    trie_entry_t *entry;
    child    = array_ptr(trie->entries, trie_entry_new(trie));
    entry    = array_ptr(trie->entries, id);
    if (pos == 0) {
        child->c_offset = entry->c_offset;
        child->c_len    = entry->c_len;
        entry->c_offset = 0;
        entry->c_len    = 0;
    } else {
        assert(pos <= entry->c_len);
        child->c_offset = entry->c_offset + pos;
        child->c_len    = entry->c_len - pos;
        entry->c_len    = pos;
    }
    child->children_offset = entry->children_offset;
    child->children_len    = entry->children_len;
    child->regexp_offset   = entry->regexp_offset;
    entry->children_offset = trie->entries.len - 1;
    entry->children_len    = 1;
    entry->regexp_offset   = -1;
}

bool trie_insert_regexp_str(trie_t *trie, const clstr_t *key,
                            const clstr_t *regexp)
{
    assert(trie->entries.len == 0 && "Trie already compiled");

    trie_key_t key_pos = { trie->keys.len, -1 };
    if (regexp != NULL) {
        key_pos.regexp = trie->regexps.len;

        regexp_t re;
        if (!regexp_compile_str(&re, regexp, false)) {
            return false;
        }
        array_add(trie->regexps, re);
    }
    array_add(trie->keys_offset, key_pos);
    array_append(trie->keys, key->str, key->len);
    array_add(trie->keys, '\0');
    return true;
}

bool trie_insert_regexp(trie_t *trie, const char *key, const char *regexp)
{
    clstr_t skey = { key, m_strlen(key) };
    clstr_t sreg = { regexp, m_strlen(regexp) };
    return trie_insert_regexp_str(trie, &skey, &sreg);
}

bool trie_insert_str(trie_t *trie, const clstr_t *key)
{
    return trie_insert_regexp_str(trie, key, NULL);
}

bool trie_insert(trie_t *trie, const char *key)
{
    clstr_t skey = { key, m_strlen(key) };
    return trie_insert_regexp_str(trie, &skey, NULL);
}

static bool trie_compile_aux(trie_t *trie, uint32_t id,
                             uint32_t first_key, uint32_t last_key,
                             int offset, int initial_diff)
{
    /* The forks list will contain the list of row number where splits
     * are found.
     */
    uint32_t forks[256];
    uint32_t fork_pos = 0;
    char current = '\0';

#ifdef CHECK_INTEGRITY
    assert(strcmp(key(trie, first_key) + offset, str(trie, entry)) == 0);
#endif

    /* Walk through the entries, column per column, and the first column where
     * for one or more row entries[row,column] is not the same as
     * entries[row-1,column].
     *
     * The corresponding rows are stored in forks and a new node is created
     * each time a fork is found.
     */
    for (int off_diff = initial_diff ; fork_pos == 0 ; ++off_diff, ++offset) {
        current = key(trie, first_key)[offset];
        for (uint32_t i = first_key + 1 ; i < last_key ; ++i) {
            const char *ckey = key(trie, i) + offset;
            const int  reg   = rek(trie, i);
            const char c = *ckey;
            if (c != current) {
                /* Split found, create a new node.
                 */
                array_ensure_capacity_delta(trie->entries, 2);
                if (fork_pos == 0) {
                    /* Mark the current column as the split point
                     */
                    trie_entry_split(trie, id, off_diff);
                }
                /* Mark this row as a split point, create a node.
                 */
                trie_entry_insert_child(trie, id,
                                        trie_add_leaf(trie, ckey, reg));
                forks[fork_pos++] = i;
                current = c;
            } else if (current == '\0') {
                /* Found a '\0', This should not happen since the rows are
                 * sorted, so, we are sure this is a duplicated ==> check
                 * consistency and skip the first line.
                 */
                if (rek(trie, first_key) != reg) {
                    err("duplicate entry in the trie with different "
                        "associated regexps: %s", key(trie, i));
                    return false;
                } else {
                    debug("dropping duplicate for key %s", key(trie, i));
                }
                return trie_compile_aux(trie, id, i, last_key,
                                        offset - (off_diff - initial_diff),
                                        initial_diff);
            }
        }
        if (fork_pos == 0 && current == '\0') {
            return true;
        }
    }
    forks[fork_pos] = last_key;

    /* Recursively call compile_aux to build the subtree for each fork.
     */
    const uint8_t children_len = array_elt(trie->entries, id).children_len;
    for (uint16_t i = 0 ; i < children_len ; ++i) {
        int child = array_elt(trie->entries, id).children_offset + i;
        if (forks[i] - 1 > first_key) {
            if (!trie_compile_aux(trie, child, first_key, forks[i],
                                  offset, 1)) {
                return false;
            }
        }
        first_key = forks[i];
    }
    return true;
}

bool trie_compile(trie_t *trie, bool memlock)
{
    assert(trie->entries.len == 0 && "Trie already compiled");
    assert(trie->keys.len != 0 && "Trying to compile an empty trie");

    /* First of all, sort all the entries
     */
    {
#       define QSORT_TYPE trie_key_t
#       define QSORT_BASE trie->keys_offset.data
#       define QSORT_NELT trie->keys_offset.len
#       define QSORT_LT(a,b) strcmp(trie->keys.data + a->offset,             \
                                    trie->keys.data + b->offset) < 0
#       include "qsort.c"
    }

    array_ensure_capacity(trie->entries, trie->keys_offset.len);

    /* Build the tree
     */
    if (!trie_compile_aux(trie,
                          trie_add_leaf(trie, key(trie, 0), rek(trie, 0)),
                          0, trie->keys_offset.len, 0, 0)) {
        return false;
    }

    /* Cleanup structure and reduce memory consumption.
     */
    trie_wipe_build_data(trie);
    array_adjust(trie->entries);
    array_adjust(trie->c);
    if (memlock) {
        trie_lock(trie);
    }
    return true;
}


#define FILL_MATCH(LEN, ALL, PREFIX, RES)                                    \
    if (match != NULL) {                                                     \
        match->match_len = (LEN);                                            \
        match->match_all = (ALL);                                            \
        match->match_prefix = (PREFIX);                                      \
        match->regexp  = (RES);                                              \
    }

bool trie_lookup_match(const trie_t *trie, const char *key,
                       trie_match_t *match)
{
    assert(trie->keys.len == 0L && "Can't lookup: trie not compiled");
    if (trie->entries.len == 0) {
        FILL_MATCH(0, false, false, NULL);
        return false;
    } else {
        const char * const orig = key;
        const trie_entry_t *current = array_ptr(trie->entries, 0);
        while (true) {
            if (trie_entry_is_leaf(current)) {
                if (trie_entry_match(trie, current, key)) {
                    FILL_MATCH(key - orig + current->c_len - 1,
                               true, true, rex(trie, current));
                    return true;
                } else if (match && trie_entry_prefix(trie, current, key)) {
                    FILL_MATCH(key - orig + current->c_len - 1,
                               false, true, rex(trie, current));
                    return false;
                } else {
                    FILL_MATCH(key - orig, false, false, NULL);
                    return false;
                }
            } else if (trie_entry_c_match(trie, current, key)) {
                key += current->c_len;
                const trie_entry_t *nexte
                    = trie_entry_child(trie, current, key[0]);
                if (nexte == NULL) {
                    if (match) {
                      nexte = trie_entry_child(trie, current, '\0');
                      if (nexte != NULL) {
                        FILL_MATCH(key - orig, false, true, rex(trie, nexte));
                        return false;
                      }
                    }
                    FILL_MATCH(key - orig, false, false, NULL);
                    return false;
                }
                current = nexte;
            } else {
                FILL_MATCH(key - orig, false, false, NULL);
                return false;
            }
        }
    }
}

bool trie_prefix_match(const trie_t *trie, const char *key,
                       trie_match_t *match)
{
    assert(trie->keys.len == 0L && "Can't lookup: trie not compiled");
    if (trie->entries.len == 0) {
        FILL_MATCH(0, false, false, NULL);
        return false;
    } else {
        const char * const orig = key;
        const trie_entry_t *current = array_ptr(trie->entries, 0);
        while (true) {
            if (trie_entry_is_leaf(current)) {
                if (trie_entry_prefix(trie, current, key)) {
                    FILL_MATCH(key - orig + current->c_len - 1,
                               key[current->c_len - 1] == '\0',
                               true, rex(trie, current));
                    return true;
                } else {
                    FILL_MATCH(key - orig, false, false, NULL);
                    return false;
                }
            } else if (trie_entry_c_match(trie, current, key)) {
                key += current->c_len;
                const trie_entry_t *nexte
                    = trie_entry_child(trie, current, key[0]);
                if (nexte == NULL) {
                    nexte = trie_entry_child(trie, current, '\0');
                    if (nexte != NULL) {
                      FILL_MATCH(key - orig, false, true, rex(trie, nexte));
                      return true;
                    }
                    FILL_MATCH(key - orig, false, false, NULL);
                    return false;
                }
                current = nexte;
            } else {
                FILL_MATCH(key - orig, false, false, NULL);
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
    if (!array_lock(trie->entries)) {
        UNIXERR("mlock");
    }
    if (!array_lock(trie->c)) {
        UNIXERR("mlock");
    }
    if (mlock(trie, sizeof(trie_t)) != 0) {
        UNIXERR("mlock");
        return;
    }
    trie->locked = true;
}

void trie_unlock(trie_t *trie)
{
    if (!trie->locked) {
        return;
    }
    array_unlock(trie->entries);
    array_unlock(trie->c);
    munlock(trie, sizeof(trie_t));
    trie->locked = false;
}

/* Debug {{{1
 */

static void trie_entry_inspect(const trie_t *trie, bool show_content,
                               const trie_entry_t *entry, int level)
{
    static int max_depth = 0;
    static int leaves    = 0;
    static int depth_sum = 0;

    if (entry == array_ptr(trie->entries, 0)) {
      max_depth = 0;
      leaves    = 0;
      depth_sum = 0;
    }
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
            fputs("(0)", stdout);
        } else {
            const char *c = str(trie, entry);
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
    for (uint32_t i = 0 ; i < entry->children_len ; ++i) {
        trie_entry_inspect(trie, show_content,
                           array_ptr(trie->entries,
                                     entry->children_offset + i),
                           level + 1);
    }
    if (level == 0) {
        printf("Average char per node: %d\n",
               trie->c.len / trie->entries.len);
        printf("Number of nodes: %d\n", trie->entries.len);
        printf("Number of leaves: %d\n", leaves);
        printf("Max depth: %d\n", max_depth);
        printf("Average leaf depth: %d\n", depth_sum / leaves);
        printf("Memory used: %zd\n",
               (trie->entries.size * sizeof(trie_entry_t))
               + (trie->c.size) + sizeof(trie_t));
    }
}

void trie_inspect(const trie_t *trie, bool show_content)
{
    trie_entry_inspect(trie, show_content, trie->entries.data, 0);
}

/* vim:set et sw=4 sts=4 sws=4: */
