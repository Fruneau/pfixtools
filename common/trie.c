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
    int  c_offset;
    int  c_len;

    int* children;
    int children_len;
    int children_size;

    bool locked;
};

struct trie_t {
    trie_entry_t *entries;
    int entries_len;
    int entries_size;

    char *c;
    int  c_len;
    int  c_size;

    bool locked;
};

trie_t *trie_new(void)
{
    return p_new(trie_t, 1);
}

void trie_delete(trie_t **trie)
{
    if (*trie) {
        for (int i = 0 ; i < (*trie)->entries_len ; ++i) {
            trie_entry_t *entry = &(*trie)->entries[i];
            p_delete(&(entry->children));
        }
        p_delete(&(*trie)->entries);
        p_delete(&(*trie)->c);
        p_delete(trie);
    }
}

/** Check that the given entry is a prefix for the given key.
 */
static inline bool trie_entry_c_match(const trie_t *trie,
                                      const trie_entry_t *entry,
                                      const char *key, int *pos)
{
    const char *c = trie->c + entry->c_offset;
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
    return !!(strcmp(trie->c + entry->c_offset, key) == 0);
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
    int start = 0;
    int end   = entry->children_len;
    const char c = *key;

    while (start < end) {
        int mid = (start + end) / 2;
        trie_entry_t* child = &trie->entries[entry->children[mid]];
        const char c2 = trie->c[child->c_offset];

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

#define GROW(Buffer, Added, Len, Size)                  \
  do {                                                  \
      const int required_size = (Len) + (Added);        \
      int next_size = (Size);                           \
      if (next_size >= required_size) {                 \
          break;                                        \
      }                                                 \
      do {                                              \
          next_size = p_alloc_nr(next_size);            \
      } while (next_size < required_size);              \
      p_allocgrow(&(Buffer), next_size, &(Size));       \
  } while(0)

static inline void trie_grow(trie_t *trie, int delta)
{
    GROW(trie->entries, delta, trie->entries_len, trie->entries_size);
}

static inline int trie_entry_new(trie_t *trie)
{
    memset(trie->entries + trie->entries_len, 0, sizeof(trie_entry_t));
    return trie->entries_len++;
}

static inline int trie_add_leaf(trie_t *trie, const char *key)
{
    trie_entry_t *entry;
    int len = m_strlen(key) + 1;
    entry = &trie->entries[trie_entry_new(trie)];
    GROW(trie->c, len, trie->c_len, trie->c_size);
    memcpy(trie->c + trie->c_len, key, len);
    entry->c_offset = trie->c_len;
    entry->c_len    = len;
    trie->c_len    += len;
    return trie->entries_len - 1;
}

static inline void trie_entry_insert_child(trie_t *trie, trie_entry_t *entry,
                                           int pchild)
{
    const char c = trie->c[trie->entries[pchild].c_offset];
    int start = 0;
    int end   = entry->children_len;

    p_allocgrow(&entry->children, entry->children_len + 1, &entry->children_size);
    while (start < end) {
        int mid = (start + end) / 2;
        const trie_entry_t* child = &trie->entries[entry->children[mid]];
        const char c2 = trie->c[child->c_offset];

        if (child->c_len) {
            if (c2 == c) {
                abort();
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
        child->c_offset = entry->c_offset;
        child->c_len    = entry->c_len;
        entry->c_offset = 0;
        entry->c_len    = 0;
    } else {
        child->c_offset = entry->c_offset + pos;
        child->c_len    = entry->c_len - pos;
        entry->c_len    = pos;
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
            if (trie_entry_c_match(trie, current, key, &pos)) {
                if (trie_entry_is_leaf(current)) {
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


/* Debug {{{1
 */

static inline void trie_entry_inspect(const trie_t *trie,
                                      const trie_entry_t *entry, int level)
{
    static int c_sum = 0;
    static int nodes = 0;

    ++nodes;
    c_sum += entry->c_len;
    for (int i = 0 ; i < level ; ++i) {
        fputs("  ", stdout);
    }
    if (entry->c_len == 0) {
        fputs("(nil)", stdout);
    } else {
        const char *c = trie->c + entry->c_offset;
        for (int i = 0 ; i < entry->c_len ; ++i) {
            if (c[i]) {
                printf("%c ", c[i]);
            } else {
                fputs("\\0 ", stdout);
            }
        }
    }
    fputs("\n", stdout);
    for (int i = 0 ; i < entry->children_len ; ++i) {
        trie_entry_inspect(trie, &trie->entries[entry->children[i]], level + 1);
    }
    if (level == 0) {
        printf("Mean char per node: %d\n", c_sum / nodes);
    }
}

void trie_inspect(const trie_t *trie)
{
    trie_entry_inspect(trie, trie->entries, 0);
}
