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
/*   Copyright (c) 2006-2009 the Authors                                      */
/*   see AUTHORS and source files for details                                 */
/******************************************************************************/

/*
 * Copyright © 2008 Florent Bruneau
 */

#include "str.h"
#include "array.h"
#include "resources.h"

typedef struct resource_t {
    char *key;
    void *data;
    int  refcount;
    resource_destructor_t destructor;
} resource_t;
ARRAY(resource_t);

#define RESOURCE_INIT { NULL, NULL, 0, NULL }

static A(resource_t) resources = ARRAY_INIT;

#define RESOURCE_KEY                                                           \
    char rskey[BUFSIZ];                                                        \
    m_strcpy(rskey, BUFSIZ, ns);                                               \
    m_strcat(rskey, BUFSIZ, "@@");                                             \
    m_strcat(rskey, BUFSIZ, key);

static inline void resource_wipe(resource_t *res)
{
    static const resource_t vr = RESOURCE_INIT;
    if (res->destructor) {
        res->destructor(res->data);
    }
    p_delete(&res->key);
    *res = vr;
}

static inline resource_t *resource_find(const char *key, bool create)
{
    foreach (resource_t* res, resources) {
        if (strcmp(res->key, key) == 0) {
            return res;
        }
    }}
    if (create) {
        resource_t res = RESOURCE_INIT;
        res.key = m_strdup(key);
        array_add(resources, res);
        return &array_last(resources);
    }
    return NULL;
}

void *resource_get(const char *ns, const char *key)
{
    RESOURCE_KEY;
    resource_t *entry = resource_find(rskey, false);
    if (entry == NULL) {
        return NULL;
    } else {
        ++entry->refcount;
        return entry->data;
    }
}

bool resource_set(const char *ns, const char *key, void *data,
                  resource_destructor_t destructor) {
    RESOURCE_KEY;
    resource_t *entry = resource_find(rskey, true);
    if (entry->data != NULL) {
        if (entry->destructor) {
            entry->destructor(entry->data);
        }
    }
    entry->refcount  += 1;
    entry->data       = data;
    entry->destructor = destructor;
    return true;
}

void resource_release(const char *ns, const char *key)
{
    RESOURCE_KEY;
    resource_t *entry = resource_find(rskey, false);
    if (entry != NULL) {
        assert(entry->refcount > 0);
        --entry->refcount;
    }
}

void resource_garbage_collect(void)
{
    uint32_t used = 0;
    foreach (resource_t *res, resources) {
        if (res->key != NULL && res->refcount == 0) {
            debug("resource gc: %s not referenced anymore", res->key);
            resource_wipe(res);
        } else if (res->key != NULL) {
            debug("resource gc: keeping %s, still %d references",
                  res->key, res->refcount);
            if (used < __Ai) {
                array_elt(resources, used) = *res;
            }
            ++used;
        }
    }}
    debug("resource gc: before %d resources, after %d",
          array_len(resources), used);
    array_len(resources) = used;
}

static void resources_exit(void)
{
    array_deep_wipe(resources, resource_wipe);
}
module_exit(resources_exit);
