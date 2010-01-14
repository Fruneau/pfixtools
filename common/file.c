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
 * Copyright © 2008 Florent Bruneau
 */

#include <sys/mman.h>
#include <sys/stat.h>

#include "file.h"

file_map_t *file_map_new(const char *file, bool memlock)
{
    file_map_t *map = p_new(file_map_t, 1);
    if (!file_map_open(map, file, memlock)) {
        p_delete(&map);
        return NULL;
    }
    return map;
}

void file_map_delete(file_map_t **map)
{
    if (*map) {
        file_map_close(*map);
        p_delete(map);
    }
}

bool file_map_open(file_map_t *map, const char *file, bool memlock)
{
    int fd;

    fd = open(file, O_RDONLY, 0000);
    if (fd < 0) {
        UNIXERR("open");
        return false;
    }

    if (fstat(fd, &map->st) < 0) {
        UNIXERR("fstat");
        close(fd);
        return false;
    }

    map->map = mmap(NULL, map->st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map->map == MAP_FAILED) {
        UNIXERR("mmap");
        close(fd);
        map->map = NULL;
        return false;
    }
    close(fd);

    map->end = map->map + map->st.st_size;
    map->locked = memlock && mlock(map->map, map->st.st_size) == 0;
    return true;
}

void file_map_close(file_map_t *map)
{
    if (!map->map) {
        return;
    }
    if (map->locked) {
        munlock(map->map, map->end - map->map);
    }
    munmap((void*)map->map, map->end - map->map);
    map->map = NULL;
    map->end = NULL;
    map->locked = false;
}

/* vim:set et sw=4 sts=4 sws=4: */
