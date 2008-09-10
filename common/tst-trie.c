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

#include "common.h"
#include "trie.h"

int main(void)
{
    trie_t *trie = trie_new();
    trie_insert(trie, "abcdefghi");
    trie_insert(trie, "abcde123654789");
    trie_insert(trie, "abcde123456789");
    trie_insert(trie, "abcde123654789");
    trie_insert(trie, "coucou");
    trie_insert(trie, "coucou chez vous");
    trie_inspect(trie);

#define ASSERT_TRUE(str)                            \
    if (!trie_lookup(trie, str)) {                  \
        printf("\"%s\" not found in trie\n", str);  \
        return 1;                                   \
    }
#define ASSERT_FALSE(str)                           \
    if (trie_lookup(trie, str)) {                   \
        printf("\"%s\" found in trie\n", str);      \
        return 1;                                   \
    }

    ASSERT_FALSE("");
    ASSERT_FALSE("coucou ");
    ASSERT_FALSE("abcde123");
    ASSERT_FALSE("abcde");
    ASSERT_TRUE("abcdefghi");
    ASSERT_TRUE("coucou");
    ASSERT_FALSE("coucou chez vous tous");

    trie_delete(&trie);
    return 0;
}
