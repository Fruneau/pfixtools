##############################################################################
#          pfixtools: a collection of postfix related tools                  #
#          ~~~~~~~~~                                                         #
#  ________________________________________________________________________  #
#                                                                            #
#  Redistribution and use in source and binary forms, with or without        #
#  modification, are permitted provided that the following conditions        #
#  are met:                                                                  #
#                                                                            #
#  1. Redistributions of source code must retain the above copyright         #
#     notice, this list of conditions and the following disclaimer.          #
#  2. Redistributions in binary form must reproduce the above copyright      #
#     notice, this list of conditions and the following disclaimer in the    #
#     documentation and/or other materials provided with the distribution.   #
#  3. The names of its contributors may not be used to endorse or promote    #
#     products derived from this software without specific prior written     #
#     permission.                                                            #
#                                                                            #
#  THIS SOFTWARE IS PROVIDED BY THE CONTRIBUTORS ``AS IS'' AND ANY EXPRESS   #
#  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED         #
#  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE    #
#  DISCLAIMED.  IN NO EVENT SHALL THE CONTRIBUTORS BE LIABLE FOR ANY         #
#  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL        #
#  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS   #
#  OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)     #
#  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,       #
#  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN  #
#  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE           #
#  POSSIBILITY OF SUCH DAMAGE.                                               #
#                                                                            #
#   Copyright (c) 2006-2009 the Authors                                      #
#   see AUTHORS and source files for details                                 #
##############################################################################

LIBS  = lib
TESTS = tst-trie tst-regexp

lib_SOURCES = str.c buffer.c common.c server.c trie.c file.c rbl.c regexp.c
tst-trie_SOURCES = tst-trie.c lib.a
tst-trie_LIBADD = -lpcre
tst-regexp_SOURCES = tst-regexp.c lib.a
tst-regexp_LIBADD = -lpcre

all:

.server.o: CFLAGS=$(if $(DARWIN),$(filter-out -Wredundant-decls,$(filter-out -Wshadow,$(CFLAGSBASE))),$(CFLAGSBASE))

include ../mk/common.mk
