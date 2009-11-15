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

include ../mk/tc.mk

PROGRAMS  = postlicyd
DOCS      = postlicyd.8 postlicyd.conf.5
GENERATED = policy_tokens.h policy_tokens.c \
						filter_tokens.h filter_tokens.c \
						hook_tokens.h hook_tokens.c \
						param_tokens.h param_tokens.c

LIBS = libpostlicyd

FILTERS		= $(shell grep '^filter_declare' filter.c | sed -e 's/filter_declare(\(.*\)).*/\1.c/')

libpostlicyd_SOURCES = filter.c config.c query.c resources.c db.c $(FILTERS) $(GENERATED)

postlicyd_SOURCES = main-postlicyd.c $(libpostlicyd_SOURCES) ../common/lib.a
postlicyd_LIBADD  = $(TC_LIBS) -lev -lpcre -lunbound

all:

hook_tokens.c hook_tokens.h: $(FILTERS)
param_tokens.c param_tokens.h: $(FILTERS) config.c
filter_tokens.c filter_tokens.h: $(FILTERS)

include ../mk/common.mk
