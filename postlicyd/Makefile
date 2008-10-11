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
#  THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND   #
#  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE     #
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR        #
#  PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS    #
#  BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR    #
#  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF      #
#  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS  #
#  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN   #
#  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)   #
#  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF    #
#  THE POSSIBILITY OF SUCH DAMAGE.                                           #
##############################################################################

include ../mk/tc.mk

PROGRAMS  = postlicyd
GENERATED = policy_tokens.h policy_tokens.c \
						filter_tokens.h filter_tokens.c \
						hook_tokens.h hook_tokens.c \
						param_tokens.h param_tokens.c
TESTS     = tst-rbl tst-filters tst-greylist

UB_LIBS   = -L/usr/local/lib -lunbound

FILTERS		= iplist.c greylist.c match.c

postlicyd_SOURCES = main-postlicyd.c ../common/lib.a filter.c config.c query.c $(FILTERS) $(GENERATED)
postlicyd_LIBADD  = $(UB_LIBS) $(TC_LIBS)

tst-rbl_SOURCES   = tst-rbl.c ../common/lib.a filter.c config.c query.c iplist.c $(GENERATED)

tst-filters_SOURCES = tst-filters.c ../common/lib.a config.c filter.c query.c $(FILTERS) $(GENERATED)
tst-filters_LIBADD  = $(UB_LIBS) $(TC_LIBS)

tst-greylist_SOURCES = tst-greylist.c ../common/lib.a
tst-greylist_LIBADD  = $(TC_LIBS)

hook_tokens.h hook_tokens.c: $(FILTERS)
param_tokens.c param_tokens.h: $(FILTERS) config.c

all:

include ../mk/common.mk
