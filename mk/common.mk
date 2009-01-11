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
#   Copyright (c) 2006-2008 the Authors                                      #
#   see AUTHORS and source files for details                                 #
##############################################################################

include ../mk/cflags.mk

prefix ?= /usr/local
LDFLAGSBASE += $(if $(DARWIN),-L/opt/local/lib,-Wl,-warn-common)
CFLAGSBASE  += --std=gnu99 -I../ -I../common $(if $(DARWIN),-I/opt/local/include,)

INSTALL_PROGS = $(addprefix install-,$(PROGRAMS))

all: $(GENERATED) $(LIBS) $(PROGRAMS) | $(GENERATED)

install: all $(INSTALL_PROGS)

$(INSTALL_PROGS): install-%:
	install $* $(DESTDIR)$(prefix)/sbin

clean:
	$(RM) $(LIBS:=.a) $(PROGRAMS) $(TESTS) .*.o .*.dep

distclean: clean
	$(RM) $(GENERATED)

tags: .tags
.tags: $(shell git ls-files | egrep '\.[hc]$$')
	ctags -o $@ $^

headers: HEADACHEOPTS=-c mk/headache.cfg -h mk/COPYING
headers:
	@which headache > /dev/null || \
		( echo "package headache not installed" ; exit 1 )
	@git ls-files | egrep '(\.h|\.c|Makefile|*\.mk)$$' | xargs -t headache $(HEADACHEOPTS)

%.h: %.sh
	./$< $@ || ($(RM) $@; exit 1)

%.c: %.sh
	./$< $@ || ($(RM) $@; exit 1)

.%.o: %.c Makefile
	$(shell test -d $(@D) || mkdir -p $(@D))
	$(CC) $(CFLAGS) -MMD -MT ".$*.dep $@" -MF .$*.dep -g -c -o $@ $<

.%.dep: .%.o

$(LIBS): %: %.a

.SECONDEXPANSION:

$(LIBS:=.a): $$(patsubst %.c,.%.o,$$($$(patsubst %.a,%,$$@)_SOURCES)) Makefile
	$(RM) $@
	$(AR) rcs $@ $(filter %.o,$^)

$(PROGRAMS) $(TESTS): $$(patsubst %.c,.%.o,$$($$@_SOURCES)) Makefile
	$(CC) -o $@ $(filter %.o,$^) $(LDFLAGS) $($@_LIBADD) $(filter %.a,$^)

-include $(foreach p,$(PROGRAMS) $(TESTS),$(patsubst %.c,.%.dep,$(filter %.c,$($p_SOURCES))))

.PHONY: install-dir $(INSTALL_PROGS)
