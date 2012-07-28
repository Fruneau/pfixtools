############################################################################
#          pfixtools: a collection of postfix related tools                #
#          ~~~~~~~~~                                                       #
#  ______________________________________________________________________  #
#                                                                          #
#  Redistribution and use in source and binary forms, with or without      #
#  modification, are permitted provided that the following conditions      #
#  are met:                                                                #
#                                                                          #
#  1. Redistributions of source code must retain the above copyright       #
#     notice, this list of conditions and the following disclaimer.        #
#  2. Redistributions in binary form must reproduce the above copyright    #
#     notice, this list of conditions and the following disclaimer in      #
#     the documentation and/or other materials provided with the           #
#     distribution.                                                        #
#  3. The names of its contributors may not be used to endorse or promote  #
#     products derived from this software without specific prior written   #
#     permission.                                                          #
#                                                                          #
#  THIS SOFTWARE IS PROVIDED BY THE CONTRIBUTORS ``AS IS'' AND ANY         #
#  EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE       #
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR      #
#  PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE CONTRIBUTORS BE LIABLE   #
#  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR            #
#  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF    #
#  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR         #
#  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,   #
#  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE    #
#  OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,       #
#  EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.                      #
#                                                                          #
#   Copyright (c) 2006-2011 the Authors                                    #
#   see AUTHORS and source files for details                               #
############################################################################

__DIR__:=$(realpath $(dir $(lastword $(MAKEFILE_LIST))))

include $(__DIR__)/cflags.mk

prefix      ?= /usr/local
LDFLAGSBASE += $(if $(DARWIN),,-Wl,-warn-common)
CFLAGSBASE  += --std=gnu99 -I../ -I../common
ASCIIDOC     = asciidoc -f $(__DIR__)/asciidoc.conf -d manpage \
	       -apft_version=$(shell git describe)
XMLTO        = xmlto -m $(__DIR__)/callouts.xsl
MAN_SECTIONS = 1 2 3 4 5 6 7 8 9

TESTPROGAMS = $(addprefix tst-,$(TESTS))

INSTALL_PROGS = $(addprefix install-,$(PROGRAMS))

all: $(GENERATED) $(LIBS) $(PROGRAMS) $(TESTPROGAMS)

DOCS_SRC  = $(foreach s,$(MAN_SECTIONS),$(patsubst %.$(s),%.asciidoc,$(filter %.$(s),$(DOCS))))
DOCS_HTML = $(DOCS_SRC:.asciidoc=.html)
DOCS_XML  = $(DOCS_SRC:.asciidoc=.xml)
doc: $(DOCS) $(DOCS_HTML)

install: all $(INSTALL_PROGS)

install-doc: doc
	$(if $(DOCS),\
	    set -e\
	    $(foreach s,$(MAN_SECTIONS),\
		$(foreach m,$(filter %.$(s),$(DOCS)),\
		    ; install -d $(DESTDIR)$(prefix)/share/man/man$(s)/ \
		    ; install $(m) $(DESTDIR)$(prefix)/share/man/man$(s)/ \
	)))
	$(if $(DOCS_HTML),install $(DOCS_HTML) $(DESTDIR)$(prefix)/share/doc/pfixtools)

$(INSTALL_PROGS): install-%:
	install $* $(DESTDIR)$(prefix)/sbin

clean:
	$(RM) $(LIBS:=.a) $(PROGRAMS) $(TESTS) .*.o .*.dep
	$(RM) $(DOCS) $(DOCS_XML) $(DOCS_HTML)

distclean: clean
	$(RM) $(GENERATED)

tags: .tags
.tags: $(shell git ls-files | egrep '\.[hc]$$')
	ctags -o $@ $^

headers: HEADACHEOPTS=-c mk/headache.cfg -h LICENSE
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

$(DOCS_HTML): %.html: %.asciidoc
	$(ASCIIDOC) -b xhtml11 -o $@ $<

$(DOCS_XML): %.xml: %.asciidoc
	$(ASCIIDOC) -b docbook -o $@ $<

%.1 %.2 %.3 %.4 %.5 %.6 %.7 %.8 %.9: %.xml
	$(XMLTO) man $<

.SECONDEXPANSION:

$(LIBS:=.a): $$(patsubst %.c,.%.o,$$($$(patsubst %.a,%,$$@)_SOURCES)) Makefile
	$(RM) $@
	$(AR) rcs $@ $(filter %.o,$^)

$(TESTPROGAMS): %: .$$(subst tst-,,%).o ../postlicyd/libpostlicyd.a ../common/lib.a Makefile
	$(CC) -o $@ $(filter %.o,$^) $(LDFLAGS) $(TESTLIBS) $(filter %.a,$^)

$(PROGRAMS): $$(patsubst %.c,.%.o,$$($$@_SOURCES)) Makefile
	$(CC) -o $@ $(filter %.o,$^) $(LDFLAGS) $($@_LIBADD) $(filter %.a,$^)

$(DOCS):

-include $(foreach p,$(PROGRAMS) $(TESTS),$(patsubst %.c,.%.dep,$(filter %.c,$($p_SOURCES))))

.PHONY: install-doc install-dir $(INSTALL_PROGS)
