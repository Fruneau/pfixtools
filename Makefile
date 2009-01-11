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

prefix ?= /usr/local

PROGRAMS = postlicyd pfix-srsd
LIBS     = common
SUBDIRS  = $(LIBS) $(PROGRAMS)

CLEAN_TARGETS     = $(addprefix clean-,$(SUBDIRS))
DISTCLEAN_TARGETS = $(addprefix distclean-,$(SUBDIRS))
INSTALL_TARGETS   = $(addprefix install-,$(SUBDIRS))

# RULES ###################################################################{{{

all: $(SUBDIRS)

clean: $(CLEAN_TARGETS)

distclean: $(DISTCLEAN_TARGETS)

install: all $(INSTALL_TARGETS)

$(PROGRAMS): $(LIBS)

$(SUBDIRS): %:
	make -C $@ all

$(CLEAN_TARGETS): clean-%:
	make -C $* clean

$(DISTCLEAN_TARGETS): distclean-%:
	make -C $* distclean

$(INSTALL_TARGETS): install-%: % install-dir
	make -C $* install

install-postlicyd: install-postlicyd-tools install-postlicyd-conf
install-dir:
	install -d $(DESTDIR)$(prefix)/sbin
	install -d $(DESTDIR)$(prefix)/bin
	install -d $(DESTDIR)/etc/pfixtools

install-postlicyd-tools:
	install tools/postlicyd-rsyncrbl $(DESTDIR)$(prefix)/bin/postlicyd-rsyncrbl
	install tools/postgrey2postlicyd $(DESTDIR)$(prefix)/bin/postgrey2postlicyd
	install tools/rbldns2postlicyd	 $(DESTDIR)$(prefix)/bin/rbldns2postlicyd

install-postlicyd-conf:
	install -m 640 example/postlicyd.conf $(DESTDIR)/etc/pfixtools/postlicyd.example.conf
	install -m 640 example/postlicyd-rsyncrbl.conf $(DESTDIR)/etc/pfixtools/postlicyd-rsyncrbl.example.conf

.PHONY: clean distclean install install-dir $(SUBDIRS) $(CLEAN_TARGETS) \
				$(DISTCLEAN_TARGETS) $(INSTALL_TARGETS) install-postlicyd-tools \
				install-postlicyd-conf

###########################################################################}}}
