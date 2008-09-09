include ../mk/cflags.mk

prefix ?= /usr/local
LDFLAGS += -Wl,--warn-common
CFLAGS  += --std=gnu99 -D_GNU_SOURCE -I../ -I../common

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

$(PROGRAMS) $(TESTS): $$(patsubst %.c,.%.o,$$($$@_SOURCES)) Makefile ../common.ld
	$(CC) -o $@ $(filter %.ld,$^) $(filter %.o,$^) $(LDFLAGS) $($@_LIBADD) $(filter %.a,$^)

-include $(foreach p,$(PROGRAMS) $(TESTS),$(patsubst %.c,.%.dep,$(filter %.c,$($p_SOURCES))))

.PHONY: install-dir $(INSTALL_PROGS)
