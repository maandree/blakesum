.POSIX:

CONFIGFILE = config.mk
include $(CONFIGFILE)

OBJ =\
	bsum.o

HDR =\
	arg.h\
	common.h

all: bsum
$(OBJ): $(HDR)

.c.o:
	$(CC) -c -o $@ $< $(CFLAGS) $(CPPFLAGS)

bsum: $(OBJ)
	$(CC) -o $@ $(OBJ) $(LDFLAGS)

install: bsum
	mkdir -p -- "$(DESTDIR)$(PREFIX)/bin"
	mkdir -p -- "$(DESTDIR)$(MANPREFIX)/man1/"
	cp -- bsum "$(DESTDIR)$(PREFIX)/bin/"
	ln -sf -- bsum "$(DESTDIR)$(PREFIX)/bin/b224sum"
	ln -sf -- bsum "$(DESTDIR)$(PREFIX)/bin/b256sum"
	ln -sf -- bsum "$(DESTDIR)$(PREFIX)/bin/b384sum"
	ln -sf -- bsum "$(DESTDIR)$(PREFIX)/bin/b512sum"
	cp -- bsum.1 "$(DESTDIR)$(MANPREFIX)/man1/"

uninstall:
	-rm -f -- "$(DESTDIR)$(PREFIX)/bin/bsum"
	-rm -f -- "$(DESTDIR)$(PREFIX)/bin/b224sum"
	-rm -f -- "$(DESTDIR)$(PREFIX)/bin/b256sum"
	-rm -f -- "$(DESTDIR)$(PREFIX)/bin/b384sum"
	-rm -f -- "$(DESTDIR)$(PREFIX)/bin/b512sum"
	-rm -f -- "$(DESTDIR)$(MANPREFIX)/man1/bsum.1"
	-rm -f -- "$(DESTDIR)$(MANPREFIX)/man1/b224sum.1"
	-rm -f -- "$(DESTDIR)$(MANPREFIX)/man1/b256sum.1"
	-rm -f -- "$(DESTDIR)$(MANPREFIX)/man1/b384sum.1"
	-rm -f -- "$(DESTDIR)$(MANPREFIX)/man1/b512sum.1"

clean:
	-rm -f -- *.o *.su *.gcov *.gcno *.gcda
	-rm -f -- bsum

.SUFFIXES:
.SUFFIXES: .o .c

.PHONY: all install uninstall clean
