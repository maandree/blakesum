.POSIX:

CONFIGFILE = config.mk
include $(CONFIGFILE)

BIN =\
	bsum\
	b2sum

OBJ =\
	$(BIN:=.o)\
	common.o

HDR =\
	arg.h\
	common.h

all: $(BIN)
$(OBJ): $(HDR)

.c.o:
	$(CC) -c -o $@ $< $(CFLAGS) $(CPPFLAGS)

bsum: bsum.o common.o
	$(CC) -o $@ $@.o common.o $(LDFLAGS)

b2sum: b2sum.o common.o
	$(CC) -o $@ $@.o common.o $(LDFLAGS)

install: $(BIN)
	mkdir -p -- "$(DESTDIR)$(PREFIX)/bin"
	mkdir -p -- "$(DESTDIR)$(MANPREFIX)/man1/"
	cp -- $(BIN) "$(DESTDIR)$(PREFIX)/bin/"
	ln -sf -- bsum "$(DESTDIR)$(PREFIX)/bin/b224sum"
	ln -sf -- bsum "$(DESTDIR)$(PREFIX)/bin/b256sum"
	ln -sf -- bsum "$(DESTDIR)$(PREFIX)/bin/b384sum"
	ln -sf -- bsum "$(DESTDIR)$(PREFIX)/bin/b512sum"
	cp -- $(BIN:=.1) "$(DESTDIR)$(MANPREFIX)/man1/"
	cp -- b224sum.1 "$(DESTDIR)$(MANPREFIX)/man1/b224sum.1"
	cp -- b256sum.1 "$(DESTDIR)$(MANPREFIX)/man1/b256sum.1"
	cp -- b384sum.1 "$(DESTDIR)$(MANPREFIX)/man1/b384sum.1"
	cp -- b512sum.1 "$(DESTDIR)$(MANPREFIX)/man1/b512sum.1"

uninstall:
	-rm -f -- "$(DESTDIR)$(PREFIX)/bin/bsum"
	-rm -f -- "$(DESTDIR)$(PREFIX)/bin/b224sum"
	-rm -f -- "$(DESTDIR)$(PREFIX)/bin/b256sum"
	-rm -f -- "$(DESTDIR)$(PREFIX)/bin/b384sum"
	-rm -f -- "$(DESTDIR)$(PREFIX)/bin/b512sum"
	-rm -f -- "$(DESTDIR)$(PREFIX)/bin/b2sum"
	-rm -f -- "$(DESTDIR)$(MANPREFIX)/man1/bsum.1"
	-rm -f -- "$(DESTDIR)$(MANPREFIX)/man1/b224sum.1"
	-rm -f -- "$(DESTDIR)$(MANPREFIX)/man1/b256sum.1"
	-rm -f -- "$(DESTDIR)$(MANPREFIX)/man1/b384sum.1"
	-rm -f -- "$(DESTDIR)$(MANPREFIX)/man1/b512sum.1"
	-rm -f -- "$(DESTDIR)$(MANPREFIX)/man1/b2sum.1"

clean:
	-rm -f -- *.o *.su *.gcov *.gcno *.gcda
	-rm -f -- $(BIN)

.SUFFIXES:
.SUFFIXES: .o .c

.PHONY: all install uninstall clean
