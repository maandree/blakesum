.POSIX:

CONFIGFILE = config.mk
include $(CONFIGFILE)


BIN =\
	bsum\
	b2sum

OBJ =\
	$(BIN:=.o)\
	common.o\
	test.o

HDR =\
	arg.h\
	common.h

ALIASES =\
	b224sum\
	b256sum\
	b384sum\
	b512sum

SRC =\
	$(OBJ:.o=.c)\
	$(HDR)\
	test.c

# Known answers tests 
KAT_FILES =\
        kat/blake2b\
        kat/blake2bp\
        kat/blake2s\
        kat/blake2sp\
        kat/blake2xb\
        kat/blake2xs


all: $(BIN) test
$(OBJ): $(HDR)

.c.o:
	$(CC) -c -o $@ $< $(CFLAGS) $(CPPFLAGS)

bsum: bsum.o common.o
	$(CC) -o $@ $@.o common.o $(LDFLAGS)

b2sum: b2sum.o common.o
	$(CC) -o $@ $@.o common.o $(LDFLAGS)

test: test.o
	$(CC) -o $@ $@.o $(LDFLAGS)

check: test $(BIN) $(KAT_FILES)
	./test

install: $(BIN)
	mkdir -p -- "$(DESTDIR)$(PREFIX)/bin"
	mkdir -p -- "$(DESTDIR)$(MANPREFIX)/man1/"
	cp -- $(BIN) "$(DESTDIR)$(PREFIX)/bin/"
	ln -sf -- bsum "$(DESTDIR)$(PREFIX)/bin/b224sum"
	ln -sf -- bsum "$(DESTDIR)$(PREFIX)/bin/b256sum"
	ln -sf -- bsum "$(DESTDIR)$(PREFIX)/bin/b384sum"
	ln -sf -- bsum "$(DESTDIR)$(PREFIX)/bin/b512sum"
	cp -- $(BIN:=.1) $(ALIASES:=.1) "$(DESTDIR)$(MANPREFIX)/man1/"

uninstall:
	-cd -- "$(DESTDIR)$(PREFIX)/bin/" && rm -f -- $(BIN) $(ALIASES)
	-cd -- "$(DESTDIR)$(MANPREFIX)/man1/" && rm -f -- $(BIN:=.1) $(ALIASES:=.1)

clean:
	-rm -f -- *.o *.su *.gcov *.gcno *.gcda
	-rm -f -- $(BIN) test

.SUFFIXES:
.SUFFIXES: .o .c

.PHONY: all check install uninstall clean
