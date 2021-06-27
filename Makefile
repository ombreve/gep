.POSIX:
.SUFFIXES:
CC      = cc
CFLAGS  = -ansi -Wall -O3
LDFLAGS =
LDLIBS  =
PREFIX  = ${HOME}/.local

sources = src/gep.c src/rfc8439.c
objects = $(sources:.c=.o)

gep: $(objects)
	$(CC) $(LDFLAGS) -o $@ $(objects) $(LDLIBS)

src/gep.o: config.h src/docs.h src/optparse.h src/sha256.h src/rfc8439.h
src/rfc8439.o: src/rfc8439.h

test : rfc8439
rfc8439 : src/rfc8439.c src/rfc8439.h
	$(CC) $(CFLAGS) -DRFC8439_TEST -o $@ $<

clean:
	rm -f gep rfc8439 $(objects)

install: gep gep.1
	mkdir -p $(PREFIX)/bin
	mkdir -p $(PREFIX)/share/man/man1
	install -m 755 gep $(PREFIX)/bin
	gzip < gep.1 > $(PREFIX)/share/man/man1/gep.1.gz

uninstall:
	rm -f $(PREFIX)/bin/gep
	rm -f $(PREFIX)/share/man/man1/gep.1.gz

.SUFFIXES: .c .o
.c.o:
	$(CC) -c $(CFLAGS) -o $@ $<
