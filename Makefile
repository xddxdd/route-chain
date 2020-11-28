ifeq ($(PREFIX),)
	PREFIX := /usr/local
endif

CC := gcc
CFLAGS += -std=c99 -Wall -O3 -Wl,--build-id=none
STRIPFLAGS += -s -R ".comment"

default: route-chain.c
	${CC} ${CFLAGS} -o route-chain route-chain.c
	strip ${STRIPFLAGS} route-chain

static: route-chain.c
	${CC} ${CFLAGS} -static -o route-chain route-chain.c
	strip ${STRIPFLAGS} route-chain

install: default
	install -d $(PREFIX)/bin/
	install -m 755 route-chain $(PREFIX)/bin/

install-static: static
	install -d $(PREFIX)/bin/
	install -m 755 route-chain $(PREFIX)/bin/

clean:
	rm route-chain
