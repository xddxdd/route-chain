ifeq ($(PREFIX),)
	PREFIX := /usr/local
endif

route-chain: route-chain.c
	gcc -Wall -O3 -s -o route-chain route-chain.c

install: route-chain
	install -d $(PREFIX)/bin/
	install -m 755 route-chain $(PREFIX)/bin/

clean:
	rm route-chain