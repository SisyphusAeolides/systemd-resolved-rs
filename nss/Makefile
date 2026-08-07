CC ?= cc
CFLAGS ?= -O2 -g -fPIC -std=c17 -Wall -Wextra -Werror -Wpedantic -fstack-protector-strong -D_FORTIFY_SOURCE=3
LDFLAGS_SO ?= -shared -Wl,-soname,libnss_resolve.so.2 -Wl,-z,relro,-z,now

OBJS = nss_resolve.o nss_resolve_shm.o nss_varlink.o
TEST_OBJS = test_nss.o

.PHONY: all check clean install

all: libnss_resolve.so.2

libnss_resolve.so.2: $(OBJS)
	$(CC) $(LDFLAGS_SO) -o $@ $(OBJS)

test_nss: $(TEST_OBJS) $(OBJS)
	$(CC) -o $@ $(TEST_OBJS) $(OBJS)

check: all test_nss
	bash run-tests.sh

%.o: %.c nss_resolve_shm.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TEST_OBJS) libnss_resolve.so.2 test_nss

install: all
	install -d $(DESTDIR)/usr/lib64
	install -m 755 libnss_resolve.so.2 $(DESTDIR)/usr/lib64/libnss_resolve.so.2
