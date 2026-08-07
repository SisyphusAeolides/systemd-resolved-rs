CC ?= gcc
CFLAGS ?= -O2 -fPIC -Wall -Wextra -Wno-unused-parameter
LDFLAGS_SO ?= -shared -Wl,-soname,libnss_resolve.so.2

OBJS = nss_resolve.o nss_resolve_shm.o nss_varlink.o

.PHONY: all clean install

all: libnss_resolve.so.2

libnss_resolve.so.2: $(OBJS)
	$(CC) $(LDFLAGS_SO) -o $@ $(OBJS)

%.o: %.c nss_resolve_shm.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) libnss_resolve.so.2

install: all
	install -d $(DESTDIR)/usr/lib64
	install -m 755 libnss_resolve.so.2 $(DESTDIR)/usr/lib64/libnss_resolve.so.2
