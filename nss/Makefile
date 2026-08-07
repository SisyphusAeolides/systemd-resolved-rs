CC ?= gcc
CFLAGS ?= -O2 -fPIC -Wall -Wextra
LDFLAGS_SO ?= -shared -Wl,-soname,libnss_resolve.so.2

OBJS = nss_resolve.o nss_resolve_shm.o nss_varlink.o

all: libnss_resolve.so.2

libnss_resolve.so.2: $(OBJS)
	$(CC) $(LDFLAGS_SO) -o $@ $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o libnss_resolve.so.2

install: all
	install -m 755 libnss_resolve.so.2 $(DESTDIR)/usr/lib64/libnss_resolve.so.2
