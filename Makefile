SHELL := /bin/sh
CC ?= cc
FC ?= gfortran
CFLAGS ?= -O2 -g -std=c17 -Wall -Wextra -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=3
FFLAGS ?= -O2 -g -std=f2018 -Wall -Wextra -Werror -fimplicit-none
PREFIX ?= /usr
LIBEXECDIR ?= $(PREFIX)/lib/systemd
UNITDIR ?= $(PREFIX)/lib/systemd/system
TMPFILESDIR ?= $(PREFIX)/lib/tmpfiles.d

.PHONY: all build test check-native check-rust check-formal clean install

all: build

build:
	cargo build --release --locked

check-native:
	mkdir -p build
	$(FC) $(FFLAGS) -Jbuild -c ffi/routing.f90 -o build/routing.o
	$(CC) $(CFLAGS) -Iffi -c ffi/native.c -o build/native.o
	$(CC) $(CFLAGS) -Iffi -c ffi/test_native.c -o build/test_native.o
	$(FC) build/test_native.o build/native.o build/routing.o -o build/test_native
	./build/test_native

check-rust:
	cargo test --all-targets --locked

check-formal:
	idris2 --build formal/idris/resolved-policy.ipkg
	agda -i formal/agda formal/agda/Resolved/DNS/Name.agda

test: check-native check-rust

install: build
	install -Dm0755 target/release/systemd-resolved $(DESTDIR)$(LIBEXECDIR)/systemd-resolved
	install -Dm0755 target/release/resolvectl $(DESTDIR)$(PREFIX)/bin/resolvectl
	install -Dm0644 packaging/systemd/systemd-resolved.service $(DESTDIR)$(UNITDIR)/systemd-resolved.service
	install -Dm0644 packaging/systemd/systemd-resolved-varlink.socket $(DESTDIR)$(UNITDIR)/systemd-resolved-varlink.socket
	install -Dm0644 packaging/tmpfiles/systemd-resolved.conf $(DESTDIR)$(TMPFILESDIR)/systemd-resolved.conf

clean:
	rm -rf build target
