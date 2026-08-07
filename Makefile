SHELL := /bin/sh
CC ?= cc
undefine FC
FC ?= gfortran
CFLAGS ?= -O2 -g -std=c17 -Wall -Wextra -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=3
FFLAGS ?= -O2 -g -std=f2018 -Wall -Wextra -Werror -fimplicit-none
LDLIBS ?= -lssl -lcrypto
PREFIX ?= /usr
LIBEXECDIR ?= $(PREFIX)/lib/systemd
UNITDIR ?= $(PREFIX)/lib/systemd/system
TMPFILESDIR ?= $(PREFIX)/lib/tmpfiles.d

.PHONY: all build test check-native check-rust check-formal check-packaging check-live check-nss clean install
.PHONY: supremacy-dirs nss release release-with-nss install-replace uninstall boot-smoke bench

all: build

build:
	cargo build --release --all-features --locked

check-native:
	mkdir -p build
	$(FC) $(FFLAGS) -Jbuild -c ffi/routing.f90 -o build/routing.o
	$(CC) $(CFLAGS) -Iffi -c ffi/native.c -o build/native.o
	$(CC) $(CFLAGS) -Iffi -c ffi/interface.c -o build/interface.o
	$(CC) $(CFLAGS) -Iffi -c ffi/tls.c -o build/tls.o
	$(CC) $(CFLAGS) -Iffi -c ffi/dnssec.c -o build/dnssec.o
	$(CC) $(CFLAGS) -Iffi -c ffi/netlink.c -o build/netlink.o
	$(CC) $(CFLAGS) -Iffi -c ffi/networkd.c -o build/networkd.o
	$(CC) $(CFLAGS) -Iffi -c ffi/test_native.c -o build/test_native.o
	$(FC) build/test_native.o build/native.o build/interface.o build/tls.o build/dnssec.o build/netlink.o build/networkd.o build/routing.o $(LDLIBS) -o build/test_native
	./build/test_native

check-rust:
	cargo fmt --all -- --check
	cargo clippy --all-targets --all-features --locked -- -D warnings
	cargo test --all-targets --all-features --locked

check-formal:
	idris2 --build formal/idris/resolved-policy.ipkg
	agda -i formal/agda formal/agda/Resolved/DNS/Name.agda
	agda -i formal/agda formal/agda/Resolved/DNS/Transaction.agda

check-packaging:
	bash -n scripts/install-replace.sh scripts/uninstall-restore.sh scripts/boot-smoke.sh nss/run-tests.sh
	@set -eu; \
	work=$$(mktemp -d); \
	trap 'rm -rf "$$work"' EXIT HUP INT TERM; \
	PYTHONPYCACHEPREFIX="$$work/pycache" python3 -m py_compile \
		tests/live-dns.py tests/deterministic-dns-server.py scripts/probe-stub.py; \
	test "$$(grep -Fc 'ExecStart=@SYSTEMD_RESOLVED_RS@' packaging/systemd/systemd-resolved-replacement.service)" -eq 1; \
	sed 's|@SYSTEMD_RESOLVED_RS@|/bin/true|g' \
		packaging/systemd/systemd-resolved-replacement.service >"$$work/systemd-resolved.service"; \
	cp packaging/systemd/systemd-resolved-varlink.socket "$$work/systemd-resolved-varlink.socket"; \
	SYSTEMD_UNIT_PATH="$$work" systemd-analyze verify \
		"$$work/systemd-resolved.service" \
		"$$work/systemd-resolved-varlink.socket"

check-live: build
	python3 tests/live-dns.py target/release/systemd-resolved target/release/resolvectl

check-nss:
	$(MAKE) -C nss clean check

test: check-native check-rust check-packaging check-nss

install: build
	install -Dm0755 target/release/systemd-resolved $(DESTDIR)$(LIBEXECDIR)/systemd-resolved
	install -Dm0755 target/release/resolvectl $(DESTDIR)$(PREFIX)/bin/resolvectl
	install -Dm0644 packaging/systemd/systemd-resolved.service $(DESTDIR)$(UNITDIR)/systemd-resolved.service
	install -Dm0644 packaging/systemd/systemd-resolved-varlink.socket $(DESTDIR)$(UNITDIR)/systemd-resolved-varlink.socket
	install -Dm0644 packaging/tmpfiles/systemd-resolved.conf $(DESTDIR)$(TMPFILESDIR)/systemd-resolved.conf

clean:
	rm -rf build target
	$(MAKE) -C nss clean

supremacy-dirs:
	mkdir -p src/supremacy src/llmnr src/mdns nss scripts tests/parity tests/supremacy
	mkdir -p packaging/polkit packaging/rpm

nss:
	$(MAKE) -C nss

release: build check-packaging check-nss

release-with-nss: release

install-replace: release
	sudo bash scripts/install-replace.sh

uninstall:
	sudo bash scripts/uninstall-restore.sh

boot-smoke:
	bash scripts/boot-smoke.sh

bench:
	bash tests/supremacy/bench_compare.sh
