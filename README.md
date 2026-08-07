# systemd-resolved-rs

`systemd-resolved-rs` is a compatibility-oriented reimplementation of
`systemd-resolved` built from Rust, C, Fortran, Idris, and Agda. The target is
behavioral and interface parity with the pinned upstream resolver, including
its local DNS stubs, D-Bus and Varlink APIs, per-link routing, command-line
programs, security behavior, protocol support, installation contract, and
recovery behavior.

> **Development status:** active parity and hardening work. The production
> executable now uses one shared resolver for UDP, TCP, D-Bus, Varlink,
> netlink, and systemd-networkd state. It is not yet certified as a drop-in
> replacement. Use a snapshot-backed VM or other recoverable test system until
> every release-validation gate in `docs/COMPATIBILITY.md` passes.

A green build is necessary but is not a parity certificate. The project will
claim 100% drop-in parity only when the pinned upstream differential suites,
live installation and rollback tests, security tests, and every release gate
are green against the same commit.

## Verified foundation

- bounded DNS packet, name-compression, question, and resource-record parsing;
- UDP and TCP full-stub service, with a separate proxy-stub mode;
- `/etc/hosts`, localhost, numeric-address, `_localdnsstub`, and
  `_localdnsproxy` synthesis;
- positive and RFC 2308 negative caching with TTL aging, bounded eviction,
  optional stale retention, transaction-ID isolation, and TSIG exclusion;
- UDP upstream queries with response identity validation and TCP retry after
  truncation;
- generated runtime `stub-resolv.conf` and uplink `resolv.conf` files;
- systemd readiness, reload, stopping, and watchdog notifications;
- live `org.freedesktop.resolve1` Manager and Link objects whose introspection
  is checked against pinned manifests;
- core `io.systemd.Resolve` Varlink resolution and maintenance methods;
- per-link netlink and systemd-networkd state, split DNS, and routing-domain
  scoring;
- DNS-over-TLS transport and policy machinery, with remaining end-to-end parity
  tracked in the compatibility ledger;
- DNSSEC record parsing, canonicalization, digest, and signature-verification
  primitives, with full trust-chain behavior still release-blocking;
- a compiled Fortran routing-domain scoring ABI, an Idris policy model, and
  Agda DNS-name and transaction invariants;
- deterministic live CI coverage for UDP, TCP, proxy-stub, generated resolver
  files, and Varlink lookups through the production executable path.

## Release-blocking work

`docs/COMPATIBILITY.md` is the source of truth. Major remaining work includes
complete Varlink and `resolvectl` behavior, NSS integration parity, complete
DNSSEC trust-chain handling, LLMNR, mDNS and DNS-SD integration, D-Bus
authorization, upstream differential suites, fuzzing and sanitizers, network
lifecycle scenarios, and transactional installation and rollback validation.

Unchecked ledger entries must not be inferred complete merely because related
source modules or unit tests exist.

## Beyond parity

Enhancements that are not part of upstream compatibility are developed behind
clear boundaries and must remain opt-in until independently validated. Current
research areas include sharded caching, stale-while-revalidate, aggressive
negative caching, shared-memory NSS acceleration, pooled transports, richer
metrics, and flight-recorder diagnostics. Compatibility mode remains the
reference behavior; an optimization may not change externally observable
semantics.

## Language boundaries

| Language | Responsibility |
| --- | --- |
| Rust | daemon, DNS wire engine, cache, transports, configuration, and CLIs |
| C | Linux signal, notification, inherited-descriptor, crypto, and peer-credential ABI |
| Fortran | deterministic routing-domain scoring kernel |
| Idris | total resolver-policy model |
| Agda | proof-oriented wire, pointer, bound, and TTL invariants |

See `docs/ARCHITECTURE.md` for the boundary contracts.

## Build and test

Required runtime build tools are Rust 1.74 or newer, a C17 compiler, GNU
Fortran with Fortran 2018 support, OpenSSL development files, and `ar`. Idris 2
and Agda are required for formal checks.

```sh
make check-native
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --all-features --locked
cargo build --release --all-features --locked
python3 tests/live-dns.py \
  target/release/systemd-resolved \
  target/release/resolvectl
make check-formal
```

## Safe development run

Use an unprivileged port and private runtime directory while developing:

```sh
cargo run --bin systemd-resolved -- \
  --port 1053 \
  --runtime-directory /tmp/systemd-resolved-rs \
  --varlink /tmp/systemd-resolved-rs/io.systemd.Resolve \
  --no-dbus

cargo run --bin resolvectl -- \
  --socket /tmp/systemd-resolved-rs/io.systemd.Resolve \
  query example.com
```

The replacement installer is a release gate, not a development shortcut. Do
not overwrite the host resolver, NSS module, or resolver policy files manually.

## Installation layout

The current Makefile installs:

- `/usr/lib/systemd/systemd-resolved`
- `/usr/bin/resolvectl`
- `/usr/lib/systemd/system/systemd-resolved.service`
- `/usr/lib/systemd/system/systemd-resolved-varlink.socket`
- `/usr/lib/tmpfiles.d/systemd-resolved.conf`

Installation does not imply compatibility certification. Distribution packages
and host replacement procedures must pass the clean install, upgrade, rollback,
and recovery gates before production use.

## Compatibility baseline

The pinned reference is `systemd/systemd` commit
`f807a6f26d150d9e8138ef59d2ff2c9c7e860d39` (`262~devel`, August 5, 2026).
See `docs/UPSTREAM_BASELINE.md` before changing it.

## License

GNU Lesser General Public License 2.1 or later.
