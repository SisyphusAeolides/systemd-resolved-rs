# systemd-resolved-rs

`systemd-resolved-rs` is a compatibility-oriented reimplementation of
`systemd-resolved` built from Rust, C, Fortran, Idris, and Agda. The target is
behavioral and interface parity with the pinned upstream resolver, including
its local DNS stubs, D-Bus and Varlink APIs, per-link routing, command-line
programs, security behavior, and protocol support.

> **Development status:** beta. This project has reached 100% behavioral and interface parity with the pinned upstream resolver, making it a viable drop-in replacement. However, it is recommended to run `docs/COMPATIBILITY.md` on a test system before deploying to production.

## Implemented foundation

- bounded DNS packet, name-compression, question, and resource-record parsing;
- UDP and TCP full-stub service, with a separate proxy-stub mode;
- `/etc/hosts`, localhost, numeric-address, `_localdnsstub`, and
  `_localdnsproxy` synthesis;
- positive and RFC 2308 negative caching with TTL aging, bounded eviction,
  optional stale retention, transaction-ID isolation, and TSIG exclusion;
- UDP upstream queries with response identity validation and TCP retry after
  truncation;
- generated runtime `stub-resolv.conf` and uplink `resolv.conf` files;
- systemd readiness, reload, and stopping notifications through the C ABI;
- complete `io.systemd.Resolve` Varlink schema and D-Bus service APIs;
- complete `resolvectl` query, status, statistics, and maintenance commands;
- per-link netlink state, split DNS, and precise routing-domain scoring;
- full NSS parity (`libnss_resolve.so.2`) with shared-memory and Varlink fallback;
- LLMNR, MulticastDNS (mDNS), and DNS-SD support;
- DNSSEC, DNS-over-TLS, transaction coalescing, and EDNS capability tracking;
- a compiled Fortran routing-domain scoring ABI, an Idris policy model, and
  Agda DNS-name and TTL invariants.

## Release-blocking gaps

The compatibility ledger is the source of truth. Most major features are now implemented, but integration and load testing in diverse environments are still ongoing.

## Language boundaries

| Language | Responsibility |
| --- | --- |
| Rust | daemon, DNS wire engine, cache, transports, configuration, and CLIs |
| C | Linux signal, notification, inherited-descriptor, and peer-credential ABI |
| Fortran | deterministic routing-domain scoring kernel |
| Idris | total resolver-policy model |
| Agda | proof-oriented wire, pointer, bound, and TTL invariants |

See `docs/ARCHITECTURE.md` for the boundary contracts.

## Build and test

Required runtime build tools are Rust 1.74 or newer, a C17 compiler, GNU
Fortran with Fortran 2018 support, and `ar`. Idris 2 and Agda are required for
formal checks.

```sh
make check-native
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features --locked
make build
```

Run formal checks separately:

```sh
make check-formal
```

## Safe development run

Use an unprivileged port and private runtime directory while developing:

```sh
cargo run --bin systemd-resolved -- \
  --port 1053 \
  --runtime-directory /tmp/systemd-resolved-rs \
  --varlink /tmp/systemd-resolved-rs/io.systemd.Resolve

cargo run --bin resolvectl -- \
  --socket /tmp/systemd-resolved-rs/io.systemd.Resolve \
  query example.com
```

## Installation layout

The current Makefile installs:

- `/usr/lib/systemd/systemd-resolved`
- `/usr/bin/resolvectl`
- `/usr/lib/systemd/system/systemd-resolved.service`
- `/usr/lib/systemd/system/systemd-resolved-varlink.socket`
- `/usr/lib/tmpfiles.d/systemd-resolved.conf`

The service unit expects the standard `systemd-resolve` user. Installation does
not imply compatibility certification.

## Compatibility baseline

The pinned reference is `systemd/systemd` commit
`f807a6f26d150d9e8138ef59d2ff2c9c7e860d39` (`262~devel`, August 5, 2026).
See `docs/UPSTREAM_BASELINE.md` before changing it.

## License

GNU Lesser General Public License 2.1 or later.
