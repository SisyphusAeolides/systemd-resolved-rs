# systemd-resolved-rs

`systemd-resolved-rs` is a compatibility-oriented reimplementation of
`systemd-resolved` built as one system from Rust, C, Fortran, Idris, and Agda.
The target is behavioral and interface parity with the pinned upstream
`systemd` resolver, not merely a DNS forwarding daemon.

> **Development status:** pre-alpha. The current tree is an executable resolver
> foundation, but it is not yet a drop-in replacement. D-Bus, Varlink, DNSSEC,
> DNS-over-TLS, LLMNR, MulticastDNS, DNS-SD, per-link state, and the complete
> `resolvectl` surface remain release-blocking work. See
> [the compatibility ledger](docs/COMPATIBILITY.md).

## Implemented foundation

- UDP and TCP DNS service on the full `127.0.0.53` stub
- UDP and TCP proxy service on `127.0.0.54`
- hardened DNS name decompression and response validation
- `/etc/hosts`, localhost, `_localdnsstub`, and `_localdnsproxy` answers
- A, AAAA, and PTR local synthesis
- bounded positive and negative cache with TTL aging
- UDP upstream transport with TCP fallback after truncation
- longest-suffix routing through the compiled Fortran policy engine
- `resolved.conf` core settings and drop-in loading
- generated `/run/systemd/resolve/{stub-resolv.conf,resolv.conf}` files
- systemd readiness/reload/stopping notifications
- local root/daemon-user control socket
- initial `resolvectl status`, `statistics`, `flush-caches`,
  `reset-statistics`, and `query`
- Idris total policy model and Agda wire-invariant proofs

## Language boundaries

| Language | Responsibility |
| --- | --- |
| Rust | daemon, DNS wire engine, cache, transports, configuration, CLIs |
| C | Linux ABI, signals, notifications, peer credentials, inherited FDs |
| Fortran | compiled DNS routing-domain scoring |
| Idris | total resolver-policy model and validation decisions |
| Agda | proof-oriented wire, pointer, bound, and TTL invariants |

The boundaries and their planned evolution are documented in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Build

Required tools:

- Rust 1.74 or newer
- a C17 compiler
- GNU Fortran with Fortran 2018 support
- `ar`
- Idris 2 and Agda for formal checks

```sh
make check-native
cargo test --all-targets --locked
make build
```

Formal modules are checked separately:

```sh
make check-formal
```

## Safe development run

Use an unprivileged port while developing:

```sh
cargo run --bin systemd-resolved -- \
  --port=1053 \
  --runtime-directory=/tmp/systemd-resolved-rs

cargo run --bin resolvectl -- \
  --server=127.0.0.53:1053 \
  --runtime-directory=/tmp/systemd-resolved-rs \
  query example.com
```

Do not replace the host resolver service or `/etc/resolv.conf` until the
remaining compatibility gates are closed and the target system has a tested
recovery path.

## Installation layout

```sh
sudo make install
```

The default layout installs:

- `/usr/lib/systemd/systemd-resolved`
- `/usr/bin/resolvectl`
- `/usr/lib/systemd/system/systemd-resolved.service`
- `/usr/lib/tmpfiles.d/systemd-resolved.conf`

The service expects the standard `systemd-resolve` user to exist.

## Compatibility baseline

The current baseline is `systemd/systemd` commit
`f807a6f26d150d9e8138ef59d2ff2c9c7e860d39` (`262~devel`, 2026-08-05).
See [docs/UPSTREAM_BASELINE.md](docs/UPSTREAM_BASELINE.md) before changing that
reference.

## License

GNU Lesser General Public License 2.1 or later.
