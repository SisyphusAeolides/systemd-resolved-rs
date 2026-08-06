# Architecture

This project is one resolver assembled from five implementation languages.
Language boundaries are deliberately narrow and testable.

## Rust

Rust owns the daemon lifecycle, DNS wire parser, cache, hosts database,
upstream transports, local stub listeners, generated resolver files, and
command-line programs. The core uses the standard library so the initial
trusted dependency set remains small.

## C

C owns Linux ABI details that are awkward to express without a libc crate:
signal installation, systemd notification datagrams, inherited descriptor
metadata, Unix peer credentials, and future netlink/capability operations.
All calls use the stable C ABI declared in `ffi/native.h`.

## Fortran

Fortran owns deterministic route scoring. The implementation performs
case-insensitive DNS suffix matching and returns a stable score used when
selecting the longest matching routing domain. It is compiled into the daemon,
not stored as an example.

## Idris

Idris defines the total resolver-policy model: legal query classes and types,
single-label routing, `.local` routing, and TTL aging witnesses. The model is
the source for future generated policy tables once runtime policy parity is
complete.

## Agda

Agda carries proof-oriented wire invariants. The first module proves that a
compression pointer cannot point to itself when every pointer step decreases,
and makes the DNS label-count bound explicit. Later modules will cover packet
cursor bounds, cache monotonicity, and routing maximality.

## Runtime flow

1. Parse `resolved.conf` and drop-ins.
2. Load `/etc/hosts` and build routing state.
3. Bind full and proxy UDP/TCP stubs.
4. Parse and validate each request before local processing.
5. Answer synthetic and hosts records on the full stub.
6. Consult the generation-isolated TTL-aware cache.
7. Select upstreams by the longest matching routing domain.
8. Forward over UDP and retry over TCP when the response is truncated.
9. Validate response identity and question before returning or caching it.
