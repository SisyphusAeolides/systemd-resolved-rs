# Compatibility ledger

A checked item means a concrete implementation exists in the current tree. It
does not, by itself, establish complete upstream parity or sufficient test coverage. The project must not be
described or installed as a drop-in replacement until every release-validation
gate at the end of this document passes against the pinned upstream baseline.

## Build integrity

- [x] Rust package paths have concrete library and binary sources
- [x] C and Fortran ABI declarations agree at the repository boundary
- [ ] Rust formatting, Clippy, and all-target test suite pass in the release environment
- [ ] Idris 2 and Agda modules pass with pinned compiler versions
- [ ] Reproducible release build and package manifest are verified

## Local resolver interfaces

The pinned D-Bus signatures live in `compat/`.

- [x] UDP DNS listener on `127.0.0.53`
- [x] TCP DNS listener on `127.0.0.53`
- [x] proxy-mode UDP/TCP listener on `127.0.0.54`
- [x] generated stub and uplink `resolv.conf` files
- [ ] `org.freedesktop.resolve1` D-Bus manager and link objects
- [ ] complete `io.systemd.Resolve` Varlink interface
- [ ] `io.systemd.Resolve.Monitor` Varlink interface
- [ ] complete `resolvectl` command and output compatibility
- [ ] NSS integration parity with `nss-resolve`

## DNS engine

- [x] bounded DNS name decompression with loop and forward-pointer rejection
- [x] request and response section-bound validation
- [x] A, AAAA, and PTR local answers
- [x] `/etc/hosts` forward and reverse answers
- [x] localhost, numeric-address, `_localdnsstub`, and `_localdnsproxy` synthesis
- [x] UDP forwarding with transaction and question validation
- [x] TCP fallback after a truncated UDP response
- [x] bounded positive and negative cache with TTL aging
- [x] RFC 2308 negative lifetime from SOA TTL and MINIMUM
- [x] optional stale-answer retention with zeroed TTLs
- [x] TSIG-bearing response cache exclusion
- [ ] EDNS feature negotiation, downgrade state, and DNS cookies
- [ ] complete CNAME and DNAME processing
- [ ] complete resource-record validation and compression expansion
- [ ] transaction coalescing
- [ ] parallel queries across equivalent scopes
- [ ] TCP and UDP connection pooling matching upstream behavior

## Secure and local-link protocols

- [ ] DNSSEC validation and trust-anchor management
- [ ] DNS-over-TLS opportunistic and strict modes
- [ ] LLMNR resolver and responder
- [ ] MulticastDNS resolver and responder
- [ ] DNS-SD registration and browsing

## Routing and configuration

- [x] core `resolved.conf` list, boolean, mode, size, and duration parsing
- [x] layered `resolved.conf.d` file selection
- [x] global and fallback upstream selection
- [x] route-only and search-domain representation
- [x] `/etc/resolv.conf` uplink discovery with local-stub exclusion
- [x] SIGHUP hosts-database reload
- [ ] live configuration reload parity
- [ ] per-link DNS state from D-Bus and netlink
- [ ] longest-suffix routing integrated with per-link scopes
- [ ] default-route link inference
- [ ] search-domain candidate expansion parity
- [ ] split-DNS parallel scope behavior
- [ ] interface binding and scoped IPv6 upstreams
- [ ] credential-based DNS and search-domain configuration
- [ ] static `.rr` record files

## Service behavior

- [x] systemd readiness, reload, status, and stopping notifications
- [x] hardened service unit and runtime directory
- [x] privileged port operation through service capabilities
- [x] bounded Varlink framing and peer-credential checks for maintenance calls
- [ ] upstream socket-activation contract
- [ ] watchdog keepalive
- [ ] privilege-drop parity when launched directly as root
- [ ] complete `systemd-resolved` command-line compatibility
- [ ] D-Bus policy and authorization parity

## Required release validation

- [ ] upstream `TEST-75-RESOLVED` passes unmodified
- [ ] upstream mDNS and resolver-adjacent unit suites pass unmodified
- [ ] D-Bus introspection is signature compatible
- [ ] Varlink schemas and error identifiers match
- [ ] `resolvectl` behavioral and output corpus matches
- [ ] packet parser passes upstream and independent fuzz corpora
- [ ] sanitizer, Miri, Valgrind, and race-test runs are clean
- [ ] failover, suspend/resume, network churn, VPN split-DNS, and captive-portal scenarios pass
- [ ] clean install, upgrade, rollback, and recovery procedures pass
- [ ] no unresolved high- or critical-severity security findings remain
