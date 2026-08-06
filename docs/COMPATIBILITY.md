# Compatibility ledger

A checked item means a concrete implementation exists in the current tree. It
does not, by itself, establish complete upstream parity or sufficient test coverage. The project must not be
described or installed as a drop-in replacement until every release-validation
gate at the end of this document passes against the pinned upstream baseline.

## Build integrity

- [x] Rust package paths have concrete library and binary sources
- [x] C and Fortran ABI declarations agree at the repository boundary
- [ ] current `main` passes Rust 1.74 and stable formatting, Clippy, tests, and release builds
- [ ] Idris 2 and Agda modules pass with pinned compiler versions
- [ ] Reproducible release build and package manifest are verified

## Local resolver interfaces

The pinned D-Bus signatures live in `compat/`.

- [x] UDP DNS listener on `127.0.0.53`
- [x] TCP DNS listener on `127.0.0.53`
- [x] proxy-mode UDP/TCP listener on `127.0.0.54`
- [x] generated stub and uplink `resolv.conf` files
- [x] live `org.freedesktop.resolve1` Manager and Link objects match the pinned introspection manifests
- [ ] DNS-SD registration, delegate behavior, and complete D-Bus authorization parity
- [x] core `ResolveHostname`, `ResolveAddress`, `ResolveRecord`, and `ResolveService` Varlink methods
- [ ] complete `io.systemd.Resolve` Varlink flags, errors, and service semantics
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
- [x] repeated UDP-loss fallback to TCP, TCP-loss recovery to UDP, and truncated-response transport telemetry
- [x] bounded positive and negative cache with TTL aging
- [x] RFC 2308 negative lifetime from SOA TTL and MINIMUM
- [x] optional stale-answer retention with zeroed TTLs
- [x] TSIG-bearing response cache exclusion
- [x] in-answer CNAME and DNAME redirect-chain validation
- [x] cross-transaction CNAME and DNAME follow-up for high-level lookups with loop detection and the upstream 16-redirect limit
- [ ] accumulated redirect-chain record reporting and complete redirect flag/error parity
- [x] EDNS0/DO feature negotiation with per-server retry downgrade, exponential recovery grace periods, 1232-byte UDP sizing, and RFC 6975 algorithm signaling
- [x] root-domain RRSIG omission detection with a persistent per-server DO clamp, allow-downgrade retry, and strict-mode failure
- [ ] adaptive MTU/fragment-size advertisement, TLS feature levels, and exact upstream retry timing
- [ ] complete resource-record validation and compression expansion
- [x] concurrent identical transaction coalescing with per-client ID restoration and one-upstream regression coverage
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
- [x] ordered search-domain candidate expansion with route-only exclusion
- [ ] live configuration reload parity
- [x] per-link DNS state from D-Bus
- [ ] netlink synchronization of per-link state
- [x] longest-suffix routing integrated with per-link scopes
- [x] default-route link inference
- [ ] split-DNS parallel scope behavior
- [ ] interface binding and scoped IPv6 upstreams
- [x] credential-based `network.dns` and `network.search_domains` configuration with explicit-setting precedence
- [x] exact-name static `.rr` A, AAAA, PTR, NS, CNAME, and DNAME records with drop-in precedence, `/dev/null` masking, bounded reads, and two-second rechecks
- [x] `ReadStaticRecords=` text-configuration toggle
- [ ] complete static-record diagnostics parity

## Service behavior

- [x] systemd readiness, reload, status, and stopping notifications
- [x] hardened service unit and runtime directory
- [x] privileged port operation through service capabilities
- [x] bounded Varlink framing and peer-credential checks for maintenance calls
- [x] named `io.systemd.Resolve` Varlink socket activation
- [ ] monitor socket and complete upstream socket-activation contract
- [x] watchdog keepalive
- [ ] privilege-drop parity when launched directly as root
- [ ] complete `systemd-resolved` command-line compatibility
- [ ] D-Bus policy and authorization parity

## Required release validation

- [ ] upstream `TEST-75-RESOLVED` passes unmodified
- [ ] upstream mDNS and resolver-adjacent unit suites pass unmodified
- [x] live Manager and Link D-Bus introspection matches the pinned upstream manifests
- [ ] Varlink schemas and error identifiers match
- [ ] `resolvectl` behavioral and output corpus matches
- [ ] packet parser passes upstream and independent fuzz corpora
- [ ] sanitizer, Miri, Valgrind, and race-test runs are clean
- [ ] failover, suspend/resume, network churn, VPN split-DNS, and captive-portal scenarios pass
- [ ] clean install, upgrade, rollback, and recovery procedures pass
- [ ] no unresolved high- or critical-severity security findings remain
