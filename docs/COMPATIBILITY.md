# Compatibility ledger

A check mark means the behavior is implemented and covered by a local test.
An open box is a required parity gate. The project must not be described as a
drop-in replacement until every required gate is closed against the pinned
upstream integration suite.

## Local resolver interfaces

The pinned D-Bus signature manifests live in `compat/`.

- [x] UDP DNS listener on 127.0.0.53
- [x] TCP DNS listener on 127.0.0.53
- [x] Proxy-mode UDP/TCP listener on 127.0.0.54
- [x] Generated stub and uplink `resolv.conf` files
- [ ] `org.freedesktop.resolve1` D-Bus manager and link objects
- [ ] `io.systemd.Resolve` Varlink interface
- [ ] `io.systemd.Resolve.Monitor` Varlink interface
- [ ] Complete `resolvectl` command and output compatibility
- [ ] NSS integration parity with `nss-resolve`

## DNS engine

- [x] Bounded DNS name decompression with loop rejection
- [x] A, AAAA, and PTR local answers
- [x] `/etc/hosts` forward and reverse answers
- [x] localhost, `_localdnsstub`, and `_localdnsproxy` synthesis
- [x] UDP forwarding with response identity validation
- [x] TCP fallback after a truncated UDP response
- [x] Positive and negative cache with TTL aging
- [x] TSIG-bearing response cache exclusion
- [ ] EDNS feature negotiation and downgrade state
- [ ] DNS cookies and feature-level server state
- [ ] CNAME/DNAME synthesis and complete RR validation
- [ ] RFC 2308 negative-cache TTL calculation from SOA MINIMUM
- [ ] stale-answer retention
- [ ] transaction coalescing
- [ ] parallel queries across equivalent scopes

## Secure and local-link protocols

- [ ] DNSSEC validation and trust-anchor management
- [ ] DNS-over-TLS opportunistic and strict modes
- [ ] LLMNR resolver and responder
- [ ] MulticastDNS resolver and responder
- [ ] DNS-SD service registration and browsing

## Routing and configuration

- [x] `DNS=`, `FallbackDNS=`, `Domains=`, `Cache=`, `DNSCacheSize=`,
      `DNSStubListener=`, `ReadEtcHosts=`, and
      `ResolveUnicastSingleLabel=` parsing
- [x] longest-suffix route selection
- [x] route-only domain representation
- [x] global and fallback upstream selection
- [x] SIGHUP configuration reload
- [ ] per-link DNS state from D-Bus and netlink
- [ ] default-route link inference
- [ ] search-domain candidate expansion
- [ ] split-DNS parallel scope behavior
- [ ] interface binding and scoped IPv6 upstreams
- [ ] credential-based DNS and search-domain configuration
- [ ] static `.rr` record files

## Service behavior

- [x] systemd readiness, reload, status, and stopping notifications
- [x] hardened service unit and runtime directory
- [x] privileged port operation through capabilities
- [x] authenticated local control socket
- [ ] upstream socket-activation contract
- [ ] watchdog keepalive
- [ ] privilege-drop parity when launched directly as root
- [ ] complete `systemd-resolved` command-line compatibility

## Required release validation

- [ ] upstream `TEST-75-RESOLVED` passes unmodified
- [ ] D-Bus introspection is byte-for-byte signature compatible
- [ ] Varlink schemas and error identifiers match
- [ ] `resolvectl` behavioral corpus matches
- [ ] packet parser passes upstream fuzz corpora
- [ ] sanitizer, Miri, Valgrind, and race-test runs are clean
- [ ] failover, suspend/resume, network churn, VPN split-DNS, and captive portal
      scenarios pass
