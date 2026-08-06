# Security model

The resolver processes attacker-controlled datagrams while holding permission
to bind privileged ports. The current implementation follows these rules:

- packet cursors and section lengths are bounds checked;
- DNS labels are limited to 63 octets and expanded names to 255 wire octets;
- compression pointers must move backward and pointer traversal is bounded;
- upstream replies must match the transaction identifier and complete question;
- TCP frames are bounded by the DNS two-byte length field;
- cached packets are transaction-ID neutral and receive the client ID only on lookup;
- cached TTLs can only decrease, and stale answers carry zero TTLs;
- TSIG-bearing and truncated responses are not cached;
- local stub addresses are excluded from discovered upstream servers;
- Varlink messages have a one-megabyte limit;
- maintenance calls on the local Varlink socket require a root peer credential;
- an existing non-socket path is never replaced when creating the Varlink endpoint.

The Rust parser remains the authoritative packet validator in this milestone.
C is restricted to narrow Linux ABI operations, and unsafe Rust is isolated in
that boundary module.

DNSSEC validation, DNS-over-TLS, LLMNR, MulticastDNS, D-Bus authorization,
per-link network state, and production fuzz certification are not complete. The
daemon never marks answers authenticated. Until the release gates close, run it
only on a recoverable test system and do not rely on it as a security boundary.
