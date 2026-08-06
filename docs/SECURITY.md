# Security model

The resolver processes attacker-controlled datagrams while holding permission
to bind privileged ports. Parsing and forwarding therefore follow these rules:

- Every packet cursor is bounds checked.
- Compression traversal is bounded and rejects repeated offsets.
- Upstream replies must match both transaction ID and question.
- TCP messages are limited by the DNS two-byte length field.
- Cached packets are ID-neutral and receive a client ID only on lookup.
- TTLs can only decrease while cached.
- Responses carrying TSIG are not cached.
- Upstream addresses pointing back to either local stub are excluded.
- Control commands require root or the daemon's effective user through
  `SO_PEERCRED`.

DNSSEC is not implemented in the first milestone. The daemon never marks
answers authenticated and the status interface reports that limitation.
