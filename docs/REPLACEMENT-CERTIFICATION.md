# Certified replacement procedure

`systemd-resolved-rs` must not replace the host resolver merely because it
builds or because ordinary CI is green. Replacement is permitted only when a
single immutable Git tree has a portable schema-2 certificate with every gate
set to `pass`.

The distribution's `systemd-resolved` package remains installed throughout the
procedure. It is the rollback payload and must not be removed.

## Certification gates

The certificate is fail-closed and binds all evidence to the same Git tree,
upstream systemd commit, daemon SHA-256, and client SHA-256. It requires:

- a clean source tree and immutable pinned upstream baseline;
- complete pinned D-Bus, Varlink, configuration, and `resolvectl` surface
  inventory coverage;
- Rust formatting, Clippy, all-target tests, Rust 1.74 compatibility, native
  C/Fortran checks, packaging checks, and NSS integration;
- byte-identical daemon, client, NSS, and normalized replacement packages from
  two independent release builds;
- live UDP, TCP, D-Bus, Varlink, NSS, mDNS resolver, mDNS responder, simultaneous
  resolver/responder, and DNS-SD publication/reload tests;
- host shadow comparison against the installed resolver without changing
  `/etc/resolv.conf`;
- the pinned upstream `TEST-75-RESOLVED` suite with proof that the candidate
  daemon actually ran;
- libFuzzer, AddressSanitizer, UndefinedBehaviorSanitizer, Miri strict
  provenance, ThreadSanitizer, and Valgrind evidence;
- two QEMU boots with the candidate healthy on both boots followed by a healthy
  rollback to the distribution resolver.

A skipped, stale, missing, malformed, or failed gate makes `certified` false.

## Produce one exact-SHA certificate

In GitHub Actions, run **Full replacement certification**. Leave `source_sha`
blank to select the dispatch-time `main` commit, or provide a full 40-character
commit ID.

The orchestrator dispatches and waits for:

1. Replacement security gates
2. Replacement upstream TEST-75 proof
3. Replacement boot and rollback proof
4. Replacement security proof
5. Replacement readiness certificate

Download the final `replacement-readiness-<sha>` artifact. The workflow only
succeeds when `replacement-certification.json` says:

```json
{"certified": true}
```

The artifact also contains the verified daemon, client, logs, proof files, and
reproducible release output.

## Verify the downloaded bundle

Check out the exact source commit named by the certificate, then verify the
bundle before acquiring root privileges:

```sh
python3 scripts/verify-readiness-bundle.py \
  --certificate /path/to/replacement-certification.json
```

The verifier rejects stale certificates, unsafe relative paths, missing files,
and daemon/client hash mismatches. A certificate is accepted for at most 24
hours by default.

## Transactionally switch the host

Run the switch script from the exact certified repository checkout:

```sh
sudo scripts/switch-resolved-transactionally.sh \
  --certificate /path/to/replacement-certification.json \
  --external-name example.com
```

The operation:

- installs versioned candidate binaries without deleting the distribution
  package;
- snapshots the existing drop-in, mask/enable state, active state, guard unit,
  `/etc/resolv.conf`, and `/etc/nsswitch.conf`;
- changes only the `systemd-resolved.service` `ExecStart` drop-in;
- verifies the actual executable, UDP, TCP, D-Bus, Varlink, statistics,
  `_localdnsstub`, NSS, `resolv.conf`, and the optional external name;
- restores the prior resolver automatically if any immediate check fails;
- leaves a boot guard active until a successful reboot is confirmed.

The script prints a transaction identifier. Reboot once, then confirm only
after the boot guard and health checks pass:

```sh
sudo reboot
sudo /usr/lib/systemd/systemd-resolved-rs-switch \
  --confirm TRANSACTION_ID
```

## Roll back

Rollback remains available before or after confirmation:

```sh
sudo /usr/lib/systemd/systemd-resolved-rs-switch \
  --rollback TRANSACTION_ID
```

The rollback restores the exact previous service drop-in and service state,
then restarts the distribution resolver. Omitting the identifier selects the
active transaction:

```sh
sudo /usr/lib/systemd/systemd-resolved-rs-switch --rollback
```

## Prohibited shortcut

Do not remove, purge, mask permanently, or overwrite the distribution
`systemd-resolved` package. Do not manually replace files under `/usr/lib` or
change `/etc/resolv.conf` as part of the switch. A failed certificate or an
uncertified source tree is a hard stop, not a warning.
