# Upstream baseline

The compatibility target is the `systemd-resolved` implementation in
`systemd/systemd` at commit:

```
f807a6f26d150d9e8138ef59d2ff2c9c7e860d39
```

That snapshot identifies itself as `262~devel` and was current when this
rewrite began on 2026-08-05. Compatibility work should be compared against
that exact tree before moving the baseline.

Primary reference surfaces:

- `src/resolve/`
- `man/systemd-resolved.service.xml`
- `man/org.freedesktop.resolve1.xml`
- `docs/WRITING_RESOLVER_CLIENTS.md`
- `docs/WRITING_NETWORK_CONFIGURATION_MANAGERS.md`
- `test/units/TEST-75-RESOLVED.sh`
