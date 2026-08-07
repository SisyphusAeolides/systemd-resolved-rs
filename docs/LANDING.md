# systemd-resolved-rs Landing

## Acceptance Commands

Run the following commands to validate the full lifecycle from build to bench and rollback.

```bash
# build
cargo test
cargo build --release && make nss

# replace (VM first!)
sudo scripts/install-replace.sh
sudo scripts/boot-smoke.sh
sudo tests/parity/check_dbus_abi.sh

# bench (save baseline with stock BEFORE replace too)
sudo scripts/uninstall-restore.sh
./tests/supremacy/bench_compare.sh /tmp/bench-stock.txt
sudo scripts/install-replace.sh
./tests/supremacy/bench_compare.sh /tmp/bench-rs.txt
diff -u /tmp/bench-stock.txt /tmp/bench-rs.txt || true

# rollback
sudo scripts/uninstall-restore.sh
```
