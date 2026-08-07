Security / ops checklist

[ ] Binary does not run as root without caps drop (use systemd-resolve user)
[ ] /dev/shm/systemd-resolved-rs-l1 is 0644, content is not secret (public DNS only)
[ ] Do not put DNSSEC private material in SHM
[ ] Open files limit / LimitNOFILE=512K in unit if high QPS
[ ] journald rate limits — use metrics not debug logs in hot path
[ ] AppArmor/SELinux policy if your distro enforces (Fedora: need .te module)
[ ] Conflict with NetworkManager dns=default vs dns=systemd-resolved
[ ] document: nmcli connection modify ... ipv4.dns-priority
[ ] Time sync: DNSSEC needs sane clock (After=time-sync.target optional)
[ ] Disable stub on containers if host already binds 127.0.0.53
[ ] Document rollback: scripts/uninstall-restore.sh

## SELinux note (Fedora)
```bash
# temporary debug
sudo setenforce 0
# then ausearch -m avc -ts recent | audit2allow
```
