from pathlib import Path

def read_lines(path: str) -> list[str]:
    return Path(path).read_text(encoding="utf-8").splitlines()

def write_lines(path: str, lines: list[str]) -> None:
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")

def unique_index(lines: list[str], needle: str, path: str) -> int:
    matches = [index for index, line in enumerate(lines) if needle in line]
    if len(matches) != 1:
        raise SystemExit(
            f"{path}: expected one line containing {needle!r}, found {len(matches)}"
        )
    return matches[0]

def insert_after(path: str, needle: str, additions: list[str]) -> None:
    lines = read_lines(path)
    index = unique_index(lines, needle, path)
    lines[index + 1:index + 1] = additions
    write_lines(path, lines)

def insert_before(path: str, needle: str, additions: list[str]) -> None:
    lines = read_lines(path)
    index = unique_index(lines, needle, path)
    lines[index:index] = additions
    write_lines(path, lines)

def replace_line(path: str, needle: str, replacement: str) -> None:
    lines = read_lines(path)
    index = unique_index(lines, needle, path)
    lines[index] = replacement
    write_lines(path, lines)

def replace_text(path: str, old: str, new: str, expected: int = 1) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != expected:
        raise SystemExit(
            f"{path}: expected {expected} copies of {old!r}, found {count}"
        )
    target.write_text(text.replace(old, new), encoding="utf-8")

# Permanent packaging validation and installation of the sibling monitor socket.
insert_after(
    "Makefile",
    'cp packaging/systemd/systemd-resolved-varlink.socket "$$work/systemd-resolved-varlink.socket"',
    ['\tcp packaging/systemd/systemd-resolved-monitor.socket "$$work/systemd-resolved-monitor.socket"; \\'],
)
insert_before(
    "Makefile",
    '\t\t"$$work/systemd-resolved-varlink.socket"',
    ['\t\t"$$work/systemd-resolved-monitor.socket" \\'],
)
insert_after(
    "Makefile",
    'install -Dm0644 packaging/systemd/systemd-resolved-varlink.socket',
    ['\tinstall -Dm0644 packaging/systemd/systemd-resolved-monitor.socket $(DESTDIR)$(UNITDIR)/systemd-resolved-monitor.socket'],
)

for path in [
    "packaging/systemd/systemd-resolved.service",
    "packaging/systemd/systemd-resolved-replacement.service",
]:
    replace_line(
        path,
        "Sockets=systemd-resolved-varlink.socket",
        "Sockets=systemd-resolved-varlink.socket systemd-resolved-monitor.socket",
    )
    replace_line(
        path,
        "Also=systemd-resolved-varlink.socket",
        "Also=systemd-resolved-varlink.socket systemd-resolved-monitor.socket",
    )

insert_after(
    "packaging/systemd/systemd-resolved-rs.service",
    "NotifyAccess=main",
    ["Sockets=systemd-resolved-rs-varlink.socket systemd-resolved-rs-monitor.socket"],
)
replace_line(
    "packaging/systemd/systemd-resolved-rs.service",
    "Also=systemd-resolved-rs.socket",
    "Also=systemd-resolved-rs.socket systemd-resolved-rs-varlink.socket systemd-resolved-rs-monitor.socket",
)
insert_after(
    "packaging/systemd/systemd-resolved-rs-varlink.socket",
    "ListenStream=/run/systemd/resolve/io.systemd.Resolve",
    [
        "Symlinks=/run/varlink/registry/io.systemd.Resolve",
        "FileDescriptorName=varlink",
    ],
)

# Transactional replacement now backs up, installs, activates, verifies, and restores both sockets.
insert_after(
    "scripts/install-replace.sh",
    'SOCKET_SOURCE="$ROOT/packaging/systemd/systemd-resolved-varlink.socket"',
    ['MONITOR_SOCKET_SOURCE="$ROOT/packaging/systemd/systemd-resolved-monitor.socket"'],
)
insert_after(
    "scripts/install-replace.sh",
    'SOCKET_DESTINATION="/etc/systemd/system/systemd-resolved-varlink.socket"',
    ['MONITOR_SOCKET_DESTINATION="/etc/systemd/system/systemd-resolved-monitor.socket"'],
)
replace_text(
    "scripts/install-replace.sh",
    "systemd-resolved.service systemd-resolved-varlink.socket",
    "systemd-resolved.service systemd-resolved-varlink.socket systemd-resolved-monitor.socket",
    expected=2,
)
insert_after(
    "scripts/install-replace.sh",
    'restore_path "$SOCKET_DESTINATION" socket',
    ['    restore_path "$MONITOR_SOCKET_DESTINATION" monitor-socket'],
)
insert_after(
    "scripts/install-replace.sh",
    'restore_activity systemd-resolved-varlink.socket socket-active',
    ['    restore_activity systemd-resolved-monitor.socket monitor-socket-active'],
)
replace_text(
    "scripts/install-replace.sh",
    '            && [[ -S /run/systemd/resolve/io.systemd.Resolve ]] \\\n            && [[ -s /run/systemd/resolve/stub-resolv.conf ]]; then',
    '            && [[ -S /run/systemd/resolve/io.systemd.Resolve ]] \\\n            && [[ -S /run/systemd/resolve/io.systemd.Resolve.Monitor ]] \\\n            && [[ -s /run/systemd/resolve/stub-resolv.conf ]]; then',
)
insert_after(
    "scripts/install-replace.sh",
    '[[ -r "$SOCKET_SOURCE" ]] || fail "missing Varlink socket unit: $SOCKET_SOURCE"',
    ['[[ -r "$MONITOR_SOCKET_SOURCE" ]] || fail "missing monitor Varlink socket unit: $MONITOR_SOCKET_SOURCE"'],
)
insert_after(
    "scripts/install-replace.sh",
    'printf \'%s\\n\' "$SOCKET_DESTINATION" >"$BACKUP/socket-destination"',
    ['printf \'%s\\n\' "$MONITOR_SOCKET_DESTINATION" >"$BACKUP/monitor-socket-destination"'],
)
insert_after(
    "scripts/install-replace.sh",
    'capture_path "$SOCKET_DESTINATION" socket',
    ['capture_path "$MONITOR_SOCKET_DESTINATION" monitor-socket'],
)
insert_after(
    "scripts/install-replace.sh",
    'unit_state is-active systemd-resolved-varlink.socket >"$BACKUP/socket-active"',
    [
        'unit_state is-enabled systemd-resolved-monitor.socket >"$BACKUP/monitor-socket-enabled"',
        'unit_state is-active systemd-resolved-monitor.socket >"$BACKUP/monitor-socket-active"',
    ],
)
insert_after(
    "scripts/install-replace.sh",
    'install_atomic "$SOCKET_SOURCE" "$SOCKET_DESTINATION" 0644',
    ['install_atomic "$MONITOR_SOCKET_SOURCE" "$MONITOR_SOCKET_DESTINATION" 0644'],
)
insert_after(
    "scripts/install-replace.sh",
    "systemctl start systemd-resolved-varlink.socket",
    ["systemctl start systemd-resolved-monitor.socket"],
)
insert_after(
    "scripts/install-replace.sh",
    '    query "$PROBE_NAME" >/dev/null',
    [
        '"$RESOLVECTL_DESTINATION" --socket /run/systemd/resolve/io.systemd.Resolve statistics >/dev/null',
        '"$RESOLVECTL_DESTINATION" --socket /run/systemd/resolve/io.systemd.Resolve show-cache >/dev/null',
        '"$RESOLVECTL_DESTINATION" --socket /run/systemd/resolve/io.systemd.Resolve show-server-state >/dev/null',
    ],
)

insert_after(
    "scripts/uninstall-restore.sh",
    'SOCKET_DESTINATION="$(cat "$BACKUP/socket-destination")"',
    ['MONITOR_SOCKET_DESTINATION="$(cat "$BACKUP/monitor-socket-destination")"'],
)
replace_text(
    "scripts/uninstall-restore.sh",
    "systemd-resolved.service systemd-resolved-varlink.socket",
    "systemd-resolved.service systemd-resolved-varlink.socket systemd-resolved-monitor.socket",
)
insert_after(
    "scripts/uninstall-restore.sh",
    'restore_path "$SOCKET_DESTINATION" socket',
    ['restore_path "$MONITOR_SOCKET_DESTINATION" monitor-socket'],
)
insert_after(
    "scripts/uninstall-restore.sh",
    'restore_enablement systemd-resolved-varlink.socket socket-enabled',
    ['restore_enablement systemd-resolved-monitor.socket monitor-socket-enabled'],
)
insert_after(
    "scripts/uninstall-restore.sh",
    'restore_activity systemd-resolved-varlink.socket socket-active',
    ['restore_activity systemd-resolved-monitor.socket monitor-socket-active'],
)
insert_after(
    "scripts/uninstall-restore.sh",
    'verify_path /etc/resolv.conf resolv-conf',
    ['verify_path "$MONITOR_SOCKET_DESTINATION" monitor-socket'],
)
insert_after(
    "scripts/uninstall-restore.sh",
    'verify_activity systemd-resolved-varlink.socket socket-active',
    ['verify_activity systemd-resolved-monitor.socket monitor-socket-active'],
)

# The live contract now exercises the sibling monitor socket through resolvectl.
insert_before(
    "tests/live-dns.py",
    '                    for name in ("stub-resolv.conf", "resolv.conf"):',
    [
        '                    monitor_commands = {',
        '                        "statistics": "Transactions",',
        '                        "show-cache": "Global, protocol dns",',
        '                        "show-server-state": "Server ",',
        '                    }',
        '                    for verb, expected in monitor_commands.items():',
        '                        monitor_result = subprocess.run(',
        '                            [str(resolvectl), "--socket", str(varlink), verb],',
        '                            text=True,',
        '                            capture_output=True,',
        '                            timeout=15,',
        '                            check=True,',
        '                        )',
        '                        if expected not in monitor_result.stdout:',
        '                            raise AssertionError(',
        '                                f"{verb} did not expose monitor data: {monitor_result.stdout!r}"',
        '                            )',
        '',
    ],
)
