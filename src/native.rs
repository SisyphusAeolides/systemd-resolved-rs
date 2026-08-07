// SPDX-License-Identifier: LGPL-2.1-or-later
use std::ffi::CString;
use std::io;
use std::net::SocketAddr;
use std::os::fd::RawFd;
use std::os::raw::{c_char, c_int, c_void};
use std::time::Duration;

const IFNAME_MAX: usize = 16;
const LINK_SNAPSHOT_RETRIES: usize = 4;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct NativeLinkSnapshot {
    ifindex: i32,
    flags: u32,
    mtu: u32,
    operstate: u8,
    has_ipv4_global: u8,
    has_ipv4_link_local: u8,
    has_ipv6_global: u8,
    has_ipv6_link_local: u8,
    ifname: [c_char; IFNAME_MAX],
}

impl Default for NativeLinkSnapshot {
    fn default() -> Self {
        Self {
            ifindex: 0,
            flags: 0,
            mtu: 0,
            operstate: 0,
            has_ipv4_global: 0,
            has_ipv4_link_local: 0,
            has_ipv6_global: 0,
            has_ipv6_link_local: 0,
            ifname: [0; IFNAME_MAX],
        }
    }
}

extern "C" {
    fn resolved_notify(state: *const c_char) -> c_int;
    fn resolved_listen_fds() -> c_int;
    fn resolved_install_signal_handlers() -> c_int;
    fn resolved_take_reload() -> c_int;
    fn resolved_should_stop() -> c_int;
    fn resolved_peer_credentials(fd: c_int, pid: *mut u32, uid: *mut u32, gid: *mut u32) -> c_int;
    fn resolved_udp_connect(
        address: *const c_char,
        port: u16,
        scope_id: u32,
        ifindex: c_int,
    ) -> c_int;
    fn resolved_tcp_connect(
        address: *const c_char,
        port: u16,
        scope_id: u32,
        ifindex: c_int,
        timeout_msec: u32,
    ) -> c_int;
    fn resolved_udp_path_mtu(fd: c_int, ipv6: c_int) -> c_int;
    fn resolved_udp_enable_recvfragsize(fd: c_int, ipv6: c_int) -> c_int;
    fn resolved_udp_recv(
        fd: c_int,
        buffer: *mut c_void,
        capacity: usize,
        fragment_size: *mut u32,
    ) -> i64;
    fn resolved_dns_udp_payload_size(
        path_mtu: u32,
        ipv6: c_int,
        loopback: c_int,
        fragmented: c_int,
        received_udp_fragment_max: u32,
    ) -> u16;
    fn resolved_link_snapshot(entries: *mut NativeLinkSnapshot, capacity: usize) -> i64;
    fn resolved_rtnl_open() -> c_int;
    fn resolved_rtnl_wait(fd: c_int, timeout_msec: u32) -> c_int;
    fn resolved_networkd_open() -> c_int;
    fn resolved_networkd_wait(fd: c_int, timeout_msec: u32) -> c_int;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerCredentials {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkInfo {
    pub ifindex: i32,
    pub ifname: String,
    pub flags: u32,
    pub mtu: u32,
    pub operstate: u8,
    pub has_ipv4_global: bool,
    pub has_ipv4_link_local: bool,
    pub has_ipv6_global: bool,
    pub has_ipv6_link_local: bool,
}

pub fn install_signal_handlers() -> io::Result<()> {
    // SAFETY: the function takes no pointers and returns an errno-style integer.
    result(unsafe { resolved_install_signal_handlers() }).map(|_| ())
}

pub fn stop_requested() -> bool {
    // SAFETY: the function takes no pointers and only reads signal-safe state.
    unsafe { resolved_should_stop() != 0 }
}

pub fn take_reload() -> bool {
    // SAFETY: the function takes no pointers and atomically consumes signal state.
    unsafe { resolved_take_reload() != 0 }
}

pub fn listen_fds() -> io::Result<usize> {
    // SAFETY: the function takes no pointers and returns an errno-style integer.
    let count = result(unsafe { resolved_listen_fds() })?;
    usize::try_from(count).map_err(|_| io::Error::from_raw_os_error(libc_einval()))
}

pub fn notify(state: &str) -> io::Result<bool> {
    let state = CString::new(state)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "notification contains NUL"))?;
    // SAFETY: CString guarantees a non-null, NUL-terminated pointer for this call.
    result(unsafe { resolved_notify(state.as_ptr()) }).map(|value| value != 0)
}

pub fn udp_connect(server: SocketAddr, ifindex: Option<i32>) -> io::Result<RawFd> {
    let address = CString::new(server.ip().to_string())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid DNS server address"))?;
    let scope_id = match server {
        SocketAddr::V4(_) => 0,
        SocketAddr::V6(address) => address.scope_id(),
    };
    // SAFETY: CString provides a valid pointer for the duration of the call; all other values are scalars.
    result(unsafe {
        resolved_udp_connect(
            address.as_ptr(),
            server.port(),
            scope_id,
            ifindex.unwrap_or(0),
        )
    })
}

pub fn tcp_connect(
    server: SocketAddr,
    ifindex: Option<i32>,
    timeout: Duration,
) -> io::Result<RawFd> {
    let address = CString::new(server.ip().to_string())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid DNS server address"))?;
    let scope_id = match server {
        SocketAddr::V4(_) => 0,
        SocketAddr::V6(address) => address.scope_id(),
    };
    let timeout_msec = u32::try_from(timeout.as_millis())
        .unwrap_or(u32::MAX)
        .max(1);
    // SAFETY: CString provides a valid pointer for the duration of the call; all other values are scalars.
    result(unsafe {
        resolved_tcp_connect(
            address.as_ptr(),
            server.port(),
            scope_id,
            ifindex.unwrap_or(0),
            timeout_msec,
        )
    })
}

pub fn udp_path_mtu(fd: c_int, ipv6: bool) -> io::Result<u32> {
    // SAFETY: the descriptor is borrowed for the duration of the getsockopt call.
    let mtu = result(unsafe { resolved_udp_path_mtu(fd, bool_to_c_int(ipv6)) })?;
    u32::try_from(mtu).map_err(|_| io::Error::from_raw_os_error(libc_einval()))
}

pub fn enable_udp_fragment_size(fd: c_int, ipv6: bool) -> io::Result<bool> {
    // SAFETY: the descriptor is borrowed and the function only changes a socket option.
    result(unsafe { resolved_udp_enable_recvfragsize(fd, bool_to_c_int(ipv6)) })
        .map(|value| value != 0)
}

pub fn udp_recv(fd: c_int, buffer: &mut [u8]) -> io::Result<(usize, u32)> {
    let mut fragment_size = 0;
    // SAFETY: the buffer is valid and writable for exactly `buffer.len()` bytes.
    let length = unsafe {
        resolved_udp_recv(
            fd,
            buffer.as_mut_ptr().cast::<c_void>(),
            buffer.len(),
            &mut fragment_size,
        )
    };
    if length < 0 {
        let errno = i32::try_from(-length).unwrap_or(libc_einval());
        return Err(io::Error::from_raw_os_error(errno));
    }
    let length =
        usize::try_from(length).map_err(|_| io::Error::from_raw_os_error(libc_einval()))?;
    if length > buffer.len() {
        return Err(io::Error::from_raw_os_error(libc_einval()));
    }
    Ok((length, fragment_size))
}

#[must_use]
pub fn dns_udp_payload_size(
    path_mtu: Option<u32>,
    ipv6: bool,
    loopback: bool,
    fragmented: bool,
    received_udp_fragment_max: u32,
) -> u16 {
    // SAFETY: all arguments are plain values and the function has no side effects.
    unsafe {
        resolved_dns_udp_payload_size(
            path_mtu.unwrap_or(0),
            bool_to_c_int(ipv6),
            bool_to_c_int(loopback),
            bool_to_c_int(fragmented),
            received_udp_fragment_max,
        )
    }
}

pub fn link_snapshot() -> io::Result<Vec<LinkInfo>> {
    let mut capacity = snapshot_count()?;
    for _ in 0..LINK_SNAPSHOT_RETRIES {
        let mut entries = vec![NativeLinkSnapshot::default(); capacity.max(1)];
        // SAFETY: entries points to `entries.len()` writable, correctly aligned ABI records.
        let count =
            signed_result(unsafe { resolved_link_snapshot(entries.as_mut_ptr(), entries.len()) })?;
        let count =
            usize::try_from(count).map_err(|_| io::Error::from_raw_os_error(libc_einval()))?;
        if count > entries.len() {
            capacity = count;
            continue;
        }
        entries.truncate(count);
        return entries.into_iter().map(link_info).collect();
    }
    Err(io::Error::other(
        "kernel link set changed repeatedly during snapshot",
    ))
}

pub fn rtnl_open() -> io::Result<RawFd> {
    // SAFETY: the function takes no pointers and returns an owned descriptor or negative errno.
    result(unsafe { resolved_rtnl_open() })
}

pub fn rtnl_wait(fd: RawFd, timeout: Duration) -> io::Result<bool> {
    let timeout_msec = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
    // SAFETY: the descriptor is borrowed for the duration of poll/recv draining.
    result(unsafe { resolved_rtnl_wait(fd, timeout_msec) }).map(|value| value != 0)
}

pub fn networkd_open() -> io::Result<RawFd> {
    // SAFETY: the function takes no pointers and returns an owned descriptor or negative errno.
    result(unsafe { resolved_networkd_open() })
}

pub fn networkd_wait(fd: RawFd, timeout: Duration) -> io::Result<bool> {
    let timeout_msec = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
    // SAFETY: the descriptor is borrowed for the duration of poll/read draining.
    result(unsafe { resolved_networkd_wait(fd, timeout_msec) }).map(|value| value != 0)
}

pub fn peer_credentials(fd: c_int) -> io::Result<PeerCredentials> {
    let mut process_id = 0;
    let mut user_id = 0;
    let mut group_id = 0;
    // SAFETY: all output pointers refer to initialized writable u32 values.
    result(unsafe { resolved_peer_credentials(fd, &mut process_id, &mut user_id, &mut group_id) })?;
    Ok(PeerCredentials {
        pid: process_id,
        uid: user_id,
        gid: group_id,
    })
}

fn snapshot_count() -> io::Result<usize> {
    // SAFETY: a null pointer with zero capacity requests the required record count.
    let count = signed_result(unsafe { resolved_link_snapshot(std::ptr::null_mut(), 0) })?;
    usize::try_from(count).map_err(|_| io::Error::from_raw_os_error(libc_einval()))
}

fn link_info(snapshot: NativeLinkSnapshot) -> io::Result<LinkInfo> {
    let end = snapshot
        .ifname
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(snapshot.ifname.len());
    let bytes = snapshot.ifname[..end]
        .iter()
        .copied()
        .map(u8::try_from)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "kernel interface name contains non-ASCII bytes",
            )
        })?;
    let ifname = String::from_utf8(bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "kernel interface name is not UTF-8",
        )
    })?;
    if snapshot.ifindex <= 0 || ifname.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "kernel returned an invalid interface snapshot",
        ));
    }
    Ok(LinkInfo {
        ifindex: snapshot.ifindex,
        ifname,
        flags: snapshot.flags,
        mtu: snapshot.mtu,
        operstate: snapshot.operstate,
        has_ipv4_global: snapshot.has_ipv4_global != 0,
        has_ipv4_link_local: snapshot.has_ipv4_link_local != 0,
        has_ipv6_global: snapshot.has_ipv6_global != 0,
        has_ipv6_link_local: snapshot.has_ipv6_link_local != 0,
    })
}

fn signed_result(value: i64) -> io::Result<i64> {
    if value < 0 {
        let errno = i32::try_from(-value).unwrap_or(libc_einval());
        Err(io::Error::from_raw_os_error(errno))
    } else {
        Ok(value)
    }
}

fn result(value: c_int) -> io::Result<c_int> {
    if value < 0 {
        Err(io::Error::from_raw_os_error(-value))
    } else {
        Ok(value)
    }
}

const fn bool_to_c_int(value: bool) -> c_int {
    if value {
        1
    } else {
        0
    }
}

const fn libc_einval() -> i32 {
    22
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    #[test]
    fn kernel_link_snapshot_contains_named_links() {
        let links = link_snapshot().expect("kernel link snapshot");
        assert!(!links.is_empty());
        assert!(links
            .iter()
            .all(|link| link.ifindex > 0 && !link.ifname.is_empty()));
    }

    #[test]
    fn rtnl_monitor_socket_opens() {
        let fd = rtnl_open().expect("RTNL socket");
        // SAFETY: rtnl_open returns a new owned descriptor.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        assert!(!rtnl_wait(owned.as_raw_fd(), Duration::ZERO).expect("RTNL poll"));
    }

    #[test]
    fn networkd_monitor_socket_opens() {
        let fd = networkd_open().expect("networkd monitor socket");
        // SAFETY: networkd_open returns a new owned descriptor.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        assert!(!networkd_wait(owned.as_raw_fd(), Duration::ZERO).expect("networkd poll"));
    }
}
