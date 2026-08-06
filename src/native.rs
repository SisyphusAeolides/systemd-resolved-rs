// SPDX-License-Identifier: LGPL-2.1-or-later
use std::ffi::CString;
use std::io;
use std::os::raw::{c_char, c_int, c_void};

extern "C" {
    fn resolved_notify(state: *const c_char) -> c_int;
    fn resolved_listen_fds() -> c_int;
    fn resolved_install_signal_handlers() -> c_int;
    fn resolved_take_reload() -> c_int;
    fn resolved_should_stop() -> c_int;
    fn resolved_peer_credentials(fd: c_int, pid: *mut u32, uid: *mut u32, gid: *mut u32) -> c_int;
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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerCredentials {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
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
