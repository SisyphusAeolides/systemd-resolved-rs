// SPDX-License-Identifier: LGPL-2.1-or-later
use std::ffi::CString;
use std::io;
use std::os::raw::{c_char, c_int};

extern "C" {
    fn resolved_notify(state: *const c_char) -> c_int;
    fn resolved_listen_fds() -> c_int;
    fn resolved_install_signal_handlers() -> c_int;
    fn resolved_take_reload() -> c_int;
    fn resolved_should_stop() -> c_int;
    fn resolved_peer_credentials(fd: c_int, pid: *mut u32, uid: *mut u32, gid: *mut u32) -> c_int;
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

const fn libc_einval() -> i32 {
    22
}
