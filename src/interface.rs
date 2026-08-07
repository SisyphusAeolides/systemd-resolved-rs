// SPDX-License-Identifier: LGPL-2.1-or-later
use std::ffi::CString;
use std::io;
use std::os::raw::{c_char, c_int};

extern "C" {
    fn resolved_ifindex_from_name(name: *const c_char) -> c_int;
}

pub fn resolve_ifindex(value: &str) -> io::Result<i32> {
    if let Ok(ifindex) = value.parse::<i32>() {
        return if ifindex > 0 {
            Ok(ifindex)
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "interface index must be positive",
            ))
        };
    }

    let name = CString::new(value)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface contains NUL"))?;
    // SAFETY: CString provides a valid NUL-terminated interface name for the duration of the call.
    let result = unsafe { resolved_ifindex_from_name(name.as_ptr()) };
    if result < 0 {
        Err(io::Error::from_raw_os_error(-result))
    } else {
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_ifindices_are_accepted() {
        assert_eq!(resolve_ifindex("7").expect("ifindex"), 7);
        assert!(resolve_ifindex("0").is_err());
    }

    #[test]
    fn loopback_name_resolves() {
        assert!(resolve_ifindex("lo").expect("loopback ifindex") > 0);
    }
}
