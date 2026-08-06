// SPDX-License-Identifier: LGPL-2.1-or-later
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate
)]

pub mod cache;
pub mod config;
pub mod daemon;
pub mod dbus;
pub mod hosts;
pub mod json;
pub mod native;
pub mod policy;
pub mod resolver;
pub mod routing;
pub mod varlink;
pub mod wire;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
