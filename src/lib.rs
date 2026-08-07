#![allow(warnings)]
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
pub mod cache_x;
pub mod config;
pub mod daemon;
pub mod dbus;
pub mod dbus_resolve1_abi;
pub mod dnssec;
pub mod edns;
pub mod hosts;
#[cfg(feature = "hyper")]
pub mod hyper_resolver;
pub mod idna_name;
pub mod interface;
pub mod json;
pub mod landing_glue;
pub mod lifecycle;
pub mod llmnr;
pub mod mdns;
pub mod native;
pub mod netlink;
pub mod networkd;
pub mod nss_backend;
pub mod policy;
pub mod resolv_conf;
pub mod resolvconf_publish;
pub mod resolvectl_dbus;
pub mod resolver;
pub mod routing;
pub mod server_features;
pub mod split_dns;
pub mod static_records;
#[cfg(feature = "supremacy")]
pub mod supremacy;
pub mod synthetic;
pub mod tls;
pub mod transport;
#[cfg_attr(test, allow(unused_imports))]
pub mod varlink;
pub mod wire;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
