//! systemd integration — notify, watchdog, signals.
#![allow(missing_debug_implementations)]

use std::sync::atomic::{AtomicBool, Ordering};

pub static RELOAD: AtomicBool = AtomicBool::new(false);
pub static FLUSH: AtomicBool = AtomicBool::new(false);
pub static STOP: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "linux")]
pub fn sd_notify_ready() {
    let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Ready]);
}

#[cfg(target_os = "linux")]
pub fn sd_notify_watchdog() {
    let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Watchdog]);
}

#[cfg(not(target_os = "linux"))]
pub fn sd_notify_ready() {}
#[cfg(not(target_os = "linux"))]
pub fn sd_notify_watchdog() {}

pub fn install_signal_handlers() {
    tokio::spawn(async {
        use tokio::signal::unix::{signal, SignalKind};
        let mut hup = signal(SignalKind::hangup()).expect("SIGHUP");
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM");
        let mut usr2 = signal(SignalKind::user_defined2()).expect("SIGUSR2");
        loop {
            tokio::select! {
                _ = hup.recv() => { RELOAD.store(true, Ordering::SeqCst); }
                _ = term.recv() => { STOP.store(true, Ordering::SeqCst); }
                _ = usr2.recv() => { FLUSH.store(true, Ordering::SeqCst); }
            }
        }
    });
}
