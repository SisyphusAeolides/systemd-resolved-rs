//! sd_notify, watchdog, reload/flush/stop flags.

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

#[cfg(target_os = "linux")]
pub fn sd_notify_stopping() {
    let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Stopping]);
}

#[cfg(not(target_os = "linux"))]
pub fn sd_notify_ready() {}
#[cfg(not(target_os = "linux"))]
pub fn sd_notify_watchdog() {}
#[cfg(not(target_os = "linux"))]
pub fn sd_notify_stopping() {}

pub fn take_reload() -> bool {
    RELOAD.swap(false, Ordering::SeqCst)
}
pub fn take_flush() -> bool {
    FLUSH.swap(false, Ordering::SeqCst)
}
pub fn stop_requested() -> bool {
    STOP.load(Ordering::SeqCst)
}

/// Call once from tokio runtime after start.
pub fn install_signal_handlers() {
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut hup = match signal(SignalKind::hangup()) {
                Ok(s) => s,
                Err(_) => return,
            };
            let mut term = match signal(SignalKind::terminate()) {
                Ok(s) => s,
                Err(_) => return,
            };
            let mut int = match signal(SignalKind::interrupt()) {
                Ok(s) => s,
                Err(_) => return,
            };
            let mut usr2 = match signal(SignalKind::user_defined2()) {
                Ok(s) => s,
                Err(_) => return,
            };
            loop {
                tokio::select! {
                    _ = hup.recv() => { RELOAD.store(true, Ordering::SeqCst); }
                    _ = term.recv() => { STOP.store(true, Ordering::SeqCst); }
                    _ = int.recv() => { STOP.store(true, Ordering::SeqCst); }
                    _ = usr2.recv() => { FLUSH.store(true, Ordering::SeqCst); }
                }
            }
        }
    });
}
