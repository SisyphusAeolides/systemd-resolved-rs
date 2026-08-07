// SPDX-License-Identifier: LGPL-2.1-or-later
use crate::native;
use crate::resolver::{QueryMode, Resolver};
use std::env;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const MAX_UDP_PACKET: usize = 65_535;
const UDP_QUEUE_PER_WORKER: usize = 256;
static LOCAL_STOP: AtomicBool = AtomicBool::new(false);

#[derive(Debug)]
struct UdpJob {
    socket: Arc<UdpSocket>,
    packet: Vec<u8>,
    peer: SocketAddr,
    mode: QueryMode,
}

#[derive(Debug)]
struct UdpEndpoint {
    socket: Arc<UdpSocket>,
    mode: QueryMode,
}

#[derive(Debug)]
struct TcpEndpoint {
    listener: TcpListener,
    mode: QueryMode,
}

#[derive(Debug)]
struct UdpDispatcher {
    senders: Vec<SyncSender<UdpJob>>,
    next: AtomicUsize,
}

impl UdpDispatcher {
    fn new(senders: Vec<SyncSender<UdpJob>>) -> Self {
        Self {
            senders,
            next: AtomicUsize::new(0),
        }
    }

    fn dispatch(&self, mut job: UdpJob) -> bool {
        if self.senders.is_empty() {
            return false;
        }

        let start = self.next.fetch_add(1, Ordering::Relaxed) % self.senders.len();
        let mut connected = false;
        for offset in 0..self.senders.len() {
            let index = (start + offset) % self.senders.len();
            match self.senders[index].try_send(job) {
                Ok(()) => return true,
                Err(TrySendError::Full(returned)) => {
                    connected = true;
                    job = returned;
                }
                Err(TrySendError::Disconnected(returned)) => job = returned,
            }
        }

        connected
    }
}

#[derive(Debug)]
struct Watchdog {
    interval: Duration,
    next: Instant,
}

impl Watchdog {
    fn from_environment() -> Option<Self> {
        let usec = env::var("WATCHDOG_USEC").ok();
        let pid = env::var("WATCHDOG_PID").ok();
        let interval = watchdog_interval(usec.as_deref(), pid.as_deref(), std::process::id())?;
        let next = Instant::now().checked_add(interval)?;
        Some(Self { interval, next })
    }

    fn ping_if_due(&mut self) {
        let now = Instant::now();
        if now < self.next {
            return;
        }
        let _ = native::notify("WATCHDOG=1");
        self.next = now.checked_add(self.interval).unwrap_or(now);
    }

    fn sleep_duration(&self) -> Duration {
        self.interval.min(Duration::from_millis(200))
    }
}

pub fn request_stop() {
    LOCAL_STOP.store(true, Ordering::SeqCst);
}

pub fn stop_requested() -> bool {
    LOCAL_STOP.load(Ordering::SeqCst) || native::stop_requested()
}

pub fn install_signal_handlers() -> io::Result<()> {
    native::install_signal_handlers()
}

pub fn run_stub(resolver: &Arc<Resolver>) -> io::Result<()> {
    let mut udp_endpoints = Vec::new();
    let mut tcp_endpoints = Vec::new();
    let stub_mode = resolver.config().dns_stub_listener;
    bind_endpoints(
        &resolver.config().listeners,
        QueryMode::Full,
        stub_mode.udp_enabled(),
        stub_mode.tcp_enabled(),
        &mut udp_endpoints,
        &mut tcp_endpoints,
    )?;
    bind_endpoints(
        &resolver.config().proxy_listeners,
        QueryMode::Proxy,
        stub_mode.udp_enabled(),
        stub_mode.tcp_enabled(),
        &mut udp_endpoints,
        &mut tcp_endpoints,
    )?;

    let workers = resolver.config().workers;
    let mut senders = Vec::with_capacity(workers);
    let mut threads = Vec::new();
    for index in 0..workers {
        let (sender, receiver) = mpsc::sync_channel::<UdpJob>(UDP_QUEUE_PER_WORKER);
        senders.push(sender);
        let resolver = Arc::clone(resolver);
        threads.push(
            thread::Builder::new()
                .name(format!("resolved-udp-worker-{index}"))
                .spawn(move || udp_worker(&resolver, &receiver))?,
        );
    }
    let dispatcher = Arc::new(UdpDispatcher::new(senders));

    for (index, endpoint) in udp_endpoints.into_iter().enumerate() {
        let dispatcher = Arc::clone(&dispatcher);
        threads.push(
            thread::Builder::new()
                .name(format!("resolved-udp-listener-{index}"))
                .spawn(move || udp_listener(&endpoint, &dispatcher))?,
        );
    }
    for (index, endpoint) in tcp_endpoints.into_iter().enumerate() {
        let resolver = Arc::clone(resolver);
        threads.push(
            thread::Builder::new()
                .name(format!("resolved-tcp-listener-{index}"))
                .spawn(move || tcp_listener(&endpoint, &resolver))?,
        );
    }

    let mut watchdog = Watchdog::from_environment();
    let _ = native::notify("READY=1\nSTATUS=Processing requests");
    while !stop_requested() {
        if native::take_reload() {
            let _ = native::notify("RELOADING=1\nSTATUS=Reloading hosts database");
            if let Err(error) = resolver.reload_hosts() {
                eprintln!("systemd-resolved: failed to reload hosts database: {error}");
            }
            let _ = native::notify("READY=1\nSTATUS=Processing requests");
        }
        if let Some(watchdog) = watchdog.as_mut() {
            watchdog.ping_if_due();
        }
        let sleep_duration = watchdog
            .as_ref()
            .map_or(Duration::from_millis(200), Watchdog::sleep_duration);
        thread::sleep(sleep_duration);
    }
    let _ = native::notify("STOPPING=1\nSTATUS=Shutting down");
    drop(dispatcher);
    join_all(threads);
    Ok(())
}

fn bind_endpoints(
    addresses: &[SocketAddr],
    mode: QueryMode,
    udp_enabled: bool,
    tcp_enabled: bool,
    udp_endpoints: &mut Vec<UdpEndpoint>,
    tcp_endpoints: &mut Vec<TcpEndpoint>,
) -> io::Result<()> {
    for &address in addresses {
        if udp_enabled {
            let udp = UdpSocket::bind(address)?;
            udp.set_read_timeout(Some(Duration::from_millis(250)))?;
            udp_endpoints.push(UdpEndpoint {
                socket: Arc::new(udp),
                mode,
            });
        }

        if tcp_enabled {
            let tcp = TcpListener::bind(address)?;
            tcp.set_nonblocking(true)?;
            tcp_endpoints.push(TcpEndpoint {
                listener: tcp,
                mode,
            });
        }
    }
    Ok(())
}

fn udp_listener(endpoint: &UdpEndpoint, dispatcher: &UdpDispatcher) {
    let mut buffer = vec![0; MAX_UDP_PACKET];
    while !stop_requested() {
        match endpoint.socket.recv_from(&mut buffer) {
            Ok((length, peer)) => {
                let job = UdpJob {
                    socket: Arc::clone(&endpoint.socket),
                    packet: buffer[..length].to_vec(),
                    peer,
                    mode: endpoint.mode,
                };
                if !dispatcher.dispatch(job) {
                    break;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(error) => {
                eprintln!("systemd-resolved: UDP receive failed: {error}");
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

fn udp_worker(resolver: &Resolver, receiver: &Receiver<UdpJob>) {
    while !stop_requested() {
        let job = match receiver.recv_timeout(Duration::from_millis(250)) {
            Ok(job) => job,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        };
        let response = match resolver.query_or_servfail(&job.packet, job.mode) {
            Ok(response) => response,
            Err(error) => {
                eprintln!(
                    "systemd-resolved: rejected UDP query from {}: {error}",
                    job.peer
                );
                continue;
            }
        };
        if let Err(error) = job.socket.send_to(&response, job.peer) {
            eprintln!("systemd-resolved: UDP reply failed: {error}");
        }
    }
}

fn tcp_listener(endpoint: &TcpEndpoint, resolver: &Arc<Resolver>) {
    while !stop_requested() {
        match endpoint.listener.accept() {
            Ok((stream, peer)) => {
                let resolver = Arc::clone(resolver);
                let mode = endpoint.mode;
                let _ = thread::Builder::new()
                    .name("resolved-tcp-client".to_owned())
                    .spawn(move || {
                        if let Err(error) = tcp_client(stream, &resolver, mode) {
                            eprintln!("systemd-resolved: TCP client {peer} failed: {error}");
                        }
                    });
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => {
                eprintln!("systemd-resolved: TCP accept failed: {error}");
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

fn tcp_client(mut stream: TcpStream, resolver: &Resolver, mode: QueryMode) -> io::Result<()> {
    stream.set_read_timeout(Some(resolver.config().query_timeout))?;
    stream.set_write_timeout(Some(resolver.config().query_timeout))?;
    for _ in 0..128 {
        let mut length = [0; 2];
        match stream.read_exact(&mut length) {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::BrokenPipe
                ) =>
            {
                return Ok(());
            }
            Err(error) => return Err(error),
        }
        let length = usize::from(u16::from_be_bytes(length));
        if length == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "zero-length DNS-over-TCP frame",
            ));
        }
        let mut query = vec![0; length];
        stream.read_exact(&mut query)?;
        let response = resolver
            .query_or_servfail(&query, mode)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let response_length = u16::try_from(response.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "DNS response is too large"))?;
        stream.write_all(&response_length.to_be_bytes())?;
        stream.write_all(&response)?;
    }
    Ok(())
}

fn watchdog_interval(
    watchdog_usec: Option<&str>,
    watchdog_pid: Option<&str>,
    current_pid: u32,
) -> Option<Duration> {
    if let Some(pid) = watchdog_pid {
        if pid.parse::<u32>().ok()? != current_pid {
            return None;
        }
    }
    let usec = watchdog_usec?.parse::<u64>().ok()?;
    if usec == 0 {
        return None;
    }
    Some(Duration::from_micros((usec / 2).max(1)))
}

fn join_all(threads: Vec<JoinHandle<()>>) {
    for thread in threads {
        let _ = thread.join();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_udp_job(socket: &Arc<UdpSocket>) -> UdpJob {
        UdpJob {
            socket: Arc::clone(socket),
            packet: vec![0; 12],
            peer: socket.local_addr().expect("test UDP address"),
            mode: QueryMode::Full,
        }
    }

    #[test]
    fn udp_dispatcher_spreads_jobs_across_worker_queues() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").expect("bind test UDP socket"));
        let (first_sender, first_receiver) = mpsc::sync_channel(1);
        let (second_sender, second_receiver) = mpsc::sync_channel(1);
        let dispatcher = UdpDispatcher::new(vec![first_sender, second_sender]);

        assert!(dispatcher.dispatch(test_udp_job(&socket)));
        assert!(dispatcher.dispatch(test_udp_job(&socket)));
        assert!(first_receiver.try_recv().is_ok());
        assert!(second_receiver.try_recv().is_ok());
    }

    #[test]
    fn udp_dispatcher_detects_when_all_workers_disconnect() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").expect("bind test UDP socket"));
        let (first_sender, first_receiver) = mpsc::sync_channel(1);
        let (second_sender, second_receiver) = mpsc::sync_channel(1);
        drop(first_receiver);
        drop(second_receiver);
        let dispatcher = UdpDispatcher::new(vec![first_sender, second_sender]);

        assert!(!dispatcher.dispatch(test_udp_job(&socket)));
    }

    #[test]
    fn watchdog_uses_half_the_configured_period() {
        assert_eq!(
            watchdog_interval(Some("1000000"), None, 42),
            Some(Duration::from_millis(500))
        );
        assert_eq!(
            watchdog_interval(Some("1000000"), Some("42"), 42),
            Some(Duration::from_millis(500))
        );
    }

    #[test]
    fn watchdog_rejects_invalid_or_foreign_configuration() {
        assert_eq!(watchdog_interval(None, None, 42), None);
        assert_eq!(watchdog_interval(Some("0"), None, 42), None);
        assert_eq!(watchdog_interval(Some("invalid"), None, 42), None);
        assert_eq!(watchdog_interval(Some("1000"), Some("invalid"), 42), None);
        assert_eq!(watchdog_interval(Some("1000"), Some("7"), 42), None);
    }

    #[test]
    fn watchdog_never_uses_a_zero_ping_interval() {
        assert_eq!(
            watchdog_interval(Some("1"), None, 42),
            Some(Duration::from_micros(1))
        );
    }
}
