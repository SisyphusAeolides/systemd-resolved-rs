// SPDX-License-Identifier: LGPL-2.1-or-later
use crate::native;
use crate::resolver::{QueryMode, Resolver};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const MAX_UDP_PACKET: usize = 65_535;
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

pub fn request_stop() {
    LOCAL_STOP.store(true, Ordering::SeqCst);
}

pub fn stop_requested() -> bool {
    LOCAL_STOP.load(Ordering::SeqCst) || native::stop_requested()
}

pub fn install_signal_handlers() -> io::Result<()> {
    native::install_signal_handlers()
}

pub fn run_stub(resolver: Arc<Resolver>) -> io::Result<()> {
    let mut udp_endpoints = Vec::new();
    let mut tcp_endpoints = Vec::new();
    bind_endpoints(
        &resolver.config().listeners,
        QueryMode::Full,
        &mut udp_endpoints,
        &mut tcp_endpoints,
    )?;
    bind_endpoints(
        &resolver.config().proxy_listeners,
        QueryMode::Proxy,
        &mut udp_endpoints,
        &mut tcp_endpoints,
    )?;

    let workers = resolver.config().workers;
    let (sender, receiver) = mpsc::sync_channel::<UdpJob>(workers.saturating_mul(256).max(256));
    let receiver = Arc::new(Mutex::new(receiver));
    let mut threads = Vec::new();

    for index in 0..workers {
        let resolver = Arc::clone(&resolver);
        let receiver = Arc::clone(&receiver);
        threads.push(
            thread::Builder::new()
                .name(format!("resolved-udp-worker-{index}"))
                .spawn(move || udp_worker(resolver, receiver))?,
        );
    }
    for (index, endpoint) in udp_endpoints.into_iter().enumerate() {
        let sender = sender.clone();
        threads.push(
            thread::Builder::new()
                .name(format!("resolved-udp-listener-{index}"))
                .spawn(move || udp_listener(endpoint, sender))?,
        );
    }
    for (index, endpoint) in tcp_endpoints.into_iter().enumerate() {
        let resolver = Arc::clone(&resolver);
        threads.push(
            thread::Builder::new()
                .name(format!("resolved-tcp-listener-{index}"))
                .spawn(move || tcp_listener(endpoint, resolver))?,
        );
    }

    let _ = native::notify("READY=1\nSTATUS=Processing requests");
    while !stop_requested() {
        if native::take_reload() {
            let _ = native::notify("RELOADING=1\nSTATUS=Reloading hosts database");
            if let Err(error) = resolver.reload_hosts() {
                eprintln!("systemd-resolved: failed to reload hosts database: {error}");
            }
            let _ = native::notify("READY=1\nSTATUS=Processing requests");
        }
        thread::sleep(Duration::from_millis(200));
    }
    let _ = native::notify("STOPPING=1\nSTATUS=Shutting down");
    drop(sender);
    join_all(threads);
    Ok(())
}

fn bind_endpoints(
    addresses: &[SocketAddr],
    mode: QueryMode,
    udp_endpoints: &mut Vec<UdpEndpoint>,
    tcp_endpoints: &mut Vec<TcpEndpoint>,
) -> io::Result<()> {
    for &address in addresses {
        let udp = UdpSocket::bind(address)?;
        udp.set_read_timeout(Some(Duration::from_millis(250)))?;
        udp_endpoints.push(UdpEndpoint {
            socket: Arc::new(udp),
            mode,
        });

        let tcp = TcpListener::bind(address)?;
        tcp.set_nonblocking(true)?;
        tcp_endpoints.push(TcpEndpoint {
            listener: tcp,
            mode,
        });
    }
    Ok(())
}

fn udp_listener(endpoint: UdpEndpoint, sender: SyncSender<UdpJob>) {
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
                match sender.try_send(job) {
                    Ok(()) | Err(TrySendError::Full(_)) => {}
                    Err(TrySendError::Disconnected(_)) => break,
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

fn udp_worker(resolver: Arc<Resolver>, receiver: Arc<Mutex<Receiver<UdpJob>>>) {
    while !stop_requested() {
        let result = receiver
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .recv_timeout(Duration::from_millis(250));
        let job = match result {
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

fn tcp_listener(endpoint: TcpEndpoint, resolver: Arc<Resolver>) {
    while !stop_requested() {
        match endpoint.listener.accept() {
            Ok((stream, peer)) => {
                let resolver = Arc::clone(&resolver);
                let mode = endpoint.mode;
                let _ = thread::Builder::new()
                    .name("resolved-tcp-client".to_owned())
                    .spawn(move || {
                        if let Err(error) = tcp_client(stream, resolver, mode) {
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

fn tcp_client(mut stream: TcpStream, resolver: Arc<Resolver>, mode: QueryMode) -> io::Result<()> {
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

fn join_all(threads: Vec<JoinHandle<()>>) {
    for thread in threads {
        let _ = thread.join();
    }
}
