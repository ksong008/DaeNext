use std::io::{ErrorKind, Read};
use std::net::{Shutdown, SocketAddr, SocketAddrV4, TcpStream, ToSocketAddrs};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

use dae_datapath::{TcpDirectDialOptions, TcpDirectDialReport, magic_tcp_connect};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream as TokioTcpStream;
use tokio::time;

use super::io::write_all_nonblocking;
use super::{
    RESIDENT_CONNECT_TIMEOUT, RESIDENT_IDLE_SLEEP, RESIDENT_TCP_IDLE_TIMEOUT,
    ResidentDataplaneMetrics,
};

#[derive(Debug)]
pub(super) struct DirectTcpConnection {
    pub(super) stream: TcpStream,
    pub(super) report: TcpDirectDialReport,
    pub(super) target: SocketAddrV4,
}

#[derive(Default, Debug, Eq, PartialEq)]
pub(super) struct DirectTcpRelayStats {
    pub(super) client_to_direct: usize,
    pub(super) direct_to_client: usize,
}

pub(super) fn open_direct_tcp_connection(
    dial_target: &str,
    mark: u32,
    mptcp: bool,
) -> Result<DirectTcpConnection, String> {
    let target = resolve_direct_tcp_target(dial_target)?;
    let connected = magic_tcp_connect(
        target,
        &TcpDirectDialOptions {
            mark,
            mptcp,
            timeout: RESIDENT_CONNECT_TIMEOUT,
        },
    )
    .map_err(|err| format!("connect direct TCP {target}: {err}"))?;
    connected
        .stream
        .set_nonblocking(true)
        .map_err(|err| format!("set direct TCP nonblocking: {err}"))?;
    connected
        .stream
        .set_nodelay(true)
        .map_err(|err| format!("set direct TCP_NODELAY: {err}"))?;
    Ok(DirectTcpConnection {
        stream: connected.stream,
        report: connected.report,
        target,
    })
}

pub(super) async fn open_direct_tcp_connection_async(
    dial_target: String,
    mark: u32,
    mptcp: bool,
) -> Result<DirectTcpConnection, String> {
    tokio::task::spawn_blocking(move || open_direct_tcp_connection(&dial_target, mark, mptcp))
        .await
        .map_err(|err| format!("join direct TCP connect task: {err}"))?
}

fn resolve_direct_tcp_target(dial_target: &str) -> Result<SocketAddrV4, String> {
    if let Ok(SocketAddr::V4(addr)) = dial_target.parse::<SocketAddr>() {
        return Ok(addr);
    }
    dial_target
        .to_socket_addrs()
        .map_err(|err| format!("resolve direct TCP target {dial_target}: {err}"))?
        .find_map(|addr| match addr {
            SocketAddr::V4(addr) => Some(addr),
            SocketAddr::V6(_) => None,
        })
        .ok_or_else(|| format!("resolve direct TCP target {dial_target} returned no IPv4 address"))
}

pub(super) fn relay_tcp_direct(
    inbound: &mut TcpStream,
    direct: &mut TcpStream,
    stop: &AtomicBool,
    initial_payload: &[u8],
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    let mut stats = DirectTcpRelayStats::default();
    if !initial_payload.is_empty() {
        write_all_nonblocking(
            direct,
            initial_payload,
            stop,
            "write sniffed client payload to direct TCP",
        )?;
        stats.client_to_direct += initial_payload.len();
        metrics.add_upload(initial_payload.len());
    }

    let mut inbound_closed = false;
    let mut direct_closed = false;
    let mut last_activity = Instant::now();
    let mut inbound_buf = [0_u8; 16 * 1024];
    let mut direct_buf = [0_u8; 16 * 1024];
    while !stop.load(Ordering::Relaxed) {
        let mut progressed = false;
        if !inbound_closed && !direct_closed {
            match inbound.read(&mut inbound_buf) {
                Ok(0) => {
                    inbound_closed = true;
                    let _ = direct.shutdown(Shutdown::Write);
                    progressed = true;
                }
                Ok(read) => {
                    write_all_nonblocking(
                        direct,
                        &inbound_buf[..read],
                        stop,
                        "write client payload to direct TCP",
                    )?;
                    stats.client_to_direct += read;
                    metrics.add_upload(read);
                    progressed = true;
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                    ) => {}
                Err(err) => return Err(format!("read inbound TCP for direct relay: {err}")),
            }
        }

        if !direct_closed {
            match direct.read(&mut direct_buf) {
                Ok(0) => {
                    direct_closed = true;
                    let _ = inbound.shutdown(Shutdown::Write);
                    progressed = true;
                }
                Ok(read) => {
                    write_all_nonblocking(
                        inbound,
                        &direct_buf[..read],
                        stop,
                        "write direct TCP payload to client",
                    )?;
                    stats.direct_to_client += read;
                    metrics.add_download(read);
                    progressed = true;
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                    ) => {}
                Err(err) => return Err(format!("read direct TCP: {err}")),
            }
        }

        if direct_closed || (inbound_closed && direct_closed) {
            break;
        }
        if progressed {
            last_activity = Instant::now();
        } else if last_activity.elapsed() > RESIDENT_TCP_IDLE_TIMEOUT {
            return Err("resident direct TCP relay idle timeout".to_owned());
        } else {
            thread::sleep(RESIDENT_IDLE_SLEEP);
        }
    }
    Ok(stats)
}

pub(super) async fn relay_tcp_direct_async(
    inbound: &mut TokioTcpStream,
    direct: &mut TokioTcpStream,
    stop: Arc<AtomicBool>,
    initial_payload: &[u8],
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    let mut stats = DirectTcpRelayStats::default();
    if !initial_payload.is_empty() {
        direct
            .write_all(initial_payload)
            .await
            .map_err(|err| format!("write sniffed client payload to direct TCP: {err}"))?;
        stats.client_to_direct += initial_payload.len();
        metrics.add_upload(initial_payload.len());
    }

    let mut inbound_closed = false;
    let mut direct_closed = false;
    let mut last_activity = Instant::now();
    let mut inbound_buf = [0_u8; 16 * 1024];
    let mut direct_buf = [0_u8; 16 * 1024];
    while !stop.load(Ordering::Relaxed) {
        tokio::select! {
            read = inbound.read(&mut inbound_buf), if !inbound_closed && !direct_closed => {
                match read {
                    Ok(0) => {
                        inbound_closed = true;
                        let _ = direct.shutdown().await;
                        last_activity = Instant::now();
                    }
                    Ok(read) => {
                        direct
                            .write_all(&inbound_buf[..read])
                            .await
                            .map_err(|err| format!("write client payload to direct TCP: {err}"))?;
                        stats.client_to_direct += read;
                        metrics.add_upload(read);
                        last_activity = Instant::now();
                    }
                    Err(err) => return Err(format!("read inbound TCP for direct relay: {err}")),
                }
            }
            read = direct.read(&mut direct_buf), if !direct_closed => {
                match read {
                    Ok(0) => {
                        direct_closed = true;
                        let _ = inbound.shutdown().await;
                        last_activity = Instant::now();
                    }
                    Ok(read) => {
                        inbound
                            .write_all(&direct_buf[..read])
                            .await
                            .map_err(|err| format!("write direct TCP payload to client: {err}"))?;
                        stats.direct_to_client += read;
                        metrics.add_download(read);
                        last_activity = Instant::now();
                    }
                    Err(err) => return Err(format!("read direct TCP: {err}")),
                }
            }
            _ = time::sleep(Duration::from_millis(100)) => {
                if last_activity.elapsed() > RESIDENT_TCP_IDLE_TIMEOUT {
                    return Err("resident direct TCP relay idle timeout".to_owned());
                }
            }
        }

        if direct_closed || (inbound_closed && direct_closed) {
            break;
        }
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use std::time::Duration;

    #[test]
    fn resident_direct_target_accepts_ipv4_socket_addr() {
        let target = resolve_direct_tcp_target("127.0.0.1:443").unwrap();
        assert_eq!(target, SocketAddrV4::new("127.0.0.1".parse().unwrap(), 443));
    }

    #[test]
    fn resident_direct_relay_preserves_sniffed_initial_payload() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_done = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut got = [0_u8; 5];
            stream.read_exact(&mut got).unwrap();
            assert_eq!(&got, b"HELLO");
            stream.write_all(b"WORLD").unwrap();
        });

        let inbound_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let inbound_addr = inbound_listener.local_addr().unwrap();
        let client = TcpStream::connect(inbound_addr).unwrap();
        let (mut inbound, _) = inbound_listener.accept().unwrap();
        let mut direct = TcpStream::connect(upstream_addr).unwrap();
        inbound.set_nonblocking(true).unwrap();
        direct.set_nonblocking(true).unwrap();

        let stop = AtomicBool::new(false);
        let metrics = ResidentDataplaneMetrics::default();
        let stats = relay_tcp_direct(&mut inbound, &mut direct, &stop, b"HELLO", &metrics).unwrap();
        assert_eq!(stats.client_to_direct, 5);
        assert_eq!(stats.direct_to_client, 5);

        let mut client = client;
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut response = [0_u8; 5];
        client.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"WORLD");
        stop.store(true, Ordering::Relaxed);
        upstream_done.join().unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn resident_direct_async_relay_preserves_sniffed_initial_payload() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_done = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut got = [0_u8; 5];
            stream.read_exact(&mut got).unwrap();
            assert_eq!(&got, b"HELLO");
            stream.write_all(b"WORLD").unwrap();
        });

        let inbound_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let inbound_addr = inbound_listener.local_addr().unwrap();
        let client = TcpStream::connect(inbound_addr).unwrap();
        let (inbound, _) = inbound_listener.accept().unwrap();
        let direct = TcpStream::connect(upstream_addr).unwrap();
        inbound.set_nonblocking(true).unwrap();
        direct.set_nonblocking(true).unwrap();

        let mut inbound = TokioTcpStream::from_std(inbound).unwrap();
        let mut direct = TokioTcpStream::from_std(direct).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let metrics = ResidentDataplaneMetrics::default();
        let stats = relay_tcp_direct_async(
            &mut inbound,
            &mut direct,
            Arc::clone(&stop),
            b"HELLO",
            &metrics,
        )
        .await
        .unwrap();
        assert_eq!(stats.client_to_direct, 5);
        assert_eq!(stats.direct_to_client, 5);

        let mut client = client;
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut response = [0_u8; 5];
        client.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"WORLD");
        stop.store(true, Ordering::Relaxed);
        upstream_done.join().unwrap();
    }

    #[test]
    fn resident_direct_relay_can_stop_when_requested() {
        let inbound_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let inbound_addr = inbound_listener.local_addr().unwrap();
        let _client = TcpStream::connect(inbound_addr).unwrap();
        let (mut inbound, _) = inbound_listener.accept().unwrap();

        let direct_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let direct_addr = direct_listener.local_addr().unwrap();
        let mut direct_client = TcpStream::connect(direct_addr).unwrap();
        let (_direct_server, _) = direct_listener.accept().unwrap();

        inbound.set_nonblocking(true).unwrap();
        direct_client.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        stop.store(true, Ordering::Relaxed);
        let metrics = ResidentDataplaneMetrics::default();
        let stats =
            relay_tcp_direct(&mut inbound, &mut direct_client, &stop, b"", &metrics).unwrap();
        assert_eq!(stats, DirectTcpRelayStats::default());
    }
}
