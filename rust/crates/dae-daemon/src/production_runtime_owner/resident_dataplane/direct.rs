use std::io::{self, ErrorKind};
use std::net::{SocketAddr, SocketAddrV4, TcpStream};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use dae_datapath::{
    TcpDirectDialOptions, TcpDirectDialReport, tcp_direct_connect_finish, tcp_direct_connect_start,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream as TokioTcpStream, lookup_host};
use tokio::time;

use super::{RESIDENT_CONNECT_TIMEOUT, RESIDENT_TCP_IDLE_TIMEOUT, ResidentDataplaneMetrics};

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

pub(super) async fn open_direct_tcp_connection_async(
    dial_target: String,
    mark: u32,
    mptcp: bool,
) -> Result<DirectTcpConnection, String> {
    let target = resolve_direct_tcp_target_async(&dial_target).await?;
    let opts = TcpDirectDialOptions {
        mark,
        mptcp,
        timeout: RESIDENT_CONNECT_TIMEOUT,
    };
    let connected = if mptcp {
        match connect_direct_tcp_attempt_async(target, &opts, true).await {
            Ok(mut connected) => {
                connected.report.mptcp_connect_fallback_used = false;
                Ok(connected)
            }
            Err(first_err) => match connect_direct_tcp_attempt_async(target, &opts, false).await {
                Ok(mut connected) => {
                    connected.report.mptcp_socket_attempted = true;
                    connected.report.mptcp_connect_fallback_used = true;
                    Ok(connected)
                }
                Err(_) => Err(first_err),
            },
        }
    } else {
        connect_direct_tcp_attempt_async(target, &opts, false).await
    }
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

async fn connect_direct_tcp_attempt_async(
    target: SocketAddrV4,
    opts: &TcpDirectDialOptions,
    use_mptcp: bool,
) -> io::Result<dae_datapath::TcpDirectConnection> {
    let attempt = tcp_direct_connect_start(target, opts, use_mptcp)?;
    let (stream, state) = attempt.into_parts();
    let stream = TokioTcpStream::from_std(stream)?;
    time::timeout(opts.timeout, stream.writable())
        .await
        .map_err(|_| io::Error::new(ErrorKind::TimedOut, "direct TCP connect timeout"))??;
    let stream = stream.into_std()?;
    tcp_direct_connect_finish(stream, state)
}

async fn resolve_direct_tcp_target_async(dial_target: &str) -> Result<SocketAddrV4, String> {
    if let Ok(SocketAddr::V4(addr)) = dial_target.parse::<SocketAddr>() {
        return Ok(addr);
    }
    lookup_host(dial_target)
        .await
        .map_err(|err| format!("resolve direct TCP target {dial_target}: {err}"))?
        .find_map(|addr| match addr {
            SocketAddr::V4(addr) => Some(addr),
            SocketAddr::V6(_) => None,
        })
        .ok_or_else(|| format!("resolve direct TCP target {dial_target} returned no IPv4 address"))
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
    use std::thread;
    use std::time::Duration;

    #[tokio::test(flavor = "current_thread")]
    async fn resident_direct_async_dial_completes_magic_connect_report() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = match listener.local_addr().unwrap() {
            SocketAddr::V4(addr) => addr,
            SocketAddr::V6(addr) => panic!("test listener unexpectedly bound IPv6 address {addr}"),
        };
        let connection = open_direct_tcp_connection_async(addr.to_string(), 0, false)
            .await
            .unwrap();

        assert_eq!(connection.target, addr);
        assert_eq!(connection.report.requested_mark, 0);
        assert!(!connection.report.requested_mptcp);
        assert!(connection.report.so_mark_applied);
        assert_eq!(connection.report.peer_addr, addr.to_string());
        drop(connection);
        let _ = listener.accept().unwrap();
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
}
