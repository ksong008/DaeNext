use std::io::{self, ErrorKind};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::Ordering;

use dae_datapath::{
    TcpDirectDialOptions, TcpDirectDialReport, tcp_direct_connect_finish, tcp_direct_connect_start,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream as TokioTcpStream;
use tokio::time;

#[cfg(test)]
use super::ResidentStopSignal;
use super::{
    RESIDENT_CONNECT_TIMEOUT, RESIDENT_TCP_IDLE_TIMEOUT, ResidentDataplaneMetrics,
    SharedResidentStopSignal, reset_resident_relay_idle_deadline, resident_relay_idle_deadline,
    resolve_socket_addr_candidates, try_socket_addr_candidates,
};

#[derive(Debug)]
pub(super) struct DirectTcpConnection {
    pub(super) stream: TcpStream,
    pub(super) report: TcpDirectDialReport,
    pub(super) target: SocketAddr,
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
    let targets = resolve_direct_tcp_targets_async(&dial_target).await?;
    let opts = TcpDirectDialOptions {
        mark,
        mptcp,
        timeout: RESIDENT_CONNECT_TIMEOUT,
    };
    let (target, connected) = connect_direct_tcp_candidates_async(&targets, &opts, mptcp).await?;
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

async fn connect_direct_tcp_candidates_async(
    targets: &[SocketAddr],
    opts: &TcpDirectDialOptions,
    mptcp: bool,
) -> Result<(SocketAddr, dae_datapath::TcpDirectConnection), String> {
    try_socket_addr_candidates(targets, "connect direct TCP", |target| {
        connect_direct_tcp_candidate_async(target, opts, mptcp)
    })
    .await
}

async fn connect_direct_tcp_candidate_async(
    target: SocketAddr,
    opts: &TcpDirectDialOptions,
    mptcp: bool,
) -> Result<dae_datapath::TcpDirectConnection, String> {
    if !mptcp {
        return connect_direct_tcp_attempt_async(target, opts, false)
            .await
            .map_err(|err| err.to_string());
    }
    match connect_direct_tcp_attempt_async(target, opts, true).await {
        Ok(mut connected) => {
            connected.report.mptcp_tcp_retry_used = false;
            Ok(connected)
        }
        Err(mptcp_err) => match connect_direct_tcp_attempt_async(target, opts, false).await {
            Ok(mut connected) => {
                connected.report.mptcp_socket_attempted = true;
                connected.report.mptcp_tcp_retry_used = true;
                Ok(connected)
            }
            Err(tcp_err) => Err(format!(
                "MPTCP attempt failed ({mptcp_err}); TCP retry failed ({tcp_err})"
            )),
        },
    }
}

async fn connect_direct_tcp_attempt_async(
    target: SocketAddr,
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

async fn resolve_direct_tcp_targets_async(dial_target: &str) -> Result<Vec<SocketAddr>, String> {
    resolve_socket_addr_candidates(
        dial_target,
        RESIDENT_CONNECT_TIMEOUT,
        "resolve direct TCP target",
    )
    .await
}

pub(super) async fn relay_tcp_direct_async(
    inbound: &mut TokioTcpStream,
    direct: &mut TokioTcpStream,
    stop: SharedResidentStopSignal,
    initial_payload: Vec<u8>,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    let mut stats = DirectTcpRelayStats::default();
    if !initial_payload.is_empty() {
        direct
            .write_all(&initial_payload)
            .await
            .map_err(|err| format!("write sniffed client payload to direct TCP: {err}"))?;
        stats.client_to_direct += initial_payload.len();
        metrics.add_upload(initial_payload.len());
    }
    drop(initial_payload);

    let mut inbound_closed = false;
    let mut direct_closed = false;
    let mut inbound_buf = [0_u8; 16 * 1024];
    let mut direct_buf = [0_u8; 16 * 1024];
    let mut stop_listener = stop.listener();
    let idle_deadline = resident_relay_idle_deadline(RESIDENT_TCP_IDLE_TIMEOUT);
    tokio::pin!(idle_deadline);
    while !stop.load(Ordering::Relaxed) {
        tokio::select! {
            _ = stop_listener.cancelled() => break,
            read = inbound.read(&mut inbound_buf), if !inbound_closed && !direct_closed => {
                match read {
                    Ok(0) => {
                        inbound_closed = true;
                        let _ = direct.shutdown().await;
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                    }
                    Ok(read) => {
                        direct
                            .write_all(&inbound_buf[..read])
                            .await
                            .map_err(|err| format!("write client payload to direct TCP: {err}"))?;
                        stats.client_to_direct += read;
                        metrics.add_upload(read);
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                    }
                    Err(err) => return Err(format!("read inbound TCP for direct relay: {err}")),
                }
            }
            read = direct.read(&mut direct_buf), if !direct_closed => {
                match read {
                    Ok(0) => {
                        direct_closed = true;
                        let _ = inbound.shutdown().await;
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                    }
                    Ok(read) => {
                        inbound
                            .write_all(&direct_buf[..read])
                            .await
                            .map_err(|err| format!("write direct TCP payload to client: {err}"))?;
                        stats.direct_to_client += read;
                        metrics.add_download(read);
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                    }
                    Err(err) => return Err(format!("read direct TCP: {err}")),
                }
            }
            _ = &mut idle_deadline => {
                return Err("resident direct TCP relay idle timeout".to_owned());
            }
        }

        if direct_closed {
            break;
        }
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{IpAddr, TcpListener};
    use std::sync::{Arc, atomic::Ordering};
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

        assert_eq!(connection.target, SocketAddr::V4(addr));
        assert_eq!(connection.report.requested_mark, 0);
        assert!(!connection.report.requested_mptcp);
        assert!(connection.report.so_mark_applied);
        assert_eq!(connection.report.peer_addr, addr.to_string());
        drop(connection);
        let _ = listener.accept().unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn direct_tcp_falls_back_to_later_resolved_address() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let available = listener.local_addr().unwrap();
        let unavailable =
            SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), available.port());
        let opts = TcpDirectDialOptions {
            mark: 0,
            mptcp: false,
            timeout: Duration::from_secs(1),
        };

        let (selected, connection) =
            connect_direct_tcp_candidates_async(&[unavailable, available], &opts, false)
                .await
                .unwrap();

        assert_eq!(selected, available);
        drop(connection);
        let _ = listener.accept().unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn direct_tcp_flows_own_independent_streams() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut first, _) = listener.accept().unwrap();
            let (mut second, _) = listener.accept().unwrap();
            first
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            second
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();

            let mut first_label = [0_u8; 1];
            let mut second_label = [0_u8; 1];
            first.read_exact(&mut first_label).unwrap();
            second.read_exact(&mut second_label).unwrap();
            assert_eq!(first_label, *b"A");
            assert_eq!(second_label, *b"B");

            let mut eof = [0_u8; 1];
            assert_eq!(first.read(&mut eof).unwrap(), 0);
            second.write_all(b"still-open").unwrap();
            let mut acknowledgement = [0_u8; 5];
            second.read_exact(&mut acknowledgement).unwrap();
            assert_eq!(&acknowledgement, b"alive");
        });

        let mut first = open_direct_tcp_connection_async(address.to_string(), 0, false)
            .await
            .unwrap()
            .stream;
        let mut second = open_direct_tcp_connection_async(address.to_string(), 0, false)
            .await
            .unwrap()
            .stream;
        first.set_nonblocking(false).unwrap();
        second.set_nonblocking(false).unwrap();
        first.write_all(b"A").unwrap();
        second.write_all(b"B").unwrap();
        assert_ne!(first.local_addr().unwrap(), second.local_addr().unwrap());
        drop(first);

        second
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut still_open = [0_u8; 10];
        second.read_exact(&mut still_open).unwrap();
        assert_eq!(&still_open, b"still-open");
        second.write_all(b"alive").unwrap();
        drop(second);
        server.join().unwrap();
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
        let stop = ResidentStopSignal::shared();
        let metrics = ResidentDataplaneMetrics::default();
        let stats = relay_tcp_direct_async(
            &mut inbound,
            &mut direct,
            Arc::clone(&stop),
            b"HELLO".to_vec(),
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

    #[tokio::test(flavor = "current_thread")]
    async fn direct_tcp_relay_preserves_download_after_client_half_close() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_done = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).unwrap();
            assert_eq!(request, b"request");
            stream.write_all(b"response-after-eof").unwrap();
        });

        let inbound_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let inbound_addr = inbound_listener.local_addr().unwrap();
        let mut client = TcpStream::connect(inbound_addr).unwrap();
        let (inbound, _) = inbound_listener.accept().unwrap();
        let direct = TcpStream::connect(upstream_addr).unwrap();
        inbound.set_nonblocking(true).unwrap();
        direct.set_nonblocking(true).unwrap();
        client.write_all(b"request").unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();

        let mut inbound = TokioTcpStream::from_std(inbound).unwrap();
        let mut direct = TokioTcpStream::from_std(direct).unwrap();
        let metrics = ResidentDataplaneMetrics::default();
        let stats = relay_tcp_direct_async(
            &mut inbound,
            &mut direct,
            ResidentStopSignal::shared(),
            Vec::new(),
            &metrics,
        )
        .await
        .unwrap();
        assert_eq!(stats.client_to_direct, b"request".len());
        assert_eq!(stats.direct_to_client, b"response-after-eof".len());

        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert_eq!(response, b"response-after-eof");
        upstream_done.join().unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn resident_direct_async_relay_stops_without_timer_polling() {
        let inbound_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let inbound_client = TcpStream::connect(inbound_listener.local_addr().unwrap()).unwrap();
        let (inbound, _) = inbound_listener.accept().unwrap();
        let upstream_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let direct = TcpStream::connect(upstream_listener.local_addr().unwrap()).unwrap();
        let (upstream_peer, _) = upstream_listener.accept().unwrap();
        inbound.set_nonblocking(true).unwrap();
        direct.set_nonblocking(true).unwrap();
        let mut inbound = TokioTcpStream::from_std(inbound).unwrap();
        let mut direct = TokioTcpStream::from_std(direct).unwrap();
        let stop = ResidentStopSignal::shared();
        let metrics = ResidentDataplaneMetrics::default();
        let relay = relay_tcp_direct_async(
            &mut inbound,
            &mut direct,
            Arc::clone(&stop),
            Vec::new(),
            &metrics,
        );
        tokio::pin!(relay);

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut relay)
                .await
                .is_err()
        );
        stop.store(true, Ordering::Relaxed);
        let stats = tokio::time::timeout(Duration::from_millis(50), &mut relay)
            .await
            .expect("direct relay did not observe stop broadcast")
            .unwrap();
        assert_eq!(stats, DirectTcpRelayStats::default());
        drop((inbound_client, upstream_peer));
    }
}
