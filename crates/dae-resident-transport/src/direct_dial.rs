use std::io::{self, ErrorKind};
use std::net::{SocketAddr, TcpStream};

use dae_datapath::{
    TcpDirectDialOptions, TcpDirectDialReport, tcp_direct_connect_finish, tcp_direct_connect_start,
};
use dae_resident_core::{
    RESIDENT_CONNECT_TIMEOUT, RESIDENT_TCP_CANDIDATE_ATTEMPT_DELAY,
    RESIDENT_TCP_CANDIDATE_MAX_IN_FLIGHT,
};
use tokio::net::TcpStream as TokioTcpStream;
use tokio::time;

use crate::{
    TcpCandidateRacePolicy, resolve_socket_addr_candidates, try_tcp_socket_addr_candidates,
};

#[derive(Debug)]
pub struct DirectTcpConnection {
    pub stream: TcpStream,
    pub report: TcpDirectDialReport,
    pub target: SocketAddr,
}

pub async fn open_direct_tcp_connection_async(
    dial_target: String,
    mark: u32,
    mptcp: bool,
) -> Result<DirectTcpConnection, String> {
    let targets = resolve_direct_tcp_targets_async(&dial_target).await?;
    let options = TcpDirectDialOptions {
        mark,
        mptcp,
        timeout: RESIDENT_CONNECT_TIMEOUT,
    };
    let (target, connected) =
        connect_direct_tcp_candidates_async(&targets, &options, mptcp).await?;
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
    options: &TcpDirectDialOptions,
    mptcp: bool,
) -> Result<(SocketAddr, dae_datapath::TcpDirectConnection), String> {
    try_tcp_socket_addr_candidates(
        targets,
        "connect direct TCP",
        TcpCandidateRacePolicy::new(
            RESIDENT_TCP_CANDIDATE_ATTEMPT_DELAY,
            options.timeout,
            RESIDENT_TCP_CANDIDATE_MAX_IN_FLIGHT,
        ),
        |target| connect_direct_tcp_candidate_async(target, options, mptcp),
    )
    .await
    .map_err(|err| err.to_string())
}

async fn connect_direct_tcp_candidate_async(
    target: SocketAddr,
    options: &TcpDirectDialOptions,
    mptcp: bool,
) -> Result<dae_datapath::TcpDirectConnection, String> {
    if !mptcp {
        return connect_direct_tcp_attempt_async(target, options, false)
            .await
            .map_err(|err| err.to_string());
    }
    match connect_direct_tcp_attempt_async(target, options, true).await {
        Ok(mut connected) => {
            connected.report.mptcp_tcp_retry_used = false;
            Ok(connected)
        }
        Err(mptcp_err) => match connect_direct_tcp_attempt_async(target, options, false).await {
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
    options: &TcpDirectDialOptions,
    use_mptcp: bool,
) -> io::Result<dae_datapath::TcpDirectConnection> {
    let attempt = tcp_direct_connect_start(target, options, use_mptcp)?;
    let (stream, state) = attempt.into_parts();
    let stream = TokioTcpStream::from_std(stream)?;
    time::timeout(options.timeout, stream.writable())
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
    .map_err(|err| err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{IpAddr, TcpListener};
    use std::thread;
    use std::time::Duration;

    #[tokio::test(flavor = "current_thread")]
    async fn direct_dial_completes_connect_report() {
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
    async fn direct_dial_falls_back_to_later_resolved_address() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let available = listener.local_addr().unwrap();
        let unavailable =
            SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), available.port());
        let options = TcpDirectDialOptions {
            mark: 0,
            mptcp: false,
            timeout: Duration::from_secs(1),
        };

        let (selected, connection) =
            connect_direct_tcp_candidates_async(&[unavailable, available], &options, false)
                .await
                .unwrap();

        assert_eq!(selected, available);
        drop(connection);
        let _ = listener.accept().unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn direct_dial_flows_own_independent_streams() {
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
}
