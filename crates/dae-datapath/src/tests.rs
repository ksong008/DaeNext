use base64::Engine;
use serde_json::Value;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, TcpListener, UdpSocket};
use std::os::fd::AsRawFd;
use std::thread;
use std::time::Duration;

use crate::*;

fn expected_tcp_network_type(destination: SocketAddr) -> &'static str {
    if destination.is_ipv4() {
        "tcp4"
    } else {
        "tcp6"
    }
}

#[test]
fn magic_network_matches_golden_fixture() {
    let fixture = load("datapath/magic_network/mark_mptcp.json");
    for case in fixture["cases"].as_array().unwrap() {
        let got = magic_network_bytes(
            case["network"].as_str().unwrap(),
            case["mark"].as_u64().unwrap() as u32,
            case["mptcp"].as_bool().unwrap(),
        );
        let expected = base64::engine::general_purpose::STANDARD
            .decode(case["encoded_b64"].as_str().unwrap())
            .unwrap();
        assert_eq!(got, expected);
        assert_eq!(
            got == case["network"].as_str().unwrap().as_bytes(),
            case["is_plain"].as_bool().unwrap()
        );
        assert_eq!(got.len(), case["length"].as_u64().unwrap() as usize);
    }
}

#[test]
fn route_loop_matches_golden_fixture() {
    let fixture = load("datapath/route_loop/basic.json");
    for case in fixture["cases"].as_array().unwrap() {
        let rules = case["rules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|rule| RouteRule {
                kind: rule["type"].as_str().unwrap().to_owned(),
                outbound: rule["outbound"].as_u64().unwrap() as u8,
                mark: rule["mark"].as_u64().unwrap() as u32,
                must: rule["must"].as_bool().unwrap(),
                matched: rule["matched"].as_bool().unwrap(),
            })
            .collect::<Vec<_>>();
        let got = route_loop(&rules).unwrap();
        let expected = &case["expected"];
        assert_eq!(got.outbound, expected["outbound"].as_u64().unwrap() as u8);
        assert_eq!(got.mark, expected["mark"].as_u64().unwrap() as u32);
        assert_eq!(got.must, expected["must"].as_bool().unwrap());
        assert_eq!(got.fallback, expected["fallback"].as_bool().unwrap());
    }
}

#[test]
fn tcp_route_dial_domain_plus_plus_executes_userspace_reroute() {
    let destination: SocketAddr = "198.18.52.1:18082".parse().unwrap();
    let plan = route_dial_tcp_plan(&RouteDialTcpPlanInput {
        dial_mode: TcpDialMode::DomainPlusPlus,
        initial_outbound: OUTBOUND_USER_DEFINED_MIN,
        destination,
        domain: "127.0.0.1".to_owned(),
        domain_is_real: true,
        initial_mark: 0,
        so_mark_from_dae: 1234,
        mptcp: true,
        route_rules: vec![RouteRule {
            kind: "DomainSet".to_owned(),
            outbound: OUTBOUND_USER_DEFINED_MIN,
            mark: 4321,
            must: false,
            matched: true,
        }],
    });

    assert!(plan.first_choose.should_reroute);
    assert!(plan.userspace_route_executed);
    assert_eq!(plan.final_outbound, OUTBOUND_USER_DEFINED_MIN);
    assert_eq!(plan.final_mark, 4321);
    assert!(!plan.mark_defaulted_from_so_mark);
    assert_eq!(plan.final_dial_target, "127.0.0.1:18082");
    assert!(plan.strict_ip_version);
    assert_eq!(plan.network_type, expected_tcp_network_type(destination));
    assert!(plan.magic_network.starts_with(&[0, 3, b't']));
}

#[test]
fn tcp_route_dial_defaults_mark_after_reroute_zero_mark() {
    let destination: SocketAddr = "198.18.52.1:443".parse().unwrap();
    let plan = route_dial_tcp_plan(&RouteDialTcpPlanInput {
        dial_mode: TcpDialMode::DomainPlusPlus,
        initial_outbound: OUTBOUND_USER_DEFINED_MIN,
        destination,
        domain: "example.com".to_owned(),
        domain_is_real: true,
        initial_mark: 0,
        so_mark_from_dae: 1234,
        mptcp: false,
        route_rules: vec![RouteRule {
            kind: "Fallback".to_owned(),
            outbound: OUTBOUND_USER_DEFINED_MIN,
            mark: 0,
            must: false,
            matched: true,
        }],
    });

    assert!(plan.userspace_route_executed);
    assert_eq!(plan.final_mark, 1234);
    assert!(plan.mark_defaulted_from_so_mark);
    assert_eq!(plan.final_dial_target, "example.com:443");
    assert!(!plan.strict_ip_version);
    assert_eq!(
        plan.magic_network.as_slice(),
        &[0, 3, b't', b'c', b'p', 0, 0, 4, 210, 0]
    );
}

#[test]
fn choose_dial_target_preserves_reserved_outbound_ip_mode() {
    let destination: SocketAddr = "198.18.52.1:443".parse().unwrap();
    let decision = choose_dial_target(
        TcpDialMode::DomainPlus,
        OUTBOUND_DIRECT,
        destination,
        "example.com",
        true,
    );

    assert_eq!(decision.effective_mode, TcpDialMode::Ip);
    assert_eq!(decision.dial_target, "198.18.52.1:443");
    assert!(decision.dial_ip);
    assert!(!decision.should_reroute);
}

#[test]
fn choose_dial_target_uses_domain_for_unspecified_destination() {
    let destination: SocketAddr = "0.0.0.0:443".parse().unwrap();
    let decision = choose_dial_target(
        TcpDialMode::Ip,
        OUTBOUND_DIRECT,
        destination,
        "[2606:4700:20::681a:d1f]",
        false,
    );

    assert_eq!(decision.effective_mode, TcpDialMode::Domain);
    assert_eq!(decision.dial_target, "[2606:4700:20::681a:d1f]:443");
    assert!(decision.dial_ip);
}

#[test]
fn udp_and_sniffer_pool_constants_match_golden_fixture() {
    let fixture = load("datapath/udp_pools/basic.json");
    let endpoint = &fixture["udp_endpoint_pool"];
    assert_eq!(
        DEFAULT_UDP_ENDPOINT_POOL_MAX_ENTRIES,
        endpoint["default_max_entries"].as_i64().unwrap() as i32
    );
    assert_eq!(
        DEFAULT_NAT_TIMEOUT_MS,
        endpoint["default_nat_timeout_ms"].as_i64().unwrap()
    );
    assert_eq!(
        DNS_NAT_TIMEOUT_MS,
        endpoint["dns_nat_timeout_ms"].as_i64().unwrap()
    );
    assert_eq!(
        ANYFROM_TIMEOUT_MS,
        endpoint["anyfrom_timeout_ms"].as_i64().unwrap()
    );
    assert_eq!(MAX_RETRY, endpoint["max_retry"].as_i64().unwrap() as i32);

    for case in endpoint["normalize"].as_array().unwrap() {
        assert_eq!(
            normalize_udp_endpoint_pool_max_entries(case["input"].as_i64().unwrap() as i32),
            case["output"].as_i64().unwrap() as i32
        );
    }
    for case in endpoint["trim_target"].as_array().unwrap() {
        assert_eq!(
            udp_endpoint_pool_trim_target(case["max_entries"].as_i64().unwrap() as i32),
            case["target"].as_i64().unwrap() as i32
        );
    }

    let task = &fixture["udp_task_pool"];
    assert_eq!(
        UDP_TASK_QUEUE_LENGTH,
        task["queue_length"].as_u64().unwrap() as usize
    );
    assert_eq!(
        UDP_TASK_POOL_MAX_QUEUES,
        task["max_queues"].as_u64().unwrap() as usize
    );

    let sniffer = &fixture["packet_sniffer_pool"];
    assert_eq!(PACKET_SNIFFER_TTL_MS, sniffer["ttl_ms"].as_i64().unwrap());
    assert_eq!(
        PACKET_SNIFFER_POOL_MAX_ENTRIES,
        sniffer["max_entries"].as_u64().unwrap() as usize
    );
    assert!(packet_sniffer::packet_sniffer_expired(
        0,
        PACKET_SNIFFER_TTL_MS,
        PACKET_SNIFFER_TTL_MS
    ));
}

#[test]
fn udp_task_pool_model_preserves_fifo_and_drops_on_full_queue() {
    let mut pool = UdpTaskPoolModel::default();
    assert!(pool.emit_task("flow", 1));
    assert!(pool.emit_task("flow", 2));
    assert_eq!(pool.drain_key("flow"), vec![1, 2]);

    for task in 0..UDP_TASK_QUEUE_LENGTH {
        assert!(pool.emit_task("full", task as u64));
    }
    assert!(!pool.emit_task("full", 999));
    assert_eq!(pool.dropped(), 1);
}

#[test]
fn tcp_direct_connect_records_socket_contract() {
    let (listener, listener_report) = bind_loopback_tcp_listener(false).unwrap();
    assert!(!listener_report.requested_mptcp);
    assert_eq!(listener_report.socket_protocol, libc::IPPROTO_TCP);
    let default_keep_count = tcp_i32_option(&listener, libc::IPPROTO_TCP, libc::TCP_KEEPCNT);
    let default_user_timeout = tcp_i32_option(&listener, libc::IPPROTO_TCP, libc::TCP_USER_TIMEOUT);
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        let mut buf = [0_u8; 16];
        conn.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"fixture-dp-smoke");
        conn.write_all(b"fixture-dp-ack").unwrap();
    });

    let mut conn = magic_tcp_connect(
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)),
        &TcpDirectDialOptions {
            mark: 0,
            mptcp: false,
            timeout: Duration::from_secs(2),
        },
    )
    .unwrap();
    conn.stream.write_all(b"fixture-dp-smoke").unwrap();
    let mut ack = [0_u8; 14];
    conn.stream.read_exact(&mut ack).unwrap();
    assert_eq!(&ack, b"fixture-dp-ack");
    assert_eq!(conn.report.requested_mark, 0);
    assert!(!conn.report.requested_mptcp);
    assert_eq!(conn.report.socket_protocol, libc::IPPROTO_TCP);
    assert!(conn.report.so_mark_applied);
    assert_eq!(conn.report.peer_addr, format!("127.0.0.1:{port}"));
    assert_default_tcp_liveness_policy(&conn.stream, default_keep_count, default_user_timeout);
    handle.join().unwrap();
}

#[test]
fn tcp_direct_mptcp_attempt_and_tcp_fallback_preserve_liveness_policy() {
    let (listener, _) = bind_loopback_tcp_listener(false).unwrap();
    let default_keep_count = tcp_i32_option(&listener, libc::IPPROTO_TCP, libc::TCP_KEEPCNT);
    let default_user_timeout = tcp_i32_option(&listener, libc::IPPROTO_TCP, libc::TCP_USER_TIMEOUT);
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || listener.accept().unwrap());

    let conn = magic_tcp_connect(
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)),
        &TcpDirectDialOptions {
            mark: 0,
            mptcp: true,
            timeout: Duration::from_secs(2),
        },
    )
    .unwrap();

    assert!(conn.report.mptcp_socket_attempted);
    assert_default_tcp_liveness_policy(&conn.stream, default_keep_count, default_user_timeout);
    drop(conn);
    handle.join().unwrap();
}

#[test]
fn udp_direct_packet_conn_records_socket_contract() {
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    upstream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let upstream_addr = match upstream.local_addr().unwrap() {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(_) => panic!("unexpected IPv6 upstream"),
    };
    let handle = thread::spawn(move || {
        let mut buf = [0_u8; 64];
        let (read, peer) = upstream.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"fixture-udp-smoke");
        upstream.send_to(b"fixture-udp-ack", peer).unwrap();
    });

    let conn = UdpDirectPacketConn::connect(
        SocketAddr::V4(upstream_addr),
        &UdpDirectSocketOptions {
            mark: 0,
            timeout: Duration::from_secs(2),
        },
    )
    .unwrap();
    let written = conn
        .write_to(b"fixture-udp-smoke", SocketAddr::V4(upstream_addr))
        .unwrap();
    assert_eq!(written, b"fixture-udp-smoke".len());
    let (ack, peer) = conn.read_from(b"fixture-udp-ack".len()).unwrap();
    assert_eq!(ack, b"fixture-udp-ack");
    assert_eq!(peer, SocketAddr::V4(upstream_addr));
    assert_eq!(conn.report().requested_mark, 0);
    assert!(conn.report().so_mark_applied);
    assert_eq!(conn.report().peer_addr, upstream_addr.to_string());
    handle.join().unwrap();
}

#[test]
fn tcp_direct_connect_supports_ipv6_loopback_when_available() {
    let listener = match TcpListener::bind((Ipv6Addr::LOCALHOST, 0)) {
        Ok(listener) => listener,
        Err(_) => return,
    };
    let default_keep_count = tcp_i32_option(&listener, libc::IPPROTO_TCP, libc::TCP_KEEPCNT);
    let default_user_timeout = tcp_i32_option(&listener, libc::IPPROTO_TCP, libc::TCP_USER_TIMEOUT);
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        let mut buf = [0_u8; 16];
        conn.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"fixture-ipv6-tcp");
        conn.write_all(b"fixture-ipv6-ok").unwrap();
    });

    let mut conn = magic_tcp_connect(
        SocketAddr::new(Ipv6Addr::LOCALHOST.into(), port),
        &TcpDirectDialOptions {
            mark: 0,
            mptcp: false,
            timeout: Duration::from_secs(2),
        },
    )
    .unwrap();
    conn.stream.write_all(b"fixture-ipv6-tcp").unwrap();
    let mut ack = [0_u8; 15];
    conn.stream.read_exact(&mut ack).unwrap();
    assert_eq!(&ack, b"fixture-ipv6-ok");
    assert_eq!(conn.report.peer_addr, format!("[::1]:{port}"));
    assert_default_tcp_liveness_policy(&conn.stream, default_keep_count, default_user_timeout);
    handle.join().unwrap();
}

#[test]
fn udp_direct_packet_conn_supports_ipv6_loopback_when_available() {
    let upstream = match UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)) {
        Ok(socket) => socket,
        Err(_) => return,
    };
    upstream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let mut buf = [0_u8; 64];
        let (read, peer) = upstream.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..read], b"fixture-ipv6-udp");
        upstream.send_to(b"fixture-ipv6-ok", peer).unwrap();
    });

    let conn = UdpDirectPacketConn::connect(
        upstream_addr,
        &UdpDirectSocketOptions {
            mark: 0,
            timeout: Duration::from_secs(2),
        },
    )
    .unwrap();
    let written = conn.write_to(b"fixture-ipv6-udp", upstream_addr).unwrap();
    assert_eq!(written, b"fixture-ipv6-udp".len());
    let (ack, peer) = conn.read_from(b"fixture-ipv6-ok".len()).unwrap();
    assert_eq!(ack, b"fixture-ipv6-ok");
    assert_eq!(peer, upstream_addr);
    assert_eq!(conn.report().peer_addr, upstream_addr.to_string());
    handle.join().unwrap();
}

fn load(path: &str) -> Value {
    dae_golden::load_json(path).unwrap()
}

fn tcp_i32_option(socket: &impl AsRawFd, level: i32, option: i32) -> i32 {
    let mut value = 0_i32;
    let mut len = std::mem::size_of::<i32>() as libc::socklen_t;
    let status = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            level,
            option,
            (&mut value as *mut i32).cast::<libc::c_void>(),
            &mut len as *mut libc::socklen_t,
        )
    };
    assert_eq!(status, 0, "getsockopt({option}) failed");
    value
}

fn assert_default_tcp_liveness_policy(
    stream: &impl AsRawFd,
    default_keep_count: i32,
    default_user_timeout: i32,
) {
    assert_eq!(
        tcp_i32_option(stream, libc::SOL_SOCKET, libc::SO_KEEPALIVE),
        1
    );
    assert_eq!(
        tcp_i32_option(stream, libc::IPPROTO_TCP, libc::TCP_KEEPIDLE),
        crate::tcp_liveness::DEFAULT_TCP_LIVENESS_POLICY.keepalive_idle_seconds()
    );
    assert_eq!(
        tcp_i32_option(stream, libc::IPPROTO_TCP, libc::TCP_KEEPINTVL),
        crate::tcp_liveness::DEFAULT_TCP_LIVENESS_POLICY.keepalive_interval_seconds()
    );
    assert_eq!(
        tcp_i32_option(stream, libc::IPPROTO_TCP, libc::TCP_KEEPCNT),
        default_keep_count,
        "TCP_KEEPCNT must remain at the kernel default"
    );
    assert_eq!(
        tcp_i32_option(stream, libc::IPPROTO_TCP, libc::TCP_USER_TIMEOUT),
        default_user_timeout,
        "TCP_USER_TIMEOUT must remain at the kernel default"
    );
}
