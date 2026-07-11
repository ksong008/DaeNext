use super::*;
use crate::production_runtime_owner::resident_dataplane::plan::ResidentXhttpSettingsPlan;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn proxy_plan(handler: ResidentProxyProtocolPlan) -> ResidentProxyPlan {
    ResidentProxyPlan {
        graph_id: "resident-graph:redacted".to_owned(),
        graph_link_hash: "sha256:redacted".to_owned(),
        redacted_link_source: "source:<redacted>".to_owned(),
        protocol: "redacted".to_owned(),
        group_name: "proxy".to_owned(),
        group_policy: "fixed".to_owned(),
        node_tag: "redacted".to_owned(),
        server_host: String::new(),
        server_port: 0,
        server_name: String::new(),
        alpn: Vec::new(),
        flow: String::new(),
        net: "tcp".to_owned(),
        stream_host: String::new(),
        stream_path: String::new(),
        xhttp_download: None,
        xhttp_mode: ResidentXhttpMode::PacketUp,
        xhttp_settings: ResidentXhttpSettingsPlan::official_default(),
        xhttp_xmux: None,
        tls: "none".to_owned(),
        allow_insecure: false,
        tls_fragment: None,
        utls_fingerprint: None,
        reality: None,
        handler,
        chain_parent: None,
        mark: 0,
        mptcp: false,
    }
}

async fn read_socks5_target(stream: &mut TcpStream) -> SocketAddr {
    let mut greeting = [0_u8; 3];
    stream.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 1, 0]);
    stream.write_all(&[5, 0]).await.unwrap();

    let mut head = [0_u8; 4];
    stream.read_exact(&mut head).await.unwrap();
    assert_eq!(&head[..3], &[5, 1, 0]);
    let ip = match head[3] {
        1 => {
            let mut octets = [0_u8; 4];
            stream.read_exact(&mut octets).await.unwrap();
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        4 => {
            let mut octets = [0_u8; 16];
            stream.read_exact(&mut octets).await.unwrap();
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        atyp => panic!("unexpected SOCKS5 target address type {atyp}"),
    };
    let mut port = [0_u8; 2];
    stream.read_exact(&mut port).await.unwrap();
    SocketAddr::new(ip, u16::from_be_bytes(port))
}

async fn run_chained_packet_case(original_dst: SocketAddr) {
    let child_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let child_addr = child_listener.local_addr().unwrap();
    let parent_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let parent_addr = parent_listener.local_addr().unwrap();
    let parent_seen = Arc::new(AtomicBool::new(false));
    let child_seen = Arc::new(AtomicBool::new(false));

    let child_seen_task = Arc::clone(&child_seen);
    let child_task = tokio::spawn(async move {
        let (mut stream, _) = child_listener.accept().await.unwrap();
        let mut first_write = [0_u8; 4096];
        let read = stream.read(&mut first_write).await.unwrap();
        assert!(read > 0, "VMess child received an empty first write");
        child_seen_task.store(true, Ordering::Release);
    });

    let parent_seen_task = Arc::clone(&parent_seen);
    let parent_task = tokio::spawn(async move {
        let (mut inbound, _) = parent_listener.accept().await.unwrap();
        parent_seen_task.store(true, Ordering::Release);
        let requested_target = read_socks5_target(&mut inbound).await;
        assert_eq!(requested_target, child_addr);
        let mut outbound = TcpStream::connect(requested_target).await.unwrap();
        inbound
            .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        tokio::io::copy_bidirectional(&mut inbound, &mut outbound)
            .await
            .unwrap();
    });

    let mut proxy = proxy_plan(ResidentProxyProtocolPlan::VmessAeadTcp {
        id: "00000000-0000-0000-0000-000000000001".to_owned(),
    });
    proxy.protocol = "vmess".to_owned();
    proxy.tls = "none".to_owned();
    proxy.server_host = child_addr.ip().to_string();
    proxy.server_port = child_addr.port();
    let mut parent = proxy_plan(ResidentProxyProtocolPlan::Socks5Tcp {
        username: String::new(),
        password: String::new(),
    });
    parent.protocol = "socks5".to_owned();
    parent.tls = "none".to_owned();
    parent.server_host = parent_addr.ip().to_string();
    parent.server_port = parent_addr.port();
    proxy.chain_parent = Some(Arc::new(parent));

    let mut executor = UdpSessionExecutor::new_proxy_packet(&proxy);
    let (_, result) = tokio::time::timeout(
        Duration::from_secs(2),
        executor.execute_proxy_packet(&proxy, original_dst, b"packet"),
    )
    .await
    .expect("chained UDP execution timed out")
    .expect("chained UDP execution failed");
    assert!(!result.reply_forwarded);
    executor.shutdown().await;

    child_task.await.unwrap();
    parent_task.await.unwrap();
    assert!(parent_seen.load(Ordering::Acquire));
    assert!(child_seen.load(Ordering::Acquire));
}

#[test]
fn vmess_chained_udp_carries_common_packet_shapes_over_both_hops() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        for target in [
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3478),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443),
        ] {
            run_chained_packet_case(target).await;
        }
    });
}
