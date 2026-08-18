use super::*;
use dae_resident_plan::{ResidentXhttpMode, ResidentXhttpSettingsPlan};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
use tokio::net::TcpListener;

fn proxy_plan(server: SocketAddr, handler: ResidentProxyProtocolPlan) -> ResidentProxyPlan {
    ResidentProxyPlan {
        graph_id: "graph".to_owned(),
        graph_link_hash: "hash".to_owned(),
        redacted_link_source: "source".to_owned(),
        protocol: "test",
        group_name: "group".to_owned(),
        group_policy: "fixed".to_owned(),
        node_tag: "node".to_owned(),
        server_host: server.ip().to_string(),
        server_port: server.port(),
        server_name: String::new(),
        alpn: Vec::new(),
        flow: String::new(),
        net: "tcp".to_owned(),
        stream_host: String::new(),
        stream_path: String::new(),
        grpc_mode: dae_outbound::shared_transport::GrpcMode::Gun,
        xhttp_download: None,
        xhttp_mode: ResidentXhttpMode::PacketUp,
        xhttp_settings: ResidentXhttpSettingsPlan::official_default(),
        xhttp_xmux: None,
        tls: "none".to_owned(),
        allow_insecure: false,
        tls_fragment: None,
        utls_fingerprint: None,
        ech: None,
        reality: None,
        handler,
        execution: None,
        chain_parent: None,
        mark: 0,
        mptcp: false,
    }
}

fn chained_proxy(child: SocketAddr, parent: SocketAddr) -> ResidentProxyPlan {
    let mut child = proxy_plan(
        child,
        ResidentProxyProtocolPlan::VmessAeadTcp {
            id: "00000000-0000-0000-0000-000000000001".to_owned(),
            body_security: dae_outbound::vmess::VMessBodySecurity::Aes128Gcm,
        },
    );
    child.chain_parent = Some(Arc::new(proxy_plan(
        parent,
        ResidentProxyProtocolPlan::Socks5Tcp {
            username: String::new(),
            password: String::new(),
        },
    )));
    child
}

async fn read_socks5_target(stream: &mut TokioTcpStream) -> SocketAddr {
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

async fn assert_parent_transport_reaches_child(child_ip: IpAddr) {
    let child_listener = TcpListener::bind(SocketAddr::new(child_ip, 0))
        .await
        .unwrap();
    let child_addr = child_listener.local_addr().unwrap();
    let parent_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let parent_addr = parent_listener.local_addr().unwrap();
    let parent_seen = Arc::new(AtomicBool::new(false));
    let child_seen = Arc::new(AtomicBool::new(false));

    let child_seen_task = Arc::clone(&child_seen);
    let child_task = tokio::spawn(async move {
        let (mut stream, _) = child_listener.accept().await.unwrap();
        let mut request = [0_u8; 4];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"ping");
        child_seen_task.store(true, Ordering::Release);
        stream.write_all(b"pong").await.unwrap();
    });

    let parent_seen_task = Arc::clone(&parent_seen);
    let parent_task = tokio::spawn(async move {
        let (mut inbound, _) = parent_listener.accept().await.unwrap();
        parent_seen_task.store(true, Ordering::Release);
        let requested_target = read_socks5_target(&mut inbound).await;
        assert_eq!(requested_target, child_addr);
        let mut outbound = TokioTcpStream::connect(requested_target).await.unwrap();
        inbound
            .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        tokio::io::copy_bidirectional(&mut inbound, &mut outbound)
            .await
            .unwrap();
    });

    let proxy = chained_proxy(child_addr, parent_addr);
    let mut stream = open_proxy_tcp_stream_async(&proxy).await.unwrap();
    stream.write_all(b"ping").await.unwrap();
    let mut response = [0_u8; 4];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"pong");
    drop(stream);

    child_task.await.unwrap();
    parent_task.await.unwrap();
    assert!(parent_seen.load(Ordering::Acquire));
    assert!(child_seen.load(Ordering::Acquire));
}

#[test]
fn parent_down_never_contacts_live_child() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let child_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let child_addr = child_listener.local_addr().unwrap();
        let closed_parent = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let parent_addr = closed_parent.local_addr().unwrap();
        drop(closed_parent);

        let error = open_proxy_tcp_stream_async(&chained_proxy(child_addr, parent_addr))
            .await
            .unwrap_err();
        assert!(error.contains("connect direct TCP"), "{error}");
        assert!(
            tokio::time::timeout(Duration::from_millis(100), child_listener.accept())
                .await
                .is_err(),
            "child was contacted while the parent was down"
        );
    });
}

#[test]
fn parent_transport_carries_ipv4_and_ipv6_child_streams() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        assert_parent_transport_reaches_child(IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
        assert_parent_transport_reaches_child(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    });
}
