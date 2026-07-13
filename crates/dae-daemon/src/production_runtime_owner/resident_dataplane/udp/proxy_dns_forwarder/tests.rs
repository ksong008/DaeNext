use super::*;
use crate::production_runtime_owner::resident_dataplane::RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE;
use crate::production_runtime_owner::resident_dataplane::plan::ResidentXhttpSettingsPlan;
use dae_dns::DnsPacketView;
use dae_outbound::shadowsocks::{decode_udp_packet, encode_udp_packet};
use std::net::{IpAddr, Ipv4Addr};

const TEST_CIPHER: &str = "aes-128-gcm";
const TEST_PASSWORD: &str = "fixture-password";
const TEST_DNS_QTYPE_A: u16 = 1;

fn proxy_plan(server: SocketAddr) -> ResidentProxyPlan {
    ResidentProxyPlan {
        graph_id: "resident-graph:redacted".to_owned(),
        graph_link_hash: "sha256:redacted".to_owned(),
        redacted_link_source: "source:<redacted>".to_owned(),
        protocol: "ss",
        group_name: "proxy".to_owned(),
        group_policy: "fixed".to_owned(),
        node_tag: "redacted".to_owned(),
        server_host: server.ip().to_string(),
        server_port: server.port(),
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
        handler: ResidentProxyProtocolPlan::ShadowsocksAeadTcp {
            cipher: TEST_CIPHER.to_owned(),
            password: TEST_PASSWORD.to_owned(),
            salt_len: 16,
        },
        execution: None,
        chain_parent: None,
        mark: 0,
        mptcp: false,
    }
}

fn juicity_proxy_plan(server: SocketAddr) -> ResidentProxyPlan {
    let mut proxy = proxy_plan(server);
    proxy.protocol = "juicity";
    proxy.net = "quic".to_owned();
    proxy.handler = ResidentProxyProtocolPlan::JuicityQuicTcp {
        uuid: "00000000-0000-0000-0000-000000000001".to_owned(),
        password: "fixture-password".to_owned(),
        allow_insecure: true,
        pinned_certchain_sha256: String::new(),
    };
    proxy
}

#[tokio::test(flavor = "current_thread")]
async fn proxy_dns_udp_forwarder_uses_bounded_generation_owned_actors() {
    let mut runtime = ResidentDnsUdpRuntimeConfig::standalone();
    runtime.proxy_actor_limit = 3;
    runtime.actor_worker_threads = 1;
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let actor_executor = Arc::new(ResidentDnsUdpActorExecutor::new(
        runtime.clone(),
        Arc::clone(&metrics),
    ));
    let forwarder = ResidentProxyDnsUdpForwarder::new(
        Arc::new(proxy_plan(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            9,
        ))),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53),
        runtime,
        Arc::clone(&metrics),
        Arc::clone(&actor_executor),
    );

    assert_eq!(forwarder.actor_count(), 1);
    let first = forwarder.actor_handle(0).await.unwrap();
    let reused = forwarder.actor_handle(0).await.unwrap();
    assert!(!first.is_closed());
    assert!(!reused.is_closed());
    assert_eq!(metrics.snapshot()["dnsUdpActorsOpened"], 1);

    let deadline = time::Instant::now() + RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE;
    let report = forwarder.shutdown(deadline).await;
    let executor_report = actor_executor.shutdown(deadline).await;
    let exchange_error = forwarder.exchange(&[0_u8; 12]).await.unwrap_err();

    assert_eq!(report["status"], "pass");
    assert_eq!(report["actorsOpened"], 1);
    assert_eq!(report["actorsClosed"], 1);
    assert_eq!(report["actorMode"], "multiplexed-session");
    assert_eq!(executor_report["status"], "pass");
    assert!(first.is_closed());
    assert!(exchange_error.contains("closing"), "{exchange_error}");
    let snapshot = metrics.snapshot();
    assert_eq!(
        snapshot["dnsUdpActorsOpened"],
        snapshot["dnsUdpActorsClosed"]
    );
}

#[tokio::test(flavor = "current_thread")]
async fn request_scoped_proxy_dns_udp_uses_the_profile_actor_limit() {
    let mut runtime = ResidentDnsUdpRuntimeConfig::standalone();
    runtime.proxy_actor_limit = 3;
    runtime.actor_worker_threads = 1;
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let actor_executor = Arc::new(ResidentDnsUdpActorExecutor::new(
        runtime.clone(),
        Arc::clone(&metrics),
    ));
    let forwarder = ResidentProxyDnsUdpForwarder::new(
        Arc::new(juicity_proxy_plan(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            9,
        ))),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53),
        runtime,
        metrics,
        actor_executor,
    );

    assert_eq!(forwarder.actor_count(), 3);
    assert!(forwarder.request_scoped_actor_pool);
    let (first, first_guard) = forwarder.acquire_actor_slot();
    let (second, second_guard) = forwarder.acquire_actor_slot();
    assert_ne!(first, second);
    drop(second_guard);
    drop(first_guard);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_proxy_dns_udp_actor_multiplexes_out_of_order_responses_without_head_of_line_waiting() {
    let upstream = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut first_wire = vec![0_u8; 4096];
        let mut second_wire = vec![0_u8; 4096];
        let (first_len, peer) = upstream.recv_from(&mut first_wire).await.unwrap();
        let (second_len, second_peer) = upstream.recv_from(&mut second_wire).await.unwrap();
        assert_eq!(peer, second_peer);
        let first =
            decode_udp_packet(TEST_CIPHER, TEST_PASSWORD, &first_wire[..first_len]).unwrap();
        let second =
            decode_udp_packet(TEST_CIPHER, TEST_PASSWORD, &second_wire[..second_len]).unwrap();
        let first_response = dns_a_response_for_query(&first.payload, [192, 0, 2, 1]);
        let second_response = dns_a_response_for_query(&second.payload, [192, 0, 2, 2]);
        let first_wire = encode_udp_packet(
            TEST_CIPHER,
            TEST_PASSWORD,
            &[0x31; 16],
            &first.target,
            &first_response,
        )
        .unwrap();
        let second_wire = encode_udp_packet(
            TEST_CIPHER,
            TEST_PASSWORD,
            &[0x32; 16],
            &second.target,
            &second_response,
        )
        .unwrap();
        upstream.send_to(&second_wire, peer).await.unwrap();
        upstream.send_to(&first_wire, peer).await.unwrap();
    });
    let mut runtime = ResidentDnsUdpRuntimeConfig::standalone();
    runtime.proxy_actor_limit = 1;
    runtime.actor_worker_threads = 1;
    runtime.attempts = 1;
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let actor_executor = Arc::new(ResidentDnsUdpActorExecutor::new(
        runtime.clone(),
        Arc::clone(&metrics),
    ));
    let forwarder = Arc::new(ResidentProxyDnsUdpForwarder::new(
        Arc::new(proxy_plan(upstream_addr)),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53),
        runtime,
        Arc::clone(&metrics),
        Arc::clone(&actor_executor),
    ));
    let first = dns_query(0x1111, "first.example");
    let second = dns_query(0x2222, "second.example");
    let first_forwarder = Arc::clone(&forwarder);
    let second_forwarder = Arc::clone(&forwarder);
    let (first_response, second_response) = tokio::join!(
        async move { first_forwarder.exchange(&first).await },
        async move { second_forwarder.exchange(&second).await },
    );

    assert_eq!(&first_response.unwrap()[0..2], &0x1111_u16.to_be_bytes());
    assert_eq!(&second_response.unwrap()[0..2], &0x2222_u16.to_be_bytes());
    server.await.unwrap();
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot["dnsUdpActorsOpened"], 1);
    assert_eq!(snapshot["proxyDnsUdpExecutorsOpened"], 1);
    assert!(snapshot["proxyDnsUdpExecutorsReused"].as_u64().unwrap_or(0) >= 1);
    assert_eq!(snapshot["dnsUdpPendingMaximum"], 2);

    let deadline = time::Instant::now() + RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE;
    assert_eq!(forwarder.shutdown(deadline).await["status"], "pass");
    assert_eq!(actor_executor.shutdown(deadline).await["status"], "pass");
}

fn dns_a_response_for_query(query: &[u8], address: [u8; 4]) -> Vec<u8> {
    let view = DnsPacketView::parse(query).unwrap();
    let mut response = Vec::new();
    response.extend_from_slice(&query[0..2]);
    response.extend_from_slice(&0x8180_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&query[12..view.answer_offset()]);
    response.extend_from_slice(&0xc00c_u16.to_be_bytes());
    response.extend_from_slice(&TEST_DNS_QTYPE_A.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&60_u32.to_be_bytes());
    response.extend_from_slice(&4_u16.to_be_bytes());
    response.extend_from_slice(&address);
    response
}

fn dns_query(id: u16, domain: &str) -> Vec<u8> {
    let mut query = Vec::new();
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&0x0100_u16.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    for label in domain.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&TEST_DNS_QTYPE_A.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    query
}
