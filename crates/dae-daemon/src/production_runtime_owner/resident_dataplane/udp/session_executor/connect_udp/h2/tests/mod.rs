use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use futures_util::future::join_all;
use tokio::time::{self, Duration};

use dae_outbound::NetworkType;

use super::*;
use crate::production_runtime_owner::resident_dataplane::plan::{
    build_resident_manual_probe_plan, build_resident_proxy_plan_for_node,
};
use crate::production_runtime_owner::resident_dataplane::probe_resident_candidate_manual_latency_snapshot;

mod server;

use self::server::{ConnectUdpH2TestServer, ConnectUdpH2TestServerConfig};

static NEXT_TEST_GENERATION: AtomicU64 = AtomicU64::new(10_000);
const TEST_TEMPLATE: &str =
    "%2F.well-known%2Fmasque%2Fudp%2F%7Btarget_host%7D%2F%7Btarget_port%7D%2F";

fn parse_config(input: &str) -> dae_config::Config {
    let sections = dae_config::parser::parse_config(input).unwrap();
    dae_config::schema::build_config(&sections).unwrap()
}

fn test_config() -> dae_config::Config {
    parse_config(
        r#"
        global {
            lan_interface: daerust0
            allow_insecure: false
            so_mark_from_dae: 0
            mptcp: false
            udp_check_dns: '192.0.2.53:53'
        }
        routing {
            fallback: direct
        }
        "#,
    )
}

fn test_link(server: &ConnectUdpH2TestServer, authentication: Option<(&str, &str)>) -> String {
    let authority = server.address();
    let (userinfo, auth) = match authentication {
        Some((username, password)) => (format!("{username}:{password}@"), "basic"),
        None => (String::new(), "none"),
    };
    format!(
        "masque://{userinfo}{authority}?transport=h2&auth={auth}&template={TEST_TEMPLATE}&sni={}&allowInsecure=1#h2-test",
        server.server_name(),
    )
}

fn test_proxy(
    server: &ConnectUdpH2TestServer,
    authentication: Option<(&str, &str)>,
) -> (ResidentProxyPlan, ResidentConnectUdpRuntimePlan) {
    let config = test_config();
    let authority = server.address();
    let link = test_link(server, authentication);
    let mut proxy = build_resident_proxy_plan_for_node(
        &config,
        "connect-udp-test".to_owned(),
        format!("h2-test-{}", authority.port()),
        link,
    )
    .unwrap();
    // Unit tests exercise the userspace transport without requiring CAP_NET_ADMIN.
    proxy.mark = 0;
    let runtime = ResidentConnectUdpRuntimePlan {
        generation: NEXT_TEST_GENERATION.fetch_add(1, Ordering::Relaxed),
        ..ResidentConnectUdpRuntimePlan::standalone()
    };
    proxy.apply_runtime_generation(runtime.generation, runtime);
    (proxy, runtime)
}

async fn exchange(
    session: &mut ConnectUdpH2Session,
    proxy: &ResidentProxyPlan,
    target: SocketAddr,
    payload: &[u8],
) -> Result<UdpExchangeResult, String> {
    let response = session.exchange(proxy, target, payload).await?;
    if response.reply_forwarded {
        return Ok(response);
    }
    time::timeout(Duration::from_secs(3), session.wait_response())
        .await
        .map_err(|_| "test CONNECT-UDP H2 response timeout".to_owned())?
        .and_then(|response| response.ok_or_else(|| "test response was empty".to_owned()))
}

fn clear_generation(runtime: ResidentConnectUdpRuntimePlan) {
    let report = clear_connect_udp_h2_pools(runtime.generation);
    assert!(!report.registry_locked);
    assert_eq!(report.locked_pools, 0);
}

#[tokio::test]
async fn h2_extended_connect_round_trips_ipv4_and_reuses_stream() {
    let server = ConnectUdpH2TestServer::start(ConnectUdpH2TestServerConfig::echo()).await;
    let (proxy, runtime) = test_proxy(&server, None);
    let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)), 5353);
    let mut session = ConnectUdpH2Session::new(runtime);

    for payload in [b"first-packet".as_slice(), b"second-packet".as_slice()] {
        let response = exchange(&mut session, &proxy, target, payload)
            .await
            .unwrap();
        assert_eq!(response.payload, payload);
        assert_eq!(response.execution_label, "connect-udp-h2-capsule");
    }

    let observations = server.observations();
    assert_eq!(server.connection_count(), 1);
    assert_eq!(server.stream_count(), 1);
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].method, "CONNECT");
    assert_eq!(observations[0].protocol.as_deref(), Some("connect-udp"));
    assert_eq!(
        observations[0].uri,
        format!(
            "https://{}/.well-known/masque/udp/192.0.2.9/5353/",
            server.address()
        )
    );
    assert_eq!(observations[0].authorization, None);

    session.shutdown().await;
    clear_generation(runtime);
}

#[tokio::test]
async fn h2_pool_multiplexes_independent_ipv4_and_ipv6_target_streams() {
    let server = ConnectUdpH2TestServer::start(ConnectUdpH2TestServerConfig::echo()).await;
    let (proxy, runtime) = test_proxy(&server, None);
    let ipv4_target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53);
    let ipv6_target = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 3478);
    let mut first = ConnectUdpH2Session::new(runtime);
    let mut second = ConnectUdpH2Session::new(runtime);

    assert_eq!(
        exchange(&mut first, &proxy, ipv4_target, b"ipv4")
            .await
            .unwrap()
            .payload,
        b"ipv4"
    );
    assert_eq!(
        exchange(&mut second, &proxy, ipv6_target, b"ipv6")
            .await
            .unwrap()
            .payload,
        b"ipv6"
    );

    assert_eq!(server.connection_count(), 1);
    assert_eq!(server.stream_count(), 2);
    let observations = server.observations();
    assert!(
        observations
            .iter()
            .any(|item| item.uri.ends_with("/127.0.0.1/53/"))
    );
    assert!(
        observations
            .iter()
            .any(|item| item.uri.ends_with("/%3A%3A1/3478/"))
    );

    first.shutdown().await;
    second.shutdown().await;
    clear_generation(runtime);
}

#[tokio::test]
async fn h2_burst_reuses_one_target_stream_without_response_crosstalk() {
    let server = ConnectUdpH2TestServer::start(ConnectUdpH2TestServerConfig::echo()).await;
    let (proxy, runtime) = test_proxy(&server, None);
    let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53);
    let mut session = ConnectUdpH2Session::new(runtime);

    for sequence in 0_u32..128 {
        let payload = sequence.to_be_bytes();
        let response = exchange(&mut session, &proxy, target, &payload)
            .await
            .unwrap();
        assert_eq!(response.payload, payload);
    }

    assert_eq!(server.connection_count(), 1);
    assert_eq!(server.stream_count(), 1);
    session.shutdown().await;
    clear_generation(runtime);
}

#[tokio::test]
async fn h2_pool_bounds_and_multiplexes_concurrent_target_sessions() {
    let server = ConnectUdpH2TestServer::start(ConnectUdpH2TestServerConfig::echo()).await;
    let (proxy, runtime) = test_proxy(&server, None);
    let proxy = Arc::new(proxy);
    let sessions = (0_u16..32).map(|sequence| {
        let proxy = Arc::clone(&proxy);
        async move {
            let target = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                10_000_u16.saturating_add(sequence),
            );
            let payload = sequence.to_be_bytes();
            let mut session = ConnectUdpH2Session::new(runtime);
            let response = exchange(&mut session, &proxy, target, &payload)
                .await
                .unwrap();
            session.shutdown().await;
            (payload, response.payload)
        }
    });

    for (expected, actual) in join_all(sessions).await {
        assert_eq!(actual, expected);
    }
    assert!(server.connection_count() <= runtime.h2_pool_connections);
    assert_eq!(server.stream_count(), 32);
    clear_generation(runtime);
}

#[tokio::test]
async fn h2_basic_auth_is_sensitive_and_server_enforced() {
    let server = ConnectUdpH2TestServer::start(
        ConnectUdpH2TestServerConfig::echo().with_basic_auth("fixture", "secret"),
    )
    .await;
    let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53);

    let (accepted_proxy, accepted_runtime) = test_proxy(&server, Some(("fixture", "secret")));
    let mut accepted = ConnectUdpH2Session::new(accepted_runtime);
    assert_eq!(
        exchange(&mut accepted, &accepted_proxy, target, b"authenticated")
            .await
            .unwrap()
            .payload,
        b"authenticated"
    );
    accepted.shutdown().await;
    clear_generation(accepted_runtime);

    let (rejected_proxy, rejected_runtime) = test_proxy(&server, Some(("fixture", "wrong")));
    let mut rejected = ConnectUdpH2Session::new(rejected_runtime);
    let err = rejected
        .exchange(&rejected_proxy, target, b"rejected")
        .await
        .unwrap_err();
    assert!(err.contains("status 407"), "{err}");
    rejected.shutdown().await;
    clear_generation(rejected_runtime);
}

#[tokio::test]
async fn h2_admission_requires_peer_extended_connect_setting() {
    let server = ConnectUdpH2TestServer::start(
        ConnectUdpH2TestServerConfig::echo().without_extended_connect(),
    )
    .await;
    let (proxy, runtime) = test_proxy(&server, None);
    let mut session = ConnectUdpH2Session::new(runtime);
    let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53);

    let err = session
        .exchange(&proxy, target, b"blocked")
        .await
        .unwrap_err();
    assert!(
        err.contains("did not enable the extended CONNECT protocol"),
        "{err}"
    );
    session.shutdown().await;
    clear_generation(runtime);
}

#[tokio::test]
async fn h2_admission_requires_capsule_protocol_response() {
    let server = ConnectUdpH2TestServer::start(
        ConnectUdpH2TestServerConfig::echo().without_capsule_protocol(),
    )
    .await;
    let (proxy, runtime) = test_proxy(&server, None);
    let mut session = ConnectUdpH2Session::new(runtime);
    let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53);

    let err = session
        .exchange(&proxy, target, b"blocked")
        .await
        .unwrap_err();
    assert!(err.contains("did not negotiate Capsule Protocol"), "{err}");
    session.shutdown().await;
    clear_generation(runtime);
}

#[tokio::test]
async fn h2_stream_failure_is_local_and_cross_target_reuse_is_rejected() {
    let server = ConnectUdpH2TestServer::start(ConnectUdpH2TestServerConfig::echo()).await;
    let (proxy, runtime) = test_proxy(&server, None);
    let first_target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53);
    let second_target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 54);
    let mut session = ConnectUdpH2Session::new(runtime);

    assert_eq!(
        exchange(&mut session, &proxy, first_target, b"first")
            .await
            .unwrap()
            .payload,
        b"first"
    );
    let err = session
        .exchange(&proxy, second_target, b"must-not-leak")
        .await
        .unwrap_err();
    assert!(
        err.contains("cross-target tunnel reuse is forbidden"),
        "{err}"
    );

    session.shutdown().await;
    clear_generation(runtime);
}

#[tokio::test]
async fn h2_manual_latency_uses_the_admitted_udp_executor() {
    let server = ConnectUdpH2TestServer::start(ConnectUdpH2TestServerConfig::dns_answer()).await;
    let config = test_config();
    let link = test_link(&server, None);
    let mut candidate =
        build_resident_manual_probe_plan(&config, "connect-udp-h2-manual".to_owned(), link)
            .unwrap();
    let runtime = ResidentConnectUdpRuntimePlan {
        generation: NEXT_TEST_GENERATION.fetch_add(1, Ordering::Relaxed),
        ..ResidentConnectUdpRuntimePlan::standalone()
    };
    let proxy = Arc::make_mut(&mut candidate.proxy);
    proxy.mark = 0;
    proxy.apply_runtime_generation(runtime.generation, runtime);

    let snapshot =
        probe_resident_candidate_manual_latency_snapshot(candidate, runtime.generation).await;
    assert_eq!(snapshot["alive"], true);
    assert_eq!(snapshot["scope"], "proxy-udp-check");
    assert_eq!(
        snapshot["networkDimension"],
        NetworkType::DNS_UDP4.dimension_name()
    );
    assert_eq!(snapshot["familyResults"][0]["healthState"], "alive");
    assert_eq!(snapshot["familyResults"][1]["healthState"], "unavailable");

    clear_generation(runtime);
}

#[tokio::test]
async fn h2_generation_cleanup_removes_owned_pool_once() {
    let server = ConnectUdpH2TestServer::start(ConnectUdpH2TestServerConfig::echo()).await;
    let (proxy, runtime) = test_proxy(&server, None);
    let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53);
    let mut session = ConnectUdpH2Session::new(runtime);
    assert_eq!(
        exchange(&mut session, &proxy, target, b"cleanup")
            .await
            .unwrap()
            .payload,
        b"cleanup"
    );

    let first = clear_connect_udp_h2_pools(runtime.generation);
    assert_eq!(first.pools, 1);
    assert_eq!(first.connections, 1);
    assert_eq!(first.locked_pools, 0);
    assert!(!first.registry_locked);
    let second = clear_connect_udp_h2_pools(runtime.generation);
    assert_eq!(second.pools, 0);
    assert_eq!(second.connections, 0);

    session.shutdown().await;
}

#[tokio::test]
async fn h2_maximum_bounded_capsule_crosses_flow_control_windows_without_stall() {
    let server = ConnectUdpH2TestServer::start(ConnectUdpH2TestServerConfig::echo()).await;
    let (proxy, runtime) = test_proxy(&server, None);
    let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53);
    let payload = vec![0x5a; runtime.capsule_limits.max_datagram_payload_bytes];
    let mut session = ConnectUdpH2Session::new(runtime);

    let response = exchange(&mut session, &proxy, target, &payload)
        .await
        .unwrap();
    assert_eq!(response.payload, payload);

    session.shutdown().await;
    clear_generation(runtime);
}

#[tokio::test]
async fn h2_reset_and_malformed_capsule_fail_closed() {
    let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53);

    let reset_server =
        ConnectUdpH2TestServer::start(ConnectUdpH2TestServerConfig::reset_after_headers()).await;
    let (reset_proxy, reset_runtime) = test_proxy(&reset_server, None);
    let mut reset_session = ConnectUdpH2Session::new(reset_runtime);
    let reset_result = reset_session.exchange(&reset_proxy, target, b"reset").await;
    let reset_err = match reset_result {
        Err(err) => err,
        Ok(response) if response.reply_forwarded => panic!("reset unexpectedly returned a packet"),
        Ok(_) => reset_session.wait_response().await.unwrap_err(),
    };
    assert!(
        reset_err.contains("CONNECT-UDP H2") || reset_err.contains("stream"),
        "{reset_err}"
    );
    reset_session.shutdown().await;
    clear_generation(reset_runtime);

    let malformed_server =
        ConnectUdpH2TestServer::start(ConnectUdpH2TestServerConfig::malformed_capsule()).await;
    let (malformed_proxy, malformed_runtime) = test_proxy(&malformed_server, None);
    let mut malformed_session = ConnectUdpH2Session::new(malformed_runtime);
    let result = malformed_session
        .exchange(&malformed_proxy, target, b"malformed")
        .await;
    let err = match result {
        Err(err) => err,
        Ok(response) if response.reply_forwarded => {
            panic!("malformed response unexpectedly returned a packet")
        }
        Ok(_) => malformed_session.wait_response().await.unwrap_err(),
    };
    assert!(err.contains("decode CONNECT-UDP H2 Capsule"), "{err}");
    malformed_session.shutdown().await;
    clear_generation(malformed_runtime);
}
