use dae_config::Config;
use dae_dns::DnsCacheEntry;

use super::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

const QUERY: &[u8] = &[
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x', b'a',
    b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
];
const TEST_DNS_UPSTREAM_HOST: &str = "resolver.fixture.invalid";
const TEST_UNMATCHED_DNS_HOST: &str = "unmatched-resolver.fixture.invalid";
const TEST_DNS_UPSTREAM_IPV4: &str = "192.0.2.53";
const TEST_DNS_UPSTREAM_IPV6: &str = "2001:db8::53";
static TEST_ASSET_COUNTER: AtomicUsize = AtomicUsize::new(0);

const DNS_PRESSURE_ENABLE_ENV: &str = "DAENEXT_DNS_PRESSURE_ENABLE";
const DNS_PRESSURE_BIND_IP_ENV: &str = "DAENEXT_DNS_PRESSURE_BIND_IP";
const DNS_PRESSURE_TOTAL_ENV: &str = "DAENEXT_DNS_PRESSURE_TOTAL";
const DNS_PRESSURE_CONCURRENCY_ENV: &str = "DAENEXT_DNS_PRESSURE_CONCURRENCY";
const DNS_PRESSURE_QNAME_PREFIX_ENV: &str = "DAENEXT_DNS_PRESSURE_QNAME_PREFIX";
const DNS_PRESSURE_QNAME_SUFFIX_ENV: &str = "DAENEXT_DNS_PRESSURE_QNAME_SUFFIX";
const DNS_PRESSURE_QTYPE_ENV: &str = "DAENEXT_DNS_PRESSURE_QTYPE";
const DNS_PRESSURE_UPSTREAM_TAG_ENV: &str = "DAENEXT_DNS_PRESSURE_UPSTREAM_TAG";
const DNS_PRESSURE_UPSTREAM_SCHEME_ENV: &str = "DAENEXT_DNS_PRESSURE_UPSTREAM_SCHEME";
const DNS_PRESSURE_RESPONSE_IP_ENV: &str = "DAENEXT_DNS_PRESSURE_RESPONSE_IP";
const DNS_PRESSURE_RESPONSE_TTL_ENV: &str = "DAENEXT_DNS_PRESSURE_RESPONSE_TTL";
const DNS_PRESSURE_DIRECT_SHARDS_ENV: &str = "DAENEXT_DNS_PRESSURE_DIRECT_SHARDS";
const DNS_PRESSURE_KEY_SPACE_ENV: &str = "DAENEXT_DNS_PRESSURE_KEY_SPACE";
const DNS_LIVE_PRESSURE_ENABLE_ENV: &str = "DAENEXT_DNS_LIVE_PRESSURE_ENABLE";
const DNS_LIVE_PRESSURE_TOTAL_ENV: &str = "DAENEXT_DNS_LIVE_PRESSURE_TOTAL";
const DNS_LIVE_PRESSURE_CONCURRENCY_ENV: &str = "DAENEXT_DNS_LIVE_PRESSURE_CONCURRENCY";
const DNS_LIVE_PRESSURE_QNAME_PREFIX_ENV: &str = "DAENEXT_DNS_LIVE_PRESSURE_QNAME_PREFIX";
const DNS_LIVE_PRESSURE_QNAME_SUFFIX_ENV: &str = "DAENEXT_DNS_LIVE_PRESSURE_QNAME_SUFFIX";
const DNS_LIVE_PRESSURE_QTYPE_ENV: &str = "DAENEXT_DNS_LIVE_PRESSURE_QTYPE";
const DNS_LIVE_PRESSURE_UPSTREAM_TAG_ENV: &str = "DAENEXT_DNS_LIVE_PRESSURE_UPSTREAM_TAG";
const DNS_LIVE_PRESSURE_UPSTREAM_LINK_ENV: &str = "DAENEXT_DNS_LIVE_PRESSURE_UPSTREAM_LINK";
const DNS_LIVE_PRESSURE_ORIGINAL_DST_ENV: &str = "DAENEXT_DNS_LIVE_PRESSURE_ORIGINAL_DST";
const DNS_LIVE_PRESSURE_PROXY_LINK_ENV: &str = "DAENEXT_DNS_LIVE_PRESSURE_PROXY_LINK";
const DNS_LIVE_PRESSURE_PROXY_NODE_TAG_ENV: &str = "DAENEXT_DNS_LIVE_PRESSURE_PROXY_NODE_TAG";
const DNS_LIVE_PRESSURE_PROXY_GROUP_ENV: &str = "DAENEXT_DNS_LIVE_PRESSURE_PROXY_GROUP";
const DNS_LIVE_PRESSURE_UPSTREAM_HOST_MATCH_ENV: &str =
    "DAENEXT_DNS_LIVE_PRESSURE_UPSTREAM_HOST_MATCH";

fn parse_config(input: &str) -> Config {
    let sections = dae_config::parser::parse_config(input).unwrap();
    dae_config::schema::build_config(&sections).unwrap()
}

fn local_dns_upstream_authority() -> &'static str {
    "localhost:53"
}

fn test_fallback_resolver() -> SocketAddr {
    "127.0.0.1:53".parse().unwrap()
}

fn test_dns_upstream_target_v4() -> SocketAddr {
    format!("{TEST_DNS_UPSTREAM_IPV4}:53").parse().unwrap()
}

fn test_dns_upstream_target_v6() -> SocketAddr {
    format!("[{TEST_DNS_UPSTREAM_IPV6}]:53").parse().unwrap()
}

fn test_asis_cache_key(request: &DnsPacketView<'_>) -> ResidentDnsResponseCacheKey {
    ResidentDnsResponseCacheKey::new(
        dns_cache_key_for_request(request).unwrap(),
        ResidentDnsResponseCacheScope::AsIs {
            original_dst: "127.0.0.1:53".parse().unwrap(),
        },
    )
}

fn test_scoped_cache_key(
    request: &DnsPacketView<'_>,
    scope: ResidentDnsResponseCacheScope,
) -> ResidentDnsResponseCacheKey {
    ResidentDnsResponseCacheKey::new(dns_cache_key_for_request(request).unwrap(), scope)
}

fn indexed_test_dns_upstream_link(index: usize) -> String {
    format!("quic://resolver-{index}.fixture.invalid")
}

fn test_geodata() -> ResidentGeodataStore {
    ResidentGeodataStore::new(Vec::<std::path::PathBuf>::new())
}

fn test_asset_root(name: &str) -> PathBuf {
    let sequence = TEST_ASSET_COUNTER.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "dae-resident-dns-{name}-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    root
}

fn write_asset(root: &Path, filename: &str, data: Vec<u8>) {
    fs::write(root.join(filename), data).unwrap();
}

#[test]
fn resident_dns_plan_admits_fallback_upstream_udp() {
    let input = r#"
        global { so_mark_from_dae: 1234 }
        routing {}
        dns {
          upstream {
            primary: 'udp://LOCAL_DNS_UPSTREAM'
          }
          routing {
            request {
              fallback: primary
            }
          }
        }
        "#
    .replace("LOCAL_DNS_UPSTREAM", local_dns_upstream_authority());
    let config = parse_config(&input);
    let geodata = test_geodata();
    let plan = build_resident_dns_plan(&config, &geodata).unwrap();
    match plan.request_default_action {
        ResidentDnsRequestAction::Upstream(upstream) => {
            assert_eq!(upstream.tag, "primary");
            assert_eq!(upstream.target.authority, local_dns_upstream_authority());
            assert_eq!(upstream.target.literal_addr, None);
        }
        _ => panic!("expected upstream default action"),
    }
    assert_eq!(plan.mark, 1234);
}

#[test]
fn resident_dns_plan_defaults_zero_mark_to_control_plane_mark() {
    let input = r#"
        global {}
        routing {}
        dns {
          upstream {
            primary: 'udp://resolver.fixture.invalid:53'
          }
          routing {
            request {
              fallback: primary
            }
          }
        }
        "#;
    let config = parse_config(input);
    let geodata = test_geodata();
    let plan = build_resident_dns_plan(&config, &geodata).unwrap();
    let expected = effective_so_mark_from_dae(0);
    assert_eq!(plan.mark, expected);
    match plan.request_default_action {
        ResidentDnsRequestAction::Upstream(upstream) => {
            assert_eq!(upstream.target.resolver_mark, expected);
        }
        _ => panic!("expected upstream default action"),
    }
}

fn dns_upstream_routing_config(routing: &str) -> Config {
    dns_upstream_routing_config_with_group(
        routing,
        r#"
            filter: name(node_a)
            policy: fixed(0)
            "#,
    )
}

fn dns_upstream_routing_config_with_group(routing: &str, group_body: &str) -> Config {
    let input = r#"
        global {
          lan_interface: daerust0
          so_mark_from_dae: 1234
        }
        node {
          node_a: 'socks5://identity-1:credential-1@node-1.fixture.invalid:28001'
          node_b: 'socks5://identity-2:credential-2@node-2.fixture.invalid:28002'
        }
        group {
          proxy {
            __GROUP__
          }
        }
        routing {
          __ROUTING__
        }
        dns {
          upstream {
            overseas: 'tcp+udp://__DNS_UPSTREAM_HOST__:53'
          }
          routing {
            request {
              fallback: overseas
            }
          }
        }
        "#
    .replace("__ROUTING__", routing)
    .replace("__GROUP__", group_body)
    .replace("__DNS_UPSTREAM_HOST__", TEST_DNS_UPSTREAM_HOST);
    parse_config(&input)
}

fn dns_upstream_router_for_config(
    config: &Config,
) -> (ResidentDnsUpstreamRouter, ResidentDnsUpstream) {
    let geodata = test_geodata();
    let runtime_plan = build_resident_dataplane_plan(config).unwrap();
    let dns_plan = build_resident_dns_plan(config, &geodata).unwrap();
    let matcher = build_resident_userspace_routing_matcher_with_geodata(config, &geodata).unwrap();
    let router = ResidentDnsUpstreamRouter::new(
        matcher,
        share_resident_proxy_groups(runtime_plan.proxies.clone()),
        config.global.so_mark_from_dae,
        None,
    );
    let ResidentDnsRequestAction::Upstream(upstream) = dns_plan.request_default_action else {
        panic!("expected upstream default action");
    };
    (router, upstream)
}

fn test_dns_plan_with_router(
    config: &Config,
    router: ResidentDnsUpstreamRouter,
) -> ResidentDnsPlan {
    ResidentDnsPlan::asis(config.global.so_mark_from_dae)
        .with_upstream_routing(Some(Arc::new(router)))
}

fn select_single_test_dns_upstream_target(
    config: &Config,
    router: ResidentDnsUpstreamRouter,
    upstream: &ResidentDnsUpstream,
    target: SocketAddr,
    l4proto: L4Proto,
) -> ResidentDnsUpstreamSelection {
    let plan = test_dns_plan_with_router(config, router);
    let (targets, failures) =
        transport::select_dns_upstream_targets(&plan, upstream, vec![target], l4proto).unwrap();
    assert!(failures.is_empty(), "{failures:?}");
    targets.into_iter().next().unwrap().selection
}

#[test]
fn dns_upstream_router_selects_proxy_group_for_upstream_domain() {
    let config = dns_upstream_routing_config(
        r#"
            domain(full: __DNS_UPSTREAM_HOST__) -> proxy(mark: 7)
            fallback: direct
            "#
        .replace("__DNS_UPSTREAM_HOST__", TEST_DNS_UPSTREAM_HOST)
        .as_str(),
    );
    let (router, upstream) = dns_upstream_router_for_config(&config);
    let selection = select_single_test_dns_upstream_target(
        &config,
        router,
        &upstream,
        test_dns_upstream_target_v4(),
        L4Proto::Udp,
    );
    let ResidentDnsUpstreamSelection::Proxy { binding } = selection else {
        panic!("expected proxied DNS upstream selection");
    };
    assert_eq!(binding.plan().group_name, "proxy");
    assert_eq!(binding.plan().node_tag, "node_a");
    assert_eq!(binding.effective_socket_mark(), 7);
}

#[test]
fn dns_upstream_router_keeps_direct_fallback_direct() {
    let config = dns_upstream_routing_config(&format!(
        r#"
            domain(full: {TEST_UNMATCHED_DNS_HOST}) -> proxy
            fallback: direct
            "#
    ));
    let (router, upstream) = dns_upstream_router_for_config(&config);
    let selection = select_single_test_dns_upstream_target(
        &config,
        router,
        &upstream,
        test_dns_upstream_target_v4(),
        L4Proto::Tcp,
    );
    let ResidentDnsUpstreamSelection::Direct { mark } = selection else {
        panic!("expected direct DNS upstream selection");
    };
    assert_eq!(mark, 1234);
}

#[test]
fn dns_upstream_router_rejects_blocked_upstream_target() {
    let config = dns_upstream_routing_config(&format!(
        r#"
            domain(full: {TEST_UNMATCHED_DNS_HOST}) -> proxy
            fallback: block
            "#
    ));
    let (router, upstream) = dns_upstream_router_for_config(&config);
    let plan = test_dns_plan_with_router(&config, router);
    let err = transport::select_dns_upstream_targets(
        &plan,
        &upstream,
        vec![test_dns_upstream_target_v4()],
        L4Proto::Udp,
    )
    .unwrap_err();
    assert!(err.contains("routed to block"));
}

#[test]
fn dns_upstream_router_selects_tcp_upstream_with_tcp_health_state() {
    let config = dns_upstream_routing_config_with_group(
        r#"
            domain(full: __DNS_UPSTREAM_HOST__) -> proxy
            fallback: direct
            "#
        .replace("__DNS_UPSTREAM_HOST__", TEST_DNS_UPSTREAM_HOST)
        .as_str(),
        r#"
            filter: name(node_a, node_b)
            policy: min
            "#,
    );
    let (router, upstream) = dns_upstream_router_for_config(&config);
    let group = router.proxy_groups.values().next().unwrap();
    group
        .record_check_result("node_a", NetworkType::TCP4, Some(200), 1)
        .unwrap();
    group
        .record_check_result("node_b", NetworkType::TCP4, Some(20), 2)
        .unwrap();
    group
        .record_check_result("node_a", NetworkType::DNS_TCP4, Some(1), 3)
        .unwrap();
    group
        .record_check_result("node_b", NetworkType::DNS_TCP4, None, 4)
        .unwrap();

    let selection = select_single_test_dns_upstream_target(
        &config,
        router,
        &upstream,
        test_dns_upstream_target_v4(),
        L4Proto::Tcp,
    );
    let ResidentDnsUpstreamSelection::Proxy { binding } = selection else {
        panic!("expected proxied DNS upstream selection");
    };
    assert_eq!(binding.plan().node_tag, "node_b");
}

#[test]
fn dns_upstream_router_selects_udp_upstream_with_dns_udp_health_state() {
    let config = dns_upstream_routing_config_with_group(
        r#"
            domain(full: __DNS_UPSTREAM_HOST__) -> proxy
            fallback: direct
            "#
        .replace("__DNS_UPSTREAM_HOST__", TEST_DNS_UPSTREAM_HOST)
        .as_str(),
        r#"
            filter: name(node_a, node_b)
            policy: min
            "#,
    );
    let (router, upstream) = dns_upstream_router_for_config(&config);
    let group = router.proxy_groups.values().next().unwrap();
    group
        .record_check_result("node_a", NetworkType::TCP4, Some(200), 1)
        .unwrap();
    group
        .record_check_result("node_b", NetworkType::TCP4, Some(20), 2)
        .unwrap();
    group
        .record_check_result("node_a", NetworkType::DNS_UDP4, Some(20), 3)
        .unwrap();
    group
        .record_check_result("node_b", NetworkType::DNS_UDP4, Some(200), 4)
        .unwrap();

    let selection = select_single_test_dns_upstream_target(
        &config,
        router,
        &upstream,
        test_dns_upstream_target_v4(),
        L4Proto::Udp,
    );
    let ResidentDnsUpstreamSelection::Proxy { binding } = selection else {
        panic!("expected proxied DNS upstream selection");
    };
    assert_eq!(binding.plan().node_tag, "node_a");
}

#[test]
fn dns_upstream_candidates_select_lower_latency_tcp_path_for_tcp_udp() {
    let config = dns_upstream_routing_config_with_group(
        r#"
            domain(full: __DNS_UPSTREAM_HOST__) -> proxy
            fallback: direct
            "#
        .replace("__DNS_UPSTREAM_HOST__", TEST_DNS_UPSTREAM_HOST)
        .as_str(),
        r#"
            filter: name(node_a, node_b)
            policy: min
            "#,
    );
    let (router, upstream) = dns_upstream_router_for_config(&config);
    let group = router.proxy_groups.values().next().unwrap();
    group
        .record_check_result("node_a", NetworkType::DNS_UDP4, Some(200), 1)
        .unwrap();
    group
        .record_check_result("node_b", NetworkType::TCP4, Some(20), 2)
        .unwrap();

    let plan = ResidentDnsPlan::asis(config.global.so_mark_from_dae)
        .with_upstream_routing(Some(Arc::new(router)));
    let candidates = transport::dns_upstream_candidates_for_l4protos(
        &[test_dns_upstream_target_v4()],
        &[L4Proto::Udp, L4Proto::Tcp],
    );
    let (targets, failures) =
        transport::select_dns_upstream_candidates(&plan, &upstream, candidates).unwrap();

    assert!(failures.is_empty(), "{failures:?}");
    assert_eq!(targets[0].target, test_dns_upstream_target_v4());
    assert_eq!(targets[0].l4proto, L4Proto::Tcp);
    let ResidentDnsUpstreamSelection::Proxy { binding } = &targets[0].selection else {
        panic!("expected proxied DNS upstream target");
    };
    assert_eq!(binding.plan().node_tag, "node_b");
}

#[test]
fn dns_upstream_candidates_keep_multiple_resolved_targets_generic() {
    let config = dns_upstream_routing_config_with_group(
        r#"
            domain(full: __DNS_UPSTREAM_HOST__) -> proxy
            fallback: direct
            "#
        .replace("__DNS_UPSTREAM_HOST__", TEST_DNS_UPSTREAM_HOST)
        .as_str(),
        r#"
            filter: name(node_a, node_b)
            policy: min
            "#,
    );
    let (router, upstream) = dns_upstream_router_for_config(&config);
    let group = router.proxy_groups.values().next().unwrap();
    group
        .record_check_result("node_a", NetworkType::DNS_UDP4, Some(80), 1)
        .unwrap();
    group
        .record_check_result("node_b", NetworkType::TCP6, Some(10), 2)
        .unwrap();

    let plan = ResidentDnsPlan::asis(config.global.so_mark_from_dae)
        .with_upstream_routing(Some(Arc::new(router)));
    let candidates = transport::dns_upstream_candidates_for_l4protos(
        &[test_dns_upstream_target_v4(), test_dns_upstream_target_v6()],
        &[L4Proto::Udp, L4Proto::Tcp],
    );
    let (targets, failures) =
        transport::select_dns_upstream_candidates(&plan, &upstream, candidates).unwrap();

    assert!(failures.is_empty(), "{failures:?}");
    assert_eq!(targets.len(), 4);
    assert_eq!(targets[0].target, test_dns_upstream_target_v6());
    assert_eq!(targets[0].l4proto, L4Proto::Tcp);
    let ResidentDnsUpstreamSelection::Proxy { binding } = &targets[0].selection else {
        panic!("expected proxied DNS upstream target");
    };
    assert_eq!(binding.plan().node_tag, "node_b");
}

#[tokio::test]
async fn tcp_udp_fast_udp_response_does_not_admit_a_tcp_request() {
    let tcp = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let target = tcp.local_addr().unwrap();
    let udp = tokio::net::UdpSocket::bind(target).await.unwrap();
    let udp_server = tokio::spawn(async move {
        let mut request = vec![0_u8; DNS_RESPONSE_READ_LIMIT];
        let (read, peer) = udp.recv_from(&mut request).await.unwrap();
        let response = dns_pressure_response_for_query(
            &request[..read],
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 43)),
            60,
        );
        udp.send_to(&response, peer).await.unwrap();
    });
    let tcp_server = tokio::spawn(async move {
        time::timeout(Duration::from_millis(150), tcp.accept())
            .await
            .is_ok()
    });
    let upstream = parse_dns_upstream(
        1,
        "udp-lead",
        &format!("tcp+udp://{target}"),
        test_fallback_resolver(),
        0,
    )
    .unwrap();

    let response = transport::forward_dns_to_upstream_async(
        &upstream,
        QUERY,
        &ResidentDnsPlan::asis(0),
        &Arc::new(ResidentDnsForwarderCache::default()),
        ProxyDnsRequestContext::from_timeout(RESIDENT_UDP_RESPONSE_TIMEOUT),
    )
    .await
    .unwrap();

    assert_eq!(&response[0..2], &QUERY[0..2]);
    udp_server.await.unwrap();
    assert!(!tcp_server.await.unwrap(), "fast UDP admitted TCP work");
}

#[tokio::test]
async fn tcp_udp_preserves_the_complete_udp_target_set_during_the_udp_lead() {
    let live = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let live_target = live.local_addr().unwrap();
    let unavailable_target =
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), live_target.port());
    let server = tokio::spawn(async move {
        let mut request = vec![0_u8; DNS_RESPONSE_READ_LIMIT];
        let (read, peer) = live.recv_from(&mut request).await.unwrap();
        let response = dns_pressure_response_for_query(
            &request[..read],
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 44)),
            60,
        );
        live.send_to(&response, peer).await.unwrap();
    });
    let upstream = ResidentDnsUpstream {
        index: 1,
        tag: "multi-address".to_owned(),
        target: ResidentDnsUpstreamTarget {
            authority: format!("resolver.fixture.invalid:{}", live_target.port()),
            host: "resolver.fixture.invalid".to_owned(),
            port: live_target.port(),
            literal_addr: None,
            fallback_resolver: test_fallback_resolver(),
            resolver_mark: 0,
            resolved_addrs: Arc::default(),
        },
        scheme: ResidentDnsUpstreamScheme::TcpUdp,
        path: String::new(),
    };
    upstream
        .target
        .resolved_addrs
        .seed(
            vec![unavailable_target, live_target],
            Duration::from_secs(60),
        )
        .await;

    let response = transport::forward_dns_to_upstream_async(
        &upstream,
        QUERY,
        &ResidentDnsPlan::asis(0),
        &Arc::new(ResidentDnsForwarderCache::default()),
        ProxyDnsRequestContext::from_timeout(RESIDENT_UDP_RESPONSE_TIMEOUT),
    )
    .await
    .unwrap();
    server.await.unwrap();
    assert_eq!(&response[0..2], &QUERY[0..2]);
}

#[tokio::test]
async fn tcp_udp_tcp_response_does_not_wait_for_blackholed_udp() {
    let tcp = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let target = tcp.local_addr().unwrap();
    let _udp_blackhole = tokio::net::UdpSocket::bind(target).await.unwrap();
    let tcp_server = tokio::spawn(async move {
        let (mut stream, _) = tcp.accept().await.unwrap();
        let request_len = stream.read_u16().await.unwrap() as usize;
        let mut request = vec![0_u8; request_len];
        stream.read_exact(&mut request).await.unwrap();
        let response =
            dns_pressure_response_for_query(&request, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 47)), 60);
        stream.write_u16(response.len() as u16).await.unwrap();
        stream.write_all(&response).await.unwrap();
    });
    let upstream = parse_dns_upstream(
        1,
        "parallel",
        &format!("tcp+udp://{target}"),
        test_fallback_resolver(),
        0,
    )
    .unwrap();
    let started = time::Instant::now();

    let response = transport::forward_dns_to_upstream_async(
        &upstream,
        QUERY,
        &ResidentDnsPlan::asis(0),
        &Arc::new(ResidentDnsForwarderCache::default()),
        ProxyDnsRequestContext::from_timeout(RESIDENT_UDP_RESPONSE_TIMEOUT),
    )
    .await
    .unwrap();

    assert_eq!(&response[0..2], &QUERY[0..2]);
    assert!(
        started.elapsed() >= Duration::from_millis(20),
        "TCP started without the UDP hedge lead: {:?}",
        started.elapsed()
    );
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "TCP response waited for the blackholed UDP branch: {:?}",
        started.elapsed()
    );
    tcp_server.await.unwrap();
}

#[tokio::test]
async fn tcp_udp_uses_fresh_tcp_phase_after_truncated_udp_response() {
    let tcp = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let target = tcp.local_addr().unwrap();
    let udp = tokio::net::UdpSocket::bind(target).await.unwrap();
    let (tcp_request_started, mut wait_for_tcp_request) = tokio::sync::oneshot::channel();
    let (udp_truncated_sent, wait_for_udp_truncated) = tokio::sync::oneshot::channel();
    let udp_server = tokio::spawn(async move {
        let mut request = vec![0_u8; DNS_RESPONSE_READ_LIMIT];
        let (read, peer) = udp.recv_from(&mut request).await.unwrap();
        let tcp_started_before_truncated =
            time::timeout(Duration::from_millis(20), &mut wait_for_tcp_request)
                .await
                .is_ok();
        let mut response = dns_pressure_response_for_query(
            &request[..read],
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 45)),
            60,
        );
        response[2] |= 0x02;
        udp.send_to(&response, peer).await.unwrap();
        let _ = udp_truncated_sent.send(());
        tcp_started_before_truncated
    });
    let tcp_server = tokio::spawn(async move {
        let (mut stream, _) = tcp.accept().await.unwrap();
        let request_len = stream.read_u16().await.unwrap() as usize;
        let mut request = vec![0_u8; request_len];
        stream.read_exact(&mut request).await.unwrap();
        let _ = tcp_request_started.send(());
        wait_for_udp_truncated.await.unwrap();
        let response =
            dns_pressure_response_for_query(&request, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 46)), 60);
        stream.write_u16(response.len() as u16).await.unwrap();
        stream.write_all(&response).await.unwrap();
    });
    let upstream = parse_dns_upstream(
        1,
        "mixed",
        &format!("tcp+udp://{target}"),
        test_fallback_resolver(),
        0,
    )
    .unwrap();

    let response = time::timeout(
        Duration::from_secs(2),
        transport::forward_dns_to_upstream_async(
            &upstream,
            QUERY,
            &ResidentDnsPlan::asis(0),
            &Arc::new(ResidentDnsForwarderCache::default()),
            ProxyDnsRequestContext::from_timeout(RESIDENT_UDP_RESPONSE_TIMEOUT),
        ),
    )
    .await
    .expect("parallel TCP and UDP branches did not finish after the truncated UDP response")
    .unwrap();
    let tcp_started_before_truncated = time::timeout(Duration::from_secs(2), async {
        let tcp_started_before_truncated = udp_server.await.unwrap();
        tcp_server.await.unwrap();
        tcp_started_before_truncated
    })
    .await
    .expect("tcp+udp fixture servers did not finish");
    assert!(
        !tcp_started_before_truncated,
        "TCP was admitted before the UDP truncated response"
    );
    assert_eq!(&response[0..2], &QUERY[0..2]);
    assert_eq!(response[2] & 0x02, 0);
}

#[test]
fn dns_upstream_targets_use_matching_family_as_selector_fallback_tie_breaker() {
    let config = dns_upstream_routing_config_with_group(
        r#"
            domain(full: __DNS_UPSTREAM_HOST__) -> proxy
            fallback: direct
            "#
        .replace("__DNS_UPSTREAM_HOST__", TEST_DNS_UPSTREAM_HOST)
        .as_str(),
        r#"
            filter: name(node_a, node_b)
            policy: min
            "#,
    );
    let (router, upstream) = dns_upstream_router_for_config(&config);
    let group = router.proxy_groups.values().next().unwrap();
    group
        .record_check_result("node_a", NetworkType::DNS_UDP4, None, 1)
        .unwrap();
    group
        .record_check_result("node_b", NetworkType::DNS_UDP4, None, 2)
        .unwrap();
    group
        .record_check_result("node_b", NetworkType::DNS_UDP6, Some(50), 3)
        .unwrap();

    let plan = ResidentDnsPlan::asis(config.global.so_mark_from_dae)
        .with_upstream_routing(Some(Arc::new(router)));
    let (targets, failures) = transport::select_dns_upstream_targets(
        &plan,
        &upstream,
        vec![test_dns_upstream_target_v4(), test_dns_upstream_target_v6()],
        L4Proto::Udp,
    )
    .unwrap();

    assert!(failures.is_empty(), "{failures:?}");
    assert_eq!(targets[0].target, test_dns_upstream_target_v6());
    let ResidentDnsUpstreamSelection::Proxy { binding } = &targets[0].selection else {
        panic!("expected proxied DNS upstream target");
    };
    assert_eq!(binding.plan().node_tag, "node_b");
}

#[test]
fn dns_upstream_targets_keep_single_family_selector_fallback() {
    let config = dns_upstream_routing_config_with_group(
        r#"
            domain(full: __DNS_UPSTREAM_HOST__) -> proxy
            fallback: direct
            "#
        .replace("__DNS_UPSTREAM_HOST__", TEST_DNS_UPSTREAM_HOST)
        .as_str(),
        r#"
            filter: name(node_a, node_b)
            policy: min
            "#,
    );
    let (router, upstream) = dns_upstream_router_for_config(&config);
    let group = router.proxy_groups.values().next().unwrap();
    group
        .record_check_result("node_a", NetworkType::DNS_UDP4, None, 1)
        .unwrap();
    group
        .record_check_result("node_b", NetworkType::DNS_UDP4, None, 2)
        .unwrap();
    group
        .record_check_result("node_b", NetworkType::DNS_UDP6, Some(50), 3)
        .unwrap();

    let plan = ResidentDnsPlan::asis(config.global.so_mark_from_dae)
        .with_upstream_routing(Some(Arc::new(router)));
    let (targets, failures) = transport::select_dns_upstream_targets(
        &plan,
        &upstream,
        vec![test_dns_upstream_target_v4()],
        L4Proto::Udp,
    )
    .unwrap();

    assert!(failures.is_empty(), "{failures:?}");
    assert_eq!(targets[0].target, test_dns_upstream_target_v4());
    let ResidentDnsUpstreamSelection::Proxy { binding } = &targets[0].selection else {
        panic!("expected proxied DNS upstream target");
    };
    assert_eq!(binding.plan().node_tag, "node_b");
}

#[test]
fn dns_upstream_fixed_group_stays_fixed_across_udp_and_tcp_selection() {
    let config = dns_upstream_routing_config_with_group(
        r#"
            domain(full: __DNS_UPSTREAM_HOST__) -> proxy
            fallback: direct
            "#
        .replace("__DNS_UPSTREAM_HOST__", TEST_DNS_UPSTREAM_HOST)
        .as_str(),
        r#"
            filter: name(node_a, node_b)
            policy: fixed(0)
            "#,
    );
    let (router, upstream) = dns_upstream_router_for_config(&config);
    let group = router.proxy_groups.values().next().unwrap();
    group
        .record_check_result("node_a", NetworkType::DNS_UDP4, Some(300), 1)
        .unwrap();
    group
        .record_check_result("node_a", NetworkType::TCP4, Some(300), 2)
        .unwrap();

    for l4proto in [L4Proto::Udp, L4Proto::Tcp] {
        let selection = select_single_test_dns_upstream_target(
            &config,
            router.clone(),
            &upstream,
            test_dns_upstream_target_v4(),
            l4proto,
        );
        let ResidentDnsUpstreamSelection::Proxy { binding } = selection else {
            panic!("expected proxied DNS upstream selection");
        };
        assert_eq!(binding.plan().node_tag, "node_a");
    }
}

#[test]
fn dns_upstream_selection_respects_l4_routing_per_phase() {
    let input = r#"
        global {
          lan_interface: daerust0
          so_mark_from_dae: 1234
        }
        node {
          node_a: 'socks5://identity-1:credential-1@node-1.fixture.invalid:28001'
          node_b: 'socks5://identity-2:credential-2@node-2.fixture.invalid:28002'
        }
        group {
          udp_proxy {
            filter: name(node_a)
            policy: fixed(0)
          }
          tcp_proxy {
            filter: name(node_b)
            policy: fixed(0)
          }
        }
        routing {
          domain(full: __DNS_UPSTREAM_HOST__) && l4proto(udp) -> udp_proxy
          domain(full: __DNS_UPSTREAM_HOST__) && l4proto(tcp) -> tcp_proxy
          fallback: direct
        }
        dns {
          upstream {
            overseas: 'tcp+udp://__DNS_UPSTREAM_HOST__:53'
          }
          routing {
            request {
              fallback: overseas
            }
          }
        }
        "#
    .replace("__DNS_UPSTREAM_HOST__", TEST_DNS_UPSTREAM_HOST);
    let config = parse_config(&input);
    let (router, upstream) = dns_upstream_router_for_config(&config);

    let udp = select_single_test_dns_upstream_target(
        &config,
        router.clone(),
        &upstream,
        test_dns_upstream_target_v4(),
        L4Proto::Udp,
    );
    let tcp = select_single_test_dns_upstream_target(
        &config,
        router,
        &upstream,
        test_dns_upstream_target_v4(),
        L4Proto::Tcp,
    );

    let ResidentDnsUpstreamSelection::Proxy { binding } = udp else {
        panic!("expected UDP phase to select proxy");
    };
    assert_eq!(binding.plan().group_name, "udp_proxy");
    assert_eq!(binding.plan().node_tag, "node_a");

    let ResidentDnsUpstreamSelection::Proxy { binding } = tcp else {
        panic!("expected TCP phase to select proxy");
    };
    assert_eq!(binding.plan().group_name, "tcp_proxy");
    assert_eq!(binding.plan().node_tag, "node_b");
}

#[test]
fn dns_upstream_selection_respects_ipversion_routing_per_target() {
    let input = r#"
        global {
          lan_interface: daerust0
          so_mark_from_dae: 1234
        }
        node {
          node_a: 'socks5://identity-1:credential-1@node-1.fixture.invalid:28001'
          node_b: 'socks5://identity-2:credential-2@node-2.fixture.invalid:28002'
        }
        group {
          v4_proxy {
            filter: name(node_a)
            policy: fixed(0)
          }
          v6_proxy {
            filter: name(node_b)
            policy: fixed(0)
          }
        }
        routing {
          domain(full: __DNS_UPSTREAM_HOST__) && ipversion(4) -> v4_proxy
          domain(full: __DNS_UPSTREAM_HOST__) && ipversion(6) -> v6_proxy
          fallback: direct
        }
        dns {
          upstream {
            overseas: 'tcp+udp://__DNS_UPSTREAM_HOST__:53'
          }
          routing {
            request {
              fallback: overseas
            }
          }
        }
        "#
    .replace("__DNS_UPSTREAM_HOST__", TEST_DNS_UPSTREAM_HOST);
    let config = parse_config(&input);
    let (router, upstream) = dns_upstream_router_for_config(&config);

    let v4 = select_single_test_dns_upstream_target(
        &config,
        router.clone(),
        &upstream,
        test_dns_upstream_target_v4(),
        L4Proto::Udp,
    );
    let v6 = select_single_test_dns_upstream_target(
        &config,
        router,
        &upstream,
        test_dns_upstream_target_v6(),
        L4Proto::Udp,
    );

    let ResidentDnsUpstreamSelection::Proxy { binding } = v4 else {
        panic!("expected IPv4 target to select proxy");
    };
    assert_eq!(binding.plan().group_name, "v4_proxy");
    assert_eq!(binding.plan().node_tag, "node_a");

    let ResidentDnsUpstreamSelection::Proxy { binding } = v6 else {
        panic!("expected IPv6 target to select proxy");
    };
    assert_eq!(binding.plan().group_name, "v6_proxy");
    assert_eq!(binding.plan().node_tag, "node_b");
}

#[test]
fn dns_upstream_targets_choose_lower_latency_matching_proxy_candidate() {
    let config = dns_upstream_routing_config_with_group(
        r#"
            domain(full: __DNS_UPSTREAM_HOST__) -> proxy
            fallback: direct
            "#
        .replace("__DNS_UPSTREAM_HOST__", TEST_DNS_UPSTREAM_HOST)
        .as_str(),
        r#"
            filter: name(node_a, node_b)
            policy: min
            "#,
    );
    let (router, upstream) = dns_upstream_router_for_config(&config);
    let group = router.proxy_groups.values().next().unwrap();
    group
        .record_check_result("node_a", NetworkType::DNS_UDP4, Some(200), 1)
        .unwrap();
    group
        .record_check_result("node_b", NetworkType::DNS_UDP4, Some(300), 2)
        .unwrap();
    group
        .record_check_result("node_a", NetworkType::DNS_UDP6, Some(300), 3)
        .unwrap();
    group
        .record_check_result("node_b", NetworkType::DNS_UDP6, Some(50), 4)
        .unwrap();

    let plan = ResidentDnsPlan::asis(config.global.so_mark_from_dae)
        .with_upstream_routing(Some(Arc::new(router)));
    let (targets, failures) = transport::select_dns_upstream_targets(
        &plan,
        &upstream,
        vec![test_dns_upstream_target_v4(), test_dns_upstream_target_v6()],
        L4Proto::Udp,
    )
    .unwrap();

    assert!(failures.is_empty(), "{failures:?}");
    assert_eq!(targets[0].target, test_dns_upstream_target_v6());
    let ResidentDnsUpstreamSelection::Proxy { binding } = &targets[0].selection else {
        panic!("expected proxied DNS upstream target");
    };
    assert_eq!(binding.plan().node_tag, "node_b");
}

fn query_with_qtype(qtype: u16) -> Vec<u8> {
    let mut query = QUERY.to_vec();
    let offset = query.len() - 4;
    query[offset..offset + 2].copy_from_slice(&qtype.to_be_bytes());
    query
}

fn a_response(address: [u8; 4]) -> Vec<u8> {
    a_response_for_query(QUERY, address)
}

fn a_response_for_query(query: &[u8], address: [u8; 4]) -> Vec<u8> {
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
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&60_u32.to_be_bytes());
    response.extend_from_slice(&4_u16.to_be_bytes());
    response.extend_from_slice(&address);
    response
}

fn response_with_question_qtype(mut response: Vec<u8>, qtype: u16) -> Vec<u8> {
    let view = DnsPacketView::parse(&response).unwrap();
    let qtype_offset = view.answer_offset() - 4;
    response[qtype_offset..qtype_offset + 2].copy_from_slice(&qtype.to_be_bytes());
    response
}

fn empty_response_for_query(query: &[u8]) -> Vec<u8> {
    let view = DnsPacketView::parse(query).unwrap();
    let mut response = Vec::new();
    response.extend_from_slice(&query[0..2]);
    response.extend_from_slice(&0x8180_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&query[12..view.answer_offset()]);
    response
}

fn domain_routing_test_matcher() -> RoutingMatcher {
    RoutingMatcher::from_fixture_value(&serde_json::json!({
        "domain_sets": [
            {"bit": 0, "key": "suffix", "patterns": ["example.com"]}
        ],
        "matches": [
            {"type": "domain_set", "outbound": "direct"},
            {"type": "fallback", "outbound": "block"}
        ]
    }))
    .unwrap()
}

#[test]
fn resident_dns_domain_routing_update_plan_records_accepted_response_ips() {
    let matcher = domain_routing_test_matcher();
    let mut bitmap_buffer = Vec::new();
    let response = a_response([203, 0, 113, 42]);
    let cache_plan = build_response_cache_plan_from_packet(1_700_000_000, &response, None)
        .unwrap()
        .unwrap();
    let plan =
        build_resident_dns_domain_routing_update_plan(&matcher, &mut bitmap_buffer, &cache_plan)
            .unwrap()
            .unwrap();

    assert_eq!(plan.key.qname, "example.com.");
    assert_eq!(plan.entry.route_owner_key, "example.com.|1|1");
    assert_eq!(plan.ips, vec![ip_to_key("203.0.113.42".parse().unwrap())]);
    assert_eq!(plan.entry.domain_bitmap, vec![0x1]);
}

#[test]
fn resident_dns_domain_routing_reload_plan_recomputes_bitmap_from_new_matcher() {
    let old_matcher = RoutingMatcher::from_fixture_value(&serde_json::json!({
        "domain_sets": [
            {"bit": 3, "key": "suffix", "patterns": ["example.com"]}
        ],
        "matches": [
            {"type": "domain_set", "outbound": "direct"},
            {"type": "fallback", "outbound": "block"}
        ]
    }))
    .unwrap();
    let new_matcher = domain_routing_test_matcher();
    let mut bitmap_buffer = Vec::new();
    let response = a_response([203, 0, 113, 42]);
    let cache_plan = build_response_cache_plan_from_packet(1_700_000_000, &response, None)
        .unwrap()
        .unwrap();
    let old_plan = build_resident_dns_domain_routing_update_plan(
        &old_matcher,
        &mut bitmap_buffer,
        &cache_plan,
    )
    .unwrap()
    .unwrap();
    assert_eq!(old_plan.entry.domain_bitmap, vec![0x8]);

    let reloaded = build_resident_dns_domain_routing_update_plan_from_entry(
        &new_matcher,
        &mut bitmap_buffer,
        &old_plan.key,
        &old_plan.entry,
    )
    .unwrap()
    .unwrap();

    assert_eq!(reloaded.entry.route_owner_key, "example.com.|1|1");
    assert_eq!(reloaded.entry.domain_bitmap, vec![0x1]);
    assert_eq!(
        reloaded.ips,
        vec![ip_to_key("203.0.113.42".parse().unwrap())]
    );
}

#[test]
fn resident_dns_domain_routing_update_plan_skips_unmatched_domain() {
    let matcher = domain_routing_test_matcher();
    let mut bitmap_buffer = Vec::new();
    let mut response = a_response([203, 0, 113, 42]);
    response[13] = b'i';
    response[14] = b'n';
    response[15] = b'v';
    response[16] = b'a';
    response[17] = b'l';
    response[18] = b'i';
    response[19] = b'd';
    let cache_plan = build_response_cache_plan_from_packet(1_700_000_000, &response, None)
        .unwrap()
        .unwrap();

    let plan =
        build_resident_dns_domain_routing_update_plan(&matcher, &mut bitmap_buffer, &cache_plan)
            .unwrap();

    assert_eq!(plan, None);
}

#[test]
fn resident_dns_response_cache_honors_fixed_domain_ttl() {
    let request = DnsPacketView::parse(QUERY).unwrap();
    let cache_key = test_asis_cache_key(&request);
    let mut plan = ResidentDnsPlan::asis(0);
    plan.fixed_domain_ttl = Arc::new(BTreeMap::from([("example.com".to_owned(), 0)]));

    record_accepted_dns_response(&plan, &cache_key, &a_response([203, 0, 113, 42])).unwrap();

    let mut cached_response = Vec::new();
    assert!(
        !plan
            .cache
            .lookup_response_into(&cache_key, &request, false, &mut cached_response)
            .unwrap()
    );
    assert!(cached_response.is_empty());
    assert!(
        plan.cache
            .lookup_response_into(&cache_key, &request, true, &mut cached_response)
            .unwrap()
    );
    assert!(!cached_response.is_empty());
}

#[test]
fn resident_dns_response_cache_is_scoped_by_asis_destination() {
    let cache = ResidentDnsRuntimeCache::default();
    let request = DnsPacketView::parse(QUERY).unwrap();
    let response = a_response([203, 0, 113, 42]);
    let now = unix_now();
    let cache_plan = build_response_cache_plan_from_packet(now, &response, None)
        .unwrap()
        .unwrap();
    let first = test_scoped_cache_key(
        &request,
        ResidentDnsResponseCacheScope::AsIs {
            original_dst: "192.0.2.1:53".parse().unwrap(),
        },
    );
    let second = test_scoped_cache_key(
        &request,
        ResidentDnsResponseCacheScope::AsIs {
            original_dst: "192.0.2.2:53".parse().unwrap(),
        },
    );
    cache
        .insert_response(now, first.with_base(cache_plan.key), cache_plan.entry)
        .unwrap();

    let mut cached_response = Vec::new();
    assert!(
        !cache
            .lookup_response_into(&second, &request, false, &mut cached_response)
            .unwrap()
    );
    assert!(
        cache
            .lookup_response_into(&first, &request, false, &mut cached_response)
            .unwrap()
    );
}

#[test]
fn resident_dns_response_cache_is_scoped_by_upstream_identity() {
    let cache = ResidentDnsRuntimeCache::default();
    let request = DnsPacketView::parse(QUERY).unwrap();
    let response = a_response([203, 0, 113, 42]);
    let now = unix_now();
    let cache_plan = build_response_cache_plan_from_packet(now, &response, None)
        .unwrap()
        .unwrap();
    let first = test_scoped_cache_key(
        &request,
        ResidentDnsResponseCacheScope::Upstream {
            index: 1,
            scheme: ResidentDnsUpstreamScheme::TcpUdp,
            authority: "resolver-a.fixture.invalid:53".to_owned(),
            path: String::new(),
        },
    );
    let second = test_scoped_cache_key(
        &request,
        ResidentDnsResponseCacheScope::Upstream {
            index: 2,
            scheme: ResidentDnsUpstreamScheme::TcpUdp,
            authority: "resolver-b.fixture.invalid:53".to_owned(),
            path: String::new(),
        },
    );
    cache
        .insert_response(now, first.with_base(cache_plan.key), cache_plan.entry)
        .unwrap();

    let mut cached_response = Vec::new();
    assert!(
        !cache
            .lookup_response_into(&second, &request, false, &mut cached_response)
            .unwrap()
    );
    assert!(
        cache
            .lookup_response_into(&first, &request, false, &mut cached_response)
            .unwrap()
    );
}

#[test]
fn resident_dns_response_cache_reload_snapshot_restores_live_entries() {
    let cache = ResidentDnsRuntimeCache::default();
    let request = DnsPacketView::parse(QUERY).unwrap();
    let response = a_response([203, 0, 113, 42]);
    let now = unix_now();
    let cache_plan = build_response_cache_plan_from_packet(now, &response, None)
        .unwrap()
        .unwrap();
    let cache_key = test_asis_cache_key(&request);
    cache
        .insert_response(
            now,
            cache_key.with_base(cache_plan.key.clone()),
            cache_plan.entry,
        )
        .unwrap();
    let snapshot = cache.snapshot_for_reload().unwrap();
    let restored = ResidentDnsRuntimeCache::default();

    assert_eq!(restored.restore_reload_snapshot(&snapshot).unwrap(), 1);

    let mut cached_response = Vec::new();
    assert!(
        restored
            .lookup_response_into(&cache_key, &request, false, &mut cached_response)
            .unwrap()
    );
    assert!(!cached_response.is_empty());
}

#[test]
fn resident_dns_response_cache_removes_all_scoped_siblings_for_base_key() {
    let cache = ResidentDnsRuntimeCache::default();
    let request = DnsPacketView::parse(QUERY).unwrap();
    let response = a_response([203, 0, 113, 42]);
    let now = unix_now();
    let cache_plan = build_response_cache_plan_from_packet(now, &response, None)
        .unwrap()
        .unwrap();
    let base = cache_plan.key.clone();
    for original_dst in ["192.0.2.1:53", "192.0.2.2:53"] {
        let key = test_scoped_cache_key(
            &request,
            ResidentDnsResponseCacheScope::AsIs {
                original_dst: original_dst.parse().unwrap(),
            },
        );
        cache
            .insert_response(
                now,
                key.with_base(cache_plan.key.clone()),
                cache_plan.entry.clone(),
            )
            .unwrap();
    }
    assert_eq!(cache.entry_len(), 2);
    assert_eq!(cache.deadline_len(), 2);
    let removed = cache.remove_base_key(&base).unwrap();
    assert_eq!(removed.len(), 2);
    assert_eq!(cache.entry_len(), 0);
    assert_eq!(cache.deadline_len(), 0);
}

#[test]
fn resident_dns_response_cache_base_lookup_is_limited_to_scoped_siblings() {
    let cache = ResidentDnsRuntimeCache::default();
    let response = a_response([203, 0, 113, 42]);
    let now = unix_now();
    let cache_plan = build_response_cache_plan_from_packet(now, &response, None)
        .unwrap()
        .unwrap();
    for qname in ["before.invalid", "target.invalid", "z-after.invalid"] {
        let scope = if qname == "target.invalid" {
            ResidentDnsResponseCacheScope::AsIs {
                original_dst: "192.0.2.53:53".parse().unwrap(),
            }
        } else {
            ResidentDnsResponseCacheScope::Reject
        };
        cache
            .insert_response(
                now,
                ResidentDnsResponseCacheKey::new(DnsCacheKey::new(qname, 1, 1), scope),
                cache_plan.entry.clone(),
            )
            .unwrap();
    }

    assert!(
        cache
            .lookup_key_has_any_ip(&DnsCacheKey::new("target.invalid", 1, 1), false)
            .unwrap()
    );
    assert!(
        !cache
            .lookup_key_has_any_ip(&DnsCacheKey::new("missing.invalid", 1, 1), false)
            .unwrap()
    );
}

#[tokio::test]
async fn resident_dns_request_reject_removes_scoped_cached_responses() {
    let input = r#"
        global {}
        routing {}
        dns {
          upstream {
            primary: 'udp://127.0.0.1:53'
          }
          routing {
            request {
              qtype(a) -> reject
              fallback: primary
            }
          }
        }
        "#;
    let config = parse_config(input);
    let geodata = test_geodata();
    let plan = build_resident_dns_plan(&config, &geodata).unwrap();
    let request = DnsPacketView::parse(QUERY).unwrap();
    let response = a_response([203, 0, 113, 42]);
    let now = unix_now();
    let cache_plan = build_response_cache_plan_from_packet(now, &response, None)
        .unwrap()
        .unwrap();
    let base = cache_plan.key.clone();
    let asis = test_scoped_cache_key(
        &request,
        ResidentDnsResponseCacheScope::AsIs {
            original_dst: "192.0.2.1:53".parse().unwrap(),
        },
    );
    let upstream = test_scoped_cache_key(
        &request,
        ResidentDnsResponseCacheScope::Upstream {
            index: 0,
            scheme: ResidentDnsUpstreamScheme::Udp,
            authority: "127.0.0.1:53".to_owned(),
            path: String::new(),
        },
    );
    plan.cache
        .insert_response(now, asis.with_base(base.clone()), cache_plan.entry.clone())
        .unwrap();
    plan.cache
        .insert_response(now, upstream.with_base(base), cache_plan.entry)
        .unwrap();
    assert_eq!(plan.cache.entry_len(), 2);

    let rejected = handle_resident_dns_udp_async(&plan, "127.0.0.1:53".parse().unwrap(), QUERY)
        .await
        .unwrap();

    assert_eq!(plan.cache.entry_len(), 0);
    assert_eq!(&rejected[0..2], &QUERY[0..2]);
    assert_eq!(rejected[3] & 0x0f, 0);
}

#[tokio::test]
async fn resident_dns_ipversion_prefer_rejects_non_preferred_when_preferred_has_ip() {
    let mut plan = ResidentDnsPlan::asis(0);
    plan.ipversion_prefer = Some(DNS_QTYPE_A);
    let a_query = DnsPacketView::parse(QUERY).unwrap();
    let a_cache_key = test_asis_cache_key(&a_query);
    record_accepted_dns_response(&plan, &a_cache_key, &a_response([203, 0, 113, 42])).unwrap();
    let aaaa_query = query_with_qtype(DNS_QTYPE_AAAA);
    let aaaa_request = DnsPacketView::parse(&aaaa_query).unwrap();
    let aaaa_cache_key = test_asis_cache_key(&aaaa_request);
    record_accepted_dns_response(
        &plan,
        &aaaa_cache_key,
        &response_with_question_qtype(a_response([198, 51, 100, 42]), DNS_QTYPE_AAAA),
    )
    .unwrap();

    let response =
        handle_resident_dns_udp_async(&plan, "127.0.0.1:53".parse().unwrap(), &aaaa_query)
            .await
            .unwrap();

    assert_eq!(&response[0..2], &[0x12, 0x34]);
    assert_eq!(u16::from_be_bytes([response[2], response[3]]) & 0x000f, 0);
    assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
}

#[tokio::test]
async fn resident_dns_ipversion_prefer_does_not_synthesize_preferred_lookup() {
    let socket = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let upstream_addr = socket.local_addr().unwrap();
    let received = Arc::new(AtomicUsize::new(0));
    let server_received = Arc::clone(&received);
    let query = query_with_qtype(DNS_QTYPE_AAAA);
    let expected_queries = DnsPacketView::parse(&query).unwrap().question_count();
    let server = tokio::spawn(async move {
        let mut buf = vec![0_u8; DNS_RESPONSE_READ_LIMIT];
        loop {
            let timeout = if server_received.load(Ordering::Relaxed) == 0 {
                RESIDENT_UDP_RESPONSE_TIMEOUT
            } else {
                dns_ipversion_preference_wait_timeout() + dns_ipversion_preference_wait_timeout()
            };
            let Ok(Ok((read, peer))) = time::timeout(timeout, socket.recv_from(&mut buf)).await
            else {
                break;
            };
            server_received.fetch_add(1, Ordering::Relaxed);
            let response = empty_response_for_query(&buf[..read]);
            socket.send_to(&response, peer).await.unwrap();
        }
    });

    let mut plan = ResidentDnsPlan::asis(0);
    plan.ipversion_prefer = Some(DNS_QTYPE_A);
    let response = handle_resident_dns_udp_async(&plan, upstream_addr, &query)
        .await
        .unwrap();
    assert_eq!(&response[0..2], &query[0..2]);
    server.await.unwrap();

    assert_eq!(received.load(Ordering::Relaxed), expected_queries);
}

#[tokio::test]
#[ignore = "explicit parameterized DNS pressure test"]
async fn resident_dns_pressure_uses_parameterized_mock_upstream() {
    let Some(config) = dns_pressure_config_from_env() else {
        println!(
            "dns_pressure_result {}",
            serde_json::json!({
                "status": "skipped",
                "reason": format!("{DNS_PRESSURE_ENABLE_ENV} is not enabled"),
            })
        );
        return;
    };

    let upstream = tokio::net::UdpSocket::bind((config.bind_ip, 0))
        .await
        .unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_authority = upstream_addr.to_string();
    let received = Arc::new(AtomicUsize::new(0));
    let server_received = Arc::clone(&received);
    let response_ip = config.response_ip;
    let response_ttl = config.response_ttl;
    let upstream_expected = config.key_space.min(config.total);
    let server = tokio::spawn(async move {
        let mut buf = vec![0_u8; DNS_RESPONSE_READ_LIMIT];
        while server_received.load(Ordering::Relaxed) < upstream_expected {
            let Ok((read, peer)) = upstream.recv_from(&mut buf).await else {
                break;
            };
            server_received.fetch_add(1, Ordering::Relaxed);
            let response = dns_pressure_response_for_query(&buf[..read], response_ip, response_ttl);
            let _ = upstream.send_to(&response, peer).await;
        }
    });

    let input = r#"
        global {}
        routing {}
        dns {
          upstream {
            __UPSTREAM_TAG__: '__UPSTREAM_SCHEME__://__UPSTREAM_AUTHORITY__'
          }
          routing {
            request {
              fallback: __UPSTREAM_TAG__
            }
          }
        }
        "#
    .replace("__UPSTREAM_TAG__", &config.upstream_tag)
    .replace("__UPSTREAM_SCHEME__", &config.upstream_scheme)
    .replace("__UPSTREAM_AUTHORITY__", &upstream_authority);
    let mut plan = build_resident_dns_plan(&parse_config(&input), &test_geodata()).unwrap();
    if let Some(direct_shards) = config.direct_shards {
        Arc::get_mut(&mut plan.forwarders)
            .expect("DNS pressure plan must exclusively own its forwarder cache")
            .udp_runtime
            .direct_shards = direct_shards;
    }
    let plan = Arc::new(plan);
    let semaphore = Arc::new(tokio::sync::Semaphore::new(config.concurrency));
    let latencies = Arc::new(Mutex::new(Vec::with_capacity(config.total)));
    let failures = Arc::new(Mutex::new(Vec::<String>::new()));
    let trace_qname = dns_pressure_qname(&config.qname_prefix, 0, &config.qname_suffix);
    let trace_query = build_dns_query_packet(1, &trace_qname, config.qtype).unwrap();
    let trace_request = DnsPacketView::parse(&trace_query).unwrap();
    let started = std::time::Instant::now();
    let trace_started = std::time::Instant::now();
    let trace =
        match handle_resident_dns_local_trace_async(&plan, upstream_addr, &trace_query).await {
            Ok(result) => {
                if let Err(err) =
                    validate_dns_response_for_request(&trace_request, &result.response, true)
                {
                    failures
                        .lock()
                        .unwrap()
                        .push(format!("{trace_qname}: {err}"));
                } else {
                    latencies
                        .lock()
                        .unwrap()
                        .push(trace_started.elapsed().as_micros());
                }
                dns_pressure_trace_json(&result.trace)
            }
            Err(err) => {
                failures
                    .lock()
                    .unwrap()
                    .push(format!("{trace_qname}: {err}"));
                serde_json::json!({"status": "fail", "error": err})
            }
        };
    let mut tasks = Vec::with_capacity(config.total);

    for index in 1..config.total {
        let permit = Arc::clone(&semaphore).acquire_owned().await.unwrap();
        let plan = Arc::clone(&plan);
        let latencies = Arc::clone(&latencies);
        let failures = Arc::clone(&failures);
        let qname = dns_pressure_qname(
            &config.qname_prefix,
            index % config.key_space,
            &config.qname_suffix,
        );
        let qtype = config.qtype;
        tasks.push(tokio::spawn(async move {
            let _permit = permit;
            let query =
                build_dns_query_packet((index as u16).wrapping_add(1), &qname, qtype).unwrap();
            let request = DnsPacketView::parse(&query).unwrap();
            let query_started = std::time::Instant::now();
            match handle_resident_dns_udp_async(&plan, upstream_addr, &query).await {
                Ok(response) => {
                    if let Err(err) = validate_dns_response_for_request(&request, &response, true) {
                        let mut failures = failures.lock().unwrap();
                        failures.push(format!("{qname}: {err}"));
                    } else {
                        let mut latencies = latencies.lock().unwrap();
                        latencies.push(query_started.elapsed().as_micros());
                    }
                }
                Err(err) => {
                    let mut failures = failures.lock().unwrap();
                    failures.push(format!("{qname}: {err}"));
                }
            }
        }));
    }

    for task in tasks {
        task.await.unwrap();
    }
    let elapsed = started.elapsed();
    if received.load(Ordering::Relaxed) < upstream_expected {
        server.abort();
        let _ = server.await;
    } else {
        server.await.unwrap();
    }

    let mut latency_values = latencies.lock().unwrap().clone();
    latency_values.sort_unstable();
    let success = latency_values.len();
    let failure_values = failures.lock().unwrap().clone();
    let failure = failure_values.len();
    let percentile = |percent: usize| -> u128 {
        if latency_values.is_empty() {
            return 0;
        }
        let rank = latency_values
            .len()
            .saturating_sub(1)
            .saturating_mul(percent)
            / 100;
        latency_values[rank]
    };
    let forwarder_metrics = plan.forwarders.metrics.snapshot();
    println!(
        "dns_pressure_result {}",
        serde_json::json!({
            "status": if failure == 0 && success == config.total { "pass" } else { "fail" },
            "total": config.total,
            "concurrency": config.concurrency,
            "success": success,
            "failure": failure,
            "upstream_received": received.load(Ordering::Relaxed),
            "upstream_expected": upstream_expected,
            "key_space": config.key_space,
            "elapsed_ms": elapsed.as_millis(),
            "qps": success as f64 / elapsed.as_secs_f64(),
            "latency_us": {
                "p50": percentile(50),
                "p95": percentile(95),
                "p99": percentile(99),
            },
            "dns_udp": {
                "actors_opened": forwarder_metrics["dnsUdpActorsOpened"],
                "actors_closed": forwarder_metrics["dnsUdpActorsClosed"],
                "pending_current": forwarder_metrics["dnsUdpPendingCurrent"],
                "pending_maximum": forwarder_metrics["dnsUdpPendingMaximum"],
                "pending_rejected": forwarder_metrics["dnsUdpPendingRejected"],
                "queue_wait_timeouts": forwarder_metrics["dnsUdpQueueWaitTimeouts"],
                "id_exhausted": forwarder_metrics["dnsUdpIdExhausted"],
                "retries": forwarder_metrics["dnsUdpRetries"],
            },
            "trace": trace,
            "first_errors": failure_values.into_iter().take(5).collect::<Vec<_>>(),
        })
    );
}

#[tokio::test]
#[ignore = "requires an explicitly configured live DNS upstream"]
async fn resident_dns_live_upstream_pressure_uses_parameterized_upstream() {
    let Some(config) = dns_live_pressure_config_from_env() else {
        println!(
            "dns_live_pressure_result {}",
            serde_json::json!({
                "status": "skipped",
                "reason": format!("{DNS_LIVE_PRESSURE_ENABLE_ENV} is not enabled"),
            })
        );
        return;
    };

    let input = dns_live_pressure_config_input(&config);
    let parsed = parse_config(&input);
    let geodata = test_geodata();
    let mut plan = build_resident_dns_plan(&parsed, &geodata).unwrap();
    if config.proxy.is_some() {
        let runtime_plan = build_resident_dataplane_plan(&parsed).unwrap();
        let matcher =
            build_resident_userspace_routing_matcher_with_geodata(&parsed, &geodata).unwrap();
        let router = ResidentDnsUpstreamRouter::new(
            matcher,
            share_resident_proxy_groups(runtime_plan.proxies.clone()),
            parsed.global.so_mark_from_dae,
            None,
        );
        plan = plan.with_upstream_routing(Some(Arc::new(router)));
    }
    let plan = Arc::new(plan);
    let semaphore = Arc::new(tokio::sync::Semaphore::new(config.concurrency));
    let latencies = Arc::new(Mutex::new(Vec::with_capacity(config.total)));
    let failures = Arc::new(Mutex::new(Vec::<String>::new()));
    let trace_qname = dns_pressure_qname(&config.qname_prefix, 0, &config.qname_suffix);
    let trace_query = build_dns_query_packet(1, &trace_qname, config.qtype).unwrap();
    let trace_request = DnsPacketView::parse(&trace_query).unwrap();
    let started = std::time::Instant::now();
    let trace_started = std::time::Instant::now();
    let trace =
        match handle_resident_dns_local_trace_async(&plan, config.original_dst, &trace_query).await
        {
            Ok(result) => {
                if let Err(err) =
                    validate_dns_response_for_request(&trace_request, &result.response, true)
                {
                    failures
                        .lock()
                        .unwrap()
                        .push(format!("{trace_qname}: {err}"));
                } else {
                    latencies
                        .lock()
                        .unwrap()
                        .push(trace_started.elapsed().as_micros());
                }
                dns_pressure_trace_json(&result.trace)
            }
            Err(err) => {
                failures
                    .lock()
                    .unwrap()
                    .push(format!("{trace_qname}: {err}"));
                serde_json::json!({"status": "fail", "error": err})
            }
        };
    let mut tasks = Vec::with_capacity(config.total);

    for index in 1..config.total {
        let permit = Arc::clone(&semaphore).acquire_owned().await.unwrap();
        let plan = Arc::clone(&plan);
        let latencies = Arc::clone(&latencies);
        let failures = Arc::clone(&failures);
        let qname = dns_pressure_qname(&config.qname_prefix, index, &config.qname_suffix);
        let qtype = config.qtype;
        let original_dst = config.original_dst;
        tasks.push(tokio::spawn(async move {
            let _permit = permit;
            let query =
                build_dns_query_packet((index as u16).wrapping_add(1), &qname, qtype).unwrap();
            let request = DnsPacketView::parse(&query).unwrap();
            let query_started = std::time::Instant::now();
            match handle_resident_dns_udp_async(&plan, original_dst, &query).await {
                Ok(response) => {
                    if let Err(err) = validate_dns_response_for_request(&request, &response, true) {
                        failures.lock().unwrap().push(format!("{qname}: {err}"));
                    } else {
                        latencies
                            .lock()
                            .unwrap()
                            .push(query_started.elapsed().as_micros());
                    }
                }
                Err(err) => {
                    failures.lock().unwrap().push(format!("{qname}: {err}"));
                }
            }
        }));
    }

    for task in tasks {
        task.await.unwrap();
    }
    let elapsed = started.elapsed();
    let mut latency_values = latencies.lock().unwrap().clone();
    latency_values.sort_unstable();
    let success = latency_values.len();
    let failure_values = failures.lock().unwrap().clone();
    let failure = failure_values.len();
    let percentile = |percent: usize| -> u128 {
        if latency_values.is_empty() {
            return 0;
        }
        let rank = latency_values
            .len()
            .saturating_sub(1)
            .saturating_mul(percent)
            / 100;
        latency_values[rank]
    };
    println!(
        "dns_live_pressure_result {}",
        serde_json::json!({
            "status": if failure == 0 && success == config.total { "pass" } else { "fail" },
            "total": config.total,
            "concurrency": config.concurrency,
            "success": success,
            "failure": failure,
            "elapsed_ms": elapsed.as_millis(),
            "qps": success as f64 / elapsed.as_secs_f64(),
            "latency_us": {
                "p50": percentile(50),
                "p95": percentile(95),
                "p99": percentile(99),
            },
            "trace": trace,
            "first_errors": failure_values.into_iter().take(5).collect::<Vec<_>>(),
        })
    );
}

struct DnsPressureConfig {
    bind_ip: IpAddr,
    total: usize,
    concurrency: usize,
    qname_prefix: String,
    qname_suffix: String,
    qtype: u16,
    upstream_tag: String,
    upstream_scheme: String,
    response_ip: IpAddr,
    response_ttl: u32,
    direct_shards: Option<usize>,
    key_space: usize,
}

struct DnsLivePressureConfig {
    total: usize,
    concurrency: usize,
    qname_prefix: String,
    qname_suffix: String,
    qtype: u16,
    upstream_tag: String,
    upstream_link: String,
    original_dst: SocketAddr,
    proxy: Option<DnsLivePressureProxyConfig>,
}

struct DnsLivePressureProxyConfig {
    node_tag: String,
    group_name: String,
    link: String,
    upstream_host_match: String,
}

fn dns_pressure_config_from_env() -> Option<DnsPressureConfig> {
    if std::env::var(DNS_PRESSURE_ENABLE_ENV).ok().as_deref() != Some("1") {
        return None;
    }
    Some(DnsPressureConfig {
        bind_ip: dns_pressure_env(DNS_PRESSURE_BIND_IP_ENV).parse().unwrap(),
        total: dns_pressure_env(DNS_PRESSURE_TOTAL_ENV)
            .parse::<usize>()
            .unwrap()
            .max(1),
        concurrency: dns_pressure_env(DNS_PRESSURE_CONCURRENCY_ENV)
            .parse::<usize>()
            .unwrap()
            .max(1),
        qname_prefix: dns_pressure_env(DNS_PRESSURE_QNAME_PREFIX_ENV),
        qname_suffix: dns_pressure_env(DNS_PRESSURE_QNAME_SUFFIX_ENV),
        qtype: dns_pressure_env(DNS_PRESSURE_QTYPE_ENV).parse().unwrap(),
        upstream_tag: dns_pressure_env(DNS_PRESSURE_UPSTREAM_TAG_ENV),
        upstream_scheme: dns_pressure_env(DNS_PRESSURE_UPSTREAM_SCHEME_ENV),
        response_ip: dns_pressure_env(DNS_PRESSURE_RESPONSE_IP_ENV)
            .parse()
            .unwrap(),
        response_ttl: dns_pressure_env(DNS_PRESSURE_RESPONSE_TTL_ENV)
            .parse()
            .unwrap(),
        direct_shards: std::env::var(DNS_PRESSURE_DIRECT_SHARDS_ENV)
            .ok()
            .map(|value| value.parse::<usize>().unwrap().max(1)),
        key_space: std::env::var(DNS_PRESSURE_KEY_SPACE_ENV)
            .ok()
            .map(|value| value.parse::<usize>().unwrap().max(1))
            .unwrap_or_else(|| {
                dns_pressure_env(DNS_PRESSURE_TOTAL_ENV)
                    .parse::<usize>()
                    .unwrap()
                    .max(1)
            }),
    })
}

fn dns_live_pressure_config_from_env() -> Option<DnsLivePressureConfig> {
    if std::env::var(DNS_LIVE_PRESSURE_ENABLE_ENV).ok().as_deref() != Some("1") {
        return None;
    }
    let proxy = match std::env::var(DNS_LIVE_PRESSURE_PROXY_LINK_ENV) {
        Ok(link) if !link.trim().is_empty() => Some(DnsLivePressureProxyConfig {
            node_tag: dns_pressure_env(DNS_LIVE_PRESSURE_PROXY_NODE_TAG_ENV),
            group_name: dns_pressure_env(DNS_LIVE_PRESSURE_PROXY_GROUP_ENV),
            link,
            upstream_host_match: dns_pressure_env(DNS_LIVE_PRESSURE_UPSTREAM_HOST_MATCH_ENV),
        }),
        _ => None,
    };
    Some(DnsLivePressureConfig {
        total: dns_pressure_env(DNS_LIVE_PRESSURE_TOTAL_ENV)
            .parse::<usize>()
            .unwrap()
            .max(1),
        concurrency: dns_pressure_env(DNS_LIVE_PRESSURE_CONCURRENCY_ENV)
            .parse::<usize>()
            .unwrap()
            .max(1),
        qname_prefix: dns_pressure_env(DNS_LIVE_PRESSURE_QNAME_PREFIX_ENV),
        qname_suffix: dns_pressure_env(DNS_LIVE_PRESSURE_QNAME_SUFFIX_ENV),
        qtype: dns_pressure_env(DNS_LIVE_PRESSURE_QTYPE_ENV)
            .parse()
            .unwrap(),
        upstream_tag: dns_pressure_env(DNS_LIVE_PRESSURE_UPSTREAM_TAG_ENV),
        upstream_link: dns_pressure_env(DNS_LIVE_PRESSURE_UPSTREAM_LINK_ENV),
        original_dst: dns_pressure_env(DNS_LIVE_PRESSURE_ORIGINAL_DST_ENV)
            .parse()
            .unwrap(),
        proxy,
    })
}

fn dns_live_pressure_config_input(config: &DnsLivePressureConfig) -> String {
    let base = r#"
        global {}
        __NODE__
        __GROUP__
        routing {
          __ROUTING__
        }
        dns {
          upstream {
            __UPSTREAM_TAG__: '__UPSTREAM_LINK__'
          }
          routing {
            request {
              fallback: __UPSTREAM_TAG__
            }
          }
        }
        "#;
    let (node, group, routing) = match &config.proxy {
        Some(proxy) => (
            r#"
        node {
          __PROXY_NODE_TAG__: '__PROXY_LINK__'
        }
        "#
            .to_owned()
            .replace("__PROXY_NODE_TAG__", &proxy.node_tag)
            .replace("__PROXY_LINK__", &proxy.link),
            r#"
        group {
          __PROXY_GROUP__ {
            filter: name(__PROXY_NODE_TAG__)
            policy: fixed(0)
          }
        }
        "#
            .to_owned()
            .replace("__PROXY_GROUP__", &proxy.group_name)
            .replace("__PROXY_NODE_TAG__", &proxy.node_tag),
            r#"
          domain(full: __UPSTREAM_HOST_MATCH__) -> __PROXY_GROUP__
          fallback: direct
        "#
            .to_owned()
            .replace("__UPSTREAM_HOST_MATCH__", &proxy.upstream_host_match)
            .replace("__PROXY_GROUP__", &proxy.group_name),
        ),
        None => (String::new(), String::new(), String::new()),
    };
    base.replace("__NODE__", &node)
        .replace("__GROUP__", &group)
        .replace("__ROUTING__", &routing)
        .replace("__UPSTREAM_TAG__", &config.upstream_tag)
        .replace("__UPSTREAM_LINK__", &config.upstream_link)
}

fn dns_pressure_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|err| panic!("{name} is required for DNS pressure: {err}"))
}

fn dns_pressure_qname(prefix: &str, index: usize, suffix: &str) -> String {
    format!("{prefix}-{index}.{suffix}")
}

fn dns_pressure_trace_json(trace: &ResidentDnsTraceSummary) -> serde_json::Value {
    serde_json::json!({
        "qname": &trace.qname,
        "qtype": trace.qtype,
        "qclass": trace.qclass,
        "cache": &trace.cache,
        "request_routing": &trace.request_routing,
        "response_routing": &trace.response_routing,
        "upstream": &trace.upstream,
        "upstream_scheme": trace.upstream_scheme,
        "upstream_chain": &trace.upstream_chain,
        "reroutes": trace.reroutes,
        "fallback": trace.fallback,
        "rcode": trace.rcode,
        "total_ms": trace.total_ms,
        "cache_ms": trace.cache_ms,
        "routing_ms": trace.routing_ms,
        "upstream_ms": trace.upstream_ms,
        "transport_attempts": trace.transport_attempts.iter().map(|attempt| {
            serde_json::json!({
                "upstream": &attempt.upstream,
                "scheme": attempt.scheme,
                "target": &attempt.target,
                "target_family": attempt.target_family,
                "l4proto": attempt.l4proto,
                "route": attempt.route,
                "elapsed_ms": attempt.elapsed_ms,
                "outcome": attempt.outcome,
                "error": &attempt.error,
            })
        }).collect::<Vec<_>>(),
    })
}

fn dns_pressure_response_for_query(query: &[u8], response_ip: IpAddr, ttl: u32) -> Vec<u8> {
    let view = DnsPacketView::parse(query).unwrap();
    let qtype = view.questions().next().unwrap().qtype();
    let answer_data = match (qtype, response_ip) {
        (DNS_QTYPE_A, IpAddr::V4(ip)) => Some((DNS_QTYPE_A, ip.octets().to_vec())),
        (DNS_QTYPE_AAAA, IpAddr::V6(ip)) => Some((DNS_QTYPE_AAAA, ip.octets().to_vec())),
        _ => None,
    };
    let mut response = Vec::new();
    response.extend_from_slice(&query[0..2]);
    response.extend_from_slice(&0x8180_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&(answer_data.is_some() as u16).to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&query[12..view.answer_offset()]);
    if let Some((answer_qtype, data)) = answer_data {
        response.extend_from_slice(&0xc00c_u16.to_be_bytes());
        response.extend_from_slice(&answer_qtype.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&ttl.to_be_bytes());
        response.extend_from_slice(&(data.len() as u16).to_be_bytes());
        response.extend_from_slice(&data);
    }
    response
}

#[tokio::test]
async fn resident_dns_flight_broadcasts_one_response_without_serial_locking() {
    let cache = ResidentDnsRuntimeCache::default();
    let key = ResidentDnsResponseCacheKey::new(
        DnsCacheKey::new("example.com.", DNS_QTYPE_A, 1),
        ResidentDnsResponseCacheScope::AsIs {
            original_dst: "127.0.0.1:53".parse().unwrap(),
        },
    );
    let mut leader = cache.begin_flight(key.clone()).unwrap();
    let follower = cache.begin_flight(key).unwrap();
    assert!(leader.is_leader());
    assert!(!follower.is_leader());

    let wait = follower.wait(
        ProxyDnsRequestContext::from_timeout(Duration::from_secs(1)),
        0xabcd,
    );
    let response = [0x12, 0x34, 0x81, 0x80];
    leader.publish(Ok(&response)).unwrap();
    assert_eq!(wait.await.unwrap(), [0xab, 0xcd, 0x81, 0x80]);
    assert_eq!(cache.inflight_len(), 0);
}

#[tokio::test]
async fn resident_dns_same_key_burst_wakes_all_followers_with_their_request_ids() {
    const FOLLOWERS: usize = 128;
    let cache = ResidentDnsRuntimeCache::default();
    let key = ResidentDnsResponseCacheKey::new(
        DnsCacheKey::new("burst.example.", DNS_QTYPE_A, 1),
        ResidentDnsResponseCacheScope::AsIs {
            original_dst: "127.0.0.1:53".parse().unwrap(),
        },
    );
    let mut leader = cache.begin_flight(key.clone()).unwrap();
    let followers = (0..FOLLOWERS)
        .map(|_| cache.begin_flight(key.clone()).unwrap())
        .collect::<Vec<_>>();
    assert!(leader.is_leader());
    assert!(followers.iter().all(|follower| !follower.is_leader()));
    assert_eq!(cache.inflight_len(), 1);

    leader.publish(Ok(&[0x12, 0x34, 0x81, 0x80])).unwrap();
    let waits = followers
        .into_iter()
        .enumerate()
        .map(|(index, follower)| async move {
            let request_id = u16::try_from(index + 1).unwrap();
            let response = follower
                .wait(
                    ProxyDnsRequestContext::from_timeout(Duration::from_secs(1)),
                    request_id,
                )
                .await
                .unwrap();
            assert_eq!(&response[0..2], &request_id.to_be_bytes());
        });
    futures_util::future::join_all(waits).await;
    assert_eq!(cache.inflight_len(), 0);
}

#[test]
fn resident_dns_unique_key_burst_uses_independent_bounded_entries() {
    const FLIGHTS: usize = 64;
    let cache = ResidentDnsRuntimeCache::with_flight_entry_limit(FLIGHTS);
    let mut leaders = (0..FLIGHTS)
        .map(|index| {
            let key = ResidentDnsResponseCacheKey::new(
                DnsCacheKey::new(format!("unique-{index}.example."), DNS_QTYPE_A, 1),
                ResidentDnsResponseCacheScope::AsIs {
                    original_dst: "127.0.0.1:53".parse().unwrap(),
                },
            );
            cache.begin_flight(key).unwrap()
        })
        .collect::<Vec<_>>();
    assert!(leaders.iter().all(|leader| leader.is_leader()));
    assert_eq!(cache.inflight_len(), FLIGHTS);

    for (index, leader) in leaders.iter_mut().enumerate() {
        let id = u16::try_from(index).unwrap().to_be_bytes();
        leader.publish(Ok(&[id[0], id[1], 0x81, 0x80])).unwrap();
    }
    assert_eq!(cache.inflight_len(), 0);
}

#[tokio::test]
async fn resident_dns_flight_bounds_followers_and_retained_response_bytes() {
    let cache = ResidentDnsRuntimeCache::with_flight_limits(2, 1, 4);
    let key = ResidentDnsResponseCacheKey::new(
        DnsCacheKey::new("bounded-flight.example.", DNS_QTYPE_A, 1),
        ResidentDnsResponseCacheScope::AsIs {
            original_dst: "127.0.0.1:53".parse().unwrap(),
        },
    );
    let mut leader = cache.begin_flight(key.clone()).unwrap();
    let follower = cache.begin_flight(key.clone()).unwrap();
    let follower_error = cache.begin_flight(key).err().unwrap();
    assert!(follower_error.contains("follower limit reached"));

    leader
        .publish(Ok(&[0x12, 0x34, 0x81, 0x80, 0, 0, 0, 0]))
        .unwrap();
    assert_eq!(cache.flight_retained_bytes(), 0);
    let error = follower
        .wait(
            ProxyDnsRequestContext::from_timeout(Duration::from_secs(1)),
            0x7171,
        )
        .await
        .unwrap_err();
    assert!(error.contains("retained response byte limit reached"));

    let retained_key = ResidentDnsResponseCacheKey::new(
        DnsCacheKey::new("retained-flight.example.", DNS_QTYPE_A, 1),
        ResidentDnsResponseCacheScope::AsIs {
            original_dst: "127.0.0.1:53".parse().unwrap(),
        },
    );
    let mut retained_leader = cache.begin_flight(retained_key.clone()).unwrap();
    let retained_follower = cache.begin_flight(retained_key).unwrap();
    retained_leader
        .publish(Ok(&[0x12, 0x34, 0x81, 0x80]))
        .unwrap();
    assert_eq!(cache.flight_retained_bytes(), 4);
    assert_eq!(
        retained_follower
            .wait(
                ProxyDnsRequestContext::from_timeout(Duration::from_secs(1)),
                0x7272,
            )
            .await
            .unwrap(),
        [0x72, 0x72, 0x81, 0x80]
    );
    drop(retained_follower);
    drop(retained_leader);
    assert_eq!(cache.flight_retained_bytes(), 0);
}

#[test]
fn resident_dns_flight_limit_detaches_new_leaders_without_capacity_failure() {
    let cache = ResidentDnsRuntimeCache::with_flight_entry_limit(1);
    let first_key = ResidentDnsResponseCacheKey::new(
        DnsCacheKey::new("first.example.", DNS_QTYPE_A, 1),
        ResidentDnsResponseCacheScope::AsIs {
            original_dst: "127.0.0.1:53".parse().unwrap(),
        },
    );
    let second_key = ResidentDnsResponseCacheKey::new(
        DnsCacheKey::new("second.example.", DNS_QTYPE_A, 1),
        ResidentDnsResponseCacheScope::AsIs {
            original_dst: "127.0.0.1:53".parse().unwrap(),
        },
    );
    let mut registered = cache.begin_flight(first_key).unwrap();
    let mut detached = cache.begin_flight(second_key.clone()).unwrap();
    let independent = cache.begin_flight(second_key).unwrap();

    assert!(registered.is_leader());
    assert!(detached.is_leader());
    assert!(independent.is_leader());
    assert_eq!(cache.inflight_len(), 1);
    registered.publish(Ok(&[0, 1, 0x81, 0x80])).unwrap();
    detached.publish(Ok(&[0, 2, 0x81, 0x80])).unwrap();
    assert_eq!(cache.inflight_len(), 0);
}

#[test]
fn resident_dns_runtime_cache_sweeps_expired_entries_on_write_window() {
    let cache = ResidentDnsRuntimeCache::default();
    let now = 1_700_000_000_i64;
    cache
        .insert_response(
            now,
            ResidentDnsResponseCacheKey::new(
                DnsCacheKey::new("expired.example.", DNS_QTYPE_A, 1),
                ResidentDnsResponseCacheScope::AsIs {
                    original_dst: "127.0.0.1:53".parse().unwrap(),
                },
            ),
            DnsCacheEntry::new(now - 1, now - 1),
        )
        .unwrap();
    assert_eq!(cache.entry_len(), 1);

    cache
        .insert_response(
            now + 120,
            ResidentDnsResponseCacheKey::new(
                DnsCacheKey::new("live.example.", DNS_QTYPE_A, 1),
                ResidentDnsResponseCacheScope::AsIs {
                    original_dst: "127.0.0.1:53".parse().unwrap(),
                },
            ),
            DnsCacheEntry::new(now + 180, now + 180),
        )
        .unwrap();

    assert_eq!(cache.entry_len(), 1);
    assert_eq!(cache.deadline_len(), 1);
    assert_eq!(cache.stats().expired_removal_total, 1);
}

#[test]
fn resident_dns_runtime_cache_replacement_updates_deadline_index() {
    let cache = ResidentDnsRuntimeCache::default();
    let now = 1_700_000_000_i64;
    let key = ResidentDnsResponseCacheKey::new(
        DnsCacheKey::new("replacement.example.", DNS_QTYPE_A, 1),
        ResidentDnsResponseCacheScope::AsIs {
            original_dst: "127.0.0.1:53".parse().unwrap(),
        },
    );
    cache
        .insert_response(now, key.clone(), DnsCacheEntry::new(now + 1, now + 1))
        .unwrap();
    cache
        .insert_response(now, key, DnsCacheEntry::new(now + 300, now + 300))
        .unwrap();

    assert_eq!(cache.entry_len(), 1);
    assert_eq!(cache.deadline_len(), 1);
    cache
        .insert_response(
            now + 120,
            ResidentDnsResponseCacheKey::new(
                DnsCacheKey::new("second.example.", DNS_QTYPE_A, 1),
                ResidentDnsResponseCacheScope::AsIs {
                    original_dst: "127.0.0.1:53".parse().unwrap(),
                },
            ),
            DnsCacheEntry::new(now + 300, now + 300),
        )
        .unwrap();

    assert_eq!(cache.entry_len(), 2);
    assert_eq!(cache.deadline_len(), 2);
}

#[test]
fn resident_dns_plan_admits_request_qname_and_qtype_rules() {
    let input = r#"
        global {}
        routing {}
        dns {
          upstream {
            primary: 'udp://LOCAL_DNS_UPSTREAM'
            secondary: 'udp://127.0.0.1:53'
          }
          routing {
            request {
              qname(suffix: example.com) && qtype(a, aaaa) -> primary
              qtype(https) -> reject
              fallback: secondary
            }
          }
        }
        "#
    .replace("LOCAL_DNS_UPSTREAM", local_dns_upstream_authority());
    let config = parse_config(&input);
    let geodata = test_geodata();
    let plan = build_resident_dns_plan(&config, &geodata).unwrap();

    let view = DnsPacketView::parse(QUERY).unwrap();
    match select_request_action(&plan, &view).unwrap() {
        ResidentDnsRequestAction::Upstream(upstream) => {
            assert_eq!(upstream.tag, "primary");
        }
        other => panic!("expected primary upstream action, got {other:?}"),
    }

    let https_query = query_with_qtype(65);
    let view = DnsPacketView::parse(&https_query).unwrap();
    assert!(matches!(
        select_request_action(&plan, &view).unwrap(),
        ResidentDnsRequestAction::Reject
    ));
}

#[test]
fn resident_dns_plan_admits_request_negation_and_fallback_actions() {
    let input = r#"
        global {}
        routing {}
        dns {
          upstream {
            primary: 'udp://LOCAL_DNS_UPSTREAM'
          }
          routing {
            request {
              !qname(suffix: blocked.example) -> primary
              fallback: reject
            }
          }
        }
        "#
    .replace("LOCAL_DNS_UPSTREAM", local_dns_upstream_authority());
    let config = parse_config(&input);
    let geodata = test_geodata();
    let plan = build_resident_dns_plan(&config, &geodata).unwrap();

    let allowed = DnsPacketView::parse(QUERY).unwrap();
    match select_request_action(&plan, &allowed).unwrap() {
        ResidentDnsRequestAction::Upstream(upstream) => assert_eq!(upstream.tag, "primary"),
        other => panic!("expected negated qname to route to primary, got {other:?}"),
    }

    let blocked_query = build_dns_query_packet(0x1234, "www.blocked.example", DNS_QTYPE_A).unwrap();
    let blocked = DnsPacketView::parse(&blocked_query).unwrap();
    assert!(matches!(
        select_request_action(&plan, &blocked).unwrap(),
        ResidentDnsRequestAction::Reject
    ));

    let asis_input = r#"
        global {}
        routing {}
        dns {
          upstream {
            primary: 'udp://LOCAL_DNS_UPSTREAM'
          }
          routing {
            request {
              qname(suffix: unmatched.example) -> primary
              fallback: asis
            }
          }
        }
        "#
    .replace("LOCAL_DNS_UPSTREAM", local_dns_upstream_authority());
    let asis_config = parse_config(&asis_input);
    let asis_plan = build_resident_dns_plan(&asis_config, &geodata).unwrap();
    assert!(matches!(
        select_request_action(&asis_plan, &allowed).unwrap(),
        ResidentDnsRequestAction::AsIs
    ));
}

#[test]
fn resident_dns_plan_admits_response_qname_qtype_upstream_and_ip_rules() {
    let input = r#"
        global {}
        routing {}
        dns {
          upstream {
            primary: 'udp://LOCAL_DNS_UPSTREAM'
            secondary: 'udp://127.0.0.1:53'
          }
          routing {
            request {
              fallback: primary
            }
            response {
              qname(suffix: example.com) && qtype(a) && upstream(primary) && ip(203.0.113.0/24) -> secondary
              fallback: accept
            }
          }
        }
        "#
        .replace("LOCAL_DNS_UPSTREAM", local_dns_upstream_authority());
    let config = parse_config(&input);
    let geodata = test_geodata();
    let plan = build_resident_dns_plan(&config, &geodata).unwrap();
    let request = DnsPacketView::parse(QUERY).unwrap();
    let primary = match select_request_action(&plan, &request).unwrap() {
        ResidentDnsRequestAction::Upstream(upstream) => upstream,
        other => panic!("expected primary upstream action, got {other:?}"),
    };

    match select_response_action(&plan, &request, &a_response([203, 0, 113, 42]), &primary).unwrap()
    {
        ResidentDnsResponseAction::Upstream(upstream) => {
            assert_eq!(upstream.tag, "secondary");
        }
        other => panic!("expected response reroute to secondary, got {other:?}"),
    }

    assert!(matches!(
        select_response_action(&plan, &request, &a_response([198, 51, 100, 42]), &primary).unwrap(),
        ResidentDnsResponseAction::Accept
    ));
}

#[test]
fn resident_dns_plan_admits_response_fallback_upstream() {
    let input = r#"
        global {}
        routing {}
        dns {
          upstream {
            primary: 'udp://LOCAL_DNS_UPSTREAM'
            secondary: 'udp://127.0.0.1:53'
          }
          routing {
            request {
              fallback: primary
            }
            response {
              qname(suffix: unmatched.example) -> accept
              fallback: secondary
            }
          }
        }
        "#
    .replace("LOCAL_DNS_UPSTREAM", local_dns_upstream_authority());
    let config = parse_config(&input);
    let geodata = test_geodata();
    let plan = build_resident_dns_plan(&config, &geodata).unwrap();
    let request = DnsPacketView::parse(QUERY).unwrap();
    let primary = match select_request_action(&plan, &request).unwrap() {
        ResidentDnsRequestAction::Upstream(upstream) => upstream,
        other => panic!("expected primary upstream action, got {other:?}"),
    };

    match select_response_action(&plan, &request, &a_response([203, 0, 113, 42]), &primary).unwrap()
    {
        ResidentDnsResponseAction::Upstream(upstream) => assert_eq!(upstream.tag, "secondary"),
        other => panic!("expected response fallback to secondary, got {other:?}"),
    }
}

#[test]
fn resident_dns_plan_admits_response_fallback_reject() {
    let input = r#"
        global {}
        routing {}
        dns {
          upstream {
            primary: 'udp://LOCAL_DNS_UPSTREAM'
          }
          routing {
            response {
              fallback: reject
            }
          }
        }
        "#
    .replace("LOCAL_DNS_UPSTREAM", local_dns_upstream_authority());
    let config = parse_config(&input);
    let geodata = test_geodata();
    let plan = build_resident_dns_plan(&config, &geodata).unwrap();
    let request = DnsPacketView::parse(QUERY).unwrap();
    assert!(matches!(
        select_response_action_for_upstream(
            &plan,
            &request,
            &a_response([203, 0, 113, 42]),
            DnsRequestOutboundIndex::ASIS,
        )
        .unwrap(),
        ResidentDnsResponseAction::Reject
    ));
}

#[test]
fn resident_dns_plan_rejects_bad_upstream_surface() {
    let duplicate = r#"
        global {}
        routing {}
        dns {
          upstream {
            primary: 'udp://127.0.0.1:53'
            primary: 'tcp://127.0.0.1:53'
          }
          routing {
            request {
              fallback: primary
            }
          }
        }
        "#;
    let config = parse_config(duplicate);
    let geodata = test_geodata();
    let err = build_resident_dns_plan(&config, &geodata).unwrap_err();
    assert!(err.contains("duplicated DNS upstream tag"), "{err}");

    let unknown = r#"
        global {}
        routing {}
        dns {
          upstream {
            primary: 'udp://127.0.0.1:53'
          }
          routing {
            request {
              fallback: missing
            }
          }
        }
        "#;
    let config = parse_config(unknown);
    let err = build_resident_dns_plan(&config, &geodata).unwrap_err();
    assert!(err.contains("references unknown upstream"), "{err}");

    let unsupported_scheme = r#"
        global {}
        routing {}
        dns {
          upstream {
            primary: 'doh://resolver.fixture.invalid/dns-query'
          }
          routing {
            request {
              fallback: primary
            }
          }
        }
        "#;
    let config = parse_config(unsupported_scheme);
    let err = build_resident_dns_plan(&config, &geodata).unwrap_err();
    assert!(err.contains("unsupported scheme doh"), "{err}");
}

#[test]
fn resident_dns_plan_admits_official_upstream_schemes() {
    let input = r#"
        global {}
        routing {}
        dns {
          upstream {
            udpup: 'udp://__DNS_UPSTREAM_IPV4__'
            tcpup: 'tcp://__DNS_UPSTREAM_HOST__'
            tcpudp: 'tcp+udp://__DNS_UPSTREAM_HOST__:53'
            udptcp: 'udp+tcp://__DNS_UPSTREAM_HOST__:53'
            tlsup: 'tls://__DNS_UPSTREAM_HOST__'
            httpsup: 'https://__DNS_UPSTREAM_HOST__/dns-query'
            quicup: 'quic://__DNS_UPSTREAM_HOST__'
            h3up: 'h3://__DNS_UPSTREAM_HOST__/custom'
            http3up: 'http3://[__DNS_UPSTREAM_IPV6__]/dns-query'
          }
          routing {
            request {
              fallback: h3up
            }
          }
        }
        "#
    .replace("__DNS_UPSTREAM_IPV4__", TEST_DNS_UPSTREAM_IPV4)
    .replace("__DNS_UPSTREAM_HOST__", TEST_DNS_UPSTREAM_HOST)
    .replace("__DNS_UPSTREAM_IPV6__", TEST_DNS_UPSTREAM_IPV6);
    let config = parse_config(&input);
    let geodata = test_geodata();
    let plan = build_resident_dns_plan(&config, &geodata).unwrap();
    assert_eq!(plan.request_actions.len(), 9);
    match plan.request_default_action {
        ResidentDnsRequestAction::Upstream(upstream) => {
            assert_eq!(upstream.tag, "h3up");
            assert_eq!(upstream.scheme, ResidentDnsUpstreamScheme::Http3);
            assert_eq!(
                upstream.target.authority,
                format!("{TEST_DNS_UPSTREAM_HOST}:443")
            );
            assert_eq!(upstream.path, "/custom");
        }
        other => panic!("expected h3 upstream fallback, got {other:?}"),
    }
}

#[test]
fn resident_dns_upstream_parser_applies_default_ports_and_paths() {
    let cases = vec![
        (
            "udp",
            format!("udp://{TEST_DNS_UPSTREAM_IPV4}"),
            ResidentDnsUpstreamScheme::Udp,
            format!("{TEST_DNS_UPSTREAM_IPV4}:53"),
            TEST_DNS_UPSTREAM_IPV4.to_owned(),
            53,
            "",
        ),
        (
            "tcp",
            format!("tcp://{TEST_DNS_UPSTREAM_HOST}"),
            ResidentDnsUpstreamScheme::Tcp,
            format!("{TEST_DNS_UPSTREAM_HOST}:53"),
            TEST_DNS_UPSTREAM_HOST.to_owned(),
            53,
            "",
        ),
        (
            "tcp+udp",
            format!("tcp+udp://{TEST_DNS_UPSTREAM_HOST}"),
            ResidentDnsUpstreamScheme::TcpUdp,
            format!("{TEST_DNS_UPSTREAM_HOST}:53"),
            TEST_DNS_UPSTREAM_HOST.to_owned(),
            53,
            "",
        ),
        (
            "udp+tcp",
            format!("udp+tcp://{TEST_DNS_UPSTREAM_HOST}"),
            ResidentDnsUpstreamScheme::TcpUdp,
            format!("{TEST_DNS_UPSTREAM_HOST}:53"),
            TEST_DNS_UPSTREAM_HOST.to_owned(),
            53,
            "",
        ),
        (
            "tls",
            format!("tls://{TEST_DNS_UPSTREAM_HOST}"),
            ResidentDnsUpstreamScheme::Tls,
            format!("{TEST_DNS_UPSTREAM_HOST}:853"),
            TEST_DNS_UPSTREAM_HOST.to_owned(),
            853,
            "",
        ),
        (
            "https",
            format!("https://{TEST_DNS_UPSTREAM_HOST}"),
            ResidentDnsUpstreamScheme::Https,
            format!("{TEST_DNS_UPSTREAM_HOST}:443"),
            TEST_DNS_UPSTREAM_HOST.to_owned(),
            443,
            DNS_DEFAULT_DOH_PATH,
        ),
        (
            "quic",
            format!("quic://{TEST_DNS_UPSTREAM_HOST}"),
            ResidentDnsUpstreamScheme::Quic,
            format!("{TEST_DNS_UPSTREAM_HOST}:853"),
            TEST_DNS_UPSTREAM_HOST.to_owned(),
            853,
            "",
        ),
        (
            "h3",
            format!("h3://{TEST_DNS_UPSTREAM_HOST}/custom"),
            ResidentDnsUpstreamScheme::Http3,
            format!("{TEST_DNS_UPSTREAM_HOST}:443"),
            TEST_DNS_UPSTREAM_HOST.to_owned(),
            443,
            "/custom",
        ),
        (
            "http3",
            format!("http3://[{TEST_DNS_UPSTREAM_IPV6}]"),
            ResidentDnsUpstreamScheme::Http3,
            format!("[{TEST_DNS_UPSTREAM_IPV6}]:443"),
            TEST_DNS_UPSTREAM_IPV6.to_owned(),
            443,
            DNS_DEFAULT_DOH_PATH,
        ),
    ];
    for (tag, link, scheme, authority, host, port, path) in cases {
        let upstream = parse_dns_upstream(0, tag, &link, test_fallback_resolver(), 0).unwrap();
        assert_eq!(upstream.scheme, scheme, "{tag}");
        assert_eq!(upstream.target.authority, authority, "{tag}");
        assert_eq!(upstream.target.host, host, "{tag}");
        assert_eq!(upstream.target.port, port, "{tag}");
        assert_eq!(upstream.path, path, "{tag}");
    }
}

#[test]
fn resident_dns_forwarder_cache_reuses_doq_by_upstream_and_mark() {
    let cache = ResidentDnsForwarderCache::default();
    let upstream = parse_dns_upstream(
        0,
        "quic",
        &format!("quic://{TEST_DNS_UPSTREAM_HOST}"),
        test_fallback_resolver(),
        0,
    )
    .unwrap();
    let first = cache.quic_forwarder(&upstream, 0x1234).unwrap();
    let second = cache.quic_forwarder(&upstream, 0x1234).unwrap();
    let different_mark = cache.quic_forwarder(&upstream, 0x5678).unwrap();

    assert!(Arc::ptr_eq(&first, &second));
    assert!(!Arc::ptr_eq(&first, &different_mark));
    assert_eq!(cache.len(), 2);
}

#[test]
fn resident_dns_forwarder_cache_reuses_proxy_udp_by_selection() {
    let config = dns_upstream_routing_config(
        r#"
            domain(full: __DNS_UPSTREAM_HOST__) -> proxy
            fallback: direct
            "#
        .replace("__DNS_UPSTREAM_HOST__", TEST_DNS_UPSTREAM_HOST)
        .as_str(),
    );
    let (router, upstream) = dns_upstream_router_for_config(&config);
    let target = test_dns_upstream_target_v4();
    let selection =
        select_single_test_dns_upstream_target(&config, router, &upstream, target, L4Proto::Udp);
    let ResidentDnsUpstreamSelection::Proxy { binding } = &selection else {
        panic!("expected proxied DNS upstream selection");
    };
    let cache = ResidentDnsForwarderCache::default();
    let first = cache
        .proxy_udp_forwarder(&upstream, target, binding.clone(), &selection)
        .unwrap();
    let second = cache
        .proxy_udp_forwarder(&upstream, target, binding.clone(), &selection)
        .unwrap();
    let different_target = cache
        .proxy_udp_forwarder(
            &upstream,
            test_dns_upstream_target_v6(),
            binding.clone(),
            &selection,
        )
        .unwrap();

    assert!(Arc::ptr_eq(&first, &second));
    assert!(!Arc::ptr_eq(&first, &different_target));
    assert!(first.actor_count() > 0);
}

#[test]
fn resident_dns_forwarder_cache_evicts_oldest_entry() {
    let cache = ResidentDnsForwarderCache::default();
    let first = parse_dns_upstream(
        0,
        "first",
        &indexed_test_dns_upstream_link(0),
        test_fallback_resolver(),
        0,
    )
    .unwrap();
    let first_forwarder = cache.quic_forwarder(&first, 0).unwrap();
    for index in 1..=DNS_FORWARDER_CACHE_MAX_ENTRIES {
        let upstream = parse_dns_upstream(
            index as u8,
            &format!("dns{index}"),
            &indexed_test_dns_upstream_link(index),
            test_fallback_resolver(),
            0,
        )
        .unwrap();
        let _ = cache.quic_forwarder(&upstream, 0).unwrap();
    }

    let recreated = cache.quic_forwarder(&first, 0).unwrap();
    assert_eq!(cache.len(), DNS_FORWARDER_CACHE_MAX_ENTRIES);
    assert!(!Arc::ptr_eq(&first_forwarder, &recreated));
}

#[test]
fn resident_dns_doh_http_response_parser_restores_request_id() {
    let mut packed = a_response([203, 0, 113, 42]);
    packed[0] = 0;
    packed[1] = 0;
    let mut raw =
        b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: ".to_vec();
    raw.extend_from_slice(packed.len().to_string().as_bytes());
    raw.extend_from_slice(b"\r\n\r\n");
    raw.extend_from_slice(&packed);

    let restored = parse_doh_http_response(QUERY, &raw).unwrap();
    assert_eq!(&restored[0..2], &[0x12, 0x34]);
    assert_eq!(&restored[2..], &packed[2..]);
}

#[test]
fn resident_dns_doh_http_response_parser_decodes_chunked_body() {
    let mut packed = a_response([203, 0, 113, 42]);
    packed[0] = 0;
    packed[1] = 0;
    let split = 9;
    let mut raw =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nTransfer-Encoding: chunked\r\n\r\n"
                .to_vec();
    raw.extend_from_slice(format!("{split:x}\r\n").as_bytes());
    raw.extend_from_slice(&packed[..split]);
    raw.extend_from_slice(b"\r\n");
    raw.extend_from_slice(format!("{:x}\r\n", packed.len() - split).as_bytes());
    raw.extend_from_slice(&packed[split..]);
    raw.extend_from_slice(b"\r\n0\r\n\r\n");

    let restored = parse_doh_http_response(QUERY, &raw).unwrap();
    assert_eq!(&restored[0..2], &[0x12, 0x34]);
    assert_eq!(&restored[2..], &packed[2..]);
}

#[test]
fn resident_dns_qname_geosite_uses_shared_domain_store_for_any_code() {
    let root = test_asset_root("shared-geosite");
    write_asset(
        &root,
        "test-geosite.dat",
        geosite_list(&[geosite_entry("streaming", &[(2, "example.com", &[][..])])]),
    );
    let input = r#"
        global {}
        routing {}
        dns {
          upstream {
            primary: 'udp://LOCAL_DNS_UPSTREAM'
            secondary: 'udp://127.0.0.1:53'
          }
          routing {
            request {
              qname(ext:'test-geosite:streaming') -> primary
              fallback: secondary
            }
          }
        }
        "#
    .replace("LOCAL_DNS_UPSTREAM", local_dns_upstream_authority());
    let config = parse_config(&input);
    let geodata = ResidentGeodataStore::new([root]);

    let plan = build_resident_dns_plan(&config, &geodata).unwrap();
    assert_eq!(geodata.shared_domain_set_count(), 1);
    let view = DnsPacketView::parse(QUERY).unwrap();
    match select_request_action(&plan, &view).unwrap() {
        ResidentDnsRequestAction::Upstream(upstream) => assert_eq!(upstream.tag, "primary"),
        other => panic!("expected primary upstream action, got {other:?}"),
    }

    let _second = build_resident_dns_plan(&config, &geodata).unwrap();
    assert_eq!(geodata.shared_domain_set_count(), 1);
}

#[test]
fn resident_dns_request_qname_geodata_matrix_matches_go_surface() {
    let root = test_asset_root("request-geodata-matrix");
    write_asset(
        &root,
        "geosite.dat",
        geosite_list(&[geosite_entry(
            "streaming",
            &[(2, "media.example.test", &[][..])],
        )]),
    );
    write_asset(
        &root,
        "test-geosite.dat",
        geosite_list(&[geosite_entry(
            "regional",
            &[
                (2, "example.com", &["cn"][..]),
                (2, "ignored.example.test", &["other"][..]),
            ],
        )]),
    );
    let input = r#"
        global {}
        routing {}
        dns {
          upstream {
            primary: 'udp://LOCAL_DNS_UPSTREAM'
            secondary: 'udp://127.0.0.1:53'
          }
          routing {
            request {
              qname(geosite:streaming) -> primary
              qname(ext:'test-geosite:regional@cn') -> secondary
              fallback: reject
            }
          }
        }
        "#
    .replace("LOCAL_DNS_UPSTREAM", local_dns_upstream_authority());
    let config = parse_config(&input);
    let geodata = ResidentGeodataStore::new([root]);
    let plan = build_resident_dns_plan(&config, &geodata).unwrap();

    let media_query =
        build_dns_query_packet(0x1234, "www.media.example.test", DNS_QTYPE_A).unwrap();
    let media = DnsPacketView::parse(&media_query).unwrap();
    match select_request_action(&plan, &media).unwrap() {
        ResidentDnsRequestAction::Upstream(upstream) => assert_eq!(upstream.tag, "primary"),
        other => panic!("expected geosite request route to primary, got {other:?}"),
    }

    let example = DnsPacketView::parse(QUERY).unwrap();
    match select_request_action(&plan, &example).unwrap() {
        ResidentDnsRequestAction::Upstream(upstream) => assert_eq!(upstream.tag, "secondary"),
        other => panic!("expected ext geosite request route to secondary, got {other:?}"),
    }

    let ignored_query =
        build_dns_query_packet(0x1234, "ignored.example.test", DNS_QTYPE_A).unwrap();
    let ignored = DnsPacketView::parse(&ignored_query).unwrap();
    assert!(matches!(
        select_request_action(&plan, &ignored).unwrap(),
        ResidentDnsRequestAction::Reject
    ));
}

#[test]
fn resident_dns_response_geodata_matrix_matches_go_surface() {
    let root = test_asset_root("response-geodata-matrix");
    write_asset(
        &root,
        "geosite.dat",
        geosite_list(&[geosite_entry(
            "apple",
            &[
                (2, "weather.example.test", &["cn"][..]),
                (2, "ignored.example.test", &["other"][..]),
            ],
        )]),
    );
    write_asset(
        &root,
        "geoip.dat",
        geoip_list(&[geoip_entry(
            "private",
            &[(&[203, 0, 113, 0][..], 24)],
            false,
        )]),
    );
    write_asset(
        &root,
        "test-geoip.dat",
        geoip_list(&[geoip_entry(
            "custom",
            &[(&[198, 51, 100, 0][..], 24)],
            false,
        )]),
    );
    let input = r#"
        global {}
        routing {}
        dns {
          upstream {
            primary: 'udp://LOCAL_DNS_UPSTREAM'
            secondary: 'udp://127.0.0.1:53'
            tertiary: 'udp://127.0.0.2:53'
            quaternary: 'udp://127.0.0.3:53'
          }
          routing {
            request {
              fallback: primary
            }
            response {
              qname(geosite:apple@cn) -> secondary
              ip(geoip:private) -> tertiary
              ip(ext:'test-geoip:custom') -> quaternary
              fallback: accept
            }
          }
        }
        "#
    .replace("LOCAL_DNS_UPSTREAM", local_dns_upstream_authority());
    let config = parse_config(&input);
    let geodata = ResidentGeodataStore::new([root]);
    let plan = build_resident_dns_plan(&config, &geodata).unwrap();
    let primary = match &plan.request_default_action {
        ResidentDnsRequestAction::Upstream(upstream) => upstream.clone(),
        other => panic!("expected primary request fallback, got {other:?}"),
    };

    let weather_query =
        build_dns_query_packet(0x1234, "weather.example.test", DNS_QTYPE_A).unwrap();
    let weather = DnsPacketView::parse(&weather_query).unwrap();
    match select_response_action(
        &plan,
        &weather,
        &a_response_for_query(&weather_query, [192, 0, 2, 42]),
        &primary,
    )
    .unwrap()
    {
        ResidentDnsResponseAction::Upstream(upstream) => assert_eq!(upstream.tag, "secondary"),
        other => panic!("expected response qname geosite route to secondary, got {other:?}"),
    }

    let example = DnsPacketView::parse(QUERY).unwrap();
    match select_response_action(&plan, &example, &a_response([203, 0, 113, 42]), &primary).unwrap()
    {
        ResidentDnsResponseAction::Upstream(upstream) => assert_eq!(upstream.tag, "tertiary"),
        other => panic!("expected response geoip route to tertiary, got {other:?}"),
    }
    match select_response_action(&plan, &example, &a_response([198, 51, 100, 42]), &primary)
        .unwrap()
    {
        ResidentDnsResponseAction::Upstream(upstream) => assert_eq!(upstream.tag, "quaternary"),
        other => panic!("expected response ext geoip route to quaternary, got {other:?}"),
    }
    assert!(matches!(
        select_response_action(&plan, &example, &a_response([192, 0, 2, 42]), &primary).unwrap(),
        ResidentDnsResponseAction::Accept
    ));
}

#[test]
fn resident_dns_plan_rejects_unsupported_request_function() {
    let input = r#"
        global {}
        routing {}
        dns {
          upstream {
            primary: 'udp://LOCAL_DNS_UPSTREAM'
          }
          routing {
            request {
              ip(geoip:private) -> primary
              fallback: primary
            }
          }
        }
        "#
    .replace("LOCAL_DNS_UPSTREAM", local_dns_upstream_authority());
    let config = parse_config(&input);
    let geodata = test_geodata();
    let err = build_resident_dns_plan(&config, &geodata).unwrap_err();
    assert!(err.contains("unsupported dns.routing.request function: ip"));
}

#[test]
fn resident_dns_plan_rejects_unknown_qtype_name() {
    let input = r#"
        global {}
        routing {}
        dns {
          upstream {
            primary: 'udp://LOCAL_DNS_UPSTREAM'
          }
          routing {
            request {
              qtype(not_a_type) -> primary
              fallback: primary
            }
          }
        }
        "#
    .replace("LOCAL_DNS_UPSTREAM", local_dns_upstream_authority());
    let config = parse_config(&input);
    let geodata = test_geodata();
    let err = build_resident_dns_plan(&config, &geodata).unwrap_err();
    assert!(err.contains("unknown DNS qtype: not_a_type"));
}

#[test]
fn resident_dns_reject_response_preserves_question_and_request_id() {
    let view = DnsPacketView::parse(QUERY).unwrap();
    let response = build_reject_response(QUERY, &view).unwrap();
    assert_eq!(&response[0..2], &[0x12, 0x34]);
    assert_eq!(u16::from_be_bytes([response[2], response[3]]) & 0x000f, 0);
    assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
    assert_eq!(&response[12..], &QUERY[12..]);
}

#[test]
fn resident_dns_response_validation_matches_id_and_question() {
    let request = DnsPacketView::parse(QUERY).unwrap();
    let response = a_response([203, 0, 113, 42]);
    validate_dns_response_for_request(&request, &response, true).unwrap();

    let mut id_mismatch = response.clone();
    id_mismatch[0] = 0xab;
    id_mismatch[1] = 0xcd;
    assert!(
        validate_dns_response_for_request(&request, &id_mismatch, true)
            .unwrap_err()
            .contains("IdMismatch")
    );
    validate_dns_response_for_request(&request, &id_mismatch, false).unwrap();

    let mut qname_mismatch = response;
    qname_mismatch[13] = b'x';
    assert!(
        validate_dns_response_for_request(&request, &qname_mismatch, false)
            .unwrap_err()
            .contains("QuestionMismatch")
    );
}

#[tokio::test]
async fn resident_dns_local_listener_rejects_asis() {
    let plan = ResidentDnsPlan::asis(0);
    let err =
        handle_resident_dns_local_trace_async(&plan, "127.0.0.1:8053".parse().unwrap(), QUERY)
            .await
            .unwrap_err();
    assert!(err.contains("cannot use \"asis\" for locally bound dns listener"));
}

#[tokio::test]
async fn resident_dns_local_trace_records_request_reject_path() {
    let input = r#"
        global {}
        routing {}
        dns {
          routing {
            request {
              fallback: reject
            }
          }
        }
        "#;
    let config = parse_config(input);
    let geodata = test_geodata();
    let plan = build_resident_dns_plan(&config, &geodata).unwrap();
    let result =
        handle_resident_dns_local_trace_async(&plan, "127.0.0.1:8053".parse().unwrap(), QUERY)
            .await
            .unwrap();
    let request = DnsPacketView::parse(QUERY).unwrap();
    let question = request.questions().next().unwrap();
    let request_action = select_request_action(&plan, &request).unwrap();

    assert_eq!(
        result.trace.qname,
        question.qname_to_canonical_string().unwrap()
    );
    assert_eq!(result.trace.qtype, question.qtype());
    assert_eq!(result.trace.qclass, question.qclass());
    assert_eq!(result.trace.cache, DNS_TRACE_CACHE_BYPASS);
    assert_eq!(
        result.trace.request_routing,
        dns_request_action_name(&request_action)
    );
    assert_eq!(result.trace.response_routing, DNS_TRACE_ROUTING_REJECT);
    assert_eq!(result.trace.upstream, None);
    assert!(result.trace.upstream_chain.is_empty());
    assert_eq!(result.trace.fallback, plan.request_matcher.is_none());
    assert_eq!(result.trace.rcode, dns_response_rcode(&result.response));
    assert_eq!(result.trace.reason, DNS_TRACE_REASON_REQUEST_REJECTED);
    assert_eq!(&result.response[0..2], &request.id().to_be_bytes());
}

fn geosite_list(entries: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for entry in entries {
        push_field_bytes(&mut out, 1, entry);
    }
    out
}

fn geoip_list(entries: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for entry in entries {
        push_field_bytes(&mut out, 1, entry);
    }
    out
}

fn geoip_entry(code: &str, cidrs: &[(&[u8], u64)], inverse_match: bool) -> Vec<u8> {
    let mut out = Vec::new();
    push_field_string(&mut out, 1, code);
    for (ip, prefix) in cidrs {
        let mut cidr = Vec::new();
        push_field_bytes(&mut cidr, 1, ip);
        push_field_varint(&mut cidr, 2, *prefix);
        push_field_bytes(&mut out, 2, &cidr);
    }
    if inverse_match {
        push_field_varint(&mut out, 3, 1);
    }
    out
}

fn geosite_entry(code: &str, domains: &[(u64, &str, &[&str])]) -> Vec<u8> {
    let mut out = Vec::new();
    push_field_string(&mut out, 1, code);
    for (domain_type, value, attrs) in domains {
        push_field_bytes(&mut out, 2, &domain_entry(*domain_type, value, attrs));
    }
    out
}

fn domain_entry(domain_type: u64, value: &str, attrs: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    push_field_varint(&mut out, 1, domain_type);
    push_field_string(&mut out, 2, value);
    for attr in attrs {
        let mut attribute = Vec::new();
        push_field_string(&mut attribute, 1, attr);
        push_field_bytes(&mut out, 3, &attribute);
    }
    out
}

fn push_field_string(out: &mut Vec<u8>, field: u64, value: &str) {
    push_field_bytes(out, field, value.as_bytes());
}

fn push_field_bytes(out: &mut Vec<u8>, field: u64, value: &[u8]) {
    push_varint(out, (field << 3) | 2);
    push_varint(out, value.len() as u64);
    out.extend_from_slice(value);
}

fn push_field_varint(out: &mut Vec<u8>, field: u64, value: u64) {
    push_varint(out, field << 3);
    push_varint(out, value);
}

fn push_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}
