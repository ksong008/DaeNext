use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use super::*;

fn xmux(generation: u64) -> ResidentXhttpXmuxPlan {
    ResidentXhttpXmuxPlan {
        runtime_generation: generation,
        physical_connection_limit: 2,
        max_concurrency: Some((1, 1)),
        max_connections: None,
        c_max_reuse_times: None,
        h_max_request_times: Some((600, 900)),
        h_max_reusable_secs: Some((1800, 3000)),
        h_keep_alive_period: 0,
    }
}

fn endpoint(reality: Option<ResidentRealityUnderlayPlan>) -> ResidentXhttpEndpointPlan {
    ResidentXhttpEndpointPlan {
        server_host: "transport.invalid".to_owned(),
        server_port: 443,
        server_name: "sni.invalid".to_owned(),
        alpn: vec!["h2".to_owned()],
        stream_host: "host.invalid".to_owned(),
        stream_path: "/credential-like-route".to_owned(),
        mode: ResidentXhttpMode::PacketUp,
        settings: ResidentXhttpSettingsPlan::official_default(),
        xmux: Some(xmux(9)),
        allow_insecure: false,
        tls_fragment: None,
        reality,
    }
}

fn reality(seed: u8) -> ResidentRealityUnderlayPlan {
    ResidentRealityUnderlayPlan {
        public_key: [seed; 32],
        short_id: vec![seed; 8],
        spider_x: format!("/credential-{seed}"),
    }
}

fn chrome_fingerprint() -> ResidentUtlsFingerprintPlan {
    ResidentUtlsFingerprintPlan {
        source: "link fp",
        requested: "chrome".to_owned(),
        name: "chrome".to_owned(),
        canonical: "chrome_auto".to_owned(),
        family: dae_outbound::shared_transport::UTLS_FAMILY_CHROME.to_owned(),
        client: "Chrome".to_owned(),
        randomized: false,
        alpn_policy: dae_outbound::shared_transport::UTLS_ALPN_POLICY_AUTO.to_owned(),
        default_alpn: vec!["h2".to_owned(), "http/1.1".to_owned()],
    }
}

fn test_proxy(endpoint: &ResidentXhttpEndpointPlan) -> ResidentProxyPlan {
    ResidentProxyPlan {
        graph_id: "resident-graph:primary".to_owned(),
        graph_link_hash: "sha256:primary".to_owned(),
        redacted_link_source: "vless://<redacted>".to_owned(),
        protocol: "vless",
        group_name: "group".to_owned(),
        group_policy: "fixed".to_owned(),
        node_tag: "node".to_owned(),
        server_host: endpoint.server_host.clone(),
        server_port: endpoint.server_port,
        server_name: endpoint.server_name.clone(),
        alpn: endpoint.alpn.clone(),
        flow: String::new(),
        net: "xhttp".to_owned(),
        stream_host: endpoint.stream_host.clone(),
        stream_path: endpoint.stream_path.clone(),
        xhttp_download: None,
        xhttp_mode: endpoint.mode,
        xhttp_settings: endpoint.settings.clone(),
        xhttp_xmux: Some(xmux(9)),
        tls: if endpoint.reality.is_some() {
            "reality".to_owned()
        } else {
            "tls".to_owned()
        },
        allow_insecure: endpoint.allow_insecure,
        tls_fragment: endpoint.tls_fragment.clone(),
        utls_fingerprint: None,
        reality: endpoint.reality.clone(),
        handler: ResidentProxyProtocolPlan::VlessVisionTcpTls { key: [7; 16] },
        execution: None,
        chain_parent: None,
        mark: 0,
        mptcp: false,
    }
}

fn resolved(addresses: &[&str]) -> XhttpResolvedEndpointIdentity {
    XhttpResolvedEndpointIdentity::from_candidates(
        &addresses
            .iter()
            .map(|address| address.parse().unwrap())
            .collect::<Vec<_>>(),
    )
}

fn primary_key(
    proxy: &ResidentProxyPlan,
    endpoint: &ResidentXhttpEndpointPlan,
    resolved: &XhttpResolvedEndpointIdentity,
    mark: u32,
    mptcp: bool,
) -> XhttpXmuxKey {
    XhttpXmuxKey::primary(
        proxy,
        endpoint,
        resolved,
        proxy.xhttp_xmux.as_ref().unwrap(),
        mark,
        mptcp,
    )
    .unwrap()
}

#[test]
fn equivalent_primary_endpoints_reuse_the_same_key() {
    let endpoint = endpoint(Some(reality(1)));
    let proxy = test_proxy(&endpoint);
    let first = primary_key(
        &proxy,
        &endpoint,
        &resolved(&["192.0.2.1:443", "[2001:db8::1]:443"]),
        9,
        false,
    );
    let second = primary_key(
        &proxy,
        &endpoint,
        &resolved(&["[2001:db8::1]:443", "192.0.2.1:443"]),
        9,
        false,
    );

    assert_eq!(first, second);
    let mut first_hash = DefaultHasher::new();
    first.hash(&mut first_hash);
    let mut second_hash = DefaultHasher::new();
    second.hash(&mut second_hash);
    assert_eq!(first_hash.finish(), second_hash.finish());
    assert_eq!(
        first.quic_provenance_identity(),
        second.quic_provenance_identity()
    );
}

#[test]
fn primary_h3_quic_tls_provider_partitions_xmux_key() {
    let mut endpoint = endpoint(None);
    endpoint.alpn = vec!["h3".to_owned()];
    let rustls_proxy = test_proxy(&endpoint);
    let mut boring_proxy = rustls_proxy.clone();
    boring_proxy.utls_fingerprint = Some(chrome_fingerprint());
    let resolved = resolved(&["192.0.2.30:443"]);

    let rustls = primary_key(&rustls_proxy, &endpoint, &resolved, 0, false);
    let boring = primary_key(&boring_proxy, &endpoint, &resolved, 0, false);
    assert_ne!(rustls, boring);
    assert!(format!("{rustls:?}").contains("quic_tls_provider: Some(Rustls)"));
    assert!(format!("{boring:?}").contains("quic_tls_provider: Some(ChromeBoring)"));
}

#[test]
fn quic_provenance_identity_partitions_every_hashed_transport_key_change() {
    let endpoint = endpoint(Some(reality(1)));
    let proxy = test_proxy(&endpoint);
    let resolved = resolved(&["192.0.2.1:443"]);
    let base = primary_key(&proxy, &endpoint, &resolved, 9, false);

    let mut changed_reality = endpoint.clone();
    changed_reality.reality = Some(reality(2));
    let reality_key = primary_key(
        &test_proxy(&changed_reality),
        &changed_reality,
        &resolved,
        9,
        false,
    );
    let mark_key = primary_key(&proxy, &endpoint, &resolved, 10, false);
    assert_ne!(base, reality_key);
    assert_ne!(base, mark_key);
    assert_ne!(
        base.quic_provenance_identity(),
        reality_key.quic_provenance_identity()
    );
    assert_ne!(
        base.quic_provenance_identity(),
        mark_key.quic_provenance_identity()
    );
}

#[test]
fn graph_parent_generation_mark_and_family_differences_partition() {
    let endpoint = endpoint(Some(reality(1)));
    let base_proxy = test_proxy(&endpoint);
    let base_resolved = resolved(&["192.0.2.1:443"]);
    let base = primary_key(&base_proxy, &endpoint, &base_resolved, 9, false);

    let mut changed_graph = base_proxy.clone();
    changed_graph.graph_link_hash = "sha256:other".to_owned();
    assert_ne!(
        base,
        primary_key(&changed_graph, &endpoint, &base_resolved, 9, false)
    );

    let mut changed_parent = base_proxy.clone();
    let mut parent = test_proxy(&endpoint);
    parent.graph_id = "resident-graph:parent".to_owned();
    parent.graph_link_hash = "sha256:parent".to_owned();
    changed_parent.chain_parent = Some(Arc::new(parent));
    assert_ne!(
        base,
        primary_key(&changed_parent, &endpoint, &base_resolved, 9, false)
    );

    let mut changed_generation = base_proxy.clone();
    changed_generation
        .xhttp_xmux
        .as_mut()
        .unwrap()
        .runtime_generation = 10;
    assert_ne!(
        base,
        primary_key(&changed_generation, &endpoint, &base_resolved, 9, false)
    );
    assert_ne!(
        base,
        primary_key(&base_proxy, &endpoint, &base_resolved, 10, false)
    );
    assert_ne!(
        base,
        primary_key(&base_proxy, &endpoint, &base_resolved, 9, true)
    );
    assert_ne!(
        base,
        primary_key(
            &base_proxy,
            &endpoint,
            &resolved(&["[2001:db8::1]:443"]),
            9,
            false
        )
    );
}

#[test]
fn tls_reality_fingerprint_and_request_route_differences_partition() {
    let endpoint = endpoint(Some(reality(1)));
    let proxy = test_proxy(&endpoint);
    let resolved = resolved(&["192.0.2.1:443"]);
    let base = primary_key(&proxy, &endpoint, &resolved, 0, false);

    let mut changed_reality = endpoint.clone();
    changed_reality.reality = Some(reality(2));
    let changed_reality_proxy = test_proxy(&changed_reality);
    assert_ne!(
        base,
        primary_key(
            &changed_reality_proxy,
            &changed_reality,
            &resolved,
            0,
            false
        )
    );

    let mut changed_short_id = endpoint.clone();
    changed_short_id.reality.as_mut().unwrap().short_id[0] ^= 1;
    assert_ne!(
        base,
        primary_key(
            &test_proxy(&changed_short_id),
            &changed_short_id,
            &resolved,
            0,
            false
        )
    );

    let mut changed_public_key = endpoint.clone();
    changed_public_key.reality.as_mut().unwrap().public_key[0] ^= 1;
    assert_ne!(
        base,
        primary_key(
            &test_proxy(&changed_public_key),
            &changed_public_key,
            &resolved,
            0,
            false
        )
    );

    let mut changed_spider = endpoint.clone();
    changed_spider.reality.as_mut().unwrap().spider_x = "/other-spider".to_owned();
    assert_ne!(
        base,
        primary_key(
            &test_proxy(&changed_spider),
            &changed_spider,
            &resolved,
            0,
            false
        )
    );

    let mut changed_sni = endpoint.clone();
    changed_sni.server_name = "other-sni.invalid".to_owned();
    assert_ne!(base, primary_key(&proxy, &changed_sni, &resolved, 0, false));

    let mut changed_alpn = endpoint.clone();
    changed_alpn.alpn = vec!["h3".to_owned()];
    assert_ne!(
        base,
        primary_key(&proxy, &changed_alpn, &resolved, 0, false)
    );

    let mut changed_trust = endpoint.clone();
    changed_trust.reality = None;
    changed_trust.allow_insecure = true;
    assert_ne!(
        base,
        primary_key(&proxy, &changed_trust, &resolved, 0, false)
    );

    let mut changed_route = endpoint.clone();
    changed_route.stream_path = "/other".to_owned();
    assert_ne!(
        base,
        primary_key(&proxy, &changed_route, &resolved, 0, false)
    );

    let mut fingerprint_proxy = proxy.clone();
    fingerprint_proxy.utls_fingerprint = Some(ResidentUtlsFingerprintPlan {
        source: "source",
        requested: "chrome".to_owned(),
        name: "chrome".to_owned(),
        canonical: "chrome".to_owned(),
        family: "chrome".to_owned(),
        client: "chrome".to_owned(),
        randomized: false,
        alpn_policy: "configured".to_owned(),
        default_alpn: vec!["h2".to_owned()],
    });
    assert_ne!(
        base,
        primary_key(&fingerprint_proxy, &endpoint, &resolved, 0, false)
    );
}

#[test]
fn declared_endpoint_fragment_xmux_and_role_differences_partition() {
    let endpoint = endpoint(None);
    let proxy = test_proxy(&endpoint);
    let resolved = resolved(&["192.0.2.8:443"]);
    let base = primary_key(&proxy, &endpoint, &resolved, 0, false);

    let mut changed_host = endpoint.clone();
    changed_host.server_host = "other-transport.invalid".to_owned();
    assert_ne!(
        base,
        primary_key(&proxy, &changed_host, &resolved, 0, false)
    );

    let mut changed_port = endpoint.clone();
    changed_port.server_port = 8443;
    assert_ne!(
        base,
        primary_key(&proxy, &changed_port, &resolved, 0, false)
    );

    let mut changed_fragment = endpoint.clone();
    changed_fragment.tls_fragment =
        Some(dae_outbound::shared_transport::TlsFragmentOptions::new(64, 128, 1, 2).unwrap());
    assert_ne!(
        base,
        primary_key(&proxy, &changed_fragment, &resolved, 0, false)
    );

    let mut changed_xmux = proxy.clone();
    changed_xmux
        .xhttp_xmux
        .as_mut()
        .unwrap()
        .h_keep_alive_period = 10;
    assert_ne!(
        base,
        primary_key(&changed_xmux, &endpoint, &resolved, 0, false)
    );

    let download = XhttpXmuxKey::download(
        &proxy,
        &endpoint,
        &resolved,
        endpoint.xmux.as_ref().unwrap(),
        0,
        false,
    )
    .unwrap();
    assert_ne!(base, download);
}

#[test]
fn download_reality_credentials_partition_without_exposing_secret_material() {
    let first_endpoint = endpoint(Some(reality(3)));
    let first_reality = first_endpoint.reality.as_ref().unwrap().clone();
    let proxy = test_proxy(&first_endpoint);
    let resolved = resolved(&["192.0.2.3:443"]);
    let first = XhttpXmuxKey::download(
        &proxy,
        &first_endpoint,
        &resolved,
        first_endpoint.xmux.as_ref().unwrap(),
        0,
        false,
    )
    .unwrap();
    let second_endpoint = endpoint(Some(reality(4)));
    let second = XhttpXmuxKey::download(
        &proxy,
        &second_endpoint,
        &resolved,
        second_endpoint.xmux.as_ref().unwrap(),
        0,
        false,
    )
    .unwrap();

    assert_ne!(first, second);
    let debug = format!("{first:?}");
    assert!(!debug.contains("credential-like-route"));
    assert!(!debug.contains(&first_reality.spider_x));
    assert!(!debug.contains(&format!("{:?}", first_reality.public_key)));
    assert!(!debug.contains(&format!("{:?}", first_reality.short_id)));
}
