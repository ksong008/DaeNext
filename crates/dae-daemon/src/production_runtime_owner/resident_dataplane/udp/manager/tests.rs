use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use dae_outbound::NetworkType;

use crate::production_runtime_owner::resident_dataplane::plan::{
    RESIDENT_CONTROL_PLANE_SO_MARK, ResidentXhttpSettingsPlan,
};
use crate::production_runtime_owner::udp_payload_admission::ResidentUdpPayloadAdmission;

use super::*;

#[test]
fn udp_session_manager_uses_the_generation_data_plane_executor() {
    let source = include_str!("../manager.rs");
    assert!(source.contains("process-owned-shared-multi-thread"));
    assert!(!source.contains("thread_name(\"udp-session\")"));
}

#[test]
fn udp_generation_runtime_keeps_a_drain_control_instead_of_the_heavy_generation() {
    let source = include_str!("../manager.rs");
    assert!(source.contains("generation_id: u64"));
    assert!(source.contains("drain_control: Arc<ResidentGenerationDrainControl>"));
    assert!(source.contains("router: Option<Arc<ResidentUdpRouter>>"));
    assert!(source.contains("dns_runtime: Option<ResidentUdpDnsRuntime>"));
    assert!(!source.contains("plan: ResidentUdpGenerationPlan"));
    assert!(!source.contains("generation: Arc<ResidentDataplaneGeneration>"));
}

#[test]
fn per_generation_cleanup_does_not_fail_on_shared_payload_owned_elsewhere() {
    let payload_admission = ResidentUdpPayloadAdmission::new(1, 1024);
    let retained_by_another_generation = payload_admission.try_acquire(262).unwrap();
    let passed = json!({"status": "pass"});

    assert_eq!(payload_admission.current(), 262);
    assert!(udp_generation_cleanup_passed(&passed, &passed, &passed));
    assert!(!udp_manager_cleanup_passed(0, 0, 0, false));

    drop(retained_by_another_generation);
    assert_eq!(payload_admission.current(), 0);
    assert!(udp_manager_cleanup_passed(0, 0, 0, true));
}

#[test]
fn final_udp_manager_cleanup_rejects_real_owner_failures() {
    assert!(!udp_manager_cleanup_passed(1, 0, 0, true));
    assert!(!udp_manager_cleanup_passed(0, 1, 0, true));
    assert!(!udp_manager_cleanup_passed(0, 0, 1, true));
    assert!(!udp_manager_cleanup_passed(0, 0, 0, false));
}

#[test]
fn forced_generation_cleanup_stays_safe_without_being_reported_graceful() {
    let forced = json!({
        "status": "pass",
        "safetyStatus": "pass",
        "graceful": false,
        "completionMode": "forced-bounded",
    });
    let graceful = json!({
        "status": "pass",
        "safetyStatus": "pass",
        "graceful": true,
        "completionMode": "graceful",
    });

    assert_eq!(
        udp_cleanup_completion(true, [&graceful, &forced]),
        (false, "forced-bounded")
    );
    assert_eq!(
        udp_cleanup_completion(true, [&graceful]),
        (true, "graceful")
    );
    assert_eq!(
        udp_cleanup_completion(false, [&graceful]),
        (false, "incomplete")
    );
}

#[test]
fn udp_generation_pin_is_fixed_by_peer_and_original_destination_until_expiry() {
    let peer = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 53000);
    let destination = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 1).into(), 443);
    let other_destination = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 2).into(), 443);
    let key = UdpGenerationPinKey {
        peer,
        original_dst: destination,
    };
    let now = Instant::now();
    let mut pins = HashMap::new();
    pins.insert(
        key,
        UdpGenerationPin {
            generation: 7,
            expires_at: now + RESIDENT_UDP_SESSION_IDLE_TIMEOUT,
            route: None,
        },
    );

    assert_eq!(pinned_udp_generation(&pins, key, now), Some(7));
    assert_eq!(
        pinned_udp_generation(
            &pins,
            UdpGenerationPinKey {
                peer,
                original_dst: other_destination,
            },
            now,
        ),
        None
    );
    assert_eq!(
        pinned_udp_generation(&pins, key, now + RESIDENT_UDP_SESSION_IDLE_TIMEOUT),
        None
    );
}

#[test]
fn unavailable_udp_generation_pin_does_not_fall_back_to_active_generation() {
    assert_eq!(
        udp_generation_choice(Some(7), 8, |generation| generation == 8),
        UdpGenerationChoice::PinUnavailable
    );
    assert_eq!(
        udp_generation_choice(Some(7), 8, |generation| generation == 7),
        UdpGenerationChoice::Available(7)
    );
    assert_eq!(
        udp_generation_choice(None, 8, |_| false),
        UdpGenerationChoice::Available(8)
    );
}

#[test]
fn retired_udp_generation_keeps_only_resources_required_by_its_bound_pins() {
    let peer = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 53000);
    let now = Instant::now();
    let mut pins = HashMap::new();
    let key = UdpGenerationPinKey {
        peer,
        original_dst: SocketAddr::new(Ipv4Addr::new(192, 0, 2, 1).into(), 443),
    };
    pins.insert(
        key,
        UdpGenerationPin {
            generation: 7,
            expires_at: now + RESIDENT_UDP_SESSION_IDLE_TIMEOUT,
            route: None,
        },
    );
    assert_eq!(
        retained_udp_resources_for_generation(&pins, 7),
        ResidentUdpRetainedResources {
            has_pin: true,
            router: true,
            dns_runtime: true,
        }
    );

    pins.get_mut(&key).unwrap().route = Some(ResidentUdpPinnedRoute::Direct {
        route: ResidentUdpRouteSelection {
            initial_outbound: OUTBOUND_DIRECT,
            final_outbound: OUTBOUND_DIRECT,
            final_mark: 0,
            userspace_route_executed: false,
            userspace_route_must: false,
        },
        sniffed_domain: None,
        dscp: 0,
    });
    assert_eq!(
        retained_udp_resources_for_generation(&pins, 7),
        ResidentUdpRetainedResources {
            has_pin: true,
            router: false,
            dns_runtime: false,
        }
    );

    pins.get_mut(&key).unwrap().route = Some(ResidentUdpPinnedRoute::ResidentDns);
    assert_eq!(
        retained_udp_resources_for_generation(&pins, 7),
        ResidentUdpRetainedResources {
            has_pin: true,
            router: false,
            dns_runtime: true,
        }
    );
}

#[test]
fn retired_unbound_udp_pin_lasts_only_while_rollback_or_sniffing_can_use_it() {
    assert!(udp_generation_pin_is_required(true, false, true, false));
    assert!(udp_generation_pin_is_required(false, true, true, false));
    assert!(udp_generation_pin_is_required(false, false, false, false));
    assert!(udp_generation_pin_is_required(false, false, true, true));
    assert!(!udp_generation_pin_is_required(false, false, true, false));
}

#[test]
fn udp_session_key_uses_dns_semantics_for_local_dns_destination() {
    let proxy = test_udp_proxy(ResidentProxyProtocolPlan::VlessVisionTcpTls { key: [1; 16] });
    let peer = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 53000);
    let dns_dst = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 53);
    let key = UdpSessionKey::new(&proxy, peer, dns_dst);
    let value = key.to_value();

    assert_eq!(value["packetSemantics"], UdpPacketSemantics::Dns.as_str());
    assert_eq!(value["originalDestination"], dns_dst.to_string());
    assert_eq!(
        value["sourceContract"]["wireIdentity"],
        "session-bound-fixed-target"
    );
    assert_eq!(
        value["sourceContract"]["multiTargetMode"],
        "rejected-not-admitted"
    );
    assert_eq!(
        value["sourceContract"]["compatibilityMode"],
        "strict-fixed-target"
    );
    assert_eq!(key.idle_timeout(), RESIDENT_UDP_DNS_SESSION_IDLE_TIMEOUT);
}

#[test]
fn forced_dns_session_lanes_are_distinct_and_observable() {
    let proxy = test_udp_proxy(ResidentProxyProtocolPlan::VlessVisionTcpTls { key: [1; 16] });
    let peer = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 53000);
    let dns_dst = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 53);
    let first = UdpSessionKey::with_dispatch_lane(&proxy, peer, dns_dst, 1);
    let second = UdpSessionKey::with_dispatch_lane(&proxy, peer, dns_dst, 2);
    let lane_zero = UdpSessionKey::with_dispatch_lane(&proxy, peer, dns_dst, 0);
    let unsharded = UdpSessionKey::new(&proxy, peer, dns_dst);

    assert_ne!(first, second);
    assert_ne!(lane_zero, unsharded);
    assert_eq!(lane_zero.to_value()["dispatchLane"], 0);
    assert_eq!(first.to_value()["dispatchLane"], 1);
    assert_eq!(second.to_value()["dispatchLane"], 2);
    assert_ne!(
        first.to_value()["sessionHash"],
        second.to_value()["sessionHash"]
    );
}

#[test]
fn udp_session_key_separates_packet_semantics() {
    let peer = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 10).into(), 53000);
    let original_dst = SocketAddr::new(Ipv4Addr::new(8, 8, 8, 8).into(), 443);
    let vless = test_udp_proxy(ResidentProxyProtocolPlan::VlessVisionTcpTls { key: [1; 16] });
    let socks = test_udp_proxy(ResidentProxyProtocolPlan::Socks5Tcp {
        username: String::new(),
        password: String::new(),
    });
    assert_ne!(
        UdpSessionKey::new(&vless, peer, original_dst),
        UdpSessionKey::new(&socks, peer, original_dst)
    );
    assert_eq!(
        UdpSessionKey::new(&vless, peer, original_dst).idle_timeout(),
        RESIDENT_UDP_SESSION_IDLE_TIMEOUT
    );
}

#[test]
fn udp_session_key_emits_display_and_redacted_identity() {
    let peer_ip = Ipv4Addr::new(192, 0, 2, 10);
    let original_dst_ip = Ipv4Addr::new(192, 0, 2, 53);
    let peer = ipv4_mapped_socket_addr(peer_ip, 53000);
    let original_dst = ipv4_mapped_socket_addr(original_dst_ip, 443);
    let peer_display = ipv4_socket_display(peer_ip, 53000);
    let original_dst_display = ipv4_socket_display(original_dst_ip, 443);
    let proxy = test_udp_proxy(ResidentProxyProtocolPlan::VlessVisionTcpTls { key: [1; 16] });
    let key = UdpSessionKey::new(&proxy, peer, original_dst);
    let value = key.to_value();

    assert_eq!(value["schemaVersion"], 1);
    assert_eq!(value["manager"], "resident-udp-session-manager");
    assert_eq!(value["graphId"], "resident-graph:redacted");
    assert_eq!(value["graphLinkHash"], "sha256:redacted");
    assert_eq!(value["redactedLinkSource"], "source:<redacted>");
    assert_eq!(value["peer"], peer_display);
    assert_eq!(value["originalDestination"], original_dst_display);
    assert_eq!(value["sourceDisplay"], peer_display);
    assert_eq!(value["destinationDisplay"], original_dst_display);
    assert_eq!(value["packetSemantics"], "udp-over-stream");
    assert_eq!(
        value["sourceContract"]["fixedTargetValidation"],
        "required-before-payload-consumption-or-forwarding"
    );
    assert!(
        value["graphIdentityHash"]
            .as_str()
            .is_some_and(|hash| hash.starts_with("sha256:") && hash.len() > "sha256:".len())
    );
    assert!(
        value["sessionHash"]
            .as_str()
            .is_some_and(|hash| hash.starts_with("sha256:") && hash.len() > "sha256:".len())
    );
    assert_eq!(
        value["sessionIdentity"]["sessionHash"],
        value["sessionHash"]
    );
}

#[test]
fn udp_would_block_classifier_uses_typed_io_errors() {
    assert!(
        UdpOriginalDstRecvError::Io(io::Error::from(io::ErrorKind::WouldBlock)).is_would_block()
    );
    assert!(
        !UdpOriginalDstRecvError::Io(io::Error::from(io::ErrorKind::PermissionDenied))
            .is_would_block()
    );
}

#[test]
fn udp_router_selects_proxy_from_routing_tuple_outbound() {
    let router = test_udp_router();
    let original_dst = SocketAddr::new(Ipv4Addr::new(142, 250, 72, 238).into(), 443);

    let selected_default = router
        .select_from_routing_result(original_dst, route_result(2, 0))
        .unwrap();
    let selected_sg = router
        .select_from_routing_result(original_dst, route_result(3, 0))
        .unwrap();

    assert_eq!(selected_proxy_group_name(selected_default), "proxy");
    assert_eq!(selected_proxy_group_name(selected_sg), "sg");
}

#[test]
fn udp_router_blocks_when_kernel_selected_block() {
    let router = test_udp_router();
    let original_dst = SocketAddr::new(Ipv4Addr::new(203, 0, 113, 10).into(), 443);
    let selection = router
        .select_from_routing_result(original_dst, route_result(OUTBOUND_BLOCK, 0))
        .unwrap();

    match selection {
        ResidentUdpSelection::Block(route) => {
            assert_eq!(route.initial_outbound, OUTBOUND_BLOCK);
            assert_eq!(route.final_outbound, OUTBOUND_BLOCK);
        }
        ResidentUdpSelection::Proxy(_) => panic!("block outbound must not select a proxy"),
        ResidentUdpSelection::Direct(_) => panic!("block outbound must not select direct"),
        ResidentUdpSelection::ResidentDns => {
            panic!("block outbound must not select resident DNS")
        }
    }
}

#[test]
fn udp_router_selects_direct_and_fails_closed_for_unresolved_control_plane_routing() {
    let router = test_udp_router();
    let original_dst = SocketAddr::new(Ipv4Addr::new(203, 0, 113, 10).into(), 443);

    let direct = router
        .select_from_routing_result(original_dst, route_result(OUTBOUND_DIRECT, 0x1234))
        .unwrap();
    match direct {
        ResidentUdpSelection::Direct(selection) => {
            assert_eq!(selection.route.final_outbound, OUTBOUND_DIRECT);
            assert_eq!(selection.route.final_mark, 0x1234);
        }
        ResidentUdpSelection::Proxy(_) => panic!("direct outbound must not select proxy"),
        ResidentUdpSelection::Block(_) => panic!("direct outbound must not select block"),
        ResidentUdpSelection::ResidentDns => panic!("direct outbound must not select DNS"),
    }

    let marked_router = test_udp_router_with_matcher_and_so_mark(
        fallback_matcher("user:2", 0),
        TcpDialMode::Ip,
        0x4567,
    );
    let direct = marked_router
        .select_from_routing_result(original_dst, route_result(OUTBOUND_DIRECT, 0))
        .unwrap();
    match direct {
        ResidentUdpSelection::Direct(selection) => {
            assert_eq!(selection.route.final_mark, 0x4567);
        }
        ResidentUdpSelection::Proxy(_) => panic!("direct outbound must not select proxy"),
        ResidentUdpSelection::Block(_) => panic!("direct outbound must not select block"),
        ResidentUdpSelection::ResidentDns => panic!("direct outbound must not select DNS"),
    }

    let direct = router
        .select_from_routing_result(original_dst, route_result(OUTBOUND_DIRECT, 0))
        .unwrap();
    match direct {
        ResidentUdpSelection::Direct(selection) => {
            assert_eq!(selection.route.final_mark, RESIDENT_CONTROL_PLANE_SO_MARK);
        }
        ResidentUdpSelection::Proxy(_) => panic!("direct outbound must not select proxy"),
        ResidentUdpSelection::Block(_) => panic!("direct outbound must not select block"),
        ResidentUdpSelection::ResidentDns => panic!("direct outbound must not select DNS"),
    }

    let control_plane = select_udp_route_err(
        &router,
        original_dst,
        route_result(OUTBOUND_CONTROL_PLANE_ROUTING, 0),
    );
    assert!(control_plane.contains("no UDP domain/SNI was available"));
}

#[test]
fn udp_router_reroutes_control_plane_with_sniffed_domain() {
    let router = test_udp_router_with_matcher(
        domain_matcher("video.example.com", "user:3", 0x3333),
        TcpDialMode::Ip,
    );
    let peer = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 10).into(), 53100);
    let original_dst = SocketAddr::new(Ipv4Addr::new(203, 0, 113, 10).into(), 443);
    let selection = router
        .select_from_routing_result_with_domain(
            peer,
            original_dst,
            route_result(OUTBOUND_CONTROL_PLANE_ROUTING, 0),
            "video.example.com",
        )
        .unwrap();

    match selection {
        ResidentUdpSelection::Proxy(selection) => {
            assert_eq!(selection.proxy.group_name, "sg");
            assert_eq!(selection.proxy.effective_socket_mark(), 0x3333);
        }
        ResidentUdpSelection::Block(_) => panic!("domain reroute must select proxy"),
        ResidentUdpSelection::Direct(_) => panic!("domain reroute must select proxy"),
        ResidentUdpSelection::ResidentDns => panic!("domain reroute must select proxy"),
    }
}

#[test]
fn udp_router_domain_plus_plus_reroutes_user_outbound_with_sniffed_domain() {
    let router = test_udp_router_with_matcher(
        domain_matcher("video.example.com", "user:3", 0),
        TcpDialMode::DomainPlusPlus,
    );
    let peer = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 10).into(), 53100);
    let original_dst = SocketAddr::new(Ipv4Addr::new(203, 0, 113, 10).into(), 443);
    let selection = router
        .select_from_routing_result_with_domain(
            peer,
            original_dst,
            route_result(2, 0),
            "video.example.com",
        )
        .unwrap();

    match selection {
        ResidentUdpSelection::Proxy(selection) => {
            assert_eq!(selection.proxy.group_name, "sg");
            let key = UdpSessionKey::new(&selection.proxy, peer, original_dst);
            assert_eq!(key.original_destination(), original_dst);
        }
        ResidentUdpSelection::Block(_) => panic!("domain++ reroute must select proxy"),
        ResidentUdpSelection::Direct(_) => panic!("domain++ reroute must select proxy"),
        ResidentUdpSelection::ResidentDns => panic!("domain++ reroute must select proxy"),
    }
}

#[test]
fn udp_router_overrides_proxy_mark_from_routing_result() {
    let router = test_udp_router();
    let original_dst = SocketAddr::new(Ipv4Addr::new(142, 250, 72, 238).into(), 443);
    let selection = router
        .select_from_routing_result(original_dst, route_result(3, 0x1234_5678))
        .unwrap();

    match selection {
        ResidentUdpSelection::Proxy(selection) => {
            assert_eq!(selection.proxy.group_name, "sg");
            assert_eq!(selection.proxy.effective_socket_mark(), 0x1234_5678);
        }
        ResidentUdpSelection::Block(_) => panic!("route mark override must keep proxy route"),
        ResidentUdpSelection::Direct(_) => panic!("route mark override must keep proxy route"),
        ResidentUdpSelection::ResidentDns => {
            panic!("route mark override must keep proxy route")
        }
    }
}

#[test]
fn udp_router_keeps_dns_packets_on_resident_dns_path() {
    let router = test_udp_router();
    let dns_dst = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 53).into(), 53);
    let selection = router
        .select_from_routing_result(dns_dst, route_result(OUTBOUND_BLOCK, 0))
        .unwrap();

    match selection {
        ResidentUdpSelection::ResidentDns => {}
        ResidentUdpSelection::Proxy(_) => panic!("non-must DNS must not select proxy"),
        ResidentUdpSelection::Direct(_) => panic!("non-must DNS must not select direct"),
        ResidentUdpSelection::Block(_) => panic!("non-must DNS must use resident DNS"),
    }
}

#[test]
fn udp_router_uses_destination_ip_family_for_proxy_group() {
    let router = test_udp_router_with_udp_family_latency_group();
    let v4_udp_dst = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 53).into(), 443);
    let v6_udp_dst = SocketAddr::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 53).into(), 443);

    let v4_selection = router
        .select_from_routing_result(v4_udp_dst, route_result(2, 0))
        .unwrap();
    assert_eq!(selected_proxy_node_tag(v4_selection), "node_a");

    let v6_selection = router
        .select_from_routing_result(v6_udp_dst, route_result(2, 0))
        .unwrap();
    assert_eq!(selected_proxy_node_tag(v6_selection), "node_b");
}

#[test]
fn udp_router_prefers_data_udp_health_for_client_udp() {
    let router = test_udp_router_with_data_udp_health_group();
    let udp_dst = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 53).into(), 443);
    let selection = router
        .select_from_routing_result(udp_dst, route_result(2, 0))
        .unwrap();

    match selection {
        ResidentUdpSelection::Proxy(selection) => {
            assert_eq!(selection.proxy.node_tag, "node_b");
            assert_eq!(selection.selected_network_type, NetworkType::DATA_UDP4);
        }
        ResidentUdpSelection::Block(_) => panic!("client UDP must not select block"),
        ResidentUdpSelection::Direct(_) => panic!("client UDP must not select direct"),
        ResidentUdpSelection::ResidentDns => panic!("client UDP must not select resident DNS"),
    }
}

#[test]
fn udp_dns_fast_path_applies_to_all_dns() {
    let router = test_udp_router();
    let dns_dst = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 53).into(), 53);
    let normal_dns = router
        .select_from_routing_result(dns_dst, route_result(OUTBOUND_BLOCK, 0))
        .unwrap();
    match normal_dns {
        ResidentUdpSelection::ResidentDns => {
            assert!(resident_udp_dns_fast_path_applies(dns_dst));
        }
        ResidentUdpSelection::Block(_) => panic!("non-must DNS should use resident DNS"),
        ResidentUdpSelection::Proxy(_) => panic!("non-must DNS should use resident DNS"),
        ResidentUdpSelection::Direct(_) => panic!("non-must DNS should use resident DNS"),
    }

    let must_dns = router
        .select_from_routing_result(dns_dst, route_result_must(3, 0, 1))
        .unwrap();
    match must_dns {
        ResidentUdpSelection::Proxy(selection) => {
            assert!(resident_udp_dns_fast_path_applies(dns_dst));
            assert!(selection.force_proxy_packet);
        }
        ResidentUdpSelection::Block(_) => panic!("must DNS proxy route should select proxy"),
        ResidentUdpSelection::Direct(_) => panic!("must DNS proxy route should select proxy"),
        ResidentUdpSelection::ResidentDns => {
            panic!("must DNS proxy route should select proxy")
        }
    }

    let non_dns_dst = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 53).into(), 443);
    let non_dns = router
        .select_from_routing_result(non_dns_dst, route_result(3, 0))
        .unwrap();
    match non_dns {
        ResidentUdpSelection::Proxy(selection) => {
            assert!(!resident_udp_dns_fast_path_applies(non_dns_dst));
            assert!(!selection.force_proxy_packet);
        }
        ResidentUdpSelection::Block(_) => panic!("non-DNS proxy route should select proxy"),
        ResidentUdpSelection::Direct(_) => panic!("non-DNS proxy route should select proxy"),
        ResidentUdpSelection::ResidentDns => {
            panic!("non-DNS proxy route should select proxy")
        }
    }
}

#[test]
fn udp_dns_fast_path_route_event_keeps_proxy_fields_without_packet_session() {
    let peer = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 53100);
    let original_dst = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 53);
    let proxy = test_udp_proxy_with_group("sg", 0x1234);
    let route = ResidentUdpRouteSelection {
        initial_outbound: 2,
        final_outbound: 3,
        final_mark: proxy.mark,
        userspace_route_executed: false,
        userspace_route_must: false,
    };

    let event = udp_route_chosen_event_without_packet_session(
        peer,
        original_dst,
        &route,
        &proxy,
        "",
        0,
        UDP_ROUTE_REASON_DNS_FAST_PATH,
    );

    assert_eq!(event["event"], UDP_ROUTE_CHOSEN_EVENT);
    assert_eq!(event["outbound_kind"], UDP_ROUTE_KIND_PROXY);
    assert_eq!(event["network"], resident_udp_network_name(original_dst));
    assert_eq!(event["proxy_group"], proxy.group_name);
    assert_eq!(event["group_policy"], proxy.group_policy);
    assert_eq!(event["node_tag"], proxy.node_tag);
    assert_eq!(event["task_queued"], false);
    assert_eq!(event["reason"], UDP_ROUTE_REASON_DNS_FAST_PATH);
    assert!(event.get("packetSession").is_none());
}

#[test]
fn udp_router_keeps_must_dns_proxy_route_for_reusable_session_lanes() {
    let router = test_udp_router();
    let dns_dst = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 53).into(), 53);
    let block = router
        .select_from_routing_result(dns_dst, route_result_must(OUTBOUND_BLOCK, 0, 1))
        .unwrap();
    match block {
        ResidentUdpSelection::Block(route) => {
            assert_eq!(route.initial_outbound, OUTBOUND_BLOCK);
            assert_eq!(route.final_outbound, OUTBOUND_BLOCK);
        }
        ResidentUdpSelection::Proxy(_) => panic!("must block DNS must not use resident DNS"),
        ResidentUdpSelection::Direct(_) => panic!("must block DNS must not use resident DNS"),
        ResidentUdpSelection::ResidentDns => {
            panic!("must block DNS must not use resident DNS")
        }
    }

    let proxy = router
        .select_from_routing_result(dns_dst, route_result_must(3, 0, 1))
        .unwrap();
    match proxy {
        ResidentUdpSelection::Proxy(selection) => {
            assert_eq!(selection.proxy.group_name, "sg");
            assert!(selection.force_proxy_packet);
            assert!(resident_udp_dns_fast_path_applies(dns_dst));
        }
        ResidentUdpSelection::Block(_) => panic!("user outbound DNS must select proxy"),
        ResidentUdpSelection::Direct(_) => panic!("user outbound DNS must select proxy"),
        ResidentUdpSelection::ResidentDns => {
            panic!("user outbound DNS must select proxy")
        }
    }
}

#[test]
fn udp_route_chosen_event_exposes_route_and_session_fields() {
    let peer = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 10).into(), 53100);
    let original_dst = SocketAddr::new(Ipv4Addr::new(203, 0, 113, 10).into(), 443);
    let proxy = test_udp_proxy_with_group("sg", 0x1234);
    let route = ResidentUdpRouteSelection {
        initial_outbound: 2,
        final_outbound: 3,
        final_mark: proxy.mark,
        userspace_route_executed: true,
        userspace_route_must: true,
    };

    let event = udp_route_chosen_event(
        peer,
        original_dst,
        &route,
        Some(&proxy),
        None,
        "video.example.com",
        46,
        true,
        "queued packet for resident UDP session",
    );

    assert_eq!(event["event"], "udp_route_chosen");
    assert_eq!(event["outbound_kind"], UDP_ROUTE_KIND_PROXY);
    assert_eq!(event["peer"], peer.to_string());
    assert_eq!(event["original_dst"], original_dst.to_string());
    assert_eq!(event["direct_target"], original_dst.to_string());
    assert_eq!(event["initial_outbound"], 2);
    assert_eq!(event["final_outbound"], 3);
    assert_eq!(event["final_mark"], proxy.mark);
    assert_eq!(event["userspace_route_executed"], true);
    assert_eq!(event["userspace_route_must"], true);
    assert_eq!(event["sniffed_domain"], "video.example.com");
    assert_eq!(event["network"], resident_udp_network_name(original_dst));
    assert_eq!(event["outbound"], proxy.group_name);
    assert_eq!(event["proxy_group"], proxy.group_name);
    assert_eq!(event["group_policy"], proxy.group_policy);
    assert_eq!(event["node_tag"], proxy.node_tag);
    assert_eq!(event["handler"], resident_udp_proxy_handler_name(&proxy));
    assert_eq!(event["task_queued"], true);
    assert_eq!(event["reason"], UDP_ROUTE_REASON_QUEUED);
    assert_eq!(event["dscp"], 46);
    assert_eq!(
        event["packetSession"]["manager"],
        "resident-udp-session-manager"
    );
    assert_eq!(event["packetSession"]["outbound"], proxy.group_name);
    assert_eq!(
        event["packetSession"]["packetSemantics"],
        UdpPacketSemantics::UdpAssociate.as_str()
    );

    let block = ResidentUdpRouteSelection {
        initial_outbound: OUTBOUND_BLOCK,
        final_outbound: OUTBOUND_BLOCK,
        final_mark: 0,
        userspace_route_executed: false,
        userspace_route_must: false,
    };
    let event = udp_route_chosen_event(
        peer,
        original_dst,
        &block,
        None,
        None,
        "",
        0,
        false,
        UDP_ROUTE_REASON_BLOCK,
    );
    assert_eq!(event["outbound_kind"], UDP_ROUTE_KIND_BLOCK);
    assert_eq!(event["outbound"], UDP_ROUTE_KIND_BLOCK);
    assert_eq!(event["task_queued"], false);
    assert!(event.get("packetSession").is_none());

    let v6_peer = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 53100);
    let v6_original_dst = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 443);
    let event = udp_route_chosen_event(
        v6_peer,
        v6_original_dst,
        &route,
        Some(&proxy),
        None,
        "video.example.com",
        46,
        true,
        UDP_ROUTE_REASON_QUEUED,
    );
    assert_eq!(event["network"], resident_udp_network_name(v6_original_dst));
    assert_ne!(event["network"], resident_udp_network_name(original_dst));
}

fn ipv4_mapped_socket_addr(addr: Ipv4Addr, port: u16) -> SocketAddr {
    let mut octets = [0_u8; 16];
    octets[10] = 0xff;
    octets[11] = 0xff;
    octets[12..16].copy_from_slice(&addr.octets());
    SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port)
}

fn ipv4_socket_display(addr: Ipv4Addr, port: u16) -> String {
    SocketAddr::new(IpAddr::V4(addr), port).to_string()
}

fn test_udp_router() -> ResidentUdpRouter {
    test_udp_router_with_matcher(fallback_matcher("user:2", 0), TcpDialMode::Ip)
}

fn test_udp_router_with_matcher(
    routing_matcher: RoutingMatcher,
    dial_mode: TcpDialMode,
) -> ResidentUdpRouter {
    test_udp_router_with_matcher_and_so_mark(routing_matcher, dial_mode, 0)
}

fn test_udp_router_with_matcher_and_so_mark(
    routing_matcher: RoutingMatcher,
    dial_mode: TcpDialMode,
    so_mark_from_dae: u32,
) -> ResidentUdpRouter {
    let mut groups = BTreeMap::new();
    groups.insert(
        2,
        ResidentProxyGroupPlan::fixed_single_for_test(test_udp_proxy_with_group("proxy", 0)),
    );
    groups.insert(
        3,
        ResidentProxyGroupPlan::fixed_single_for_test(test_udp_proxy_with_group("sg", 0x2222)),
    );
    ResidentUdpRouter::from_parts(
        share_resident_proxy_groups(groups),
        2,
        1,
        None,
        routing_matcher,
        dial_mode,
        so_mark_from_dae,
    )
    .unwrap()
}

fn test_udp_router_with_udp_family_latency_group() -> ResidentUdpRouter {
    let sections = dae_config::parser::parse_config(
        r#"
            global {
            lan_interface: daerust0
            }
            node {
            node_a: 'socks5://127.0.0.1:1080'
            node_b: 'socks5://127.0.0.2:1080'
            }
            group {
            proxy {
                filter: name(node_a, node_b)
                policy: min
            }
            }
            routing {
            fallback: proxy
            }
            "#,
    )
    .unwrap();
    let config = dae_config::schema::build_config(&sections).unwrap();
    let plan = super::super::super::plan::build_resident_dataplane_plan(&config).unwrap();
    let group = plan.default_proxy_group().unwrap();
    group
        .record_check_result("node_a", NetworkType::DNS_UDP4, Some(20), 1)
        .unwrap();
    group
        .record_check_result("node_b", NetworkType::DNS_UDP4, Some(200), 2)
        .unwrap();
    group
        .record_check_result("node_a", NetworkType::DNS_UDP6, Some(300), 3)
        .unwrap();
    group
        .record_check_result("node_b", NetworkType::DNS_UDP6, Some(50), 4)
        .unwrap();
    ResidentUdpRouter::from_parts(
        share_resident_proxy_groups(plan.proxies.clone()),
        plan.default_outbound.unwrap(),
        1,
        None,
        fallback_matcher("direct", 0),
        TcpDialMode::Ip,
        0,
    )
    .unwrap()
}

fn test_udp_router_with_data_udp_health_group() -> ResidentUdpRouter {
    let sections = dae_config::parser::parse_config(
        r#"
            global {
            lan_interface: daerust0
            }
            node {
            node_a: 'socks5://127.0.0.1:1080'
            node_b: 'socks5://127.0.0.2:1080'
            }
            group {
            proxy {
                filter: name(node_a, node_b)
                policy: min
            }
            }
            routing {
            fallback: proxy
            }
            "#,
    )
    .unwrap();
    let config = dae_config::schema::build_config(&sections).unwrap();
    let plan = super::super::super::plan::build_resident_dataplane_plan(&config).unwrap();
    let group = plan.default_proxy_group().unwrap();
    group
        .record_check_result("node_a", NetworkType::DNS_UDP4, Some(20), 1)
        .unwrap();
    group
        .data_udp_availability_handle("node_b")
        .unwrap()
        .record(NetworkType::DATA_UDP4, 2);
    ResidentUdpRouter::from_parts(
        share_resident_proxy_groups(plan.proxies.clone()),
        plan.default_outbound.unwrap(),
        1,
        None,
        fallback_matcher("direct", 0),
        TcpDialMode::Ip,
        0,
    )
    .unwrap()
}

fn fallback_matcher(outbound: &str, mark: u32) -> RoutingMatcher {
    RoutingMatcher::from_fixture_value(&json!({
        "matches": [
            {
                "type": "fallback",
                "outbound": outbound,
                "mark": mark
            }
        ],
        "domain_sets": [],
        "lpm_sets": []
    }))
    .unwrap()
}

fn domain_matcher(domain: &str, outbound: &str, mark: u32) -> RoutingMatcher {
    RoutingMatcher::from_fixture_value(&json!({
        "matches": [
            {
                "type": "domain_set",
                "outbound": outbound,
                "mark": mark
            },
            {
                "type": "fallback",
                "outbound": "user:2",
                "mark": 0
            }
        ],
        "domain_sets": [
            {
                "bit": 0,
                "key": "full",
                "patterns": [domain]
            }
        ],
        "lpm_sets": []
    }))
    .unwrap()
}

fn route_result(outbound: u8, mark: u32) -> BpfRoutingResult {
    route_result_must(outbound, mark, 0)
}

fn route_result_must(outbound: u8, mark: u32, must: u8) -> BpfRoutingResult {
    BpfRoutingResult {
        outbound,
        mark,
        must,
        ..Default::default()
    }
}

fn selected_proxy_group_name(selection: ResidentUdpSelection) -> String {
    match selection {
        ResidentUdpSelection::Proxy(selection) => selection.proxy.group_name.clone(),
        ResidentUdpSelection::Block(_) => panic!("expected proxy route"),
        ResidentUdpSelection::Direct(_) => panic!("expected proxy route"),
        ResidentUdpSelection::ResidentDns => panic!("expected proxy route"),
    }
}

fn selected_proxy_node_tag(selection: ResidentUdpSelection) -> String {
    match selection {
        ResidentUdpSelection::Proxy(selection) => selection.proxy.node_tag.clone(),
        ResidentUdpSelection::Block(_) => panic!("expected proxy route"),
        ResidentUdpSelection::Direct(_) => panic!("expected proxy route"),
        ResidentUdpSelection::ResidentDns => panic!("expected proxy route"),
    }
}

fn select_udp_route_err(
    router: &ResidentUdpRouter,
    original_dst: SocketAddr,
    result: BpfRoutingResult,
) -> String {
    match router.select_from_routing_result(original_dst, result) {
        Ok(_) => panic!("expected resident UDP route selection to fail"),
        Err(err) => err,
    }
}

fn test_udp_proxy_with_group(group_name: &str, mark: u32) -> ResidentProxyPlan {
    let mut proxy = test_udp_proxy(ResidentProxyProtocolPlan::Socks5Tcp {
        username: String::new(),
        password: String::new(),
    });
    proxy.group_name = group_name.to_owned();
    proxy.node_tag = group_name.to_owned();
    proxy.mark = mark;
    proxy
}

fn test_udp_proxy(handler: ResidentProxyProtocolPlan) -> ResidentProxyPlan {
    let mut proxy = ResidentProxyPlan {
        graph_id: "resident-graph:redacted".to_owned(),
        graph_link_hash: "sha256:redacted".to_owned(),
        redacted_link_source: "source:<redacted>".to_owned(),
        protocol: "redacted",
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
        tls: String::new(),
        allow_insecure: false,
        tls_fragment: None,
        utls_fingerprint: None,
        reality: None,
        handler,
        execution: None,
        chain_parent: None,
        mark: 0,
        mptcp: false,
    };
    proxy.materialize_execution();
    proxy
}
