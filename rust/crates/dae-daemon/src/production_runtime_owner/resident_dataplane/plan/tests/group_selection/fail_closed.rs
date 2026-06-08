use super::*;
#[test]
pub(super) fn resident_dataplane_plan_keeps_fixed_from_building_unselected_candidate() {
    let unsupported = vless_xhttp_parser_fixture_url("packet-up", "h3", "");
    let config_text = r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        node_a: 'socks://127.0.0.1:1080'
        unsupported: '__UNSUPPORTED_SOURCE__'
        }
        group {
        proxy {
            filter: name(node_a, unsupported)
            policy: fixed(0)
        }
        }
        routing {
        l4proto(tcp) -> proxy
        fallback: direct
        }
        "#
    .replace("__UNSUPPORTED_SOURCE__", &unsupported);
    let config = parse_config(&config_text);
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let group = plan.default_proxy_group().unwrap();
    assert_eq!(group.candidate_count(), 2);
    assert_eq!(group.admitted_candidate_count(), 1);
    assert_eq!(group.select_proxy_for_tcp().unwrap().node_tag, "node_a");
}

#[test]
pub(super) fn resident_dataplane_plan_does_not_fallback_unresolved_name_filter_to_static_ss_node() {
    let candidate = vless_xhttp_parser_fixture_url("packet-up", "h3", "");
    let config_text = r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        _022: 'ss://2022-blake3-aes-128-gcm:MTIzNDU2Nzg5MDEyMzQ1Ng==@217.116.171.227:25868'
        candidate: '__CANDIDATE_SOURCE__'
        }
        group {
        proxy {
            filter: name(node_17)
            policy: fixed
        }
        }
        routing {
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#
    .replace("__CANDIDATE_SOURCE__", &candidate);
    let config = parse_config(&config_text);
    let err = build_resident_dataplane_plan(&config).unwrap_err();
    assert!(err.contains("cannot resolve group proxy name filter node(s): node_17"));
    assert!(!err.contains("parse VLESS node _022"));
}
