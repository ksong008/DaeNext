use std::path::PathBuf;

use serde_json::{Value, json};

use crate::*;
#[test]
pub(super) fn map_stats_count_requires_map_specs() {
    let output = run_with_args(["map-stats", "count"]);
    assert_eq!(output.exit_code, 2);
    assert!(output.stderr.contains("--map name:id"));
    assert_eq!(
        parse_map_count_request("routing_tuples_map:7").unwrap(),
        MapStatsCountRequest {
            name: "routing_tuples_map".to_owned(),
            id: 7,
        }
    );
}

#[test]
pub(super) fn cgroup_monitor_attach_pin_requires_paths() {
    let output = run_with_args(["cgroup-monitor", "attach-pin", "--program-root", "/bpffs/p"]);
    assert_eq!(output.exit_code, 2);
    assert!(output.stderr.contains("--link-root"));
    let options = parse_cgroup_monitor_attach_pin_options(&[
        "--program-root=/bpffs/programs".to_owned(),
        "--link-root=/bpffs/links".to_owned(),
        "--cgroup-path=/sys/fs/cgroup".to_owned(),
    ])
    .unwrap();
    assert_eq!(
        options,
        CgroupMonitorAttachPinOptions {
            program_root: PathBuf::from("/bpffs/programs"),
            link_root: PathBuf::from("/bpffs/links"),
            cgroup_path: PathBuf::from("/sys/fs/cgroup"),
        }
    );
}

#[test]
pub(super) fn tc_attach_contract_declares_pinned_lifetime_and_matrix() {
    let output = run_with_args(["tc-attach", "contract"]);
    assert_eq!(output.exit_code, 0, "{}", output.stderr);
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(
        json["name"].as_str().unwrap(),
        "rust-tc-tcx-attach-pin-contract"
    );
    assert!(
        json["native_routing_dns_sniff_group_ready"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(json["attach_matrix"].as_array().unwrap().len(), 6);
}

#[test]
pub(super) fn tc_attach_pin_requires_full_spec() {
    let output = run_with_args(["tc-attach", "attach-pin", "--program-root", "/bpffs/p"]);
    assert_eq!(output.exit_code, 2);
    assert!(output.stderr.contains("--link-root"));
    let options = parse_tc_attach_pin_options(&[
        "--program-root=/bpffs/programs".to_owned(),
        "--link-root=/bpffs/tc-links/one".to_owned(),
        "--program-name=tproxy_lan_ingress_l2".to_owned(),
        "--iface=eth0".to_owned(),
        "--direction=ingress".to_owned(),
        "--priority=2".to_owned(),
        "--handle=539164676".to_owned(),
        "--backend=tc-netlink".to_owned(),
        "--filter-name=dae_lan_ingress_l2".to_owned(),
    ])
    .unwrap();
    assert_eq!(
        options,
        TcAttachPinOptions {
            program_root: PathBuf::from("/bpffs/programs"),
            link_root: PathBuf::from("/bpffs/tc-links/one"),
            program_name: "tproxy_lan_ingress_l2".to_owned(),
            iface: "eth0".to_owned(),
            netns: None,
            direction: dae_ebpf_support::TcAttachDirection::Ingress,
            priority: 2,
            handle: 539164676,
            backend: dae_ebpf_support::AttachBackend::TcNetlink,
            filter_name: Some("dae_lan_ingress_l2".to_owned()),
        }
    );
}

#[test]
pub(super) fn tproxy_listener_contract_keeps_native_handlers_ready() {
    let output = run_with_args(["tproxy-listener", "contract"]);
    assert_eq!(output.exit_code, 0, "{}", output.stderr);
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(
        json["name"].as_str().unwrap(),
        "rust-tproxy-listener-sockmap-handoff-contract"
    );
    assert!(
        json["native_userspace_tcp_udp_handlers_ready"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        json["listen_socket_map"]["key_0"].as_str().unwrap(),
        "tcp listener fd"
    );
    assert_eq!(
        json["listen_socket_map"]["key_1"].as_str().unwrap(),
        "udp socket fd"
    );
}

#[test]
pub(super) fn tproxy_listener_commands_require_handoff_and_socket_fds() {
    let output = run_with_args(["tproxy-listener", "open-handoff", "--map-id", "7"]);
    assert_eq!(output.exit_code, 2);
    assert!(output.stderr.contains("--port"));
    let open = parse_tproxy_listener_open_handoff_options(&[
        "--map-id=7".to_owned(),
        "--port=12345".to_owned(),
        "--handoff-fd=3".to_owned(),
    ])
    .unwrap();
    assert_eq!(
        open,
        TproxyListenerOpenHandoffOptions {
            map_id: 7,
            port: 12345,
            handoff_fd: 3,
        }
    );

    let output = run_with_args(["tproxy-listener", "update-map", "--map-id", "7"]);
    assert_eq!(output.exit_code, 2);
    assert!(output.stderr.contains("--tcp-fd"));
    let update = parse_tproxy_listener_update_map_options(&[
        "--map-id=7".to_owned(),
        "--tcp-fd=3".to_owned(),
        "--udp-fd=4".to_owned(),
    ])
    .unwrap();
    assert_eq!(
        update,
        TproxyListenerUpdateMapOptions {
            map_id: 7,
            tcp_fd: 3,
            udp_fd: 4,
        }
    );
}

#[test]
pub(super) fn connectivity_map_update_requires_full_key() {
    let output = run_with_args(["connectivity-map", "update", "--map-id", "1"]);
    assert_eq!(output.exit_code, 2);
    assert!(output.stderr.contains("--outbound"));
    let output = run_with_args(["connectivity-map", "serve"]);
    assert_eq!(output.exit_code, 2);
    assert!(output.stderr.contains("stdio entrypoint"));
    let options = parse_connectivity_map_update_options(&[
        "--map-id=7".to_owned(),
        "--outbound=2".to_owned(),
        "--l4-proto=6".to_owned(),
        "--ip-version=4".to_owned(),
        "--alive=true".to_owned(),
        "--is-init=true".to_owned(),
        "--dryrun=false".to_owned(),
    ])
    .unwrap();
    assert_eq!(
        options,
        ConnectivityMapUpdateOptions {
            map_id: 7,
            outbound: 2,
            l4_proto: 6,
            ip_version: 4,
            alive: true,
            is_init: true,
            dryrun: false,
        }
    );
}

#[test]
pub(super) fn routing_map_apply_parser_preserves_match_set_shape() {
    let request = parse_routing_map_apply_request(
        r#"{
              "routing_map_id": 7,
              "lpm_array_map_id": 8,
              "lpm_entries": [{"index": 3, "map_id": 9}],
              "lpm_maps": [{
                "index": 4,
                "flags": 1,
                "max_entries": 2048,
                "key_size": 20,
                "value_size": 4,
                "entries": [{
                  "key": {"prefix_len": 128, "data": [0,0,65535,1]},
                  "value": 1
                }]
              }],
              "routing_entries": [{
                "index": 0,
                "value": {
                  "value": [1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                  "not": false,
                  "type": 10,
                  "outbound": 2,
                  "must": true,
                  "mark": 134217728
                }
              }]
            }"#,
    )
    .unwrap();
    assert_eq!(request.routing_map_id, 7);
    assert_eq!(request.lpm_array_map_id, 8);
    assert_eq!(request.lpm_entries[0].map_id, 9);
    assert_eq!(request.lpm_maps[0].index, 4);
    assert_eq!(request.lpm_maps[0].entries[0].key.prefix_len, 128);
    assert_eq!(request.lpm_maps[0].entries[0].value, 1);
    assert_eq!(request.routing_entries[0].value.value[0], 1);
    assert_eq!(request.routing_entries[0].value.kind, 10);
    assert_eq!(request.routing_entries[0].value.must, 1);

    let output = run_with_args(["routing-map", "apply"]);
    assert_eq!(output.exit_code, 2);
    assert!(output.stderr.contains("stdio entrypoint"));
}

#[test]
pub(super) fn domain_routing_map_apply_parser_preserves_bitmap_shape() {
    let bitmap = vec![1_u32; 32];
    let payload = json!({
        "map_id": 7,
        "updates": [{
            "key": [0, 0, 65535, 1],
            "bitmap": bitmap,
        }],
        "deletes": [[0, 0, 65535, 2]],
    })
    .to_string();
    let request = parse_domain_routing_map_apply_request(&payload).unwrap();
    assert_eq!(request.map_id, 7);
    assert_eq!(request.updates[0].key, [0, 0, 65535, 1]);
    assert_eq!(request.updates[0].value.bitmap[31], 1);
    assert_eq!(request.deletes[0], [0, 0, 65535, 2]);

    let output = run_with_args(["domain-routing-map", "apply"]);
    assert_eq!(output.exit_code, 2);
    assert!(output.stderr.contains("stdio entrypoint"));
    let output = run_with_args(["domain-routing-map", "serve"]);
    assert_eq!(output.exit_code, 2);
    assert!(output.stderr.contains("stdio entrypoint"));
    let output = run_with_args(["domain-routing-map", "serve-owner"]);
    assert_eq!(output.exit_code, 2);
    assert!(output.stderr.contains("stdio entrypoint"));
}

#[test]
pub(super) fn domain_routing_map_owner_parser_preserves_snapshot_shape() {
    let bitmap = vec![2_u32; 32];
    let payload = json!({
        "op": "sync_owner",
        "map_id": 11,
        "owner_key": "q=example.test|type=A|class=IN",
        "bitmap": bitmap,
        "ips": [[0, 0, 65535, 1]],
    })
    .to_string();
    let request = parse_domain_routing_map_owner_request(&payload).unwrap();
    match request {
        DomainRoutingOwnerRequest::SyncOwner {
            map_id,
            owner_key,
            bitmap,
            ips,
        } => {
            assert_eq!(map_id, 11);
            assert_eq!(owner_key, "q=example.test|type=A|class=IN");
            assert_eq!(bitmap[31], 2);
            assert_eq!(ips[0], [0, 0, 65535, 1]);
        }
        _ => panic!("unexpected owner request"),
    }

    let reload = parse_domain_routing_map_owner_request(
        r#"{"op":"prepare_reload","map_id":12,"existing_keys":[[0,0,65535,2]]}"#,
    )
    .unwrap();
    assert_eq!(
        reload,
        DomainRoutingOwnerRequest::PrepareReload {
            map_id: 12,
            existing_keys: vec![[0, 0, 65535, 2]],
        }
    );
}
