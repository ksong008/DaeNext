#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use serde_json::Value;

    use super::*;

    #[test]
    fn contract_declares_loader_only_scope() {
        let output = run_with_args(["bpf-loader", "contract"]);
        assert_eq!(output.exit_code, 0, "{}", output.stderr);
        let json: Value = serde_json::from_str(&output.stdout).unwrap();
        assert_eq!(
            json["name"].as_str().unwrap(),
            "rust-aya-bpf-loader-go-adoption-contract"
        );
        assert_eq!(json["binary"].as_str().unwrap(), "dae-aya-bpf-loader");
        assert!(
            json["go_userspace_outbound_remains_authoritative"]
                .as_bool()
                .unwrap()
        );
        assert!(json["kernel_ebpf_program_rewrite"].as_bool().unwrap());
        assert_eq!(
            json["default_object_source"].as_str().unwrap(),
            "rust-aya-skeleton"
        );
        assert!(
            json["rust_aya_skeleton_object_supported"]
                .as_bool()
                .unwrap()
        );
        assert_eq!(json["maps"].as_array().unwrap().len(), 13);
        assert_eq!(json["tc_programs"].as_array().unwrap().len(), 6);
        assert_eq!(json["cgroup_programs"].as_array().unwrap().len(), 6);
        assert_eq!(
            json["supported_object_sources"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["c-aya", "rust-aya-skeleton"]
        );
    }

    #[test]
    fn load_pin_requires_full_param_set() {
        let output = run_with_args(["bpf-loader", "load-pin", "--pin-root", "/tmp/dae"]);
        assert_eq!(output.exit_code, 2);
        assert!(output.stderr.contains("--tproxy-port"));
    }

    #[test]
    fn load_pin_accepts_explicit_rust_skeleton_source() {
        let options = parse_load_pin_options(&[
            "--object-source=rust-aya-skeleton".to_owned(),
            "--object=/tmp/dae-ebpf-program".to_owned(),
            "--pin-root=/tmp/dae".to_owned(),
            "--tproxy-port=12345".to_owned(),
            "--control-plane-pid=7".to_owned(),
            "--dae0-ifindex=8".to_owned(),
            "--dae-netns-id=9".to_owned(),
            "--dae0peer-mac=02:00:00:00:00:01".to_owned(),
            "--has-bpf-get-current-task=true".to_owned(),
        ])
        .unwrap();
        assert_eq!(
            options.object_source,
            Some(BpfObjectSource::RustAyaSkeleton)
        );
        assert_eq!(options.object, Some(PathBuf::from("/tmp/dae-ebpf-program")));

        let options = parse_load_pin_options(&[
            "--object-source=rust-aya-skeleton".to_owned(),
            "--pin-root=/tmp/dae".to_owned(),
            "--tproxy-port=12345".to_owned(),
            "--control-plane-pid=7".to_owned(),
            "--dae0-ifindex=8".to_owned(),
            "--dae-netns-id=9".to_owned(),
            "--dae0peer-mac=02:00:00:00:00:01".to_owned(),
            "--has-bpf-get-current-task=true".to_owned(),
        ])
        .unwrap();
        assert_eq!(
            options.object_source,
            Some(BpfObjectSource::RustAyaSkeleton)
        );
        assert_eq!(options.object, None);

        let err = parse_load_pin_options(&[
            "--object-source=c-aya".to_owned(),
            "--pin-root=/tmp/dae".to_owned(),
            "--tproxy-port=12345".to_owned(),
            "--control-plane-pid=7".to_owned(),
            "--dae0-ifindex=8".to_owned(),
            "--dae-netns-id=9".to_owned(),
            "--dae0peer-mac=02:00:00:00:00:01".to_owned(),
            "--has-bpf-get-current-task=true".to_owned(),
        ])
        .unwrap_err();
        assert!(err.contains("c-aya requires --object"));
    }

    #[test]
    fn trace_loader_contract_declares_non_default_scope() {
        let output = run_with_args(["trace-loader", "contract"]);
        assert_eq!(output.exit_code, 0, "{}", output.stderr);
        let json: Value = serde_json::from_str(&output.stdout).unwrap();
        assert_eq!(
            json["name"].as_str().unwrap(),
            "rust-aya-trace-loader-contract"
        );
        assert!(!json["core_sideload_enabled"].as_bool().unwrap());
        assert!(!json["go_trace_adoption_ready"].as_bool().unwrap());
        assert!(!json["default_daemon_path"].as_bool().unwrap());
        assert!(!json["kernel_ebpf_program_rewrite"].as_bool().unwrap());
        assert_eq!(
            json["non_default_smokes"]["attach_ringbuf"]
                .as_str()
                .unwrap(),
            "disabled"
        );
        assert!(
            json["disabled_reason"]
                .as_str()
                .unwrap()
                .contains("retired from the product default path")
        );
    }

    #[test]
    fn trace_loader_core_sideload_commands_are_disabled() {
        let output = run_with_args([
            "trace-loader",
            "load-pin",
            "--object",
            "/tmp/trace.o",
            "--pin-root",
            "/sys/fs/bpf/trace",
            "--ip-version",
            "4",
            "--l4-proto",
            "6",
            "--port",
            "443",
            "--ringbuf-size",
            "65536",
        ]);
        assert_eq!(output.exit_code, 1);
        assert!(
            output
                .stderr
                .contains("retired from the product default path")
        );

        let output = run_with_args([
            "trace-loader",
            "attach-ringbuf-smoke",
            "--object",
            "/tmp/trace.o",
            "--target",
            "ip_rcv_core",
        ]);
        assert_eq!(output.exit_code, 1);
        assert!(
            output
                .stderr
                .contains("retired from the product default path")
        );
    }

    #[test]
    fn trace_attach_ringbuf_smoke_options_parse_explicit_target_and_defaults() {
        let options = parse_trace_attach_ringbuf_smoke_options(&[
            "--object=/tmp/trace.o".to_owned(),
            "--target=ip_rcv_core".to_owned(),
        ])
        .unwrap();
        assert_eq!(options.object, PathBuf::from("/tmp/trace.o"));
        assert_eq!(options.target, "ip_rcv_core");
        assert_eq!(options.program_name, "kprobe_skb_1");
        assert_eq!(options.ip_version, 4);
        assert_eq!(options.l4_proto, 6);
        assert_eq!(options.port, 443);
        assert_eq!(options.ringbuf_size, 65_536);
        assert_eq!(options.trigger, TraceLoaderAttachSmokeTrigger::LoopbackUdp);
        assert_eq!(options.trigger_count, 4);
        assert_eq!(options.poll_attempts, 50);

        let explicit = parse_trace_attach_ringbuf_smoke_options(&[
            "--object".to_owned(),
            "/tmp/trace.o".to_owned(),
            "--target".to_owned(),
            "security_file_open".to_owned(),
            "--program-name".to_owned(),
            "kprobe_skb_1".to_owned(),
            "--trigger".to_owned(),
            "open-proc-self-stat".to_owned(),
            "--trigger-count".to_owned(),
            "2".to_owned(),
            "--poll-attempts".to_owned(),
            "3".to_owned(),
        ])
        .unwrap();
        assert_eq!(explicit.target, "security_file_open");
        assert_eq!(
            explicit.trigger,
            TraceLoaderAttachSmokeTrigger::OpenProcSelfStat
        );
        assert_eq!(explicit.trigger_count, 2);
        assert_eq!(explicit.poll_attempts, 3);

        let err = parse_trace_attach_ringbuf_smoke_options(&[
            "--object=/tmp/trace.o".to_owned(),
            "--trigger=bad".to_owned(),
        ])
        .unwrap_err();
        assert!(err.contains("bad trace attach smoke trigger"));
    }

    #[test]
    fn cgroup_monitor_contract_declares_pinned_link_lifetime() {
        let output = run_with_args(["cgroup-monitor", "contract"]);
        assert_eq!(output.exit_code, 0, "{}", output.stderr);
        let json: Value = serde_json::from_str(&output.stdout).unwrap();
        assert_eq!(
            json["name"].as_str().unwrap(),
            "rust-cgroup-pname-monitor-attach-contract"
        );
        assert!(
            json["go_pname_routing_semantics_remain_authoritative"]
                .as_bool()
                .unwrap()
        );
        assert_eq!(json["attach_matrix"].as_array().unwrap().len(), 6);
    }

    #[test]
    fn map_stats_count_requires_map_specs() {
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
    fn cgroup_monitor_attach_pin_requires_paths() {
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
    fn tc_attach_contract_declares_pinned_lifetime_and_matrix() {
        let output = run_with_args(["tc-attach", "contract"]);
        assert_eq!(output.exit_code, 0, "{}", output.stderr);
        let json: Value = serde_json::from_str(&output.stdout).unwrap();
        assert_eq!(
            json["name"].as_str().unwrap(),
            "rust-tc-tcx-attach-pin-contract"
        );
        assert!(
            json["go_routing_dns_sniff_group_remain_authoritative"]
                .as_bool()
                .unwrap()
        );
        assert_eq!(json["attach_matrix"].as_array().unwrap().len(), 6);
    }

    #[test]
    fn tc_attach_pin_requires_full_spec() {
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
    fn tproxy_listener_contract_keeps_go_handlers_authoritative() {
        let output = run_with_args(["tproxy-listener", "contract"]);
        assert_eq!(output.exit_code, 0, "{}", output.stderr);
        let json: Value = serde_json::from_str(&output.stdout).unwrap();
        assert_eq!(
            json["name"].as_str().unwrap(),
            "rust-tproxy-listener-sockmap-handoff-contract"
        );
        assert!(
            json["go_userspace_tcp_udp_handlers_remain_authoritative"]
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
    fn tproxy_listener_commands_require_handoff_and_socket_fds() {
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
    fn connectivity_map_update_requires_full_key() {
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
    fn routing_map_apply_parser_preserves_match_set_shape() {
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
    fn domain_routing_map_apply_parser_preserves_bitmap_shape() {
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
    fn domain_routing_map_owner_parser_preserves_snapshot_shape() {
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

    #[test]
    fn domain_routing_map_owner_serve_reports_empty_snapshot_without_opening_map() {
        let mut owner = dae_control::DomainRoutingOwner::default();
        let response = handle_domain_routing_map_owner_serve_line(
            &mut owner,
            r#"{"op":"sync_owner","map_id":0,"owner_key":"empty","bitmap":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"ips":[]}"#,
        );
        let json: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(json["status"].as_str().unwrap(), "pass");
        assert_eq!(json["owner"].as_str().unwrap(), "dae-control");
        assert_eq!(json["scope"].as_str().unwrap(), "domain-routing-map-owner");
        assert!(json["map_id_changed"].as_bool().unwrap());
        assert!(json["skipped"].as_bool().unwrap());
        assert_eq!(json["entries_updated"].as_u64().unwrap(), 0);
    }

    #[test]
    fn connectivity_map_serve_dryrun_skip_does_not_open_map() {
        let mut owner = dae_control::OutboundConnectivityMapOwner::default();
        let response = handle_connectivity_map_serve_line(
            &mut owner,
            r#"{"map_id":0,"outbound":2,"l4_proto":6,"ip_version":4,"alive":true,"is_init":false,"dryrun":true}"#,
        );
        let json: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(json["status"].as_str().unwrap(), "pass");
        assert!(!json["written"].as_bool().unwrap());
        assert!(!json["accepted"].as_bool().unwrap());
        assert_eq!(json["owner"].as_str().unwrap(), "dae-control");
        assert_eq!(json["key"]["outbound"].as_u64().unwrap(), 2);
        assert!(owner.state_owner().state().is_empty());
    }

    #[test]
    fn connectivity_map_serve_binary_dryrun_skip_does_not_open_map() {
        let mut owner = dae_control::OutboundConnectivityMapOwner::default();
        let response = handle_connectivity_map_serve_binary_request(
            &mut owner,
            [
                0,
                0,
                0,
                0, // map id
                2,
                6,
                4,           // outbound, l4 proto, ip version
                0x01 | 0x04, // alive + dryrun, no is-init
            ],
        );
        assert_eq!(response[0], 0);
        assert_eq!(response[1], 0);
        assert_eq!(response[2], 0);
        assert_eq!(response[3], 0);
        assert_eq!(
            u32::from_le_bytes([response[4], response[5], response[6], response[7]]),
            0
        );
        assert!(owner.state_owner().state().is_empty());
    }

    #[test]
    fn connectivity_map_serve_reports_malformed_requests() {
        let mut owner = dae_control::OutboundConnectivityMapOwner::default();
        let response = handle_connectivity_map_serve_line(&mut owner, "{bad-json");
        let json: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(json["status"].as_str().unwrap(), "error");
        assert!(
            json["error"]
                .as_str()
                .unwrap()
                .contains("bad connectivity-map request")
        );
    }

    #[test]
    fn domain_routing_map_serve_reports_malformed_requests() {
        let response = handle_domain_routing_map_serve_line("{bad-json");
        let json: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(json["status"].as_str().unwrap(), "error");
        assert!(
            json["error"]
                .as_str()
                .unwrap()
                .contains("bad domain-routing-map request")
        );
    }

    #[test]
    fn domain_routing_map_owner_serve_reports_malformed_requests() {
        let mut owner = dae_control::DomainRoutingOwner::default();
        let response = handle_domain_routing_map_owner_serve_line(&mut owner, "{bad-json");
        let json: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(json["status"].as_str().unwrap(), "error");
        assert!(
            json["error"]
                .as_str()
                .unwrap()
                .contains("bad domain-routing-map owner request")
        );
    }

    #[test]
    fn parses_mac_and_bool_values() {
        assert_eq!(
            parse_mac("aa:bb:cc:dd:ee:ff").unwrap(),
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
        );
        assert!(parse_bool("on").unwrap());
        assert!(!parse_bool("off").unwrap());
    }
}
