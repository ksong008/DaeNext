use super::*;

#[test]
fn optin_runner_userspace_commands_match_engine_fixture() {
    let fixture = load("engine/userspace_runtime/optin_contract.json");

    let routing = &fixture["routing"];
    let route = run_with_args([
        "userspace",
        "route-match",
        "--domain",
        routing["domain"].as_str().unwrap(),
        "--dest",
        routing["dest"].as_str().unwrap(),
        "--port",
        "443",
    ]);
    assert_eq!(route.exit_code, 0);
    assert_eq!(route.stderr, "");
    let route_json: Value = serde_json::from_str(&route.stdout).unwrap();
    assert_eq!(
        route_json["outbound"].as_str().unwrap(),
        routing["want_outbound"].as_str().unwrap()
    );
    assert!(route_json["userspace_only"].as_bool().unwrap());

    let dns = &fixture["dns"];
    let dns_key = run_with_args([
        "userspace",
        "dns-cache-key",
        "--qname",
        dns["qname"].as_str().unwrap(),
        "--qtype",
        "1",
        "--qclass",
        "1",
    ]);
    assert_eq!(dns_key.exit_code, 0);
    assert_eq!(dns_key.stderr, "");
    let dns_json: Value = serde_json::from_str(&dns_key.stdout).unwrap();
    assert_eq!(
        dns_json["key"].as_str().unwrap(),
        dns["cache_key"].as_str().unwrap()
    );

    let outbound = &fixture["outbound_group"];
    let select = run_with_args([
        "userspace",
        "outbound-select",
        "--policy",
        outbound["policy"].as_str().unwrap(),
        "--network",
        outbound["network"].as_str().unwrap(),
    ]);
    assert_eq!(select.exit_code, 0);
    assert_eq!(select.stderr, "");
    let select_json: Value = serde_json::from_str(&select.stdout).unwrap();
    assert_eq!(
        select_json["selected_index"].as_u64().unwrap(),
        outbound["selected_index"].as_u64().unwrap()
    );
    assert_eq!(
        select_json["latency_ms"].as_i64().unwrap(),
        outbound["selected_latency_ms"].as_i64().unwrap()
    );

    let sniff = run_with_args(["userspace", "sniff-tcp", "--kind", "http"]);
    assert_eq!(sniff.exit_code, 0);
    assert_eq!(sniff.stderr, "");
    let sniff_json: Value = serde_json::from_str(&sniff.stdout).unwrap();
    assert_eq!(
        sniff_json["domain"].as_str().unwrap(),
        fixture["sniffing"]["http_host_normalized"]
            .as_str()
            .unwrap()
    );

    let magic = run_with_args([
        "userspace",
        "magic-network",
        "--network",
        "tcp",
        "--mark",
        "1234",
        "--mptcp",
        "true",
    ]);
    assert_eq!(magic.exit_code, 0);
    assert_eq!(magic.stderr, "");
    let magic_json: Value = serde_json::from_str(&magic.stdout).unwrap();
    assert_eq!(
        magic_json["parsed_mark"].as_u64().unwrap(),
        fixture["magic_network"]["mark"].as_u64().unwrap()
    );
    assert_eq!(
        magic_json["parsed_mptcp"].as_bool().unwrap(),
        fixture["magic_network"]["mptcp"].as_bool().unwrap()
    );
    assert!(!magic_json["plain"].as_bool().unwrap());
}

#[test]
fn optin_runner_active_datapath_commands_match_control_fixture() {
    let fixture = load("control/active_datapath/optin_contract.json");

    let contract = run_with_args(["active-datapath", "contract"]);
    assert_eq!(contract.exit_code, 0);
    assert_eq!(contract.stderr, "");
    let contract_json: Value = serde_json::from_str(&contract.stdout).unwrap();
    assert_eq!(
        contract_json["name"].as_str().unwrap(),
        fixture["name"].as_str().unwrap()
    );
    assert!(contract_json["default_go_attach_path"].as_bool().unwrap());
    assert_eq!(
        contract_json["ebpf"]["pinned_reuse_maps"]
            .as_array()
            .unwrap()
            .len(),
        fixture["ebpf_loader"]["pinned_reuse_maps"]
            .as_array()
            .unwrap()
            .len()
    );
    assert_eq!(
        contract_json["ebpf"]["tproxy_port_big_endian"]
            .as_u64()
            .unwrap(),
        fixture["ebpf_loader"]["tproxy_port_big_endian"]
            .as_u64()
            .unwrap()
    );
    assert!(
        contract_json["reload_rollback_injects_old_bpf"]
            .as_bool()
            .unwrap()
    );
    assert!(
        contract_json["netns_same_interface_risk"]["tc_act_pipe_required"]
            .as_bool()
            .unwrap()
    );

    let reload = run_with_args(["active-datapath", "reload-ownership"]);
    assert_eq!(reload.exit_code, 0);
    assert_eq!(reload.stderr, "");
    let reload_json: Value = serde_json::from_str(&reload.stdout).unwrap();
    assert!(
        reload_json["reload_rollback_injects_old_bpf"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(reload_json["steps"].as_array().unwrap().len(), 5);

    let magic = run_with_args([
        "active-datapath",
        "magic-dial",
        "--network",
        "tcp",
        "--mark",
        "1234",
        "--mptcp",
        "true",
    ]);
    assert_eq!(magic.exit_code, 0);
    assert_eq!(magic.stderr, "");
    let magic_json: Value = serde_json::from_str(&magic.stdout).unwrap();
    assert_eq!(
        magic_json["parsed_mark"].as_u64().unwrap(),
        fixture["magic_network"]["mark"].as_u64().unwrap()
    );
    assert_eq!(
        magic_json["parsed_mptcp"].as_bool().unwrap(),
        fixture["magic_network"]["mptcp"].as_bool().unwrap()
    );
    assert!(magic_json["active_path"].as_bool().unwrap());
}
