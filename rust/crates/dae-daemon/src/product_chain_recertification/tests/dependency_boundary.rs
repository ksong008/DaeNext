use super::*;

#[test]
fn daed2_dependency_boundary_requires_wing_and_dae_core_replaces() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-product-chain-daed2-boundary-{}",
        std::process::id()
    ));
    let daed = root.join("daed");
    let wing = daed.join("wing");
    let dae_go_mod = root.join("dae.go.mod");
    let outbound = root.join("outbound");
    let quic_go = root.join("quic-go");
    write_fixture_file(
        &dae_go_mod,
        &format!(
            "replace github.com/daeuniverse/outbound => {}\nreplace github.com/daeuniverse/quic-go => {}\n",
            path_string(&outbound),
            path_string(&quic_go)
        ),
    );
    write_fixture_file(
        &wing.join("go.mod"),
        &format!(
            "replace github.com/daeuniverse/dae => ./dae-core\nreplace github.com/daeuniverse/outbound => {}\nreplace github.com/daeuniverse/quic-go => {}\n",
            path_string(&outbound),
            path_string(&quic_go)
        ),
    );
    write_fixture_file(
        &wing.join("dae-core/go.mod"),
        &format!(
            "replace github.com/daeuniverse/outbound => {}\nreplace github.com/daeuniverse/quic-go => {}\n",
            path_string(&outbound),
            path_string(&quic_go)
        ),
    );
    let options = ProductChainRecertificationOptions {
        dae_wing_repo: wing.clone(),
        daed_repo: daed.clone(),
        outbound_repo: outbound,
        quic_go_repo: quic_go,
        go_mod_file: dae_go_mod,
        ..ProductChainRecertificationOptions::default()
    };
    let topology = product_chain_topology(&options);
    let report = go_mod_dependency_boundary_json(&options, &topology);
    assert_eq!(topology.kind, ProductChainTopologyKind::Daed2Wing);
    assert_eq!(
        report["topology"].as_str().unwrap(),
        "daed2.0-web-wing-daecore"
    );
    assert!(
        report["outbound_quic_go_dependency_boundary_preserved"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["wing"]["dae_core_replace_preserved"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        report["wing"]["outbound_replace_target"].as_str().unwrap(),
        "local"
    );
    assert_eq!(
        report["wing"]["quic_go_replace_target"].as_str().unwrap(),
        "local"
    );
    assert!(
        report["dae_core"]["outbound_quic_go_dependency_boundary_preserved"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        report["dae_core"]["outbound_replace_target"]
            .as_str()
            .unwrap(),
        "local"
    );
    assert_eq!(
        report["dae_core"]["quic_go_replace_target"]
            .as_str()
            .unwrap(),
        "local"
    );
    let _ = std::fs::remove_dir_all(root);
}
