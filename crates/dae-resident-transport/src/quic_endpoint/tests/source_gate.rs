use std::path::{Path, PathBuf};

const CENTRAL_CONSTRUCTOR: &str = "crates/dae-resident-transport/src/quic_endpoint.rs";
const PROXIED_DOH3_TEST_SERVER: &str =
    "crates/dae-resident-dns/src/runtime/transport/h3/proxied/tests/h3_server.rs";
const DNS_QUIC_TEST_SUPPORT: &str = "crates/dae-resident-dns/src/runtime/transport/test_support.rs";
const XHTTP_H3_OWNER_TEST: &str =
    "crates/dae-resident-transport/src/xhttp/h3_transport/owner_live_tests.rs";
const XHTTP_H3_PACKET_UP_TEST: &str =
    "crates/dae-resident-transport/src/xhttp/h3_transport/packet_up_tests.rs";
const SOURCE_GATE_TEST: &str =
    "crates/dae-resident-transport/src/quic_endpoint/tests/source_gate.rs";
const EXPLICIT_NON_PRODUCTION_CONSTRUCTORS: &[&str] = &[
    PROXIED_DOH3_TEST_SERVER,
    DNS_QUIC_TEST_SUPPORT,
    XHTTP_H3_OWNER_TEST,
    XHTTP_H3_PACKET_UP_TEST,
    SOURCE_GATE_TEST,
    "crates/dae-resident-dataplane/src/runtime/hysteria2_owner_live_tests.rs",
    "crates/dae-resident-dataplane/src/runtime/tuic_owner_live_tests.rs",
    "crates/dae-resident-dataplane/src/runtime/juicity_owner_live_tests.rs",
    "crates/dae-resident-transport/src/xhttp/h3_boring_tls_tests.rs",
    "crates/dae-outbound/src/hysteria2/auth/tests.rs",
    "crates/dae-outbound/src/hysteria2/quic_loopback.rs",
    "crates/dae-outbound/src/hysteria2/tls/tests.rs",
    "crates/dae-outbound/src/juicity/auth_lifecycle.rs",
    "crates/dae-outbound/src/juicity/auth_stream_ekm.rs",
    "crates/dae-outbound/src/juicity/auth_stream_live.rs",
    "crates/dae-outbound/src/juicity/h3_loopback.rs",
    "crates/dae-outbound/src/juicity/stream_packet_congestion/runner.rs",
    "crates/dae-outbound/src/juicity/stream_packet_conn.rs",
    "crates/dae-outbound/src/shared_transport/xhttp_h3.rs",
    "crates/dae-outbound/src/tuic/quic_loopback.rs",
];

#[test]
fn production_quinn_endpoint_constructors_are_centralized() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut files = Vec::new();
    collect_rust_files(&repo.join("crates"), &mut files);
    let constructors = [
        "Endpoint::new(",
        "Endpoint::new_with_abstract_socket(",
        "Endpoint::client(",
        "Endpoint::server(",
    ];
    let mut offenders = Vec::new();
    for file in files {
        let relative = file.strip_prefix(&repo).unwrap().to_string_lossy();
        let source = std::fs::read_to_string(&file).unwrap();
        for constructor in constructors {
            if source.contains(constructor)
                && relative != CENTRAL_CONSTRUCTOR
                && !EXPLICIT_NON_PRODUCTION_CONSTRUCTORS.contains(&relative.as_ref())
            {
                offenders.push(format!("{relative} contains {constructor}"));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "production Quinn Endpoint constructors must use the tagged central constructor; explicit test constructors require allow-list review:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn quic_fixture_modules_stay_behind_test_support() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let modules = [
        ("crates/dae-outbound/src/hysteria2/mod.rs", "dataplane"),
        ("crates/dae-outbound/src/hysteria2/mod.rs", "quic_loopback"),
        ("crates/dae-outbound/src/tuic/mod.rs", "dataplane"),
        ("crates/dae-outbound/src/tuic/mod.rs", "quic_loopback"),
        ("crates/dae-outbound/src/juicity/mod.rs", "auth_lifecycle"),
        ("crates/dae-outbound/src/juicity/mod.rs", "auth_stream_ekm"),
        ("crates/dae-outbound/src/juicity/mod.rs", "auth_stream_live"),
        (
            "crates/dae-outbound/src/juicity/mod.rs",
            "client_integration",
        ),
        ("crates/dae-outbound/src/juicity/mod.rs", "h3_loopback"),
        (
            "crates/dae-outbound/src/juicity/mod.rs",
            "outbound_dataplane",
        ),
        (
            "crates/dae-outbound/src/juicity/mod.rs",
            "stream_packet_congestion",
        ),
        (
            "crates/dae-outbound/src/juicity/mod.rs",
            "stream_packet_conn",
        ),
        (
            "crates/dae-outbound/src/shared_transport/mod.rs",
            "test_support",
        ),
        ("crates/dae-outbound/src/shared_transport/mod.rs", "tls"),
        (
            "crates/dae-outbound/src/shared_transport/mod.rs",
            "xhttp_h3",
        ),
    ];

    for (relative, module) in modules {
        let source = std::fs::read_to_string(repo.join(relative))
            .unwrap_or_else(|err| panic!("read {relative}: {err}"));
        let private = format!("#[cfg(any(test, feature = \"test-support\"))]\nmod {module};");
        let public = format!("#[cfg(any(test, feature = \"test-support\"))]\npub mod {module};");
        assert!(
            source.contains(&private) || source.contains(&public),
            "{relative} must compile-gate module {module} behind test-support"
        );
    }
}

#[test]
fn production_hysteria2_transport_construction_is_registry_owned() {
    const CONNECTION_CONSTRUCTOR: &str = "crates/dae-resident-transport/src/quic_connections.rs";
    const TRANSPORT_OWNER: &str = "crates/dae-resident-transport/src/hysteria2_owner.rs";
    let allowed = [CONNECTION_CONSTRUCTOR, TRANSPORT_OWNER, SOURCE_GATE_TEST];
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let files = collect_resident_production_files(&repo);
    let restricted = [
        "open_hysteria2_quic_connection_candidates_async(",
        "authenticate_hysteria2_connection(",
    ];
    let mut offenders = Vec::new();
    for file in files {
        let relative = file.strip_prefix(&repo).unwrap().to_string_lossy();
        let source = std::fs::read_to_string(&file).unwrap();
        for constructor in restricted {
            if source.contains(constructor) && !allowed.contains(&relative.as_ref()) {
                offenders.push(format!("{relative} contains {constructor}"));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "production Hysteria2 Endpoint/auth construction must remain behind the generation-owned registry:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn production_tuic_transport_construction_is_registry_owned() {
    const CONNECTION_CONSTRUCTOR: &str = "crates/dae-resident-transport/src/quic_connections.rs";
    const TRANSPORT_OWNER: &str = "crates/dae-resident-transport/src/tuic_owner.rs";
    let allowed = [CONNECTION_CONSTRUCTOR, TRANSPORT_OWNER, SOURCE_GATE_TEST];
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let files = collect_resident_production_files(&repo);
    let restricted = [
        "open_tuic_quic_connection_candidates_async(",
        "authenticate_tuic_connection(",
    ];
    let mut offenders = Vec::new();
    for file in files {
        let relative = file.strip_prefix(&repo).unwrap().to_string_lossy();
        let source = std::fs::read_to_string(&file).unwrap();
        for constructor in restricted {
            if source.contains(constructor) && !allowed.contains(&relative.as_ref()) {
                offenders.push(format!("{relative} contains {constructor}"));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "production TUIC Endpoint/auth construction must remain behind the generation-owned registry:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn production_juicity_transport_construction_is_registry_owned() {
    const CONNECTION_CONSTRUCTOR: &str = "crates/dae-resident-transport/src/quic_connections.rs";
    const TRANSPORT_OWNER: &str = "crates/dae-resident-transport/src/juicity_owner.rs";
    let allowed = [CONNECTION_CONSTRUCTOR, TRANSPORT_OWNER, SOURCE_GATE_TEST];
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let files = collect_resident_production_files(&repo);
    let restricted = [
        "open_juicity_quic_connection_candidates_async(",
        "authenticate_juicity_connection(",
    ];
    let mut offenders = Vec::new();
    for file in files {
        let relative = file.strip_prefix(&repo).unwrap().to_string_lossy();
        let source = std::fs::read_to_string(&file).unwrap();
        for constructor in restricted {
            if source.contains(constructor) && !allowed.contains(&relative.as_ref()) {
                offenders.push(format!("{relative} contains {constructor}"));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "production Juicity Endpoint/auth construction must remain behind the generation-owned registry:\n{}",
        offenders.join("\n")
    );
}

fn collect_resident_production_files(repo: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for crate_name in [
        "dae-resident-dataplane",
        "dae-resident-dns",
        "dae-resident-tcp",
        "dae-resident-transport",
    ] {
        collect_rust_files(
            &repo.join("crates").join(crate_name).join("src"),
            &mut files,
        );
    }
    files
}

fn collect_rust_files(root: &Path, files: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect_rust_files(&path, files);
        } else if path.extension().and_then(|value| value.to_str()) == Some("rs") {
            files.push(path);
        }
    }
}
