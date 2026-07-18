use std::path::{Path, PathBuf};

const CENTRAL_CONSTRUCTOR: &str = "crates/dae-daemon/src/production_runtime_owner/resident_dataplane/tcp/proxy_dispatch/quic_endpoint.rs";
const PROXIED_DOH3_TEST_SERVER: &str = "crates/dae-daemon/src/production_runtime_owner/resident_dataplane/dns/transport/h3/proxied/tests/h3_server.rs";
const SOURCE_GATE_TEST: &str = "crates/dae-daemon/src/production_runtime_owner/resident_dataplane/tcp/proxy_dispatch/quic_endpoint/tests/source_gate.rs";
const EXPLICIT_NON_PRODUCTION_CONSTRUCTORS: &[&str] = &[
    PROXIED_DOH3_TEST_SERVER,
    SOURCE_GATE_TEST,
    "crates/dae-daemon/src/production_runtime_owner/resident_dataplane/tcp/proxy_dispatch/quic_helpers_port_hopping_tests.rs",
    "crates/dae-daemon/src/production_runtime_owner/resident_dataplane/runtime/hysteria2_owner_live_tests.rs",
    "crates/dae-daemon/src/production_runtime_owner/resident_dataplane/runtime/tuic_owner_live_tests.rs",
    "crates/dae-daemon/src/production_runtime_owner/resident_dataplane/tcp/transport_helpers/xhttp_h2/h3_boring_tls_tests.rs",
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
fn production_hysteria2_transport_construction_is_registry_owned() {
    const CONNECTION_CONSTRUCTOR: &str = "crates/dae-daemon/src/production_runtime_owner/resident_dataplane/tcp/proxy_dispatch/quic_connections.rs";
    const TRANSPORT_OWNER: &str = "crates/dae-daemon/src/production_runtime_owner/resident_dataplane/runtime/hysteria2_owner.rs";
    let allowed = [CONNECTION_CONSTRUCTOR, TRANSPORT_OWNER, SOURCE_GATE_TEST];
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let root = repo.join("crates/dae-daemon/src/production_runtime_owner/resident_dataplane");
    let mut files = Vec::new();
    collect_rust_files(&root, &mut files);
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
    const CONNECTION_CONSTRUCTOR: &str = "crates/dae-daemon/src/production_runtime_owner/resident_dataplane/tcp/proxy_dispatch/quic_connections.rs";
    const TRANSPORT_OWNER: &str =
        "crates/dae-daemon/src/production_runtime_owner/resident_dataplane/runtime/tuic_owner.rs";
    let allowed = [CONNECTION_CONSTRUCTOR, TRANSPORT_OWNER, SOURCE_GATE_TEST];
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let root = repo.join("crates/dae-daemon/src/production_runtime_owner/resident_dataplane");
    let mut files = Vec::new();
    collect_rust_files(&root, &mut files);
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
