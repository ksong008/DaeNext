use std::path::{Path, PathBuf};

const CENTRAL_CONSTRUCTOR: &str = "crates/dae-daemon/src/production_runtime_owner/resident_dataplane/tcp/proxy_dispatch/quic_endpoint.rs";
const CONNECT_UDP_TEST_SERVER: &str = "crates/dae-daemon/src/production_runtime_owner/resident_dataplane/udp/session_executor/connect_udp/h3/tests/server.rs";
const SOURCE_GATE_TEST: &str = "crates/dae-daemon/src/production_runtime_owner/resident_dataplane/tcp/proxy_dispatch/quic_endpoint/tests/source_gate.rs";
const EXPLICIT_NON_PRODUCTION_CONSTRUCTORS: &[&str] = &[
    CONNECT_UDP_TEST_SERVER,
    SOURCE_GATE_TEST,
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
