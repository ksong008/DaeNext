#[path = "quic_owner_external_live_tests/config.rs"]
mod config;
#[path = "quic_owner_external_live_tests/control.rs"]
mod control;
#[path = "quic_owner_external_live_tests/owner.rs"]
mod owner;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use serde_json::{Value, json};
use tokio::task::JoinSet;
use tokio::time;

use self::config::ExternalLiveConfig;
use self::control::coordinate_remote_restart;
use self::owner::ExternalLiveOwner;
use super::ResidentTransportOwnerRegistries;
use super::plan::{ResidentProxyBinding, build_resident_proxy_plan_for_node};
use super::tcp::quic_endpoint_metrics_snapshot;
use super::udp::{ProxyUdpSessionCheckpoint, exercise_proxy_udp_packet_session};

const EXTERNAL_LIVE_GENERATION: u64 = 9_001;
const EXTERNAL_LIVE_RUNTIME_WORKERS: usize = 4;

#[test]
fn maintained_quic_owner_persists_reconnects_and_releases_resources() {
    let Some(config) = ExternalLiveConfig::load_if_enabled()
        .expect("load external QUIC owner live-test configuration")
    else {
        return;
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(EXTERNAL_LIVE_RUNTIME_WORKERS)
        .thread_name("quic-owner-external-live")
        .enable_io()
        .enable_time()
        .build()
        .expect("build shared external QUIC owner test runtime");
    runtime.block_on(async move {
        run_external_live_test(config)
            .await
            .expect("external QUIC owner live test");
    });
}

async fn run_external_live_test(config: ExternalLiveConfig) -> Result<(), String> {
    let process_before = process_resource_snapshot();
    let binding = build_external_binding(&config.link, EXTERNAL_LIVE_GENERATION)?;
    let owner = ExternalLiveOwner::start(config.protocol, EXTERNAL_LIVE_GENERATION);

    let persistent_payloads = vec![vec![0x11; 17], vec![0x22; 1_400], vec![0x33; 31]];
    let persistent = time::timeout(
        config.operation_timeout,
        exercise_proxy_udp_packet_session(
            binding.clone(),
            owner.registries(),
            config.udp_target,
            &persistent_payloads,
            None,
        ),
    )
    .await
    .map_err(|_| "persistent UDP session exercise timed out".to_owned())??;
    if persistent != persistent_payloads {
        return Err("persistent UDP session did not return exact payloads".to_owned());
    }
    if owner.cumulative_builds() != 1 {
        return Err("persistent UDP session did not retain one physical owner".to_owned());
    }

    let pressure = run_concurrent_sessions(
        binding.clone(),
        owner.registries(),
        config.udp_target,
        config.session_count,
        config.operation_timeout,
        &owner,
    )
    .await?;

    coordinate_remote_restart(
        &config.control_dir,
        config.protocol.label(),
        config.operation_timeout,
    )
    .await?;
    owner
        .wait_until_transport_closed(config.operation_timeout)
        .await?;
    let reconnect_payloads = vec![vec![0x44; 17], vec![0x55; 1_400]];
    let reconnect = time::timeout(
        config.operation_timeout,
        exercise_proxy_udp_packet_session(
            binding,
            owner.registries(),
            config.udp_target,
            &reconnect_payloads,
            None,
        ),
    )
    .await
    .map_err(|_| "same-generation UDP reconnect exercise timed out".to_owned())??;
    if reconnect != reconnect_payloads {
        return Err("same-generation reconnect did not return exact UDP payloads".to_owned());
    }
    if owner.cumulative_builds() != 2 {
        return Err(
            "same-generation reconnect did not rebuild exactly one physical owner".to_owned(),
        );
    }

    let reconnect_owner = owner.snapshot();
    let reconnect_endpoint = owner.endpoint_snapshot();
    let (closed_owner, closed_endpoint) = owner.stop(config.operation_timeout).await?;
    let process_after = process_resource_snapshot();
    let evidence = json!({
        "schema": "quic-owner-external-live-v1",
        "protocol": config.protocol.label(),
        "generation": EXTERNAL_LIVE_GENERATION,
        "runtimeWorkers": EXTERNAL_LIVE_RUNTIME_WORKERS,
        "concurrentSessions": config.session_count,
        "persistentPayloadLengths": persistent_payloads.iter().map(Vec::len).collect::<Vec<_>>(),
        "reconnectPayloadLengths": reconnect_payloads.iter().map(Vec::len).collect::<Vec<_>>(),
        "processBefore": process_before,
        "pressure": pressure,
        "reconnectedOwner": reconnect_owner,
        "reconnectedEndpoint": reconnect_endpoint,
        "closedOwner": closed_owner,
        "closedEndpoint": closed_endpoint,
        "processAfter": process_after,
    });
    println!(
        "{}",
        serde_json::to_string(&evidence)
            .map_err(|err| format!("serialize external QUIC owner evidence: {err}"))?
    );
    Ok(())
}

async fn run_concurrent_sessions(
    binding: ResidentProxyBinding,
    registries: ResidentTransportOwnerRegistries,
    target: SocketAddr,
    session_count: usize,
    timeout: std::time::Duration,
    owner: &ExternalLiveOwner,
) -> Result<Value, String> {
    let checkpoint = ProxyUdpSessionCheckpoint::new(session_count);
    let mut sessions = JoinSet::new();
    for index in 0..session_count {
        let binding = binding.clone();
        let registries = registries.clone();
        let checkpoint = checkpoint.clone();
        let payloads = vec![concurrent_payload(index)];
        sessions.spawn(async move {
            let responses = exercise_proxy_udp_packet_session(
                binding,
                registries,
                target,
                &payloads,
                Some(checkpoint),
            )
            .await?;
            if responses != payloads {
                return Err("concurrent UDP session did not return its exact payload".to_owned());
            }
            Ok::<(), String>(())
        });
    }
    let held = time::timeout(timeout, checkpoint.wait_until_held()).await;
    let hold_error = match held {
        Ok(Ok(())) => None,
        Ok(Err(error)) => Some(error),
        Err(_) => Some(
            "concurrent UDP sessions did not reach the hold checkpoint before timeout".to_owned(),
        ),
    };
    if let Some(error) = hold_error {
        checkpoint.release_sessions();
        sessions.abort_all();
        while sessions.join_next().await.is_some() {}
        return Err(error);
    }
    owner.assert_pressure(session_count);
    let evidence = json!({
        "owner": owner.snapshot(),
        "endpoint": owner.endpoint_snapshot(),
        "process": process_resource_snapshot(),
    });
    checkpoint.release_sessions();
    time::timeout(timeout, async {
        while let Some(result) = sessions.join_next().await {
            result.map_err(|err| format!("join concurrent UDP session: {err}"))??;
        }
        Ok::<(), String>(())
    })
    .await
    .map_err(|_| "concurrent UDP session cleanup timed out".to_owned())??;
    Ok(evidence)
}

fn concurrent_payload(index: usize) -> Vec<u8> {
    let mut payload = vec![0x66; 64];
    payload[..std::mem::size_of::<u64>()].copy_from_slice(&(index as u64).to_be_bytes());
    payload
}

fn build_external_binding(link: &str, generation: u64) -> Result<ResidentProxyBinding, String> {
    let config = dae_config::Config {
        global: dae_config::Global::default(),
        subscription: Vec::new(),
        node: Vec::new(),
        group: Vec::new(),
        routing: dae_config::Routing::default(),
        dns: dae_config::Dns::default(),
    };
    let mut proxy = build_resident_proxy_plan_for_node(
        &config,
        "external-quic-owner".to_owned(),
        "external-quic-owner-node".to_owned(),
        link.to_owned(),
    )
    .map_err(|_| "build external QUIC owner plan from configured link failed".to_owned())?;
    proxy.materialize_execution();
    ResidentProxyBinding::resident(
        Arc::new(proxy),
        dae_runtime_control::OwnerGeneration::new(generation),
    )
    .map_err(|_| "materialize external QUIC owner binding failed".to_owned())
}

fn process_resource_snapshot() -> Value {
    json!({
        "fds": directory_entry_count(Path::new("/proc/self/fd")),
        "threads": directory_entry_count(Path::new("/proc/self/task")),
        "endpointGeneration": quic_endpoint_metrics_snapshot(EXTERNAL_LIVE_GENERATION),
    })
}

fn directory_entry_count(path: &Path) -> Option<usize> {
    std::fs::read_dir(path).ok().map(|entries| entries.count())
}
