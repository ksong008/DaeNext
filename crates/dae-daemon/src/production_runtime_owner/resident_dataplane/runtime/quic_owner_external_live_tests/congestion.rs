use std::net::SocketAddr;
use std::time::{Duration, Instant};

use serde_json::json;
use tokio::time;

#[path = "congestion/config.rs"]
mod config;
#[path = "congestion/stats.rs"]
mod stats;

use self::config::CongestionBenchmarkConfig;
use self::stats::{ProcessResourceSample, allocator_sample, duration_micros, percentile};
use super::super::udp::exercise_proxy_udp_packet_session;
use super::build_external_binding;
use super::config::QuicOwnerProtocol;
use super::owner::ExternalLiveOwner;

const BENCHMARK_GENERATION: u64 = 9_002;
const BENCHMARK_RUNTIME_WORKERS: usize = 4;
const UPLOAD_CHUNK_BYTES: usize = 64 * 1024;

struct UploadReport {
    bytes: usize,
    elapsed: Duration,
    write_micros: Vec<u64>,
    peak: ProcessResourceSample,
}

struct UdpReport {
    sent: usize,
    received: usize,
    latency_micros: Vec<u64>,
    peak: ProcessResourceSample,
}

#[test]
fn maintained_hysteria2_congestion_profile_records_bounded_resources() {
    let Some(config) = CongestionBenchmarkConfig::load_if_enabled()
        .expect("load external Hysteria2 congestion benchmark configuration")
    else {
        return;
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(BENCHMARK_RUNTIME_WORKERS)
        .thread_name("hy2-congestion-external")
        .enable_io()
        .enable_time()
        .build()
        .expect("build shared Hysteria2 congestion benchmark runtime");
    runtime.block_on(async move {
        run_benchmark(config)
            .await
            .expect("external Hysteria2 congestion benchmark");
    });
}

async fn run_benchmark(config: CongestionBenchmarkConfig) -> Result<(), String> {
    let process_before = ProcessResourceSample::capture();
    let allocator_before = allocator_sample();
    let binding = build_external_binding(&config.link, BENCHMARK_GENERATION)?;
    let owner = ExternalLiveOwner::start(QuicOwnerProtocol::Hysteria2, BENCHMARK_GENERATION);
    let transport = owner
        .acquire_hysteria2(binding.clone(), config.operation_timeout)
        .await?;
    let negotiated = owner.snapshot()["congestion"]["lastNegotiated"].clone();
    if negotiated["controller"] != "brutal" {
        return Err("Hysteria2 benchmark did not negotiate the fixed-rate controller".to_owned());
    }

    let upload = time::timeout(
        config.operation_timeout,
        upload_tcp(
            transport.connection(),
            config.tcp_target,
            config.upload_bytes,
        ),
    )
    .await
    .map_err(|_| "Hysteria2 benchmark TCP upload timed out".to_owned())??;
    let allocator_after_upload = allocator_sample();
    drop(transport);

    let udp = measure_udp(&config, binding, owner.registries()).await;
    let allocator_after_udp = allocator_sample();
    let pressure_owner = owner.snapshot();
    let pressure_endpoint = owner.endpoint_snapshot();
    let (closed_owner, closed_endpoint) = owner.stop(config.operation_timeout).await?;
    let process_after = ProcessResourceSample::capture();
    let allocator_after_close = allocator_sample();
    let elapsed_seconds = upload.elapsed.as_secs_f64();
    let throughput_mbps = if elapsed_seconds > 0.0 {
        (upload.bytes as f64) * 8.0 / elapsed_seconds / 1_000_000.0
    } else {
        0.0
    };
    let evidence = json!({
        "schema": "hy2-congestion-external-v1",
        "profile": config.profile,
        "generation": BENCHMARK_GENERATION,
        "runtimeWorkers": BENCHMARK_RUNTIME_WORKERS,
        "negotiated": negotiated,
        "upload": {
            "bytes": upload.bytes,
            "elapsedMicros": duration_micros(upload.elapsed),
            "throughputMbps": throughput_mbps,
            "writeSamples": upload.write_micros.len(),
            "writeP50Micros": percentile(&upload.write_micros, 50),
            "writeP95Micros": percentile(&upload.write_micros, 95),
            "writeP99Micros": percentile(&upload.write_micros, 99),
            "peak": upload.peak.to_json(),
        },
        "udp": {
            "sent": udp.sent,
            "received": udp.received,
            "lost": udp.sent.saturating_sub(udp.received),
            "lossRatio": 1.0 - (udp.received as f64 / udp.sent as f64),
            "latencyP50Micros": percentile(&udp.latency_micros, 50),
            "latencyP95Micros": percentile(&udp.latency_micros, 95),
            "latencyP99Micros": percentile(&udp.latency_micros, 99),
            "peak": udp.peak.to_json(),
        },
        "ownerAtPressure": pressure_owner,
        "endpointAtPressure": pressure_endpoint,
        "closedOwner": closed_owner,
        "closedEndpoint": closed_endpoint,
        "processBefore": process_before.to_json(),
        "processAfter": process_after.to_json(),
        "allocator": {
            "before": allocator_before,
            "afterUpload": allocator_after_upload,
            "afterUdp": allocator_after_udp,
            "afterClose": allocator_after_close,
        },
    });
    println!(
        "{}",
        serde_json::to_string(&evidence)
            .map_err(|err| format!("serialize Hysteria2 congestion evidence: {err}"))?
    );
    Ok(())
}

async fn upload_tcp(
    connection: &quinn::Connection,
    target: SocketAddr,
    upload_bytes: usize,
) -> Result<UploadReport, String> {
    let (mut send, mut receive) = connection
        .open_bi()
        .await
        .map_err(|err| format!("open Hysteria2 benchmark TCP stream: {err}"))?;
    dae_outbound::hysteria2::write_hysteria2_tcp_request(&mut send, &target.to_string())
        .await
        .map_err(|err| format!("write Hysteria2 benchmark TCP request: {err}"))?;
    let response = dae_outbound::hysteria2::read_hysteria2_tcp_response(&mut receive)
        .await
        .map_err(|err| format!("read Hysteria2 benchmark TCP response: {err}"))?;
    if !response.ok {
        return Err("Hysteria2 benchmark TCP target was rejected".to_owned());
    }

    send.write_all(&(upload_bytes as u64).to_be_bytes())
        .await
        .map_err(|err| format!("write Hysteria2 benchmark payload length: {err}"))?;
    let payload = vec![0xa5_u8; UPLOAD_CHUNK_BYTES];
    let mut remaining = upload_bytes;
    let mut write_micros = Vec::with_capacity(upload_bytes.div_ceil(UPLOAD_CHUNK_BYTES));
    let mut peak = ProcessResourceSample::capture();
    let started = Instant::now();
    while remaining != 0 {
        let len = remaining.min(payload.len());
        let write_started = Instant::now();
        send.write_all(&payload[..len])
            .await
            .map_err(|err| format!("write Hysteria2 benchmark TCP payload: {err}"))?;
        write_micros.push(duration_micros(write_started.elapsed()));
        peak.observe();
        remaining -= len;
    }
    send.finish()
        .map_err(|err| format!("finish Hysteria2 benchmark TCP upload: {err}"))?;
    send.stopped()
        .await
        .map_err(|err| format!("wait for Hysteria2 benchmark upload completion: {err}"))?;
    let _ = receive
        .read_to_end(64)
        .await
        .map_err(|err| format!("drain Hysteria2 benchmark TCP response: {err}"))?;
    peak.observe();
    Ok(UploadReport {
        bytes: upload_bytes,
        elapsed: started.elapsed(),
        write_micros,
        peak,
    })
}

async fn measure_udp(
    config: &CongestionBenchmarkConfig,
    binding: super::super::plan::ResidentProxyBinding,
    registries: super::super::ResidentTransportOwnerRegistries,
) -> UdpReport {
    let mut latency_micros = Vec::with_capacity(config.udp_samples);
    let mut received = 0_usize;
    let mut peak = ProcessResourceSample::capture();
    for sequence in 0..config.udp_samples {
        let mut payload = vec![0x5a; config.udp_payload_bytes];
        payload[..std::mem::size_of::<u64>()].copy_from_slice(&(sequence as u64).to_be_bytes());
        let started = Instant::now();
        let exchange = time::timeout(
            config.udp_sample_timeout,
            exercise_proxy_udp_packet_session(
                binding.clone(),
                registries.clone(),
                config.udp_target,
                std::slice::from_ref(&payload),
                None,
            ),
        )
        .await;
        if matches!(exchange, Ok(Ok(ref responses)) if responses == std::slice::from_ref(&payload))
        {
            received = received.saturating_add(1);
            latency_micros.push(duration_micros(started.elapsed()));
        }
        peak.observe();
    }
    UdpReport {
        sent: config.udp_samples,
        received,
        latency_micros,
        peak,
    }
}
