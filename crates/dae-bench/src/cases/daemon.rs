use std::hint::black_box;

use dae_daemon::{
    daemon_runtime_native_owner_summary_json, datapath_outbound_ebpf_deep_area_summary_json,
    product_global_normalize_benchmark_fixture, resident_proxy_ownership_benchmark_fixture,
    resident_tcp_selection_benchmark_fixture,
};

use crate::{BenchCase, Measurement, measure};

pub(crate) fn cases() -> Vec<BenchCase> {
    vec![
        BenchCase {
            id: "daemon/runtime_native_owner_summary",
            default_iters: 100_000,
            run: bench_daemon_runtime_native_owner_summary,
        },
        BenchCase {
            id: "daemon/datapath_outbound_ebpf_summary",
            default_iters: 100_000,
            run: bench_datapath_outbound_ebpf_summary,
        },
        BenchCase {
            id: "daemon/resident_tcp_proxy_selection",
            default_iters: 100_000,
            run: bench_resident_tcp_proxy_selection,
        },
        BenchCase {
            id: "daemon/resident_default_proxy_binding",
            default_iters: 100_000,
            run: bench_resident_default_proxy_binding,
        },
        BenchCase {
            id: "daemon/resident_udp_route_binding",
            default_iters: 100_000,
            run: bench_resident_udp_route_binding,
        },
        BenchCase {
            id: "daemon/resident_dns_route_binding",
            default_iters: 100_000,
            run: bench_resident_dns_route_binding,
        },
        BenchCase {
            id: "daemon/resident_health_descriptors_1",
            default_iters: 100_000,
            run: bench_resident_health_descriptors_one,
        },
        BenchCase {
            id: "daemon/resident_health_descriptors_10",
            default_iters: 100_000,
            run: bench_resident_health_descriptors_ten,
        },
        BenchCase {
            id: "daemon/resident_health_descriptors_large",
            default_iters: 100_000,
            run: bench_resident_health_descriptors_large,
        },
        BenchCase {
            id: "daemon/resident_transport_handoff",
            default_iters: 100_000,
            run: bench_resident_transport_handoff,
        },
        BenchCase {
            id: "daemon/resident_credential_view",
            default_iters: 100_000,
            run: bench_resident_credential_view,
        },
        BenchCase {
            id: "product/global_normalize_simple",
            default_iters: 100_000,
            run: bench_product_global_normalize_simple,
        },
        BenchCase {
            id: "product/global_normalize_complex",
            default_iters: 100_000,
            run: bench_product_global_normalize_complex,
        },
        BenchCase {
            id: "product/global_normalize_json",
            default_iters: 100_000,
            run: bench_product_global_normalize_json,
        },
        BenchCase {
            id: "product/global_display_raw",
            default_iters: 100_000,
            run: bench_product_global_display_raw,
        },
    ]
}

fn bench_daemon_runtime_native_owner_summary(
    iters: u64,
    warmup: u64,
) -> Result<Measurement, String> {
    Ok(measure(
        || {
            let summary = daemon_runtime_native_owner_summary_json();
            let groups = summary["accepted_native_groups"]
                .as_array()
                .expect("accepted native groups");
            let blockers = summary["runtime_owner_blockers"]
                .as_array()
                .expect("runtime owner blockers");
            black_box(groups.len() as u64 ^ ((blockers.len() as u64) << 8))
        },
        iters,
        warmup,
    ))
}

fn bench_datapath_outbound_ebpf_summary(iters: u64, warmup: u64) -> Result<Measurement, String> {
    Ok(measure(
        || {
            let summary = datapath_outbound_ebpf_deep_area_summary_json();
            let surfaces = summary["surfaces"].as_array().expect("deep area surfaces");
            let blockers = summary["production_admission_blockers"]
                .as_array()
                .expect("deep area production admission blockers");
            black_box(surfaces.len() as u64 ^ ((blockers.len() as u64) << 8))
        },
        iters,
        warmup,
    ))
}

fn bench_resident_tcp_proxy_selection(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let fixture = resident_tcp_selection_benchmark_fixture()?;
    Ok(measure(|| black_box(fixture.run_once()), iters, warmup))
}

fn bench_resident_default_proxy_binding(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let fixture = resident_proxy_ownership_benchmark_fixture()?;
    Ok(measure(
        || black_box(fixture.default_binding_once()),
        iters,
        warmup,
    ))
}

fn bench_resident_udp_route_binding(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let fixture = resident_proxy_ownership_benchmark_fixture()?;
    Ok(measure(
        || black_box(fixture.udp_route_binding_once()),
        iters,
        warmup,
    ))
}

fn bench_resident_dns_route_binding(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let fixture = resident_proxy_ownership_benchmark_fixture()?;
    Ok(measure(
        || black_box(fixture.dns_route_binding_once()),
        iters,
        warmup,
    ))
}

fn bench_resident_health_descriptors_one(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let fixture = resident_proxy_ownership_benchmark_fixture()?;
    Ok(measure(
        || black_box(fixture.health_descriptors_one_once()),
        iters,
        warmup,
    ))
}

fn bench_resident_health_descriptors_ten(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let fixture = resident_proxy_ownership_benchmark_fixture()?;
    Ok(measure(
        || black_box(fixture.health_descriptors_ten_once()),
        iters,
        warmup,
    ))
}

fn bench_resident_health_descriptors_large(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let fixture = resident_proxy_ownership_benchmark_fixture()?;
    Ok(measure(
        || black_box(fixture.health_descriptors_large_once()),
        iters,
        warmup,
    ))
}

fn bench_resident_transport_handoff(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let fixture = resident_proxy_ownership_benchmark_fixture()?;
    Ok(measure(
        || black_box(fixture.transport_handoff_once()),
        iters,
        warmup,
    ))
}

fn bench_resident_credential_view(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let fixture = resident_proxy_ownership_benchmark_fixture()?;
    Ok(measure(
        || black_box(fixture.credential_view_once()),
        iters,
        warmup,
    ))
}

fn bench_product_global_normalize_simple(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let fixture = product_global_normalize_benchmark_fixture();
    Ok(measure(
        || black_box(fixture.normalize_simple_once()),
        iters,
        warmup,
    ))
}

fn bench_product_global_normalize_complex(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let fixture = product_global_normalize_benchmark_fixture();
    Ok(measure(
        || black_box(fixture.normalize_complex_once()),
        iters,
        warmup,
    ))
}

fn bench_product_global_normalize_json(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let fixture = product_global_normalize_benchmark_fixture();
    Ok(measure(
        || black_box(fixture.normalize_json_once()),
        iters,
        warmup,
    ))
}

fn bench_product_global_display_raw(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let fixture = product_global_normalize_benchmark_fixture();
    Ok(measure(
        || black_box(fixture.display_raw_once()),
        iters,
        warmup,
    ))
}
