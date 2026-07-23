use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use dae_routing::{IpPrefix, SharedIpPrefixSet};

use crate::{BenchCase, Measurement, measure};

const SMALL_PREFIX_COUNT: usize = 32;
const INDEX_BOUNDARY_PREFIX_COUNT: usize = 64;
const LARGE_PREFIX_COUNT: usize = 4096;
const BUILD_PREFIX_COUNT: usize = 65_536;

pub(super) fn cases() -> Vec<BenchCase> {
    vec![
        BenchCase {
            id: "routing/prefix_lookup_linear_32",
            default_iters: 100_000,
            run: bench_linear_32,
        },
        BenchCase {
            id: "routing/prefix_lookup_adaptive_32",
            default_iters: 100_000,
            run: bench_adaptive_32,
        },
        BenchCase {
            id: "routing/prefix_lookup_linear_64",
            default_iters: 100_000,
            run: bench_linear_64,
        },
        BenchCase {
            id: "routing/prefix_lookup_adaptive_64",
            default_iters: 100_000,
            run: bench_adaptive_64,
        },
        BenchCase {
            id: "routing/prefix_lookup_linear_4096",
            default_iters: 10_000,
            run: bench_linear_4096,
        },
        BenchCase {
            id: "routing/prefix_lookup_adaptive_4096",
            default_iters: 100_000,
            run: bench_adaptive_4096,
        },
        BenchCase {
            id: "routing/prefix_lookup_ipv6_linear_4096",
            default_iters: 10_000,
            run: bench_ipv6_linear_4096,
        },
        BenchCase {
            id: "routing/prefix_lookup_ipv6_adaptive_4096",
            default_iters: 100_000,
            run: bench_ipv6_adaptive_4096,
        },
        BenchCase {
            id: "routing/prefix_linear_build_65536",
            default_iters: 20,
            run: bench_linear_build_65536,
        },
        BenchCase {
            id: "routing/prefix_index_build_65536",
            default_iters: 20,
            run: bench_index_build_65536,
        },
    ]
}

fn bench_linear_32(iters: u64, warmup: u64) -> Result<Measurement, String> {
    bench_ipv4_lookup(SMALL_PREFIX_COUNT, false, iters, warmup)
}

fn bench_adaptive_32(iters: u64, warmup: u64) -> Result<Measurement, String> {
    bench_ipv4_lookup(SMALL_PREFIX_COUNT, true, iters, warmup)
}

fn bench_linear_64(iters: u64, warmup: u64) -> Result<Measurement, String> {
    bench_ipv4_lookup(INDEX_BOUNDARY_PREFIX_COUNT, false, iters, warmup)
}

fn bench_adaptive_64(iters: u64, warmup: u64) -> Result<Measurement, String> {
    bench_ipv4_lookup(INDEX_BOUNDARY_PREFIX_COUNT, true, iters, warmup)
}

fn bench_linear_4096(iters: u64, warmup: u64) -> Result<Measurement, String> {
    bench_ipv4_lookup(LARGE_PREFIX_COUNT, false, iters, warmup)
}

fn bench_adaptive_4096(iters: u64, warmup: u64) -> Result<Measurement, String> {
    bench_ipv4_lookup(LARGE_PREFIX_COUNT, true, iters, warmup)
}

fn bench_ipv6_linear_4096(iters: u64, warmup: u64) -> Result<Measurement, String> {
    bench_ipv6_lookup(false, iters, warmup)
}

fn bench_ipv6_adaptive_4096(iters: u64, warmup: u64) -> Result<Measurement, String> {
    bench_ipv6_lookup(true, iters, warmup)
}

fn bench_ipv4_lookup(
    count: usize,
    adaptive: bool,
    iters: u64,
    warmup: u64,
) -> Result<Measurement, String> {
    let prefixes = ipv4_host_prefixes(count)?;
    let set = SharedIpPrefixSet::new(prefixes);
    let query = IpAddr::V4(ipv4_host(count.saturating_sub(1)));
    Ok(measure(
        || {
            let query = black_box(query);
            let matched = if adaptive {
                set.contains(query)
            } else {
                set.iter().any(|prefix| prefix.contains(query))
            };
            black_box(matched as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_ipv6_lookup(adaptive: bool, iters: u64, warmup: u64) -> Result<Measurement, String> {
    let prefixes = ipv6_host_prefixes(LARGE_PREFIX_COUNT)?;
    let set = SharedIpPrefixSet::new(prefixes);
    let query = IpAddr::V6(ipv6_host(LARGE_PREFIX_COUNT - 1));
    Ok(measure(
        || {
            let query = black_box(query);
            let matched = if adaptive {
                set.contains(query)
            } else {
                set.iter().any(|prefix| prefix.contains(query))
            };
            black_box(matched as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_index_build_65536(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let prefixes = ipv4_host_prefixes(BUILD_PREFIX_COUNT)?;
    Ok(measure(
        || {
            let set = SharedIpPrefixSet::new(black_box(prefixes.clone()));
            black_box(set.as_slice().len() as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_linear_build_65536(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let prefixes = ipv4_host_prefixes(BUILD_PREFIX_COUNT)?;
    Ok(measure(
        || {
            let prefixes: Arc<[IpPrefix]> = Arc::from(black_box(prefixes.clone()));
            black_box(prefixes.len() as u64)
        },
        iters,
        warmup,
    ))
}

fn ipv4_host_prefixes(count: usize) -> Result<Vec<IpPrefix>, String> {
    (0..count)
        .map(|index| IpPrefix::new(IpAddr::V4(ipv4_host(index)), 32).map_err(|err| err.to_string()))
        .collect()
}

fn ipv6_host_prefixes(count: usize) -> Result<Vec<IpPrefix>, String> {
    (0..count)
        .map(|index| {
            IpPrefix::new(IpAddr::V6(ipv6_host(index)), 128).map_err(|err| err.to_string())
        })
        .collect()
}

fn ipv4_host(index: usize) -> Ipv4Addr {
    Ipv4Addr::from(0x0a00_0001_u32.wrapping_add((index as u32).wrapping_mul(257)))
}

fn ipv6_host(index: usize) -> Ipv6Addr {
    Ipv6Addr::from(0x2001_0db8_0000_0000_0000_0000_0000_0001_u128 + index as u128 * 257)
}
