use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use dae_datapath::{
    OUTBOUND_DIRECT, OUTBOUND_USER_DEFINED_MIN, TcpDialMode, choose_dial_target,
    magic_network_bytes, udp_endpoint_pool_trim_target,
};

use crate::{BenchCase, Measurement, measure};

pub(crate) fn cases() -> Vec<BenchCase> {
    vec![
        BenchCase {
            id: "control/magic_network_mark_mptcp",
            default_iters: 100_000,
            run: bench_magic_network_mark_mptcp,
        },
        BenchCase {
            id: "control/choose_dial_target_domain",
            default_iters: 100_000,
            run: bench_choose_dial_target_domain,
        },
        BenchCase {
            id: "control/choose_dial_target_domain_plus_plus",
            default_iters: 100_000,
            run: bench_choose_dial_target_domain_plus_plus,
        },
        BenchCase {
            id: "control/udp_endpoint_trim_target",
            default_iters: 100_000,
            run: bench_udp_endpoint_trim_target,
        },
    ]
}

fn bench_magic_network_mark_mptcp(iters: u64, warmup: u64) -> Result<Measurement, String> {
    const TPROXY_MARK: u32 = 0x0800_0000;
    Ok(measure(
        || {
            let network = magic_network_bytes(black_box("tcp"), black_box(TPROXY_MARK), true);
            black_box(network.len() as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_choose_dial_target_domain(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 443);
    Ok(measure(
        || {
            let decision = choose_dial_target(
                black_box(TcpDialMode::Ip),
                black_box(OUTBOUND_DIRECT),
                black_box(dest),
                black_box("example.com"),
                black_box(false),
            );
            black_box(decision.dial_target.len() as u64 ^ decision.dial_ip as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_choose_dial_target_domain_plus_plus(
    iters: u64,
    warmup: u64,
) -> Result<Measurement, String> {
    let dest: SocketAddr = "93.184.216.34:443".parse().unwrap();
    Ok(measure(
        || {
            let decision = choose_dial_target(
                black_box(TcpDialMode::DomainPlusPlus),
                black_box(OUTBOUND_USER_DEFINED_MIN),
                black_box(dest),
                black_box("example.com"),
                black_box(true),
            );
            black_box(
                decision.dial_target.len() as u64
                    ^ ((decision.should_reroute as u64) << 8)
                    ^ decision.dial_ip as u64,
            )
        },
        iters,
        warmup,
    ))
}

fn bench_udp_endpoint_trim_target(iters: u64, warmup: u64) -> Result<Measurement, String> {
    Ok(measure(
        || black_box(udp_endpoint_pool_trim_target(black_box(4096)) as u64),
        iters,
        warmup,
    ))
}
