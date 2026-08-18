use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Instant;

use serde_json::json;

use super::*;
use crate::dns::transport::test_support::{
    Socks5UdpRelay, dns_a_test_response, dns_proxy_binding, socks5_dns_proxy,
};
use crate::udp::probe_resident_proxy_dns_udp_with_forwarder_async;

const PERIODIC_HEALTH_SAMPLE_ROUNDS: usize = 32;

fn percentile(samples: &mut [u128], percent: usize) -> u128 {
    samples.sort_unstable();
    let index = samples.len().saturating_sub(1).saturating_mul(percent) / 100;
    samples[index]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn periodic_health_rebuild_and_held_lease_close_to_zero() {
    let upstream = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let target = upstream.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut query = vec![0_u8; DNS_RESPONSE_READ_LIMIT];
        for _ in 0..PERIODIC_HEALTH_SAMPLE_ROUNDS.saturating_mul(2) {
            let (read, peer) = upstream.recv_from(&mut query).await.unwrap();
            let response = dns_a_test_response(&query[..read], [192, 0, 2, 80]);
            upstream.send_to(&response, peer).await.unwrap();
        }
    });
    let socks = Socks5UdpRelay::start().await;
    let binding = dns_proxy_binding(socks5_dns_proxy(socks.address()), 7_372);

    let rebuild_cache = Arc::new(test_resident_dns_forwarder_cache());
    let mut rebuild_samples = Vec::with_capacity(PERIODIC_HEALTH_SAMPLE_ROUNDS);
    for _ in 0..PERIODIC_HEALTH_SAMPLE_ROUNDS {
        let started = Instant::now();
        let lease = rebuild_cache
            .acquire_health_proxy_udp_forwarder(target, binding.clone())
            .await
            .unwrap();
        probe_resident_proxy_dns_udp_with_forwarder_async(
            lease.forwarder(),
            "periodic-health.example",
        )
        .await
        .unwrap();
        lease.release().await.unwrap();
        rebuild_samples.push(started.elapsed().as_micros());
        assert_eq!(rebuild_cache.health_len(), 0);
    }
    let rebuild_metrics = rebuild_cache.metrics.snapshot();

    let held_cache = Arc::new(test_resident_dns_forwarder_cache());
    let held_lease = held_cache
        .acquire_health_proxy_udp_forwarder(target, binding)
        .await
        .unwrap();
    let mut held_samples = Vec::with_capacity(PERIODIC_HEALTH_SAMPLE_ROUNDS);
    for _ in 0..PERIODIC_HEALTH_SAMPLE_ROUNDS {
        let started = Instant::now();
        probe_resident_proxy_dns_udp_with_forwarder_async(
            held_lease.forwarder(),
            "periodic-health.example",
        )
        .await
        .unwrap();
        held_samples.push(started.elapsed().as_micros());
    }
    assert_eq!(held_cache.health_len(), 1);
    assert_eq!(
        held_cache.metrics.snapshot()["proxyDnsHealthForwardersCurrent"],
        1
    );
    held_lease.release().await.unwrap();
    let held_metrics = held_cache.metrics.snapshot();
    server.await.unwrap();

    let rebuild_p50 = percentile(&mut rebuild_samples, 50);
    let rebuild_p99 = percentile(&mut rebuild_samples, 99);
    let held_p50 = percentile(&mut held_samples, 50);
    let held_p99 = percentile(&mut held_samples, 99);
    println!(
        "periodic_health_lifecycle_comparison {}",
        json!({
            "rounds": PERIODIC_HEALTH_SAMPLE_ROUNDS,
            "rebuildEachRound": {
                "p50Us": rebuild_p50,
                "p99Us": rebuild_p99,
                "executorsOpened": rebuild_metrics["proxyDnsUdpExecutorsOpened"],
                "executorsReused": rebuild_metrics["proxyDnsUdpExecutorsReused"],
            },
            "heldLease": {
                "p50Us": held_p50,
                "p99Us": held_p99,
                "executorsOpened": held_metrics["proxyDnsUdpExecutorsOpened"],
                "executorsReused": held_metrics["proxyDnsUdpExecutorsReused"],
            },
        })
    );

    for (cache, metrics) in [
        (&rebuild_cache, rebuild_metrics),
        (&held_cache, held_metrics),
    ] {
        assert_eq!(cache.health_len(), 0);
        assert_eq!(metrics["proxyDnsHealthForwardersCurrent"], 0);
        assert_eq!(metrics["proxyDnsHealthLeasesCurrent"], 0);
        assert_eq!(metrics["dnsTransportOwnersCurrent"], 0);
        assert_eq!(
            metrics["dnsUdpActorsOpened"], metrics["dnsUdpActorsClosed"],
            "{metrics}"
        );
    }
    assert_eq!(
        socks.control_connections(),
        PERIODIC_HEALTH_SAMPLE_ROUNDS + 1
    );
}
