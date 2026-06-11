use std::time::Instant;

use dae_control::{DomainRoutingOwnerSnapshot, DomainRoutingTracker};

fn main() {
    let iters = std::env::var("CONTROL_BENCH_ITERS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(100_000);
    let started = Instant::now();
    for _ in 0..iters {
        let mut tracker = DomainRoutingTracker::default();
        tracker.sync_owner(
            "a",
            DomainRoutingOwnerSnapshot::new(&[3, 8], &["192.0.2.1", "2001:db8::1"]),
        );
        tracker.sync_owner(
            "b",
            DomainRoutingOwnerSnapshot::new(&[4], &["192.0.2.1", "198.51.100.7"]),
        );
        tracker.sync_owner("a", DomainRoutingOwnerSnapshot::default());
    }
    let elapsed = started.elapsed();
    let ns_per_op = elapsed.as_nanos() as f64 / iters as f64;
    println!("case_domain_routing_owner_merge_ns_per_op={ns_per_op:.1}");
}
