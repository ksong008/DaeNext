use std::time::Duration;

use dae_resident_core::{
    RESIDENT_UDP_RESPONSE_TIMEOUT, ResidentRuntimeProfile, ResidentUdpPayloadAdmission,
    resident_udp_runtime_topology,
};

const DNS_TRANSPORT_WORKER_STACK_BYTES_MIN: usize = 2 * 1024 * 1024;
const TCP_FLOW_STACK_BYTES_DEFAULT: usize = 512 * 1024;
const UDP_SOCKET_BUFFER_BYTES_DEFAULT: usize = 512 * 1024;
const UDP_SOCKET_BUFFER_BYTES_MIN: usize = 64 * 1024;
const UDP_SOCKET_BUFFER_BYTES_MAX: usize = 8 * 1024 * 1024;
const RUNTIME_RESOURCE_DRAIN_GRACE: Duration = Duration::from_millis(1_500);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResidentDnsUdpRuntimeConfig {
    pub generation: u64,
    pub direct_shards: usize,
    pub proxy_actor_limit: usize,
    pub actor_worker_threads: usize,
    pub worker_stack_bytes: usize,
    pub socket_buffer_bytes: usize,
    pub queue_depth: usize,
    pub pending_limit: usize,
    pub inflight_window: usize,
    pub send_batch_limit: usize,
    pub attempts: usize,
    pub attempt_timeout: Duration,
    pub shard_idle_timeout: Duration,
    pub actor_idle_timeout: Option<Duration>,
    pub shutdown_timeout: Duration,
    pub payload_admission: ResidentUdpPayloadAdmission,
}

impl ResidentDnsUdpRuntimeConfig {
    pub fn standalone() -> Self {
        let available_parallelism = std::thread::available_parallelism()
            .map(|parallelism| parallelism.get())
            .unwrap_or(1);
        let profile = ResidentRuntimeProfile::Balanced;
        let requested_shards = profile.udp_runtime_shards_default(available_parallelism);
        let (direct_shards, actor_worker_threads) =
            resident_udp_runtime_topology(requested_shards, available_parallelism);
        let attempts = profile.dns_udp_forwarder_attempts_default();
        Self {
            generation: 0,
            direct_shards,
            proxy_actor_limit: profile.dns_proxy_udp_actors_default(),
            actor_worker_threads: actor_worker_threads.max(1),
            worker_stack_bytes: TCP_FLOW_STACK_BYTES_DEFAULT
                .max(DNS_TRANSPORT_WORKER_STACK_BYTES_MIN),
            socket_buffer_bytes: standalone_socket_buffer_bytes(),
            queue_depth: profile.dns_udp_forwarder_queue_depth_default(),
            pending_limit: profile.dns_udp_forwarder_pending_limit_default(),
            inflight_window: profile.dns_udp_forwarder_inflight_window_default(),
            send_batch_limit: profile.udp_syscall_batch_limit(),
            attempts,
            attempt_timeout: Self::attempt_timeout_for(attempts),
            shard_idle_timeout: profile.dns_udp_shard_idle_timeout(),
            actor_idle_timeout: None,
            shutdown_timeout: RUNTIME_RESOURCE_DRAIN_GRACE,
            payload_admission: ResidentUdpPayloadAdmission::new(
                0,
                profile.udp_queued_payload_bytes_default(),
            ),
        }
    }

    pub fn actor_partition(&self, actor_index: usize, actor_count: usize) -> Self {
        let actor_count = actor_count.max(1);
        let actor_index = actor_index.min(actor_count - 1);
        let mut partition = self.clone();
        partition.queue_depth = partitioned_resource(self.queue_depth, actor_index, actor_count);
        partition.pending_limit =
            partitioned_resource(self.pending_limit, actor_index, actor_count);
        partition.inflight_window =
            partitioned_resource(self.inflight_window, actor_index, actor_count)
                .min(partition.pending_limit);
        partition
    }

    pub fn attempt_timeout_for(attempts: usize) -> Duration {
        let divisor = (attempts.max(1) as u128).saturating_add(1);
        let millis = RESIDENT_UDP_RESPONSE_TIMEOUT
            .as_millis()
            .saturating_div(divisor)
            .max(1);
        Duration::from_millis(millis.min(u128::from(u64::MAX)) as u64)
    }
}

fn partitioned_resource(total: usize, index: usize, partitions: usize) -> usize {
    let partitions = partitions.max(1).min(total.max(1));
    let index = index.min(partitions - 1);
    let base = total.max(1) / partitions;
    let remainder = total.max(1) % partitions;
    base.saturating_add(usize::from(index < remainder)).max(1)
}

fn standalone_socket_buffer_bytes() -> usize {
    std::env::var("RESIDENT_UDP_SOCKET_BUFFER_BYTES")
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(UDP_SOCKET_BUFFER_BYTES_DEFAULT)
        .clamp(UDP_SOCKET_BUFFER_BYTES_MIN, UDP_SOCKET_BUFFER_BYTES_MAX)
}
