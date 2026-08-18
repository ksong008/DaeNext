use std::collections::{HashMap, HashSet, VecDeque};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::thread::JoinHandle;
use std::time::Instant;

use bytes::BytesMut;
use dae_outbound::anytls::{AnyTlsPaddingScheme, contract as anytls_contract, link as anytls_link};
use dae_runtime_control::{AbsoluteDeadline, OwnerGeneration};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;
use tokio::time;

use crate::{
    AnyTlsFrameReader, AsyncResidentTlsClient, async_resident_tls_underlay_name,
    open_async_resident_tls_client_with_binding,
};
#[cfg(test)]
use dae_resident_core::ResidentRuntimeProfile;
use dae_resident_core::{
    ANYTLS_LOCAL_CLOSE_DRAIN_TIMEOUT, AnyTlsOwnerResourceProfile,
    RESIDENT_ANYTLS_RELAY_BUFFER_SIZE, RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE,
    SharedResidentStopSignal,
};
use dae_resident_model::{ResidentProxyBinding, ResidentProxyPlan, ResidentProxyProtocolPlan};

const ANYTLS_OWNER_IDENTITY_DOMAIN: &[u8] = b"dae/anytls-owner/v1";
/// Base delay for the AnyTLS acquisition retry backoff.
///
/// Retries are caused by transient conditions (idle session commands,
/// active physical-session conflicts, idle heartbeat failures). Without a
/// backoff the acquire loop hammers the TLS endpoint with connection
/// attempts; the deadline only bounds the total window, not the churn rate.
const ANYTLS_ACQUIRE_RETRY_BACKOFF_BASE_MS: u64 = 50;
/// Exponential cap: 50ms * 2^6 = 3.2s before jitter.
const ANYTLS_ACQUIRE_RETRY_BACKOFF_MAX_EXPONENT: u32 = 6;

/// Exponential backoff with uniform jitter for AnyTLS acquire retries.
///
/// Returns a duration in `[base, 2*base)` where `base = 50ms * 2^min(n, 6)`,
/// i.e. 50-100ms on the first retry up to 3.2-6.4s once capped. The jitter
/// avoids thundering-herd synchronisation across sessions retrying together.
fn anytls_acquire_retry_backoff(retry_count: u32) -> std::time::Duration {
    let exponent = retry_count.min(ANYTLS_ACQUIRE_RETRY_BACKOFF_MAX_EXPONENT);
    let base_ms = ANYTLS_ACQUIRE_RETRY_BACKOFF_BASE_MS.saturating_mul(1_u64 << exponent);
    let jitter_ms = fastrand::u64(..base_ms);
    std::time::Duration::from_millis(base_ms.saturating_add(jitter_ms))
}

#[cfg(test)]
mod backoff_tests {
    use super::*;

    #[test]
    fn backoff_grows_exponentially_within_jitter_bounds() {
        // retry n -> exponent min(n, 6) -> base 50ms * 2^n, backoff in
        // [base, 2*base)
        let cases = [(1, 100, 200), (2, 200, 400), (3, 400, 800), (6, 3200, 6400)];
        for (count, lo, hi) in cases {
            for _ in 0..64 {
                let ms = anytls_acquire_retry_backoff(count).as_millis() as u64;
                assert!(
                    (lo..hi).contains(&ms),
                    "retry {count} backoff {ms}ms outside [{lo},{hi})"
                );
            }
        }
    }

    #[test]
    fn backoff_caps_at_max_exponent() {
        let capped = (6..=20)
            .flat_map(|count| {
                (0..16).map(move |_| anytls_acquire_retry_backoff(count).as_millis() as u64)
            })
            .collect::<Vec<_>>();
        assert!(
            capped.iter().all(|ms| *ms < 6400),
            "backoff must cap below 6.4s"
        );
    }
}
const ANYTLS_DATA_FLUSH_BYTES: usize = 128 * 1024;
const ANYTLS_DATA_FLUSH_DELAY: std::time::Duration = std::time::Duration::from_millis(1);

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
struct AnyTlsOwnerKey {
    generation: OwnerGeneration,
    digest: [u8; 32],
}

impl AnyTlsOwnerKey {
    fn for_binding(binding: &ResidentProxyBinding) -> Self {
        let mut digest = Sha256::new();
        digest.update(ANYTLS_OWNER_IDENTITY_DOMAIN);
        update_proxy_identity_with_mark(
            &mut digest,
            binding.plan(),
            binding.effective_socket_mark(),
            Some(binding),
        );
        Self {
            generation: binding.runtime_generation(),
            digest: digest.finalize().into(),
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
pub fn anytls_owner_key_digest_for_test(proxy: &ResidentProxyPlan) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(ANYTLS_OWNER_IDENTITY_DOMAIN);
    update_proxy_identity(&mut digest, proxy);
    digest.finalize().into()
}

impl std::fmt::Debug for AnyTlsOwnerKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AnyTlsOwnerKey")
            .field("generation", &self.generation)
            .field("digest", &"<redacted>")
            .finish()
    }
}

fn update_identity_part(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

fn update_identity_field(digest: &mut Sha256, field: &[u8], value: &[u8]) {
    update_identity_part(digest, field);
    update_identity_part(digest, value);
}

fn update_proxy_identity(digest: &mut Sha256, proxy: &ResidentProxyPlan) {
    update_proxy_identity_with_mark(digest, proxy, proxy.mark, None);
}

fn update_proxy_identity_with_mark(
    digest: &mut Sha256,
    proxy: &ResidentProxyPlan,
    effective_mark: u32,
    binding: Option<&ResidentProxyBinding>,
) {
    update_identity_field(digest, b"proxy", b"begin");
    update_identity_field(digest, b"graph-link-hash", proxy.graph_link_hash.as_bytes());
    update_identity_field(digest, b"server-host", proxy.server_host.as_bytes());
    update_identity_field(digest, b"server-port", &proxy.server_port.to_be_bytes());
    update_identity_field(digest, b"server-name", proxy.server_name.as_bytes());
    update_identity_field(digest, b"tls", proxy.tls.as_bytes());
    update_identity_field(digest, b"so-mark", &effective_mark.to_be_bytes());
    update_identity_field(digest, b"mptcp", &[u8::from(proxy.mptcp)]);
    update_identity_field(digest, b"allow-insecure", &[u8::from(proxy.allow_insecure)]);
    update_identity_field(
        digest,
        b"alpn-count",
        &(proxy.alpn.len() as u64).to_be_bytes(),
    );
    for alpn in &proxy.alpn {
        update_identity_field(digest, b"alpn", alpn.as_bytes());
    }
    update_identity_field(
        digest,
        b"tls-fragment-present",
        &[u8::from(proxy.tls_fragment.is_some())],
    );
    if let Some(fragment) = proxy.tls_fragment.as_ref() {
        update_identity_field(
            digest,
            b"tls-fragment-min-length",
            &fragment.min_length.to_be_bytes(),
        );
        update_identity_field(
            digest,
            b"tls-fragment-max-length",
            &fragment.max_length.to_be_bytes(),
        );
        update_identity_field(
            digest,
            b"tls-fragment-min-interval-ms",
            &fragment.min_interval_ms.to_be_bytes(),
        );
        update_identity_field(
            digest,
            b"tls-fragment-max-interval-ms",
            &fragment.max_interval_ms.to_be_bytes(),
        );
    }
    update_identity_field(
        digest,
        b"utls-fingerprint-present",
        &[u8::from(proxy.utls_fingerprint.is_some())],
    );
    if let Some(fingerprint) = proxy.utls_fingerprint.as_ref() {
        update_identity_field(digest, b"utls-source", fingerprint.source.as_bytes());
        update_identity_field(digest, b"utls-requested", fingerprint.requested.as_bytes());
        update_identity_field(digest, b"utls-name", fingerprint.name.as_bytes());
        update_identity_field(digest, b"utls-canonical", fingerprint.canonical.as_bytes());
        update_identity_field(digest, b"utls-family", fingerprint.family.as_bytes());
        update_identity_field(digest, b"utls-client", fingerprint.client.as_bytes());
        update_identity_field(
            digest,
            b"utls-randomized",
            &[u8::from(fingerprint.randomized)],
        );
        update_identity_field(
            digest,
            b"utls-alpn-policy",
            fingerprint.alpn_policy.as_bytes(),
        );
        update_identity_field(
            digest,
            b"utls-default-alpn-count",
            &(fingerprint.default_alpn.len() as u64).to_be_bytes(),
        );
        for alpn in &fingerprint.default_alpn {
            update_identity_field(digest, b"utls-default-alpn", alpn.as_bytes());
        }
    }
    update_identity_field(
        digest,
        b"reality-present",
        &[u8::from(proxy.reality.is_some())],
    );
    if let Some(reality) = proxy.reality.as_ref() {
        update_identity_field(digest, b"reality-public-key", &reality.public_key);
        update_identity_field(digest, b"reality-short-id", &reality.short_id);
        update_identity_field(digest, b"reality-spider-x", reality.spider_x.as_bytes());
    }
    if let ResidentProxyProtocolPlan::AnyTlsTcpTls { auth } = &proxy.handler {
        update_identity_field(digest, b"anytls-auth", auth.as_bytes());
    }
    if let Some(binding) = binding {
        let parent = binding
            .chain_parent()
            .expect("published AnyTLS proxy chain execution must be materialized");
        update_identity_field(
            digest,
            b"chain-parent-present",
            &[u8::from(parent.is_some())],
        );
        if let Some(parent) = parent.as_ref() {
            update_proxy_identity_with_mark(
                digest,
                parent.plan(),
                parent.effective_socket_mark(),
                Some(parent),
            );
        }
    } else {
        update_identity_field(
            digest,
            b"chain-parent-present",
            &[u8::from(proxy.chain_parent.is_some())],
        );
        if let Some(parent) = proxy.chain_parent.as_deref() {
            update_proxy_identity(digest, parent);
        }
    }
    update_identity_field(digest, b"proxy", b"end");
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AnyTlsPhysicalState {
    Building,
    Active,
    Idle,
}

struct AnyTlsPhysicalSlot {
    state: AnyTlsPhysicalState,
    sender: mpsc::Sender<AnyTlsPhysicalCommand>,
}

struct AnyTlsOwnerPool {
    physical: HashMap<u64, AnyTlsPhysicalSlot>,
    padding_scheme: Arc<AnyTlsPaddingScheme>,
}

impl Default for AnyTlsOwnerPool {
    fn default() -> Self {
        Self {
            physical: HashMap::new(),
            padding_scheme: default_anytls_padding_scheme(),
        }
    }
}

fn default_anytls_padding_scheme() -> Arc<AnyTlsPaddingScheme> {
    static SCHEME: std::sync::OnceLock<Arc<AnyTlsPaddingScheme>> = std::sync::OnceLock::new();
    Arc::clone(SCHEME.get_or_init(|| Arc::new(AnyTlsPaddingScheme::official_default())))
}

struct AnyTlsOwnerIndex {
    pools: HashMap<AnyTlsOwnerKey, AnyTlsOwnerPool>,
    next_instance_id: u64,
    draining: bool,
}

impl AnyTlsOwnerIndex {
    fn new() -> Self {
        Self {
            pools: HashMap::new(),
            next_instance_id: 1,
            draining: false,
        }
    }

    fn physical_count(&self) -> usize {
        self.pools.values().map(|pool| pool.physical.len()).sum()
    }

    fn allocate_instance_id(&mut self) -> u64 {
        let instance_id = self.next_instance_id.max(1);
        self.next_instance_id = self.next_instance_id.wrapping_add(1).max(1);
        instance_id
    }
}

#[derive(Default)]
struct AnyTlsOwnerMetrics {
    active_physical: AtomicUsize,
    high_water_physical: AtomicUsize,
    idle_physical: AtomicUsize,
    high_water_idle: AtomicUsize,
    active_logical: AtomicUsize,
    high_water_logical: AtomicUsize,
    current_logical_buffer_bytes: AtomicUsize,
    high_water_logical_buffer_bytes: AtomicUsize,
    active_builds: AtomicUsize,
    cumulative_builds: AtomicU64,
    cumulative_build_failures: AtomicU64,
    cumulative_reuses: AtomicU64,
    cumulative_sid_allocations: AtomicU64,
    cumulative_idle_probes: AtomicU64,
    cumulative_idle_probe_failures: AtomicU64,
    cumulative_idle_expirations: AtomicU64,
    cumulative_padding_updates: AtomicU64,
    cumulative_padding_update_rejections: AtomicU64,
    cumulative_padding_waste_frames: AtomicU64,
    cumulative_padding_waste_bytes: AtomicU64,
    peer_version: AtomicU64,
    late_frames: AtomicU64,
    unknown_frames: AtomicU64,
    owner_limit_rejections: AtomicU64,
    physical_limit_rejections: AtomicU64,
    command_queue_rejections: AtomicU64,
    shutdown_timed_out: AtomicBool,
}

impl AnyTlsOwnerMetrics {
    fn update_high_water(counter: &AtomicUsize, value: usize) {
        let mut current = counter.load(Ordering::Relaxed);
        while value > current {
            match counter.compare_exchange_weak(
                current,
                value,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
    }

    fn physical_opened(&self) {
        let current = self.active_physical.fetch_add(1, Ordering::Relaxed) + 1;
        Self::update_high_water(&self.high_water_physical, current);
    }

    fn physical_closed(&self) {
        self.active_physical.fetch_sub(1, Ordering::Relaxed);
    }

    fn logical_opened(&self, charged_buffer_bytes: usize) {
        let current = self.active_logical.fetch_add(1, Ordering::Relaxed) + 1;
        Self::update_high_water(&self.high_water_logical, current);
        let current_bytes = self
            .current_logical_buffer_bytes
            .fetch_add(charged_buffer_bytes, Ordering::Relaxed)
            .saturating_add(charged_buffer_bytes);
        Self::update_high_water(&self.high_water_logical_buffer_bytes, current_bytes);
    }

    fn logical_closed(&self, charged_buffer_bytes: usize) {
        self.active_logical.fetch_sub(1, Ordering::Relaxed);
        self.current_logical_buffer_bytes
            .fetch_sub(charged_buffer_bytes, Ordering::Relaxed);
    }

    fn idle_opened(&self) {
        let current = self.idle_physical.fetch_add(1, Ordering::Relaxed) + 1;
        Self::update_high_water(&self.high_water_idle, current);
    }

    fn idle_closed(&self) {
        self.idle_physical.fetch_sub(1, Ordering::Relaxed);
    }
}

enum AnyTlsAcquireFailure {
    Retry(String),
    Terminal(String),
}

struct AnyTlsAcquireCommand {
    key: AnyTlsOwnerKey,
    binding: ResidentProxyBinding,
    target: String,
    initial_payload: Option<AnyTlsInitialPayload>,
    deadline: AbsoluteDeadline,
    response: oneshot::Sender<Result<AnyTlsLogicalStreamLease, AnyTlsAcquireFailure>>,
}

#[derive(Clone)]
struct AnyTlsInitialPayload(Arc<[u8]>);

impl AnyTlsInitialPayload {
    fn new(payload: Vec<u8>, resources: AnyTlsOwnerResourceProfile) -> Result<Self, String> {
        let maximum = resources.logical_buffer_bytes().min(u16::MAX as usize);
        if payload.len() > maximum {
            return Err(format!(
                "AnyTLS initial logical payload exceeds the bounded frame budget: {} > {} bytes",
                payload.len(),
                maximum
            ));
        }
        Ok(Self(payload.into()))
    }

    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

enum AnyTlsOwnerCommand {
    Acquire(AnyTlsAcquireCommand),
}

enum AnyTlsPhysicalCommand {
    Open {
        target: String,
        initial_payload: Option<AnyTlsInitialPayload>,
        deadline: AbsoluteDeadline,
        response: oneshot::Sender<Result<AnyTlsLogicalStreamLease, AnyTlsAcquireFailure>>,
    },
    Close,
}

enum AnyTlsPhysicalEvent {
    Active {
        key: AnyTlsOwnerKey,
        instance_id: u64,
    },
    Idle {
        key: AnyTlsOwnerKey,
        instance_id: u64,
    },
    PaddingUpdated {
        key: AnyTlsOwnerKey,
        instance_id: u64,
        scheme: Arc<AnyTlsPaddingScheme>,
    },
}

struct AnyTlsPhysicalCompletion {
    key: AnyTlsOwnerKey,
    instance_id: u64,
}

#[derive(Clone)]
pub struct AnyTlsOwnerRegistryHandle {
    generation: OwnerGeneration,
    sender: mpsc::Sender<AnyTlsOwnerCommand>,
    index: Arc<Mutex<AnyTlsOwnerIndex>>,
    resources: AnyTlsOwnerResourceProfile,
    metrics: Arc<AnyTlsOwnerMetrics>,
}

impl AnyTlsOwnerRegistryHandle {
    pub async fn acquire(
        &self,
        binding: ResidentProxyBinding,
        target: String,
        deadline: AbsoluteDeadline,
    ) -> Result<AnyTlsLogicalStreamLease, String> {
        self.acquire_inner(binding, target, None, deadline).await
    }

    pub async fn acquire_with_initial_payload(
        &self,
        binding: ResidentProxyBinding,
        target: String,
        initial_payload: Vec<u8>,
        deadline: AbsoluteDeadline,
    ) -> Result<AnyTlsLogicalStreamLease, String> {
        let initial_payload = AnyTlsInitialPayload::new(initial_payload, self.resources)?;
        self.acquire_inner(binding, target, Some(initial_payload), deadline)
            .await
    }

    async fn acquire_inner(
        &self,
        binding: ResidentProxyBinding,
        target: String,
        initial_payload: Option<AnyTlsInitialPayload>,
        deadline: AbsoluteDeadline,
    ) -> Result<AnyTlsLogicalStreamLease, String> {
        let key = AnyTlsOwnerKey::for_binding(&binding);
        if key.generation != self.generation {
            return Err(format!(
                "AnyTLS owner generation mismatch: requested={} active={}",
                key.generation.get(),
                self.generation.get()
            ));
        }
        let mut last_retry_error = None::<String>;
        let mut retry_count = 0_u32;
        loop {
            let remaining = deadline.remaining_at(Instant::now()).ok_or_else(|| {
                last_retry_error.map_or_else(
                    || "AnyTLS owner acquisition deadline elapsed".to_owned(),
                    |error| {
                        format!("AnyTLS owner acquisition deadline elapsed after retry: {error}")
                    },
                )
            })?;
            let (response, receiver) = oneshot::channel();
            let command = AnyTlsOwnerCommand::Acquire(AnyTlsAcquireCommand {
                key,
                binding: binding.clone(),
                target: target.clone(),
                initial_payload: initial_payload.clone(),
                deadline,
                response,
            });
            self.sender.try_send(command).map_err(|_| {
                self.metrics
                    .command_queue_rejections
                    .fetch_add(1, Ordering::Relaxed);
                "AnyTLS owner command queue is unavailable".to_owned()
            })?;
            match time::timeout(remaining, receiver)
                .await
                .map_err(|_| "AnyTLS owner acquisition timeout".to_owned())?
                .map_err(|_| "AnyTLS owner runtime stopped during acquisition".to_owned())?
            {
                Ok(lease) => return Ok(lease),
                Err(AnyTlsAcquireFailure::Retry(error)) => {
                    last_retry_error = Some(error.clone());
                    retry_count = retry_count.saturating_add(1);
                    let backoff = anytls_acquire_retry_backoff(retry_count);
                    let Some(remaining) = deadline.remaining_at(Instant::now()) else {
                        return Err(format!(
                            "AnyTLS owner acquisition deadline elapsed after retry: {error}"
                        ));
                    };
                    tokio::time::sleep(backoff.min(remaining)).await;
                }
                Err(AnyTlsAcquireFailure::Terminal(error)) => return Err(error),
            }
        }
    }

    pub fn metrics_snapshot(&self) -> Value {
        // Poisoned locks are recovered via into_inner: the critical section
        // below is pure state access, so a single panic must not permanently
        // wedge the owner registry.
        let index = self
            .index
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let physical_count = index.physical_count();
        let owner_padding_scheme_bytes = index
            .pools
            .values()
            .map(|pool| pool.padding_scheme.raw().len())
            .sum::<usize>();
        let owner_state_bytes_lower_bound = index
            .pools
            .len()
            .saturating_mul(
                std::mem::size_of::<AnyTlsOwnerKey>()
                    .saturating_add(std::mem::size_of::<AnyTlsOwnerPool>()),
            )
            .saturating_add(
                physical_count.saturating_mul(std::mem::size_of::<AnyTlsPhysicalSlot>()),
            )
            .saturating_add(owner_padding_scheme_bytes);
        json!({
            "schemaVersion": 1,
            "owner": "resident-anytls-owner-registry",
            "generation": self.generation.get(),
            "mode": "bounded-idle-reuse",
            "concurrentLogicalMultiplexing": false,
            "draining": index.draining,
            "registeredKeys": index.pools.len(),
            "registeredPhysicalSessions": physical_count,
            "ownerStateBytesLowerBound": owner_state_bytes_lower_bound,
            "ownerPaddingSchemeBytes": owner_padding_scheme_bytes,
            "activePhysicalSessions": self.metrics.active_physical.load(Ordering::Relaxed),
            "highWaterPhysicalSessions": self.metrics.high_water_physical.load(Ordering::Relaxed),
            "idlePhysicalSessions": self.metrics.idle_physical.load(Ordering::Relaxed),
            "highWaterIdleSessions": self.metrics.high_water_idle.load(Ordering::Relaxed),
            "activeLogicalStreams": self.metrics.active_logical.load(Ordering::Relaxed),
            "highWaterLogicalStreams": self.metrics.high_water_logical.load(Ordering::Relaxed),
            "currentLogicalBufferBytes": self.metrics.current_logical_buffer_bytes.load(Ordering::Relaxed),
            "highWaterLogicalBufferBytes": self.metrics.high_water_logical_buffer_bytes.load(Ordering::Relaxed),
            "activeBuilds": self.metrics.active_builds.load(Ordering::Relaxed),
            "cumulativeBuilds": self.metrics.cumulative_builds.load(Ordering::Relaxed),
            "cumulativeBuildFailures": self.metrics.cumulative_build_failures.load(Ordering::Relaxed),
            "cumulativeReuses": self.metrics.cumulative_reuses.load(Ordering::Relaxed),
            "cumulativeSidAllocations": self.metrics.cumulative_sid_allocations.load(Ordering::Relaxed),
            "cumulativeIdleProbes": self.metrics.cumulative_idle_probes.load(Ordering::Relaxed),
            "cumulativeIdleProbeFailures": self.metrics.cumulative_idle_probe_failures.load(Ordering::Relaxed),
            "cumulativeIdleExpirations": self.metrics.cumulative_idle_expirations.load(Ordering::Relaxed),
            "cumulativePaddingUpdates": self.metrics.cumulative_padding_updates.load(Ordering::Relaxed),
            "cumulativePaddingUpdateRejections": self.metrics.cumulative_padding_update_rejections.load(Ordering::Relaxed),
            "cumulativePaddingWasteFrames": self.metrics.cumulative_padding_waste_frames.load(Ordering::Relaxed),
            "cumulativePaddingWasteBytes": self.metrics.cumulative_padding_waste_bytes.load(Ordering::Relaxed),
            "peerVersion": self.metrics.peer_version.load(Ordering::Relaxed),
            "lateFrames": self.metrics.late_frames.load(Ordering::Relaxed),
            "unknownFrames": self.metrics.unknown_frames.load(Ordering::Relaxed),
            "ownerLimitRejections": self.metrics.owner_limit_rejections.load(Ordering::Relaxed),
            "physicalLimitRejections": self.metrics.physical_limit_rejections.load(Ordering::Relaxed),
            "commandQueueRejections": self.metrics.command_queue_rejections.load(Ordering::Relaxed),
            "shutdownTimedOut": self.metrics.shutdown_timed_out.load(Ordering::Relaxed),
            "admissionEnforced": true,
            "budget": {
                "owners": self.resources.owner_limit(),
                "physicalSessions": self.resources.physical_session_limit(),
                "physicalSessionsPerOwner": self.resources.physical_sessions_per_owner(),
                "idleSessionsPerOwner": self.resources.idle_session_limit(),
                "commandQueueDepth": self.resources.command_queue_depth(),
                "physicalControlQueueDepth": self.resources.physical_control_queue_depth(),
                "logicalBufferBytesPerDirection": self.resources.logical_buffer_bytes(),
                "idleSessionTimeoutMs": self.resources.idle_session_timeout().as_millis(),
                "idleProbeThresholdMs": self.resources.idle_probe_threshold().as_millis(),
                "idleProbeTimeoutMs": self.resources.idle_probe_timeout().as_millis(),
                "sidQuarantineLimit": self.resources.sid_quarantine_limit(),
                "sidQuarantineTtlMs": self.resources.sid_quarantine_ttl().as_millis(),
            },
        })
    }
}

pub struct AnyTlsLogicalStreamLease {
    stream: DuplexStream,
    sid: u32,
    physical_instance_id: u64,
    reused: bool,
    tls_underlay: &'static str,
    charged_buffer_bytes: usize,
    metrics: Arc<AnyTlsOwnerMetrics>,
}

impl AnyTlsLogicalStreamLease {
    pub fn sid(&self) -> u32 {
        self.sid
    }

    pub fn physical_instance_id(&self) -> u64 {
        self.physical_instance_id
    }

    pub fn reused(&self) -> bool {
        self.reused
    }

    pub fn tls_underlay(&self) -> &'static str {
        self.tls_underlay
    }
}

impl Drop for AnyTlsLogicalStreamLease {
    fn drop(&mut self) {
        self.metrics.logical_closed(self.charged_buffer_bytes);
    }
}

impl AsyncRead for AnyTlsLogicalStreamLease {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(context, buffer)
    }
}

impl AsyncWrite for AnyTlsLogicalStreamLease {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }
}

struct AnyTlsPhysicalMetricGuard {
    metrics: Arc<AnyTlsOwnerMetrics>,
}

impl AnyTlsPhysicalMetricGuard {
    fn new(metrics: Arc<AnyTlsOwnerMetrics>) -> Self {
        metrics.physical_opened();
        Self { metrics }
    }
}

impl Drop for AnyTlsPhysicalMetricGuard {
    fn drop(&mut self) {
        self.metrics.physical_closed();
    }
}

struct AnyTlsPhysicalPadding {
    scheme: Arc<AnyTlsPaddingScheme>,
    packet_counter: u32,
    enabled: bool,
    sampled_sizes: Vec<i32>,
    scratch: Vec<u8>,
    frame: Vec<u8>,
    key: AnyTlsOwnerKey,
    instance_id: u64,
    events: mpsc::Sender<AnyTlsPhysicalEvent>,
    metrics: Arc<AnyTlsOwnerMetrics>,
}

#[derive(Clone)]
struct AnyTlsPaddingUpdateObserver {
    key: AnyTlsOwnerKey,
    instance_id: u64,
    events: mpsc::Sender<AnyTlsPhysicalEvent>,
    metrics: Arc<AnyTlsOwnerMetrics>,
}

impl AnyTlsPaddingUpdateObserver {
    async fn observe(&self, raw: &[u8]) {
        match AnyTlsPaddingScheme::parse(raw) {
            Ok(scheme) => {
                let _ = self
                    .events
                    .send(AnyTlsPhysicalEvent::PaddingUpdated {
                        key: self.key,
                        instance_id: self.instance_id,
                        scheme: Arc::new(scheme),
                    })
                    .await;
            }
            Err(_) => {
                self.metrics
                    .cumulative_padding_update_rejections
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

impl AnyTlsPhysicalPadding {
    fn new(
        scheme: Arc<AnyTlsPaddingScheme>,
        key: AnyTlsOwnerKey,
        instance_id: u64,
        events: mpsc::Sender<AnyTlsPhysicalEvent>,
        metrics: Arc<AnyTlsOwnerMetrics>,
    ) -> Self {
        Self {
            scheme,
            packet_counter: 0,
            enabled: true,
            sampled_sizes: Vec::new(),
            scratch: Vec::new(),
            frame: Vec::new(),
            key,
            instance_id,
            events,
            metrics,
        }
    }

    fn settings_bytes(&self) -> Vec<u8> {
        self.scheme.settings_bytes()
    }

    fn update_observer(&self) -> AnyTlsPaddingUpdateObserver {
        AnyTlsPaddingUpdateObserver {
            key: self.key,
            instance_id: self.instance_id,
            events: self.events.clone(),
            metrics: Arc::clone(&self.metrics),
        }
    }

    async fn observe_update(&self, raw: &[u8]) {
        self.update_observer().observe(raw).await;
    }

    async fn write_frame<W>(
        &mut self,
        client: &mut W,
        cmd: u8,
        sid: u32,
        data: &[u8],
        label: &str,
        deadline: Option<AbsoluteDeadline>,
    ) -> Result<(), String>
    where
        W: AsyncWrite + Unpin,
    {
        self.write_frame_with_flush(client, cmd, sid, data, label, deadline, true)
            .await
    }

    async fn write_frame_coalesced<W>(
        &mut self,
        client: &mut W,
        cmd: u8,
        sid: u32,
        data: &[u8],
        label: &str,
    ) -> Result<(), String>
    where
        W: AsyncWrite + Unpin,
    {
        self.write_frame_with_flush(client, cmd, sid, data, label, None, false)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn write_frame_with_flush<W>(
        &mut self,
        client: &mut W,
        cmd: u8,
        sid: u32,
        data: &[u8],
        label: &str,
        deadline: Option<AbsoluteDeadline>,
        flush: bool,
    ) -> Result<(), String>
    where
        W: AsyncWrite + Unpin,
    {
        if data.len() > usize::from(u16::MAX) {
            return Err(format!(
                "{label}: AnyTLS frame payload exceeds {} bytes",
                u16::MAX
            ));
        }
        // Keep the frame allocation on the physical owner.  AnyTLS payloads
        // are already bounded by the relay buffer; allocating a fresh Vec
        // for every PSH/FIN/heartbeat frame needlessly puts that hot path on
        // the allocator while preserving no protocol state.
        let mut frame = std::mem::take(&mut self.frame);
        frame.clear();
        frame.reserve(anytls_contract::HEADER_OVERHEAD_SIZE + data.len());
        frame.push(cmd);
        frame.extend_from_slice(&sid.to_be_bytes());
        frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
        frame.extend_from_slice(data);
        let result = self
            .write_bytes(client, &frame, label, deadline, flush)
            .await;
        self.frame = frame;
        result
    }

    async fn write_bytes<W>(
        &mut self,
        client: &mut W,
        frame: &[u8],
        label: &str,
        deadline: Option<AbsoluteDeadline>,
        flush: bool,
    ) -> Result<(), String>
    where
        W: AsyncWrite + Unpin,
    {
        let mut remaining = frame;
        if self.enabled {
            self.packet_counter = self.packet_counter.wrapping_add(1);
            if self.packet_counter < self.scheme.stop() {
                self.scheme
                    .sample_record_payload_sizes(self.packet_counter, &mut self.sampled_sizes);
                for index in 0..self.sampled_sizes.len() {
                    let target = self.sampled_sizes[index];
                    if target == anytls_contract::CHECK_MARK {
                        if remaining.is_empty() {
                            break;
                        }
                        continue;
                    }
                    let target = usize::try_from(target).unwrap_or_default();
                    if remaining.len() > target {
                        write_anytls_physical_plain(client, &remaining[..target], label, deadline)
                            .await?;
                        remaining = &remaining[target..];
                        continue;
                    }
                    if !remaining.is_empty() {
                        let padding_bytes = target
                            .saturating_sub(remaining.len())
                            .saturating_sub(anytls_contract::HEADER_OVERHEAD_SIZE)
                            .min(usize::from(u16::MAX));
                        self.scratch.clear();
                        self.scratch.reserve(
                            remaining
                                .len()
                                .saturating_add(anytls_contract::HEADER_OVERHEAD_SIZE)
                                .saturating_add(padding_bytes),
                        );
                        self.scratch.extend_from_slice(remaining);
                        if padding_bytes > 0 {
                            append_anytls_waste_frame(&mut self.scratch, padding_bytes);
                        }
                        write_anytls_physical_plain(client, &self.scratch, label, deadline).await?;
                        if padding_bytes > 0 {
                            self.metrics
                                .cumulative_padding_waste_frames
                                .fetch_add(1, Ordering::Relaxed);
                            self.metrics
                                .cumulative_padding_waste_bytes
                                .fetch_add(padding_bytes as u64, Ordering::Relaxed);
                        }
                        remaining = &[];
                        continue;
                    }
                    let padding_bytes = target.min(usize::from(u16::MAX));
                    self.scratch.clear();
                    append_anytls_waste_frame(&mut self.scratch, padding_bytes);
                    write_anytls_physical_plain(client, &self.scratch, label, deadline).await?;
                    self.metrics
                        .cumulative_padding_waste_frames
                        .fetch_add(1, Ordering::Relaxed);
                    self.metrics
                        .cumulative_padding_waste_bytes
                        .fetch_add(padding_bytes as u64, Ordering::Relaxed);
                }
                if remaining.is_empty() {
                    if flush {
                        flush_anytls_physical(client, label, deadline).await?;
                    }
                    return Ok(());
                }
            } else {
                self.enabled = false;
            }
        }
        write_anytls_physical_plain(client, remaining, label, deadline).await?;
        if flush {
            flush_anytls_physical(client, label, deadline).await?;
        }
        Ok(())
    }
}

fn append_anytls_waste_frame(output: &mut Vec<u8>, padding_bytes: usize) {
    output.push(anytls_contract::CMD_WASTE);
    output.extend_from_slice(&0_u32.to_be_bytes());
    output.extend_from_slice(&(padding_bytes as u16).to_be_bytes());
    output.resize(output.len().saturating_add(padding_bytes), 0);
}

async fn write_anytls_physical_plain<W>(
    client: &mut W,
    payload: &[u8],
    label: &str,
    deadline: Option<AbsoluteDeadline>,
) -> Result<(), String>
where
    W: AsyncWrite + Unpin,
{
    let write = async {
        client
            .write_all(payload)
            .await
            .map_err(|error| format!("{label}: {error}"))
    };
    if let Some(deadline) = deadline {
        let remaining = deadline
            .remaining_at(Instant::now())
            .ok_or_else(|| format!("{label}: absolute deadline elapsed"))?;
        time::timeout(remaining, write)
            .await
            .map_err(|_| format!("{label}: absolute deadline elapsed"))?
    } else {
        write.await
    }
}

async fn flush_anytls_physical<W>(
    client: &mut W,
    label: &str,
    deadline: Option<AbsoluteDeadline>,
) -> Result<(), String>
where
    W: AsyncWrite + Unpin,
{
    let flush = async {
        client
            .flush()
            .await
            .map_err(|error| format!("flush {label}: {error}"))
    };
    if let Some(deadline) = deadline {
        let remaining = deadline
            .remaining_at(Instant::now())
            .ok_or_else(|| format!("flush {label}: absolute deadline elapsed"))?;
        time::timeout(remaining, flush)
            .await
            .map_err(|_| format!("flush {label}: absolute deadline elapsed"))?
    } else {
        flush.await
    }
}

fn observe_anytls_server_settings(data: &[u8], metrics: &AnyTlsOwnerMetrics) {
    let Some(version) = std::str::from_utf8(data).ok().and_then(|settings| {
        settings.lines().find_map(|line| {
            line.strip_prefix("v=")
                .and_then(|value| value.parse::<u8>().ok())
        })
    }) else {
        return;
    };
    metrics
        .peer_version
        .store(u64::from(version), Ordering::Relaxed);
}

struct AnyTlsSidAllocator {
    next: u32,
    quarantine: VecDeque<(u32, Instant)>,
    quarantined: HashSet<u32>,
}

impl AnyTlsSidAllocator {
    fn new() -> Self {
        Self {
            next: 0,
            quarantine: VecDeque::new(),
            quarantined: HashSet::new(),
        }
    }

    fn allocate(&mut self, resources: AnyTlsOwnerResourceProfile) -> Result<u32, String> {
        self.prune(resources);
        for _ in 0..=self.quarantined.len().saturating_add(1) {
            self.next = self.next.wrapping_add(1).max(1);
            if !self.quarantined.contains(&self.next) {
                return Ok(self.next);
            }
        }
        Err("AnyTLS SID allocator has no collision-free identifier".to_owned())
    }

    fn retire(&mut self, sid: u32, resources: AnyTlsOwnerResourceProfile) {
        self.prune(resources);
        while self.quarantine.len() >= resources.sid_quarantine_limit().max(1) {
            if let Some((expired, _)) = self.quarantine.pop_front() {
                self.quarantined.remove(&expired);
            }
        }
        self.quarantined.insert(sid);
        self.quarantine.push_back((sid, Instant::now()));
    }

    fn is_quarantined(&mut self, sid: u32, resources: AnyTlsOwnerResourceProfile) -> bool {
        self.prune(resources);
        self.quarantined.contains(&sid)
    }

    fn prune(&mut self, resources: AnyTlsOwnerResourceProfile) {
        let now = Instant::now();
        while self.quarantine.front().is_some_and(|(_, retired_at)| {
            now.saturating_duration_since(*retired_at) >= resources.sid_quarantine_ttl()
        }) {
            if let Some((sid, _)) = self.quarantine.pop_front() {
                self.quarantined.remove(&sid);
            }
        }
    }
}

pub fn start_anytls_owner_registry(
    generation: u64,
    stop: SharedResidentStopSignal,
    stack_bytes: usize,
) -> Result<(AnyTlsOwnerRegistryHandle, JoinHandle<()>), String> {
    start_anytls_owner_registry_with_resources(
        generation,
        stop,
        stack_bytes,
        AnyTlsOwnerResourceProfile::selected(),
    )
}

pub fn start_anytls_owner_registry_with_resources(
    generation: u64,
    stop: SharedResidentStopSignal,
    stack_bytes: usize,
    resources: AnyTlsOwnerResourceProfile,
) -> Result<(AnyTlsOwnerRegistryHandle, JoinHandle<()>), String> {
    let generation = OwnerGeneration::new(generation);
    let (sender, receiver) = mpsc::channel(resources.command_queue_depth().max(1));
    let index = Arc::new(Mutex::new(AnyTlsOwnerIndex::new()));
    let metrics = Arc::new(AnyTlsOwnerMetrics::default());
    let handle = AnyTlsOwnerRegistryHandle {
        generation,
        sender,
        index: Arc::clone(&index),
        resources,
        metrics: Arc::clone(&metrics),
    };
    let (initialized, initialization) = std::sync::mpsc::sync_channel(1);
    let thread = std::thread::Builder::new()
        .name(format!("resident-anytls-owner-{}", generation.get()))
        .stack_size(stack_bytes)
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build();
            let runtime = match runtime {
                Ok(runtime) => {
                    let _ = initialized.send(Ok(()));
                    runtime
                }
                Err(error) => {
                    let _ =
                        initialized.send(Err(format!("build AnyTLS owner Tokio runtime: {error}")));
                    return;
                }
            };
            runtime.block_on(run_anytls_owner_registry(
                receiver, index, resources, metrics, stop,
            ));
        })
        .map_err(|error| format!("spawn AnyTLS owner runtime: {error}"))?;
    initialization
        .recv()
        .map_err(|_| "AnyTLS owner runtime stopped during initialization".to_owned())??;
    Ok((handle, thread))
}

pub fn start_anytls_owner_registry_on(
    runtime: &tokio::runtime::Handle,
    generation: u64,
    stop: SharedResidentStopSignal,
) -> (AnyTlsOwnerRegistryHandle, tokio::task::JoinHandle<()>) {
    let generation = OwnerGeneration::new(generation);
    let resources = AnyTlsOwnerResourceProfile::selected();
    let (sender, receiver) = mpsc::channel(resources.command_queue_depth().max(1));
    let index = Arc::new(Mutex::new(AnyTlsOwnerIndex::new()));
    let metrics = Arc::new(AnyTlsOwnerMetrics::default());
    let handle = AnyTlsOwnerRegistryHandle {
        generation,
        sender,
        index: Arc::clone(&index),
        resources,
        metrics: Arc::clone(&metrics),
    };
    let task = runtime.spawn(run_anytls_owner_registry(
        receiver, index, resources, metrics, stop,
    ));
    (handle, task)
}

async fn run_anytls_owner_registry(
    mut receiver: mpsc::Receiver<AnyTlsOwnerCommand>,
    index: Arc<Mutex<AnyTlsOwnerIndex>>,
    resources: AnyTlsOwnerResourceProfile,
    metrics: Arc<AnyTlsOwnerMetrics>,
    stop: SharedResidentStopSignal,
) {
    let (events, mut event_receiver) = mpsc::channel(resources.command_queue_depth().max(1));
    let mut tasks = JoinSet::<AnyTlsPhysicalCompletion>::new();
    let mut stop_listener = stop.listener();
    loop {
        tokio::select! {
            biased;
            _ = stop_listener.cancelled() => break,
            event = event_receiver.recv() => {
                if let Some(event) = event {
                    apply_anytls_physical_event(event, &index, resources, &metrics);
                }
            }
            completion = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Ok(completion)) = completion {
                    remove_anytls_physical(completion, &index, &metrics);
                }
            }
            command = receiver.recv() => match command {
                Some(AnyTlsOwnerCommand::Acquire(command)) => {
                    admit_anytls_acquire(
                        command,
                        &index,
                        &mut tasks,
                        &events,
                        resources,
                        &metrics,
                    );
                }
                None => break,
            },
        }
    }
    let senders = {
        let mut index = index
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        index.draining = true;
        index
            .pools
            .values()
            .flat_map(|pool| pool.physical.values().map(|slot| slot.sender.clone()))
            .collect::<Vec<_>>()
    };
    for sender in senders {
        let _ = sender.try_send(AnyTlsPhysicalCommand::Close);
    }
    let drain = async {
        while let Some(completion) = tasks.join_next().await {
            if let Ok(completion) = completion {
                remove_anytls_physical(completion, &index, &metrics);
            }
        }
    };
    if time::timeout(RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE, drain)
        .await
        .is_err()
    {
        metrics.shutdown_timed_out.store(true, Ordering::Relaxed);
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
    index
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .pools
        .clear();
    metrics.idle_physical.store(0, Ordering::Relaxed);
    metrics.active_builds.store(0, Ordering::Relaxed);
}

fn admit_anytls_acquire(
    command: AnyTlsAcquireCommand,
    index: &Arc<Mutex<AnyTlsOwnerIndex>>,
    tasks: &mut JoinSet<AnyTlsPhysicalCompletion>,
    events: &mpsc::Sender<AnyTlsPhysicalEvent>,
    resources: AnyTlsOwnerResourceProfile,
    metrics: &Arc<AnyTlsOwnerMetrics>,
) {
    let mut index_guard = index
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if index_guard.draining {
        let _ = command.response.send(Err(AnyTlsAcquireFailure::Terminal(
            "AnyTLS owner registry is draining".to_owned(),
        )));
        return;
    }
    if let Some((instance_id, sender)) = index_guard.pools.get(&command.key).and_then(|pool| {
        pool.physical.iter().find_map(|(instance_id, slot)| {
            (slot.state == AnyTlsPhysicalState::Idle).then(|| (*instance_id, slot.sender.clone()))
        })
    }) {
        if let Some(slot) = index_guard
            .pools
            .get_mut(&command.key)
            .and_then(|pool| pool.physical.get_mut(&instance_id))
        {
            slot.state = AnyTlsPhysicalState::Active;
        }
        metrics.idle_closed();
        metrics.cumulative_reuses.fetch_add(1, Ordering::Relaxed);
        drop(index_guard);
        if let Err(error) = sender.try_send(AnyTlsPhysicalCommand::Open {
            target: command.target,
            initial_payload: command.initial_payload,
            deadline: command.deadline,
            response: command.response,
        }) && let AnyTlsPhysicalCommand::Open { response, .. } = error.into_inner()
        {
            let _ = response.send(Err(AnyTlsAcquireFailure::Retry(
                "AnyTLS idle session command channel closed".to_owned(),
            )));
        }
        return;
    }

    let is_new_key = !index_guard.pools.contains_key(&command.key);
    if is_new_key && index_guard.pools.len() >= resources.owner_limit() {
        metrics
            .owner_limit_rejections
            .fetch_add(1, Ordering::Relaxed);
        let _ = command
            .response
            .send(Err(AnyTlsAcquireFailure::Terminal(format!(
                "AnyTLS owner key budget is full ({})",
                resources.owner_limit()
            ))));
        return;
    }
    let key_physical = index_guard
        .pools
        .get(&command.key)
        .map_or(0, |pool| pool.physical.len());
    if index_guard.physical_count() >= resources.physical_session_limit()
        || key_physical >= resources.physical_sessions_per_owner()
    {
        metrics
            .physical_limit_rejections
            .fetch_add(1, Ordering::Relaxed);
        let _ = command
            .response
            .send(Err(AnyTlsAcquireFailure::Terminal(format!(
                "AnyTLS physical session budget is full ({})",
                resources.physical_session_limit()
            ))));
        return;
    }

    let instance_id = index_guard.allocate_instance_id();
    let (sender, physical_receiver) =
        mpsc::channel(resources.physical_control_queue_depth().max(1));
    let initial_padding_scheme = {
        let pool = index_guard.pools.entry(command.key).or_default();
        pool.physical.insert(
            instance_id,
            AnyTlsPhysicalSlot {
                state: AnyTlsPhysicalState::Building,
                sender,
            },
        );
        pool.padding_scheme.clone()
    };
    drop(index_guard);
    metrics.cumulative_builds.fetch_add(1, Ordering::Relaxed);
    metrics.active_builds.fetch_add(1, Ordering::Relaxed);
    let events = events.clone();
    let metrics = Arc::clone(metrics);
    let completion_key = command.key;
    tasks.spawn(async move {
        run_anytls_physical(
            command,
            instance_id,
            initial_padding_scheme,
            physical_receiver,
            events,
            resources,
            metrics,
        )
        .await;
        AnyTlsPhysicalCompletion {
            key: completion_key,
            instance_id,
        }
    });
}

fn apply_anytls_physical_event(
    event: AnyTlsPhysicalEvent,
    index: &Arc<Mutex<AnyTlsOwnerIndex>>,
    resources: AnyTlsOwnerResourceProfile,
    metrics: &AnyTlsOwnerMetrics,
) {
    let (key, instance_id, state) = match event {
        AnyTlsPhysicalEvent::Active { key, instance_id } => {
            (key, instance_id, AnyTlsPhysicalState::Active)
        }
        AnyTlsPhysicalEvent::Idle { key, instance_id } => {
            (key, instance_id, AnyTlsPhysicalState::Idle)
        }
        AnyTlsPhysicalEvent::PaddingUpdated {
            key,
            instance_id,
            scheme,
        } => {
            let mut index = index
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(pool) = index.pools.get_mut(&key)
                && pool.physical.contains_key(&instance_id)
            {
                pool.padding_scheme = scheme;
                metrics
                    .cumulative_padding_updates
                    .fetch_add(1, Ordering::Relaxed);
            }
            return;
        }
    };
    let mut index = index
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let Some(pool) = index.pools.get_mut(&key) else {
        return;
    };
    let previous = pool.physical.get(&instance_id).map(|slot| slot.state);
    if let Some(slot) = pool.physical.get_mut(&instance_id) {
        slot.state = state;
    }
    if previous == Some(AnyTlsPhysicalState::Idle) && state != AnyTlsPhysicalState::Idle {
        metrics.idle_closed();
    }
    if state == AnyTlsPhysicalState::Idle && previous != Some(AnyTlsPhysicalState::Idle) {
        let idle_count = pool
            .physical
            .values()
            .filter(|slot| slot.state == AnyTlsPhysicalState::Idle)
            .count();
        metrics.idle_opened();
        if idle_count > resources.idle_session_limit()
            && let Some(slot) = pool.physical.get(&instance_id)
        {
            let _ = slot.sender.try_send(AnyTlsPhysicalCommand::Close);
        }
    }
}

fn remove_anytls_physical(
    completion: AnyTlsPhysicalCompletion,
    index: &Arc<Mutex<AnyTlsOwnerIndex>>,
    metrics: &AnyTlsOwnerMetrics,
) {
    let mut index = index
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(pool) = index.pools.get_mut(&completion.key)
        && pool
            .physical
            .remove(&completion.instance_id)
            .is_some_and(|slot| slot.state == AnyTlsPhysicalState::Idle)
    {
        metrics.idle_closed();
    }
}

async fn run_anytls_physical(
    initial: AnyTlsAcquireCommand,
    instance_id: u64,
    initial_padding_scheme: Arc<AnyTlsPaddingScheme>,
    mut commands: mpsc::Receiver<AnyTlsPhysicalCommand>,
    events: mpsc::Sender<AnyTlsPhysicalEvent>,
    resources: AnyTlsOwnerResourceProfile,
    metrics: Arc<AnyTlsOwnerMetrics>,
) {
    let build = build_anytls_physical(&initial.binding, initial.deadline).await;
    metrics.active_builds.fetch_sub(1, Ordering::Relaxed);
    let (mut client, tls_underlay) = match build {
        Ok(opened) => opened,
        Err(error) => {
            metrics
                .cumulative_build_failures
                .fetch_add(1, Ordering::Relaxed);
            let _ = initial
                .response
                .send(Err(AnyTlsAcquireFailure::Terminal(error)));
            return;
        }
    };
    let _physical_guard = AnyTlsPhysicalMetricGuard::new(Arc::clone(&metrics));
    let mut allocator = AnyTlsSidAllocator::new();
    let mut frame_reader = AnyTlsFrameReader::default();
    let mut padding = AnyTlsPhysicalPadding::new(
        initial_padding_scheme,
        initial.key,
        instance_id,
        events.clone(),
        Arc::clone(&metrics),
    );
    let opened = open_anytls_logical_stream(
        &mut client,
        &mut frame_reader,
        &mut allocator,
        &mut padding,
        initial.target,
        initial.initial_payload,
        initial.deadline,
        false,
        instance_id,
        tls_underlay,
        resources,
        Arc::clone(&metrics),
    )
    .await;
    let (lease, mut owner_stream, sid) = match opened {
        Ok(opened) => opened,
        Err(error) => {
            let _ = initial
                .response
                .send(Err(AnyTlsAcquireFailure::Terminal(error)));
            client.shutdown().await;
            return;
        }
    };
    if initial.response.send(Ok(lease)).is_err() {
        let _ = owner_stream.shutdown().await;
    }
    let _ = events
        .send(AnyTlsPhysicalEvent::Active {
            key: initial.key,
            instance_id,
        })
        .await;

    let mut current_sid = sid;
    loop {
        if run_anytls_active_stream(
            &mut client,
            &mut frame_reader,
            &mut owner_stream,
            current_sid,
            &mut allocator,
            &mut padding,
            &mut commands,
            resources,
            &metrics,
        )
        .await
        .is_err()
        {
            break;
        }
        allocator.retire(current_sid, resources);
        let idle_since = Instant::now();
        let _ = events
            .send(AnyTlsPhysicalEvent::Idle {
                key: initial.key,
                instance_id,
            })
            .await;
        let next = wait_anytls_idle_command(
            &mut client,
            &mut frame_reader,
            &mut commands,
            &mut allocator,
            &mut padding,
            idle_since,
            resources,
            &metrics,
        )
        .await;
        let Some((target, initial_payload, deadline, response)) = next else {
            break;
        };
        let opened = open_anytls_logical_stream(
            &mut client,
            &mut frame_reader,
            &mut allocator,
            &mut padding,
            target,
            initial_payload,
            deadline,
            true,
            instance_id,
            tls_underlay,
            resources,
            Arc::clone(&metrics),
        )
        .await;
        match opened {
            Ok((lease, stream, next_sid)) => {
                owner_stream = stream;
                current_sid = next_sid;
                if response.send(Ok(lease)).is_err() {
                    let _ = owner_stream.shutdown().await;
                }
                let _ = events
                    .send(AnyTlsPhysicalEvent::Active {
                        key: initial.key,
                        instance_id,
                    })
                    .await;
            }
            Err(error) => {
                let _ = response.send(Err(AnyTlsAcquireFailure::Retry(error)));
                break;
            }
        }
    }
    client.shutdown().await;
}

async fn build_anytls_physical(
    binding: &ResidentProxyBinding,
    deadline: AbsoluteDeadline,
) -> Result<(AsyncResidentTlsClient, &'static str), String> {
    let proxy = binding.plan();
    if !matches!(
        &proxy.handler,
        ResidentProxyProtocolPlan::AnyTlsTcpTls { .. }
    ) {
        return Err("AnyTLS owner received non-AnyTLS credentials".to_owned());
    }
    let remaining = deadline
        .remaining_at(Instant::now())
        .ok_or_else(|| "AnyTLS physical connect deadline elapsed".to_owned())?;
    let mut client = time::timeout(
        remaining,
        open_async_resident_tls_client_with_binding(binding, proxy.mptcp),
    )
    .await
    .map_err(|_| "AnyTLS physical TLS connect deadline elapsed".to_owned())??;
    let auth = match &proxy.handler {
        ResidentProxyProtocolPlan::AnyTlsTcpTls { auth } => auth,
        _ => unreachable!(),
    };
    let remaining = deadline
        .remaining_at(Instant::now())
        .ok_or_else(|| "AnyTLS auth deadline elapsed".to_owned())?;
    time::timeout(
        remaining,
        client.write_plain_all(
            &anytls_link::handshake_auth_bytes(auth),
            "write AnyTLS auth handshake",
        ),
    )
    .await
    .map_err(|_| "AnyTLS auth deadline elapsed".to_owned())??;
    let tls_underlay = async_resident_tls_underlay_name(&client);
    Ok((client, tls_underlay))
}

#[allow(clippy::too_many_arguments)]
async fn open_anytls_logical_stream(
    client: &mut AsyncResidentTlsClient,
    frame_reader: &mut AnyTlsFrameReader,
    allocator: &mut AnyTlsSidAllocator,
    padding: &mut AnyTlsPhysicalPadding,
    target: String,
    initial_payload: Option<AnyTlsInitialPayload>,
    deadline: AbsoluteDeadline,
    reused: bool,
    instance_id: u64,
    tls_underlay: &'static str,
    resources: AnyTlsOwnerResourceProfile,
    metrics: Arc<AnyTlsOwnerMetrics>,
) -> Result<(AnyTlsLogicalStreamLease, DuplexStream, u32), String> {
    let sid = allocator.allocate(resources)?;
    metrics
        .cumulative_sid_allocations
        .fetch_add(1, Ordering::Relaxed);
    let settings = padding.settings_bytes();
    write_anytls_frame_until(
        padding,
        client,
        anytls_contract::CMD_SETTINGS,
        sid,
        &settings,
        "write AnyTLS settings",
        deadline,
    )
    .await?;
    write_anytls_frame_until(
        padding,
        client,
        anytls_contract::CMD_SYN,
        sid,
        &[],
        "write AnyTLS SYN",
        deadline,
    )
    .await?;
    let target_addr = anytls_link::socks_addr(&target)
        .map_err(|error| format!("build AnyTLS target address: {error}"))?;
    write_anytls_frame_until(
        padding,
        client,
        anytls_contract::CMD_PSH,
        sid,
        &target_addr,
        "write AnyTLS target",
        deadline,
    )
    .await?;
    if let Some(initial_payload) = initial_payload.as_ref() {
        write_anytls_frame_until(
            padding,
            client,
            anytls_contract::CMD_PSH,
            sid,
            initial_payload.as_ref(),
            "write AnyTLS initial logical payload",
            deadline,
        )
        .await?;
    }
    let pending_response = wait_anytls_synack_until(
        client,
        frame_reader,
        sid,
        allocator,
        padding,
        resources,
        deadline,
        &metrics,
    )
    .await?;
    let charged_buffer_bytes = resources.logical_buffer_bytes().saturating_mul(2);
    let (caller, mut owner) = tokio::io::duplex(resources.logical_buffer_bytes());
    if !pending_response.is_empty() {
        let remaining = deadline.remaining_at(Instant::now()).ok_or_else(|| {
            "buffer AnyTLS response received before SYNACK deadline elapsed".to_owned()
        })?;
        time::timeout(remaining, owner.write_all(&pending_response))
            .await
            .map_err(|_| {
                "buffer AnyTLS response received before SYNACK deadline elapsed".to_owned()
            })?
            .map_err(|error| format!("buffer AnyTLS response received before SYNACK: {error}"))?;
    }
    metrics.logical_opened(charged_buffer_bytes);
    Ok((
        AnyTlsLogicalStreamLease {
            stream: caller,
            sid,
            physical_instance_id: instance_id,
            reused,
            tls_underlay,
            charged_buffer_bytes,
            metrics,
        },
        owner,
        sid,
    ))
}

async fn write_anytls_frame_until(
    padding: &mut AnyTlsPhysicalPadding,
    client: &mut AsyncResidentTlsClient,
    cmd: u8,
    sid: u32,
    data: &[u8],
    label: &str,
    deadline: AbsoluteDeadline,
) -> Result<(), String> {
    padding
        .write_frame(client, cmd, sid, data, label, Some(deadline))
        .await
}

#[allow(clippy::too_many_arguments)]
async fn wait_anytls_synack_until(
    client: &mut AsyncResidentTlsClient,
    frame_reader: &mut AnyTlsFrameReader,
    sid: u32,
    allocator: &mut AnyTlsSidAllocator,
    padding: &mut AnyTlsPhysicalPadding,
    resources: AnyTlsOwnerResourceProfile,
    deadline: AbsoluteDeadline,
    metrics: &AnyTlsOwnerMetrics,
) -> Result<Vec<u8>, String> {
    let mut pending_response = Vec::new();
    loop {
        let remaining = deadline
            .remaining_at(Instant::now())
            .ok_or_else(|| "wait AnyTLS SYNACK absolute deadline elapsed".to_owned())?;
        let frame = time::timeout(remaining, frame_reader.read_frame(client))
            .await
            .map_err(|_| "wait AnyTLS SYNACK absolute deadline elapsed".to_owned())??;
        match frame.cmd {
            anytls_contract::CMD_SYNACK if frame.sid == sid && frame.data.is_empty() => {
                return Ok(pending_response);
            }
            anytls_contract::CMD_SYNACK if frame.sid == sid => {
                return Err(format!(
                    "AnyTLS SYNACK rejected logical stream: {} bytes",
                    frame.data.len()
                ));
            }
            anytls_contract::CMD_HEART_REQUEST => {
                write_anytls_frame_until(
                    padding,
                    client,
                    anytls_contract::CMD_HEART_RESPONSE,
                    frame.sid,
                    &[],
                    "write AnyTLS heartbeat response",
                    deadline,
                )
                .await?;
            }
            anytls_contract::CMD_SERVER_SETTINGS => {
                observe_anytls_server_settings(&frame.data, metrics);
            }
            anytls_contract::CMD_UPDATE_PADDING if !frame.data.is_empty() => {
                padding.observe_update(&frame.data).await;
            }
            anytls_contract::CMD_WASTE
            | anytls_contract::CMD_UPDATE_PADDING
            | anytls_contract::CMD_HEART_RESPONSE => {}
            anytls_contract::CMD_PSH | anytls_contract::CMD_FIN
                if allocator.is_quarantined(frame.sid, resources) =>
            {
                metrics.late_frames.fetch_add(1, Ordering::Relaxed);
            }
            anytls_contract::CMD_ALERT => {
                return Err(format!(
                    "AnyTLS alert before SYNACK: {} bytes",
                    frame.data.len()
                ));
            }
            anytls_contract::CMD_PSH if frame.sid == sid => {
                let next_len = pending_response.len().saturating_add(frame.data.len());
                if next_len > resources.logical_buffer_bytes() {
                    return Err(format!(
                        "AnyTLS response before SYNACK exceeds the logical buffer budget: {} > {} bytes",
                        next_len,
                        resources.logical_buffer_bytes()
                    ));
                }
                pending_response.extend_from_slice(&frame.data);
            }
            anytls_contract::CMD_FIN if frame.sid == sid => {
                return Err("AnyTLS logical stream closed before SYNACK".to_owned());
            }
            anytls_contract::CMD_PSH | anytls_contract::CMD_FIN => {
                metrics.unknown_frames.fetch_add(1, Ordering::Relaxed);
            }
            anytls_contract::CMD_SYNACK => {}
            command => return Err(format!("invalid AnyTLS command before SYNACK: {command}")),
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_anytls_active_stream(
    client: &mut AsyncResidentTlsClient,
    frame_reader: &mut AnyTlsFrameReader,
    logical: &mut DuplexStream,
    sid: u32,
    allocator: &mut AnyTlsSidAllocator,
    padding: &mut AnyTlsPhysicalPadding,
    commands: &mut mpsc::Receiver<AnyTlsPhysicalCommand>,
    resources: AnyTlsOwnerResourceProfile,
    metrics: &AnyTlsOwnerMetrics,
) -> Result<(), String> {
    enum WriterCommand {
        HeartbeatResponse { sid: u32 },
    }

    let padding_updates = padding.update_observer();
    let (mut client_read, mut client_write) = tokio::io::split(&mut *client);
    let (mut logical_read, mut logical_write) = tokio::io::split(&mut *logical);
    let (writer_commands, mut writer_command_receiver) =
        mpsc::channel(resources.physical_control_queue_depth().max(1));

    let writer = async {
        let mut buffer = vec![0_u8; RESIDENT_ANYTLS_RELAY_BUFFER_SIZE];
        let mut pending_flush_bytes = 0_usize;
        let mut pending_flush_deadline = None;
        loop {
            tokio::select! {
                biased;
                command = writer_command_receiver.recv() => match command {
                    Some(WriterCommand::HeartbeatResponse { sid }) => {
                        padding.write_frame(
                            &mut client_write,
                            anytls_contract::CMD_HEART_RESPONSE,
                            sid,
                            &[],
                            "write AnyTLS heartbeat response",
                            None,
                        ).await?;
                        pending_flush_bytes = 0;
                        pending_flush_deadline = None;
                    }
                    None => return Ok::<(), String>(()),
                },
                read = logical_read.read(&mut buffer) => match read {
                    Ok(0) => {
                        padding.write_frame(
                            &mut client_write,
                            anytls_contract::CMD_FIN,
                            sid,
                            &[],
                            "write AnyTLS FIN",
                            None,
                        ).await?;
                        return Ok(());
                    }
                    Ok(read) => {
                        padding.write_frame_coalesced(
                            &mut client_write,
                            anytls_contract::CMD_PSH,
                            sid,
                            &buffer[..read],
                            "write AnyTLS logical payload",
                        ).await?;
                        if pending_flush_bytes == 0 {
                            pending_flush_deadline = Some(Instant::now() + ANYTLS_DATA_FLUSH_DELAY);
                        }
                        pending_flush_bytes = pending_flush_bytes.saturating_add(read);
                        if pending_flush_bytes >= ANYTLS_DATA_FLUSH_BYTES {
                            flush_anytls_physical(
                                &mut client_write,
                                "flush AnyTLS logical payload",
                                None,
                            ).await?;
                            pending_flush_bytes = 0;
                            pending_flush_deadline = None;
                        }
                    }
                    Err(error) => return Err(format!("read AnyTLS logical stream: {error}")),
                },
                _ = time::sleep_until(time::Instant::from_std(
                    pending_flush_deadline.unwrap_or_else(Instant::now),
                )), if pending_flush_deadline.is_some() => {
                    flush_anytls_physical(
                        &mut client_write,
                        "flush AnyTLS logical payload",
                        None,
                    ).await?;
                    pending_flush_bytes = 0;
                    pending_flush_deadline = None;
                },
            }
        }
    };

    let reader = async {
        let mut frame_data = BytesMut::with_capacity(16 * 1024);
        loop {
            let (cmd, frame_sid) = frame_reader
                .read_into(&mut client_read, &mut frame_data)
                .await?;
            match cmd {
                anytls_contract::CMD_PSH if frame_sid == sid => {
                    if !frame_data.is_empty() {
                        logical_write
                            .write_all(&frame_data)
                            .await
                            .map_err(|error| format!("write AnyTLS logical response: {error}"))?;
                    }
                }
                anytls_contract::CMD_FIN if frame_sid == sid => {
                    let _ = logical_write.shutdown().await;
                    return Ok::<(), String>(());
                }
                anytls_contract::CMD_HEART_REQUEST => {
                    writer_commands
                        .send(WriterCommand::HeartbeatResponse { sid: frame_sid })
                        .await
                        .map_err(|_| {
                            "AnyTLS physical writer closed before heartbeat response".to_owned()
                        })?;
                }
                anytls_contract::CMD_SERVER_SETTINGS => {
                    observe_anytls_server_settings(&frame_data, metrics);
                }
                anytls_contract::CMD_UPDATE_PADDING if !frame_data.is_empty() => {
                    padding_updates.observe(&frame_data).await;
                }
                anytls_contract::CMD_WASTE
                | anytls_contract::CMD_UPDATE_PADDING
                | anytls_contract::CMD_HEART_RESPONSE => {}
                anytls_contract::CMD_PSH | anytls_contract::CMD_FIN
                    if allocator.is_quarantined(frame_sid, resources) =>
                {
                    metrics.late_frames.fetch_add(1, Ordering::Relaxed);
                }
                anytls_contract::CMD_ALERT => {
                    return Err(format!(
                        "AnyTLS alert frame: sid={} len={}",
                        frame_sid,
                        frame_data.len()
                    ));
                }
                anytls_contract::CMD_PSH | anytls_contract::CMD_FIN => {
                    metrics.unknown_frames.fetch_add(1, Ordering::Relaxed);
                }
                anytls_contract::CMD_SYNACK => {}
                command => return Err(format!("invalid AnyTLS command: {command}")),
            }
        }
    };

    tokio::pin!(writer);
    tokio::pin!(reader);
    let close_deadline = time::sleep(ANYTLS_LOCAL_CLOSE_DRAIN_TIMEOUT);
    tokio::pin!(close_deadline);
    let mut writer_done = false;
    loop {
        tokio::select! {
            command = commands.recv() => match command {
                Some(AnyTlsPhysicalCommand::Close) | None =>
                    return Err("AnyTLS physical owner is closing".to_owned()),
                Some(AnyTlsPhysicalCommand::Open { response, .. }) => {
                    let _ = response.send(Err(AnyTlsAcquireFailure::Retry(
                        "AnyTLS physical session is already active".to_owned(),
                    )));
                }
            },
            result = &mut writer, if !writer_done => {
                result?;
                writer_done = true;
                close_deadline.as_mut().reset(
                    time::Instant::now() + ANYTLS_LOCAL_CLOSE_DRAIN_TIMEOUT,
                );
            }
            result = &mut reader => return result,
            _ = &mut close_deadline, if writer_done => return Ok(()),
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn wait_anytls_idle_command(
    client: &mut AsyncResidentTlsClient,
    frame_reader: &mut AnyTlsFrameReader,
    commands: &mut mpsc::Receiver<AnyTlsPhysicalCommand>,
    allocator: &mut AnyTlsSidAllocator,
    padding: &mut AnyTlsPhysicalPadding,
    idle_since: Instant,
    resources: AnyTlsOwnerResourceProfile,
    metrics: &AnyTlsOwnerMetrics,
) -> Option<(
    String,
    Option<AnyTlsInitialPayload>,
    AbsoluteDeadline,
    oneshot::Sender<Result<AnyTlsLogicalStreamLease, AnyTlsAcquireFailure>>,
)> {
    let idle_deadline = time::Instant::from_std(idle_since + resources.idle_session_timeout());
    loop {
        tokio::select! {
            command = commands.recv() => match command {
                Some(AnyTlsPhysicalCommand::Open {
                    target,
                    initial_payload,
                    deadline,
                    response,
                }) => {
                    if idle_since.elapsed() >= resources.idle_probe_threshold() {
                        metrics.cumulative_idle_probes.fetch_add(1, Ordering::Relaxed);
                        if probe_anytls_idle_session(
                            client,
                            frame_reader,
                            allocator,
                            padding,
                            resources,
                            metrics,
                        )
                        .await
                        .is_err()
                        {
                            metrics.cumulative_idle_probe_failures.fetch_add(1, Ordering::Relaxed);
                            let _ = response.send(Err(AnyTlsAcquireFailure::Retry(
                                "AnyTLS idle session heartbeat failed".to_owned(),
                            )));
                            return None;
                        }
                    }
                    return Some((target, initial_payload, deadline, response));
                }
                Some(AnyTlsPhysicalCommand::Close) | None => return None,
            },
            _ = time::sleep_until(idle_deadline) => {
                metrics.cumulative_idle_expirations.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            frame = frame_reader.read_frame(client) => match frame {
                Ok(frame) => match frame.cmd {
                    anytls_contract::CMD_HEART_REQUEST => {
                        if padding.write_frame(
                            client,
                            anytls_contract::CMD_HEART_RESPONSE,
                            frame.sid,
                            &[],
                            "write AnyTLS heartbeat response",
                            None,
                        ).await.is_err() {
                            return None;
                        }
                    }
                    anytls_contract::CMD_PSH | anytls_contract::CMD_FIN
                        if allocator.is_quarantined(frame.sid, resources) =>
                    {
                        metrics.late_frames.fetch_add(1, Ordering::Relaxed);
                    }
                    anytls_contract::CMD_SERVER_SETTINGS => {
                        observe_anytls_server_settings(&frame.data, metrics);
                    }
                    anytls_contract::CMD_UPDATE_PADDING if !frame.data.is_empty() => {
                        padding.observe_update(&frame.data).await;
                    }
                    anytls_contract::CMD_WASTE
                    | anytls_contract::CMD_UPDATE_PADDING
                    | anytls_contract::CMD_HEART_RESPONSE => {}
                    anytls_contract::CMD_ALERT => return None,
                    anytls_contract::CMD_PSH | anytls_contract::CMD_FIN => {
                        metrics.unknown_frames.fetch_add(1, Ordering::Relaxed);
                    }
                    anytls_contract::CMD_SYNACK => {}
                    _ => return None,
                },
                Err(_) => return None,
            }
        }
    }
}

async fn probe_anytls_idle_session(
    client: &mut AsyncResidentTlsClient,
    frame_reader: &mut AnyTlsFrameReader,
    allocator: &mut AnyTlsSidAllocator,
    padding: &mut AnyTlsPhysicalPadding,
    resources: AnyTlsOwnerResourceProfile,
    metrics: &AnyTlsOwnerMetrics,
) -> Result<(), String> {
    padding
        .write_frame(
            client,
            anytls_contract::CMD_HEART_REQUEST,
            0,
            &[],
            "write AnyTLS idle heartbeat",
            None,
        )
        .await?;
    time::timeout(resources.idle_probe_timeout(), async {
        loop {
            let frame = frame_reader.read_frame(client).await?;
            match frame.cmd {
                anytls_contract::CMD_HEART_RESPONSE => return Ok(()),
                anytls_contract::CMD_HEART_REQUEST => {
                    padding
                        .write_frame(
                            client,
                            anytls_contract::CMD_HEART_RESPONSE,
                            frame.sid,
                            &[],
                            "write AnyTLS heartbeat response",
                            None,
                        )
                        .await?;
                }
                anytls_contract::CMD_SERVER_SETTINGS => {
                    observe_anytls_server_settings(&frame.data, metrics);
                }
                anytls_contract::CMD_UPDATE_PADDING if !frame.data.is_empty() => {
                    padding.observe_update(&frame.data).await;
                }
                anytls_contract::CMD_PSH | anytls_contract::CMD_FIN
                    if allocator.is_quarantined(frame.sid, resources) =>
                {
                    metrics.late_frames.fetch_add(1, Ordering::Relaxed);
                }
                anytls_contract::CMD_WASTE | anytls_contract::CMD_UPDATE_PADDING => {}
                anytls_contract::CMD_ALERT => {
                    return Err("AnyTLS idle heartbeat received alert".to_owned());
                }
                anytls_contract::CMD_PSH | anytls_contract::CMD_FIN => {
                    metrics.unknown_frames.fetch_add(1, Ordering::Relaxed);
                }
                anytls_contract::CMD_SYNACK => {}
                command => {
                    return Err(format!(
                        "invalid AnyTLS command during idle heartbeat: {command}"
                    ));
                }
            }
        }
    })
    .await
    .map_err(|_| "AnyTLS idle heartbeat timeout".to_owned())?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resources() -> AnyTlsOwnerResourceProfile {
        AnyTlsOwnerResourceProfile::from_runtime_profile(ResidentRuntimeProfile::LowMemory)
    }

    #[test]
    fn sid_allocator_is_nonzero_wrap_aware_and_quarantines_retired_ids() {
        let resources = resources();
        let mut allocator = AnyTlsSidAllocator::new();
        assert_eq!(allocator.allocate(resources).unwrap(), 1);
        allocator.retire(1, resources);
        allocator.next = 0;
        assert_eq!(allocator.allocate(resources).unwrap(), 2);

        allocator.next = u32::MAX - 1;
        assert_eq!(allocator.allocate(resources).unwrap(), u32::MAX);
        allocator.retire(u32::MAX, resources);
        assert_eq!(allocator.allocate(resources).unwrap(), 2);
        assert!(allocator.is_quarantined(1, resources));
        assert!(allocator.is_quarantined(u32::MAX, resources));
    }

    #[test]
    fn production_anytls_callers_cannot_reopen_physical_tls_directly() {
        let owner = include_str!("anytls_owner.rs");
        let tcp = include_str!("../../dae-resident-tcp/src/proxy_dispatch/anytls.rs");
        let udp = include_str!("../../dae-resident-udp/src/udp/session_executor/anytls.rs");
        let native_probe =
            include_str!("../../dae-resident-dataplane/src/probe/native_tcp/frame_tls.rs");
        let manual_runtime = include_str!("../../dae-resident-dataplane/src/runtime_owner.rs");
        let health_checks =
            include_str!("../../dae-resident-dataplane/src/runtime/health_checks.rs");
        let constructor = "open_async_resident_tls_client_with_binding";
        let owner_production = owner
            .split_once("#[cfg(test)]\nmod tests")
            .map_or(owner, |(production, _)| production);
        assert!(owner_production.contains(constructor));
        assert!(owner_production.contains("anytls_link::handshake_auth_bytes"));
        assert!(!tcp.contains(constructor));
        assert!(!udp.contains(constructor));
        assert!(!native_probe.contains(constructor));
        assert!(!tcp.contains("let sid = 1_u32"));
        assert!(!udp.contains("sid == 1"));
        assert!(manual_runtime.contains("owners.anytls()"));
        assert!(health_checks.contains(".with_anytls(anytls_owner_registry)"));
    }
}
