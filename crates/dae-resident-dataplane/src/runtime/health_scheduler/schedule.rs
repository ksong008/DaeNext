use super::*;
use futures_util::{StreamExt, stream::FuturesUnordered};
use std::hash::{Hash, Hasher};
use std::pin::Pin;
use tokio::sync::{mpsc::Receiver, watch};

pub(super) const RESIDENT_HEALTH_INITIAL_JITTER_CEILING: Duration = Duration::from_secs(5);
const RESIDENT_HEALTH_STOP_MONITOR_INTERVAL: Duration = Duration::from_millis(50);

#[derive(Clone, Copy, Debug)]
pub(crate) struct ResidentHealthResuscitationRequest {
    pub(super) outbound: u8,
    pub(super) network_type: dae_core_types::NetworkTypeId,
}

#[derive(Clone)]
pub(super) struct ResidentHealthScheduleContext {
    pub(super) stop: SharedResidentStopSignal,
    pub(super) event_file: PathBuf,
    pub(super) event_lock: Arc<Mutex<()>>,
    pub(super) metrics: Arc<ResidentDataplaneMetrics>,
    pub(super) dns: Arc<dns::ResidentDnsPlan>,
    pub(super) periodic_candidate_concurrency: usize,
    pub(super) bootstrap_candidate_concurrency: usize,
    pub(super) candidate_admission: Arc<tokio::sync::Semaphore>,
    pub(super) hysteria2_owner_registry: Option<Hysteria2OwnerRegistryHandle>,
    pub(super) tuic_owner_registry: Option<TuicOwnerRegistryHandle>,
    pub(super) juicity_owner_registry: Option<JuicityOwnerRegistryHandle>,
    pub(super) anytls_owner_registry: Option<AnyTlsOwnerRegistryHandle>,
}

struct ResidentHealthRoundGuard {
    metrics: Arc<ResidentDataplaneMetrics>,
    active: bool,
}

impl ResidentHealthRoundGuard {
    fn new(metrics: Arc<ResidentDataplaneMetrics>) -> Self {
        metrics.health_round_started();
        Self {
            metrics,
            active: true,
        }
    }

    fn finish(mut self, status: HealthCheckRoundStatus) {
        self.metrics.health_round_finished(status.is_cancelled());
        self.active = false;
    }
}

impl Drop for ResidentHealthRoundGuard {
    fn drop(&mut self) {
        if self.active {
            self.metrics.health_round_finished(true);
        }
    }
}

pub(super) async fn run_resident_health_group_schedule(
    group: Arc<plan::ResidentProxyGroupPlan>,
    mut stop_rx: watch::Receiver<bool>,
    context: ResidentHealthScheduleContext,
) {
    let ResidentHealthScheduleContext {
        stop,
        event_file,
        event_lock,
        metrics,
        dns,
        periodic_candidate_concurrency: concurrency,
        bootstrap_candidate_concurrency: bootstrap_concurrency,
        candidate_admission,
        hysteria2_owner_registry,
        tuic_owner_registry,
        juicity_owner_registry,
        anytls_owner_registry,
    } = context;
    let interval = group.check_interval();
    let initial_jitter =
        resident_health_initial_jitter(&group.group_name, group.candidate_count(), interval);
    append_event(
        &event_file,
        &event_lock,
        json!({
            "event": "resident_health_checker_started",
            "group": group.group_name,
            "group_policy": group.group_policy_name(),
            "candidate_count": group.candidate_count(),
            "admitted_candidate_count": group.admitted_candidate_count(),
            "check_interval": format!("{interval:?}"),
            "concurrency": concurrency,
            "initial_jitter": format!("{initial_jitter:?}"),
            "probe": "tokio-proxy-tcp-and-dns-udp-check",
            "tcp_probe_executor": "tokio-proxy-tcp-probe",
            "udp_probe_executor": "tokio-proxy-packet-dns-probe",
            "tcp_check_target": group.probe_profile.tcp_check.target.clone(),
            "udp_check_target": group.probe_profile.udp_check.target.authority().to_owned(),
            "scheduler": "shared-resident-health-runtime",
        }),
    );
    group.begin_health_bootstrap();
    let bootstrap_status = run_resident_health_round(
        Arc::clone(&group),
        Arc::clone(&stop),
        Arc::clone(&metrics),
        bootstrap_concurrency,
        Arc::clone(&candidate_admission),
        Arc::clone(&dns),
        ResidentTransportOwnerRegistries::new(
            hysteria2_owner_registry.clone(),
            tuic_owner_registry.clone(),
            juicity_owner_registry.clone(),
        )
        .with_anytls(anytls_owner_registry.clone()),
    )
    .await;
    group.complete_health_bootstrap(bootstrap_status.is_cancelled());
    if bootstrap_status.is_cancelled() || interval.is_zero() || !group.needs_background_checks() {
        return;
    }

    let first_periodic_delay = interval.saturating_add(initial_jitter);
    if wait_for_resident_health_delay_or_stop(&mut stop_rx, first_periodic_delay).await {
        return;
    }
    loop {
        let status = run_resident_health_round(
            Arc::clone(&group),
            Arc::clone(&stop),
            Arc::clone(&metrics),
            concurrency,
            Arc::clone(&candidate_admission),
            Arc::clone(&dns),
            ResidentTransportOwnerRegistries::new(
                hysteria2_owner_registry.clone(),
                tuic_owner_registry.clone(),
                juicity_owner_registry.clone(),
            )
            .with_anytls(anytls_owner_registry.clone()),
        )
        .await;
        if status.is_cancelled() {
            return;
        }
        if wait_for_resident_health_delay_or_stop(&mut stop_rx, interval).await {
            return;
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_resident_health_resuscitation_dispatcher(
    proxy_groups: SharedResidentProxyGroupMap,
    mut receiver: Receiver<ResidentHealthResuscitationRequest>,
    stop: SharedResidentStopSignal,
    mut stop_rx: watch::Receiver<bool>,
    metrics: Arc<ResidentDataplaneMetrics>,
    dns: Arc<dns::ResidentDnsPlan>,
    concurrency: usize,
    candidate_admission: Arc<tokio::sync::Semaphore>,
    hysteria2_owner_registry: Option<Hysteria2OwnerRegistryHandle>,
    tuic_owner_registry: Option<TuicOwnerRegistryHandle>,
    juicity_owner_registry: Option<JuicityOwnerRegistryHandle>,
    anytls_owner_registry: Option<AnyTlsOwnerRegistryHandle>,
) {
    type ResuscitationRound =
        Pin<Box<dyn std::future::Future<Output = HealthCheckRoundStatus> + Send + 'static>>;
    let maximum_active_rounds = concurrency.max(1);
    let mut active = FuturesUnordered::<ResuscitationRound>::new();
    let mut receiver_closed = false;
    loop {
        if receiver_closed && active.is_empty() {
            return;
        }
        tokio::select! {
            _ = wait_for_resident_health_stop(&mut stop_rx) => return,
            status = active.next(), if !active.is_empty() => {
                if status.is_some_and(HealthCheckRoundStatus::is_cancelled) {
                    return;
                }
            }
            request = receiver.recv(), if !receiver_closed && active.len() < maximum_active_rounds => {
                let Some(request) = request else {
                    receiver_closed = true;
                    continue;
                };
                let Some(group) = proxy_groups.get(&request.outbound).cloned() else {
                    continue;
                };
                if !group.try_begin_resuscitation(request.network_type.into()) {
                    continue;
                }
                let stop = Arc::clone(&stop);
                let metrics = Arc::clone(&metrics);
                let candidate_admission = Arc::clone(&candidate_admission);
                let dns = Arc::clone(&dns);
                let owners = ResidentTransportOwnerRegistries::new(
                    hysteria2_owner_registry.clone(),
                    tuic_owner_registry.clone(),
                    juicity_owner_registry.clone(),
                )
                .with_anytls(anytls_owner_registry.clone());
                active.push(Box::pin(async move {
                    run_resident_health_round(
                        group,
                        stop,
                        metrics,
                        concurrency,
                        candidate_admission,
                        dns,
                        owners,
                    )
                    .await
                }));
            }
        }
    }
}

pub(super) async fn run_resident_health_stop_monitor(
    stop: SharedResidentStopSignal,
    stop_tx: watch::Sender<bool>,
) {
    while !stop.load(Ordering::Relaxed) {
        tokio::time::sleep(RESIDENT_HEALTH_STOP_MONITOR_INTERVAL).await;
    }
    let _ = stop_tx.send(true);
}

async fn run_resident_health_round(
    group: Arc<plan::ResidentProxyGroupPlan>,
    stop: SharedResidentStopSignal,
    metrics: Arc<ResidentDataplaneMetrics>,
    concurrency: usize,
    candidate_admission: Arc<tokio::sync::Semaphore>,
    dns: Arc<dns::ResidentDnsPlan>,
    owners: ResidentTransportOwnerRegistries,
) -> HealthCheckRoundStatus {
    if stop.load(Ordering::Relaxed) {
        return HealthCheckRoundStatus::Cancelled;
    }
    let guard = ResidentHealthRoundGuard::new(metrics);
    let status = run_resident_group_health_check_round_async(
        group,
        stop,
        concurrency.max(1),
        candidate_admission,
        dns,
        owners,
    )
    .await;
    guard.finish(status);
    status
}

async fn wait_for_resident_health_delay_or_stop(
    stop_rx: &mut watch::Receiver<bool>,
    duration: Duration,
) -> bool {
    if duration.is_zero() {
        return *stop_rx.borrow();
    }
    tokio::select! {
        _ = tokio::time::sleep(duration) => false,
        _ = wait_for_resident_health_stop(stop_rx) => true,
    }
}

async fn wait_for_resident_health_stop(stop_rx: &mut watch::Receiver<bool>) {
    while !*stop_rx.borrow_and_update() {
        if stop_rx.changed().await.is_err() {
            return;
        }
    }
}

pub(super) fn resident_health_initial_jitter(
    group_name: &str,
    candidate_count: usize,
    interval: Duration,
) -> Duration {
    if interval.is_zero() {
        return Duration::ZERO;
    }
    let interval_ms = duration_millis_i64(interval).max(0) as u64;
    let ceiling_ms = duration_millis_i64(RESIDENT_HEALTH_INITIAL_JITTER_CEILING).max(0) as u64;
    let window_ms = (interval_ms / 4).min(ceiling_ms);
    if window_ms == 0 {
        return Duration::ZERO;
    }
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    group_name.hash(&mut hasher);
    candidate_count.hash(&mut hasher);
    Duration::from_millis(hasher.finish() % (window_ms + 1))
}

fn duration_millis_i64(duration: Duration) -> i64 {
    duration.as_millis().min(i64::MAX as u128) as i64
}
