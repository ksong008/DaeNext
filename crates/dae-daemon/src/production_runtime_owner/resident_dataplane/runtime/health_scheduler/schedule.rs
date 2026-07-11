use super::*;
use std::hash::{Hash, Hasher};
use tokio::sync::{mpsc::Receiver, watch};

pub(super) const RESIDENT_HEALTH_INITIAL_JITTER_CEILING: Duration = Duration::from_secs(5);
const RESIDENT_HEALTH_STOP_MONITOR_INTERVAL: Duration = Duration::from_millis(50);

#[derive(Clone, Copy, Debug)]
pub(in crate::production_runtime_owner::resident_dataplane) struct ResidentHealthResuscitationRequest
{
    pub(super) outbound: u8,
    pub(super) network_type: NetworkType,
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
    stop: Arc<AtomicBool>,
    mut stop_rx: watch::Receiver<bool>,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    metrics: Arc<ResidentDataplaneMetrics>,
    concurrency: usize,
) {
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
            "tcp_check_target": group.tcp_check.target.clone(),
            "udp_check_target": group.udp_check.target.authority().to_owned(),
            "scheduler": "shared-resident-health-runtime",
        }),
    );
    if wait_for_resident_health_delay_or_stop(&mut stop_rx, initial_jitter).await {
        return;
    }
    loop {
        let status = run_resident_health_round(
            Arc::clone(&group),
            Arc::clone(&stop),
            Arc::clone(&metrics),
            concurrency,
        )
        .await;
        if status.is_cancelled() || interval.is_zero() {
            return;
        }
        if wait_for_resident_health_delay_or_stop(&mut stop_rx, interval).await {
            return;
        }
    }
}

pub(super) async fn run_resident_health_resuscitation_dispatcher(
    proxy_groups: SharedResidentProxyGroupMap,
    mut receiver: Receiver<ResidentHealthResuscitationRequest>,
    stop: Arc<AtomicBool>,
    mut stop_rx: watch::Receiver<bool>,
    metrics: Arc<ResidentDataplaneMetrics>,
    concurrency: usize,
) {
    loop {
        let request = tokio::select! {
            _ = wait_for_resident_health_stop(&mut stop_rx) => return,
            request = receiver.recv() => match request {
                Some(request) => request,
                None => return,
            },
        };
        if !request.network_type.is_data_udp() {
            continue;
        }
        let Some(group) = proxy_groups.get(&request.outbound).cloned() else {
            continue;
        };
        if !group.try_begin_resuscitation() {
            continue;
        }
        if run_resident_health_round(group, Arc::clone(&stop), Arc::clone(&metrics), concurrency)
            .await
            .is_cancelled()
        {
            return;
        }
    }
}

pub(super) async fn run_resident_health_stop_monitor(
    stop: Arc<AtomicBool>,
    stop_tx: watch::Sender<bool>,
) {
    while !stop.load(Ordering::Relaxed) {
        tokio::time::sleep(RESIDENT_HEALTH_STOP_MONITOR_INTERVAL).await;
    }
    let _ = stop_tx.send(true);
}

async fn run_resident_health_round(
    group: Arc<plan::ResidentProxyGroupPlan>,
    stop: Arc<AtomicBool>,
    metrics: Arc<ResidentDataplaneMetrics>,
    concurrency: usize,
) -> HealthCheckRoundStatus {
    if stop.load(Ordering::Relaxed) {
        return HealthCheckRoundStatus::Cancelled;
    }
    let guard = ResidentHealthRoundGuard::new(metrics);
    let status = run_resident_group_health_check_round_async(group, stop, concurrency.max(1)).await;
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
