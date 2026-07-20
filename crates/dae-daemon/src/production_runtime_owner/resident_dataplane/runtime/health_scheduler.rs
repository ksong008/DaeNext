use super::plan::SharedResidentProxyGroupMap;
use super::*;
use tokio::sync::{
    Semaphore,
    mpsc::{self, Receiver, Sender, error::TrySendError},
    watch,
};
use tokio::task::JoinSet;

#[path = "health_scheduler/executor.rs"]
mod executor;
pub(in crate::production_runtime_owner::resident_dataplane) use self::executor::ResidentHealthRuntimeConfig;
#[cfg(test)]
use self::executor::build_resident_health_runtime;
use self::executor::resident_health_runtime_contract;
#[path = "health_scheduler/schedule.rs"]
mod schedule;
use self::schedule::*;

pub(crate) const RESIDENT_HEALTH_RESUSCITATION_QUEUE_DEPTH: usize = 64;

pub(in crate::production_runtime_owner::resident_dataplane) fn resident_health_scheduler_contract()
-> Value {
    json!({
        "runtime": resident_health_runtime_contract(),
        "runtimeInstances": "one when at least one materialized group needs alive-state checks",
        "resuscitationQueueDepth": RESIDENT_HEALTH_RESUSCITATION_QUEUE_DEPTH,
        "stopSignal": "one atomic monitor with watch broadcast; no per-group idle polling timer",
        "selectorState": "shared Arc<ResidentProxyGroupPlan>",
    })
}

#[derive(Clone, Debug)]
pub(in crate::production_runtime_owner::resident_dataplane) struct ResidentHealthResuscitationHandle
{
    sender: Sender<ResidentHealthResuscitationRequest>,
    metrics: Arc<ResidentDataplaneMetrics>,
}

impl ResidentHealthResuscitationHandle {
    pub(in crate::production_runtime_owner::resident_dataplane) fn trigger(
        &self,
        outbound: u8,
        network_type: NetworkType,
    ) {
        let request = ResidentHealthResuscitationRequest {
            outbound,
            network_type,
        };
        match self.sender.try_send(request) {
            Ok(()) => self.metrics.health_resuscitation_queued(),
            Err(TrySendError::Full(_)) => self.metrics.health_resuscitation_queue_full(),
            Err(TrySendError::Closed(_)) => self.metrics.health_resuscitation_disconnected(),
        }
    }
}

pub(in crate::production_runtime_owner::resident_dataplane) fn resident_health_resuscitation_channel(
    metrics: Arc<ResidentDataplaneMetrics>,
) -> (
    ResidentHealthResuscitationHandle,
    Receiver<ResidentHealthResuscitationRequest>,
) {
    resident_health_resuscitation_channel_with_depth(
        RESIDENT_HEALTH_RESUSCITATION_QUEUE_DEPTH,
        metrics,
    )
}

fn resident_health_resuscitation_channel_with_depth(
    queue_depth: usize,
    metrics: Arc<ResidentDataplaneMetrics>,
) -> (
    ResidentHealthResuscitationHandle,
    Receiver<ResidentHealthResuscitationRequest>,
) {
    let (sender, receiver) = mpsc::channel(queue_depth.max(1));
    (
        ResidentHealthResuscitationHandle { sender, metrics },
        receiver,
    )
}

pub(in crate::production_runtime_owner::resident_dataplane) fn resident_health_scheduler_value(
    group_count: usize,
    per_group_candidate_concurrency: usize,
    bootstrap_candidate_concurrency: usize,
    runtime_config: ResidentHealthRuntimeConfig,
) -> Value {
    json!({
        "schemaVersion": 1,
        "runtime": runtime_config.json(),
        "runtimeInstances": if group_count > 0 { 1 } else { 0 },
        "osThreadCount": if group_count > 0 { runtime_config.os_thread_count() } else { 0 },
        "maximumOsThreadCount": if group_count > 0 {
            runtime_config.maximum_os_thread_count()
        } else {
            0
        },
        "scheduledGroupCount": group_count,
        "scheduledTasks": group_count,
        "perGroupCandidateConcurrency": per_group_candidate_concurrency.max(1),
        "bootstrapCandidateConcurrency": bootstrap_candidate_concurrency.max(1),
        "globalCandidateAdmission": bootstrap_candidate_concurrency
            .max(per_group_candidate_concurrency)
            .max(1),
        "resuscitationQueueDepth": RESIDENT_HEALTH_RESUSCITATION_QUEUE_DEPTH,
        "roundAdmission": "one static schedule task per materialized group; one sequential bounded resuscitation consumer",
        "stopSignal": "one atomic monitor with watch broadcast; no per-group idle polling timer",
        "selectorState": "shared Arc<ResidentProxyGroupPlan>",
    })
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub(in crate::production_runtime_owner::resident_dataplane) fn resident_health_scheduler_loop(
    groups: Vec<Arc<plan::ResidentProxyGroupPlan>>,
    proxy_groups: SharedResidentProxyGroupMap,
    resuscitation_rx: Receiver<ResidentHealthResuscitationRequest>,
    stop: SharedResidentStopSignal,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    metrics: Arc<ResidentDataplaneMetrics>,
    dns: Arc<dns::ResidentDnsPlan>,
    per_group_candidate_concurrency: usize,
    bootstrap_candidate_concurrency: usize,
    runtime_config: ResidentHealthRuntimeConfig,
    hysteria2_owner_registry: Option<Hysteria2OwnerRegistryHandle>,
    tuic_owner_registry: Option<TuicOwnerRegistryHandle>,
    juicity_owner_registry: Option<JuicityOwnerRegistryHandle>,
    anytls_owner_registry: Option<AnyTlsOwnerRegistryHandle>,
) {
    let runtime = match build_resident_health_runtime(runtime_config) {
        Ok(runtime) => runtime,
        Err(err) => {
            append_event(
                &event_file,
                &event_lock,
                json!({"event": "resident_health_scheduler_runtime_failed", "error": err}),
            );
            return;
        }
    };
    runtime.block_on(resident_health_scheduler_async(
        groups,
        proxy_groups,
        resuscitation_rx,
        stop,
        event_file,
        event_lock,
        metrics,
        dns,
        per_group_candidate_concurrency,
        bootstrap_candidate_concurrency,
        runtime_config,
        None,
        hysteria2_owner_registry,
        tuic_owner_registry,
        juicity_owner_registry,
        anytls_owner_registry,
    ));
}

#[allow(clippy::too_many_arguments)]
pub(in crate::production_runtime_owner::resident_dataplane) async fn resident_health_scheduler_async(
    groups: Vec<Arc<plan::ResidentProxyGroupPlan>>,
    proxy_groups: SharedResidentProxyGroupMap,
    resuscitation_rx: Receiver<ResidentHealthResuscitationRequest>,
    stop: SharedResidentStopSignal,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    metrics: Arc<ResidentDataplaneMetrics>,
    dns: Arc<dns::ResidentDnsPlan>,
    per_group_candidate_concurrency: usize,
    bootstrap_candidate_concurrency: usize,
    runtime_config: ResidentHealthRuntimeConfig,
    shared_worker_threads: Option<usize>,
    hysteria2_owner_registry: Option<Hysteria2OwnerRegistryHandle>,
    tuic_owner_registry: Option<TuicOwnerRegistryHandle>,
    juicity_owner_registry: Option<JuicityOwnerRegistryHandle>,
    anytls_owner_registry: Option<AnyTlsOwnerRegistryHandle>,
) {
    let per_group_candidate_concurrency = per_group_candidate_concurrency.max(1);
    let bootstrap_candidate_concurrency = bootstrap_candidate_concurrency.max(1);
    let needs_resuscitation_runtime = groups.iter().any(|group| group.needs_background_checks());
    let global_candidate_admission = Arc::new(Semaphore::new(
        bootstrap_candidate_concurrency.max(per_group_candidate_concurrency),
    ));
    let mut runtime_report = resident_health_scheduler_value(
        groups.len(),
        per_group_candidate_concurrency,
        bootstrap_candidate_concurrency,
        runtime_config,
    );
    if let Some(worker_threads) = shared_worker_threads {
        runtime_report["osThreadCount"] = json!(0);
        runtime_report["maximumOsThreadCount"] = json!(0);
        runtime_report["sharedDataPlaneWorkerThreads"] = json!(worker_threads);
        runtime_report["runtime"]["executor"] = json!("generation-owned-shared-multi-thread");
    }
    append_event(
        &event_file,
        &event_lock,
        json!({
            "event": "resident_health_scheduler_started",
            "runtime": runtime_report,
        }),
    );
    let mut tasks = JoinSet::new();
    let (stop_tx, stop_rx) = watch::channel(stop.load(Ordering::Relaxed));
    if needs_resuscitation_runtime {
        tasks.spawn(run_resident_health_stop_monitor(Arc::clone(&stop), stop_tx));
    }
    for group in groups {
        tasks.spawn(run_resident_health_group_schedule(
            group,
            stop_rx.clone(),
            ResidentHealthScheduleContext {
                stop: Arc::clone(&stop),
                event_file: event_file.clone(),
                event_lock: Arc::clone(&event_lock),
                metrics: Arc::clone(&metrics),
                dns: Arc::clone(&dns),
                periodic_candidate_concurrency: per_group_candidate_concurrency,
                bootstrap_candidate_concurrency,
                candidate_admission: Arc::clone(&global_candidate_admission),
                hysteria2_owner_registry: hysteria2_owner_registry.clone(),
                tuic_owner_registry: tuic_owner_registry.clone(),
                juicity_owner_registry: juicity_owner_registry.clone(),
                anytls_owner_registry: anytls_owner_registry.clone(),
            },
        ));
    }
    if needs_resuscitation_runtime {
        tasks.spawn(run_resident_health_resuscitation_dispatcher(
            proxy_groups,
            resuscitation_rx,
            Arc::clone(&stop),
            stop_rx,
            Arc::clone(&metrics),
            Arc::clone(&dns),
            per_group_candidate_concurrency,
            Arc::clone(&global_candidate_admission),
            hysteria2_owner_registry.clone(),
            tuic_owner_registry.clone(),
            juicity_owner_registry.clone(),
            anytls_owner_registry.clone(),
        ));
    }
    while let Some(result) = tasks.join_next().await {
        if let Err(err) = result {
            append_event(
                &event_file,
                &event_lock,
                json!({"event": "resident_health_scheduler_task_failed", "error": err.to_string()}),
            );
        }
    }
    append_event(
        &event_file,
        &event_lock,
        json!({"event": "resident_health_scheduler_stopped"}),
    );
}

#[cfg(test)]
#[path = "health_scheduler/tests.rs"]
mod tests;
