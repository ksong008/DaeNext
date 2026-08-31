use super::*;
use dae_resident_core::ResidentGenerationLifecycle;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[derive(Debug)]
struct TestDrainControl {
    id: LogicalGenerationId,
    lifecycle: ResidentGenerationLifecycle,
    stop_requests: Arc<AtomicUsize>,
    flow_stop: AtomicBool,
    udp_stop: AtomicBool,
}

impl ResidentDrainControl for TestDrainControl {
    fn id(&self) -> LogicalGenerationId {
        self.id
    }

    fn close_admission(&self) {
        self.lifecycle.close_admission();
    }

    fn reopen_admission(&self) -> Result<(), String> {
        self.lifecycle.reopen_admission().map_err(str::to_owned)
    }

    fn stop_is_requested(&self) -> bool {
        self.lifecycle.stop_is_requested()
    }

    fn udp_stop_is_requested(&self) -> bool {
        self.udp_stop.load(Ordering::Acquire)
    }

    fn flow_stop_is_requested(&self) -> bool {
        self.flow_stop.load(Ordering::Acquire)
    }

    fn udp_router_is_retained(&self) -> bool {
        false
    }

    fn udp_dns_runtime_is_retained(&self) -> bool {
        false
    }

    fn request_force_stop(&self) {
        self.retire_workloads();
        self.flow_stop.store(true, Ordering::Release);
        self.udp_stop.store(true, Ordering::Release);
        self.lifecycle.stop();
    }
}

impl TestDrainControl {
    fn retire_workloads(&self) {
        if self.lifecycle.request_stop() {
            self.stop_requests.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[derive(Debug)]
struct TestGeneration {
    control: Arc<TestDrainControl>,
}

impl TestGeneration {
    fn new(id: u64) -> (Arc<Self>, Arc<AtomicUsize>) {
        let stop_requests = Arc::new(AtomicUsize::new(0));
        let lifecycle = ResidentGenerationLifecycle::default();
        lifecycle.activate().unwrap();
        (
            Arc::new(Self {
                control: Arc::new(TestDrainControl {
                    id: LogicalGenerationId::new(id),
                    lifecycle,
                    stop_requests: Arc::clone(&stop_requests),
                    flow_stop: AtomicBool::new(false),
                    udp_stop: AtomicBool::new(false),
                }),
            }),
            stop_requests,
        )
    }
}

impl ResidentDrainableGeneration for TestGeneration {
    fn drain_control(&self) -> Arc<dyn ResidentDrainControl> {
        self.control.clone()
    }

    fn retire_workloads(&self) {
        self.control.retire_workloads();
    }

    fn request_force_stop(&self) {
        self.control.request_force_stop();
    }
}

fn test_drain(maximum_age: Duration, maximum_retired: usize) -> ResidentGenerationDrain {
    ResidentGenerationDrain::new(ResidentGenerationDrainPolicy::for_test(
        maximum_age,
        maximum_retired,
    ))
}

#[test]
fn retired_generation_survives_the_old_cleanup_grace() {
    let drain = test_drain(Duration::from_secs(60), 2);
    let now = Instant::now();
    let (generation, stop_requests) = TestGeneration::new(1);
    drain.retire_shared_at(generation.clone(), now);

    drain.reap(now + Duration::from_secs(2));

    assert_eq!(stop_requests.load(Ordering::Relaxed), 0);
    assert!(!generation.control.lifecycle.admission_is_open());
    assert_eq!(drain.snapshot()["retired"], 1);
    assert_eq!(drain.snapshot()["forcedTotal"], 0);
}

#[test]
fn idle_drain_only_polls_while_retirements_exist() {
    let drain = test_drain(Duration::from_secs(60), 2);
    assert!(!drain.has_pending_retirements());
    let (generation, _) = TestGeneration::new(1);
    drain.retire_shared_at(generation, Instant::now());
    assert!(drain.has_pending_retirements());
    drain.stop_all();
    assert!(!drain.has_pending_retirements());
}

#[test]
fn final_owner_release_reaps_generation_naturally() {
    let drain = test_drain(Duration::from_secs(60), 2);
    let now = Instant::now();
    let (generation, stop_requests) = TestGeneration::new(1);
    drain.retire_shared_at(generation.clone(), now);
    drop(generation);

    drain.reap(now + Duration::from_secs(2));

    assert_eq!(stop_requests.load(Ordering::Relaxed), 1);
    let snapshot = drain.snapshot();
    assert_eq!(snapshot["retired"], 0);
    assert_eq!(snapshot["releasedTotal"], 1);
    assert_eq!(snapshot["naturalTotal"], 1);
    assert_eq!(snapshot["forcedTotal"], 0);
}

#[test]
fn maximum_age_requests_stop_without_losing_retirement_record() {
    let drain = test_drain(Duration::from_secs(10), 2);
    let now = Instant::now();
    let (generation, stop_requests) = TestGeneration::new(1);
    drain.retire_shared_at(generation.clone(), now);

    drain.reap(now + Duration::from_secs(11));

    assert_eq!(stop_requests.load(Ordering::Relaxed), 1);
    assert!(generation.control.lifecycle.stop_is_requested());
    let snapshot = drain.snapshot();
    assert_eq!(snapshot["retired"], 1);
    assert_eq!(snapshot["deadlineForcedTotal"], 1);
    assert_eq!(snapshot["forcedTotal"], 1);
}

#[test]
fn rollback_reactivation_removes_stale_retirement_record() {
    let drain = test_drain(Duration::from_secs(60), 2);
    let now = Instant::now();
    let (generation, stop_requests) = TestGeneration::new(7);
    drain.retire_shared_at(generation.clone(), now);

    drain.reactivate(generation.control.id).unwrap();
    drain.reap(now + Duration::from_secs(120));

    assert!(generation.control.lifecycle.admission_is_open());
    assert!(!generation.control.flow_stop.load(Ordering::Acquire));
    assert!(!generation.control.udp_stop.load(Ordering::Acquire));
    assert_eq!(stop_requests.load(Ordering::Relaxed), 0);
    let snapshot = drain.snapshot();
    assert_eq!(snapshot["retired"], 0);
    assert_eq!(snapshot["reactivatedTotal"], 1);
}

#[test]
fn stopped_generation_cannot_be_reactivated() {
    let drain = test_drain(Duration::from_secs(60), 1);
    let now = Instant::now();
    let (generation, stop_requests) = TestGeneration::new(3);
    drain.retire_shared_at(generation.clone(), now);

    assert!(drain.prepare_publication_at(now).is_ok());
    assert_eq!(stop_requests.load(Ordering::Relaxed), 1);
    assert!(drain.reactivate(generation.control.id).is_err());
    assert!(!generation.control.lifecycle.admission_is_open());
    assert_eq!(drain.snapshot()["retired"], 0);
}

#[test]
fn capacity_pressure_evicts_the_oldest_generation_and_keeps_publication_admitted() {
    let drain = test_drain(Duration::from_secs(60), 2);
    let now = Instant::now();
    let (first, first_stop_requests) = TestGeneration::new(1);
    let (second, second_stop_requests) = TestGeneration::new(2);
    drain.retire_shared_at(first.clone(), now);
    drain.retire_shared_at(second.clone(), now + Duration::from_secs(1));

    assert!(
        drain
            .prepare_publication_at(now + Duration::from_secs(2))
            .is_ok()
    );

    assert_eq!(first_stop_requests.load(Ordering::Relaxed), 1);
    assert_eq!(second_stop_requests.load(Ordering::Relaxed), 0);
    let snapshot = drain.snapshot();
    assert_eq!(snapshot["retired"], 1);
    assert_eq!(snapshot["pressureForcedTotal"], 1);
    assert_eq!(snapshot["pressureEvictedTotal"], 1);
    assert_eq!(snapshot["publicationRejectedTotal"], 0);
}

#[test]
fn direct_retire_calls_remain_bounded_without_prepare_publication() {
    let drain = test_drain(Duration::from_secs(60), 1);
    let now = Instant::now();
    let (first, first_stop_requests) = TestGeneration::new(1);
    let (second, second_stop_requests) = TestGeneration::new(2);

    drain.retire_shared_at(first, now);
    drain.retire_shared_at(second, now + Duration::from_secs(1));

    assert_eq!(first_stop_requests.load(Ordering::Relaxed), 1);
    assert_eq!(second_stop_requests.load(Ordering::Relaxed), 0);
    let snapshot = drain.snapshot();
    assert_eq!(snapshot["retired"], 1);
    assert_eq!(snapshot["maximumRetired"], 1);
    assert_eq!(snapshot["pressureEvictedTotal"], 1);
}

#[test]
fn committed_publication_keeps_owned_retired_generation_draining() {
    let drain = test_drain(Duration::from_secs(60), 2);
    let now = Instant::now();
    let (generation, stop_requests) = TestGeneration::new(1);
    drain.retire_shared_at(generation.clone(), now);

    drain.commit_retirements();

    assert_eq!(stop_requests.load(Ordering::Relaxed), 0);
    assert!(!generation.control.lifecycle.stop_is_requested());
    assert!(!generation.control.flow_stop.load(Ordering::Acquire));
    assert!(!generation.control.udp_stop.load(Ordering::Acquire));
    assert_eq!(drain.snapshot()["retired"], 1);
    assert_eq!(drain.snapshot()["finalizationForcedTotal"], 0);
}

#[test]
fn committed_publication_detaches_heavy_state_without_stopping_owned_flows() {
    let drain = test_drain(Duration::from_secs(60), 2);
    let now = Instant::now();
    let (generation, stop_requests) = TestGeneration::new(1);
    let flow_owner = Arc::clone(&generation.control);
    drain.retire_shared_at(generation.clone(), now);
    drop(generation);

    drain.commit_retirements();

    assert_eq!(stop_requests.load(Ordering::Relaxed), 1);
    assert!(!flow_owner.flow_stop.load(Ordering::Acquire));
    assert!(!flow_owner.udp_stop.load(Ordering::Acquire));
    let snapshot = drain.snapshot();
    assert_eq!(snapshot["retired"], 1);
    assert_eq!(snapshot["detachedTotal"], 1);
    assert_eq!(snapshot["releasedTotal"], 0);
    assert_eq!(snapshot["naturalTotal"], 0);
    assert_eq!(snapshot["finalizationForcedTotal"], 0);
}

#[test]
fn committed_publication_does_not_stop_the_active_generation() {
    let drain = test_drain(Duration::from_secs(60), 2);
    let now = Instant::now();
    let (retired, retired_stop_requests) = TestGeneration::new(1);
    let (active, active_stop_requests) = TestGeneration::new(2);
    drain.retire_shared_at(retired.clone(), now);

    drain.commit_retirements();

    assert_eq!(retired_stop_requests.load(Ordering::Relaxed), 0);
    assert!(!retired.control.flow_stop.load(Ordering::Acquire));
    assert!(!retired.control.udp_stop.load(Ordering::Acquire));
    assert_eq!(active_stop_requests.load(Ordering::Relaxed), 0);
    assert!(active.control.lifecycle.admission_is_open());
    assert!(!active.control.flow_stop.load(Ordering::Acquire));
    assert!(!active.control.udp_stop.load(Ordering::Acquire));
}

#[test]
fn process_shutdown_stops_every_retired_generation() {
    let drain = test_drain(Duration::from_secs(60), 2);
    let now = Instant::now();
    let (first, first_stop_requests) = TestGeneration::new(1);
    let (second, second_stop_requests) = TestGeneration::new(2);
    drain.retire_shared_at(first, now);
    drain.retire_shared_at(second, now);

    drain.stop_all();

    assert_eq!(first_stop_requests.load(Ordering::Relaxed), 1);
    assert_eq!(second_stop_requests.load(Ordering::Relaxed), 1);
    assert_eq!(drain.snapshot()["retired"], 0);
}

#[test]
fn lightweight_drain_owner_does_not_retain_heavy_generation() {
    let drain = test_drain(Duration::from_secs(60), 2);
    let now = Instant::now();
    let (generation, stop_requests) = TestGeneration::new(1);
    let drain_owner = Arc::clone(&generation.control);
    drain.retire_shared_at(generation.clone(), now);
    drop(generation);

    drain.reap(now + Duration::from_secs(1));

    assert_eq!(stop_requests.load(Ordering::Relaxed), 1);
    assert!(!drain_owner.udp_stop.load(Ordering::Acquire));
    let snapshot = drain.snapshot();
    assert_eq!(snapshot["retired"], 1);
    assert_eq!(snapshot["detachedTotal"], 1);
    assert_eq!(snapshot["releasedTotal"], 0);
    assert_eq!(
        snapshot["ownerEvidence"][0]["heavyGenerationRetained"],
        false
    );
    assert_eq!(snapshot["ownerEvidence"][0]["externalDrainOwners"], 1);
    assert_eq!(snapshot["ownerEvidence"][0]["udpStopRequested"], false);

    drop(drain_owner);
    drain.reap(now + Duration::from_secs(2));

    let snapshot = drain.snapshot();
    assert_eq!(snapshot["retired"], 0);
    assert_eq!(snapshot["releasedTotal"], 1);
    assert_eq!(snapshot["naturalTotal"], 1);
}

#[test]
fn detached_udp_owner_is_force_stopped_at_the_generation_deadline() {
    let drain = test_drain(Duration::from_secs(10), 2);
    let now = Instant::now();
    let (generation, stop_requests) = TestGeneration::new(1);
    let drain_owner = Arc::clone(&generation.control);
    drain.retire_shared_at(generation.clone(), now);
    drop(generation);

    drain.reap(now + Duration::from_secs(1));
    assert_eq!(stop_requests.load(Ordering::Relaxed), 1);
    assert!(!drain_owner.udp_stop.load(Ordering::Acquire));

    drain.reap(now + Duration::from_secs(11));
    assert!(drain_owner.udp_stop.load(Ordering::Acquire));
    let snapshot = drain.snapshot();
    assert_eq!(snapshot["retired"], 1);
    assert_eq!(snapshot["deadlineForcedTotal"], 1);
    assert_eq!(snapshot["ownerEvidence"][0]["udpStopRequested"], true);

    drop(drain_owner);
    drain.reap(now + Duration::from_secs(12));
    assert_eq!(drain.snapshot()["retired"], 0);
}
