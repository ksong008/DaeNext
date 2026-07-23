use super::*;
use std::sync::atomic::AtomicUsize;

#[derive(Debug)]
struct TestGeneration {
    id: u64,
    lifecycle: ResidentGenerationLifecycle,
    stop_requests: Arc<AtomicUsize>,
}

impl TestGeneration {
    fn new(id: u64) -> (Arc<Self>, Arc<AtomicUsize>) {
        let stop_requests = Arc::new(AtomicUsize::new(0));
        (
            Arc::new(Self {
                id,
                lifecycle: ResidentGenerationLifecycle::default(),
                stop_requests: Arc::clone(&stop_requests),
            }),
            stop_requests,
        )
    }
}

impl ResidentDrainableGeneration for TestGeneration {
    fn id(&self) -> u64 {
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

    fn request_stop(&self) {
        if self.lifecycle.request_stop() {
            self.stop_requests.fetch_add(1, Ordering::Relaxed);
        }
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
    assert!(!generation.lifecycle.admission_is_open());
    assert_eq!(drain.snapshot()["retired"], 1);
    assert_eq!(drain.snapshot()["forcedTotal"], 0);
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
    assert!(generation.lifecycle.stop_is_requested());
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

    drain.reactivate(generation.id).unwrap();
    drain.reap(now + Duration::from_secs(120));

    assert!(generation.lifecycle.admission_is_open());
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

    assert!(drain.prepare_publication_at(now).is_err());
    assert_eq!(stop_requests.load(Ordering::Relaxed), 1);
    assert!(drain.reactivate(generation.id).is_err());
    assert!(!generation.lifecycle.admission_is_open());
}

#[test]
fn capacity_rejection_stops_the_oldest_generation_first() {
    let drain = test_drain(Duration::from_secs(60), 2);
    let now = Instant::now();
    let (first, first_stop_requests) = TestGeneration::new(1);
    let (second, second_stop_requests) = TestGeneration::new(2);
    drain.retire_shared_at(first.clone(), now);
    drain.retire_shared_at(second.clone(), now + Duration::from_secs(1));

    assert!(
        drain
            .prepare_publication_at(now + Duration::from_secs(2))
            .is_err()
    );
    assert!(
        drain
            .prepare_publication_at(now + Duration::from_secs(3))
            .is_err()
    );

    assert_eq!(first_stop_requests.load(Ordering::Relaxed), 1);
    assert_eq!(second_stop_requests.load(Ordering::Relaxed), 0);
    let snapshot = drain.snapshot();
    assert_eq!(snapshot["retired"], 2);
    assert_eq!(snapshot["pressureForcedTotal"], 1);
    assert_eq!(snapshot["publicationRejectedTotal"], 2);
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
