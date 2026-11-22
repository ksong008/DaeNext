use super::*;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

fn lead(
    reconciler: &ProductRuntimeReconciler<u64, String>,
    fingerprint: &str,
) -> ProductRuntimeReconcileLead<u64, String> {
    match reconciler
        .begin(RuntimeApplyIntent::ApiReload)
        .admit(fingerprint)
        .unwrap()
    {
        ProductRuntimeReconcileAdmission::Lead(lead) => lead,
        ProductRuntimeReconcileAdmission::Follow(_) => panic!("request must lead"),
    }
}

#[test]
fn every_follower_observes_the_shared_result() {
    let reconciler = ProductRuntimeReconciler::new(RuntimeApplyCoordinator::new());
    let lead = lead(&reconciler, "same");
    let ProductRuntimeReconcileAdmission::Follow(first) = reconciler
        .begin(RuntimeApplyIntent::SubscriptionRefresh)
        .admit("same")
        .unwrap()
    else {
        panic!("first follower must join the flight");
    };
    let ProductRuntimeReconcileAdmission::Follow(second) = reconciler
        .begin(RuntimeApplyIntent::LocalControlReload)
        .admit("same")
        .unwrap()
    else {
        panic!("second follower must join the flight");
    };

    lead.finish(Ok(42)).unwrap();
    assert_eq!(first.wait().unwrap(), 42);
    assert_eq!(second.wait().unwrap(), 42);
}

#[test]
fn abandoned_lead_wakes_followers_with_an_error() {
    let reconciler = ProductRuntimeReconciler::new(RuntimeApplyCoordinator::new());
    let lead = lead(&reconciler, "abandoned");
    let ProductRuntimeReconcileAdmission::Follow(follower) = reconciler
        .begin(RuntimeApplyIntent::SubscriptionRefresh)
        .admit("abandoned")
        .unwrap()
    else {
        panic!("follower must join the flight");
    };
    let (started, ready) = mpsc::channel();
    let waiter = thread::spawn(move || {
        started.send(()).unwrap();
        follower.wait()
    });
    ready.recv().unwrap();
    drop(lead);
    let error = waiter
        .join()
        .unwrap()
        .expect_err("abandoned lead must not leave a follower blocked");
    assert!(error.contains("owner was abandoned"));
}

#[test]
fn newer_desired_state_supersedes_an_older_lead() {
    let reconciler = ProductRuntimeReconciler::new(RuntimeApplyCoordinator::new());
    let mut older = lead(&reconciler, "older");
    let mut newer = lead(&reconciler, "newer");

    let error = older.checkpoint("compiled").unwrap_err();
    assert!(error.contains("newer desired state"));
    older.finish(Err(error)).unwrap_err();
    newer.checkpoint("compiled").unwrap();
    newer.finish(Ok(7)).unwrap();
    assert_eq!(
        reconciler.summary()["supersededCount"],
        serde_json::json!(1)
    );
}

#[test]
fn late_snapshot_cannot_supersede_an_admitted_newer_request() {
    let reconciler = ProductRuntimeReconciler::new(RuntimeApplyCoordinator::new());
    let old = reconciler.begin(RuntimeApplyIntent::ApiReload);
    let mut new = lead(&reconciler, "new");

    let Err(error) = old.admit("old") else {
        panic!("old snapshot must be rejected");
    };
    assert!(error.contains("newer desired state"));
    new.begin_commit().unwrap().finish("succeeded");
    assert_eq!(new.finish(Ok(42)).unwrap(), 42);
}

#[test]
fn reverting_desired_state_cannot_join_the_superseded_flight() {
    let reconciler = ProductRuntimeReconciler::new(RuntimeApplyCoordinator::new());
    let mut first = lead(&reconciler, "a");
    let mut second = lead(&reconciler, "b");
    let mut reverted = lead(&reconciler, "a");

    assert!(first.checkpoint("prepared").is_err());
    assert!(second.checkpoint("prepared").is_err());
    reverted.begin_commit().unwrap().finish("succeeded");
    assert_eq!(reverted.finish(Ok(1)).unwrap(), 1);
}

#[test]
fn completed_stop_invalidates_snapshots_started_before_and_during_stop() {
    let reconciler: ProductRuntimeReconciler<u64, String> =
        ProductRuntimeReconciler::new(RuntimeApplyCoordinator::new());
    let before = reconciler.begin(RuntimeApplyIntent::ApiReload);
    let stop = reconciler.begin_stop().unwrap();
    let during = reconciler.begin(RuntimeApplyIntent::ApiReload);
    stop.finish("succeeded");

    for request in [before, during] {
        let Err(error) = request.admit("stale") else {
            panic!("stale snapshot must be rejected");
        };
        assert!(error.contains("superseded by stop"));
    }
    let mut next = lead(&reconciler, "after");
    next.begin_commit().unwrap().finish("succeeded");
}

#[test]
fn stop_supersedes_preparation_but_waits_for_commit_gate() {
    let reconciler = ProductRuntimeReconciler::new(RuntimeApplyCoordinator::new());
    let mut preparing = lead(&reconciler, "preparing");
    reconciler.cancel_preparation_for_stop();
    let error = preparing.checkpoint("preflight").unwrap_err();
    assert!(error.contains("superseded by stop"));
    preparing.finish(Err(error)).unwrap_err();

    let mut committing = lead(&reconciler, "committing");
    let commit = committing.begin_commit().unwrap();
    let (started_tx, started_rx) = mpsc::channel();
    let (finished_tx, finished_rx) = mpsc::channel();
    let stop_reconciler = reconciler.clone();
    let stop = thread::spawn(move || {
        stop_reconciler.cancel_preparation_for_stop();
        started_tx.send(()).unwrap();
        let permit = stop_reconciler.begin_stop().unwrap();
        permit.finish("stopped");
        finished_tx.send(()).unwrap();
    });
    started_rx.recv().unwrap();
    assert!(finished_rx.recv_timeout(Duration::from_millis(30)).is_err());
    commit.finish("succeeded");
    finished_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    committing.finish(Ok(8)).unwrap();
    stop.join().unwrap();
}
