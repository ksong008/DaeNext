use super::*;
use std::sync::mpsc;

fn completed_reload(coalesced: bool) -> AppliedRuntimeReload {
    AppliedRuntimeReload {
        applied: !coalesced,
        coalesced,
        runtime_report: json!({"status": "pass"}),
        materialized_report: json!({"status": "pass"}),
        allocator_reclaim: Value::Null,
        pending_process_transition: None,
    }
}

#[test]
fn identical_fingerprint_callers_observe_one_result() {
    let reconciler = RuntimeReconciler::new(RuntimeApplyCoordinator::new());
    let fingerprint = "same";
    let RuntimeReconcileAdmission::Lead(lead) = reconciler
        .begin(RuntimeApplyIntent::ApiReload)
        .admit(fingerprint)
        .unwrap()
    else {
        panic!("first request must lead its fingerprint flight");
    };
    let RuntimeReconcileAdmission::Follow(follower) = reconciler
        .begin(RuntimeApplyIntent::SubscriptionRefresh)
        .admit(fingerprint)
        .unwrap()
    else {
        panic!("second request must follow its fingerprint flight");
    };
    let waiter = thread::spawn(move || follower.wait());
    let owner_result = lead.finish(Ok(completed_reload(false))).unwrap();
    let follower_result = waiter.join().unwrap().unwrap();

    assert!(owner_result.applied);
    assert!(follower_result.applied);
    assert_eq!(reconciler.summary()["joinedCount"], json!(1));
    assert_eq!(reconciler.summary()["preparingCount"], json!(0));
}

#[test]
fn newer_desired_fingerprint_supersedes_prepare_before_commit() {
    let reconciler = RuntimeReconciler::new(RuntimeApplyCoordinator::new());
    let RuntimeReconcileAdmission::Lead(mut older) = reconciler
        .begin(RuntimeApplyIntent::ApiReload)
        .admit("older")
        .unwrap()
    else {
        panic!("older request must lead");
    };
    let RuntimeReconcileAdmission::Lead(mut newer) = reconciler
        .begin(RuntimeApplyIntent::LocalControlReload)
        .admit("newer")
        .unwrap()
    else {
        panic!("newer request must lead");
    };

    let error = older.checkpoint("compiled").unwrap_err();
    assert!(error.to_string().contains("newer desired state"));
    older.finish(Err(error)).unwrap_err();
    newer.checkpoint("compiled").unwrap();
    newer.finish(Ok(completed_reload(false))).unwrap();
    assert_eq!(reconciler.summary()["supersededCount"], json!(1));
}

#[test]
fn stop_cancels_prepare_but_waits_for_commit_boundary() {
    let reconciler = RuntimeReconciler::new(RuntimeApplyCoordinator::new());
    let RuntimeReconcileAdmission::Lead(mut preparing) = reconciler
        .begin(RuntimeApplyIntent::ApiReload)
        .admit("preparing")
        .unwrap()
    else {
        panic!("request must lead");
    };
    reconciler.cancel_preparation_for_stop();
    let error = preparing.checkpoint("preflight").unwrap_err();
    assert!(error.to_string().contains("superseded by stop"));
    preparing.finish(Err(error)).unwrap_err();

    let RuntimeReconcileAdmission::Lead(mut committing) = reconciler
        .begin(RuntimeApplyIntent::ApiReload)
        .admit("committing")
        .unwrap()
    else {
        panic!("request must lead");
    };
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
    assert!(finished_rx.recv_timeout(Duration::from_secs(1)).is_ok());
    committing.finish(Ok(completed_reload(false))).unwrap();
    stop.join().unwrap();
}
