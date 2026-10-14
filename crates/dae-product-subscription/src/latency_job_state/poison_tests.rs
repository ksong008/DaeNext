use super::*;

#[test]
fn poisoned_job_retains_cancel_token_identity_and_terminal_accounting() {
    let jobs = LatencyJobManager::default();
    let (job, _) = jobs.start_or_current(3).unwrap();
    let cancellation = job.cancellation();
    jobs.mark_running(job.id());
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = jobs.current.lock().unwrap();
        panic!("injected job poison");
    }));
    assert_eq!(jobs.current_value()["id"], job.id());
    assert_eq!(jobs.current_value()["lockPoisoned"], true);
    assert!(jobs.start_or_current(1).is_err());
    assert!(matches!(
        jobs.request_cancel(job.id() + 1),
        Err(LatencyJobCancelError::JobIdMismatch { .. })
    ));
    assert!(!cancellation.is_requested());
    assert_eq!(
        jobs.request_cancel(job.id()).unwrap().to_value()["status"],
        "cancelling"
    );
    assert!(cancellation.is_requested());
    jobs.mark_progress(job.id(), 2, 1, 1);
    assert_eq!(jobs.current_value()["status"], "cancelling");
    jobs.mark_cancelled(job.id(), 2, 1, 1);
    let value = jobs.current_value();
    assert_eq!(value["status"], "cancelled");
    assert_eq!(value["completed"], 2);
    jobs.mark_failed(job.id() + 1, "stale".to_owned());
    assert_eq!(jobs.current_value(), value);
    assert!(jobs.current.is_poisoned());
}
