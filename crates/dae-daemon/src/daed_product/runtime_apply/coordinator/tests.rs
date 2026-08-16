use super::*;
use std::sync::mpsc;

#[test]
fn stop_epoch_supersedes_an_apply_that_was_already_waiting() {
    let coordinator = Arc::new(RuntimeApplyCoordinator::new());
    let first = coordinator
        .begin_apply(RuntimeApplyIntent::ApiReload)
        .unwrap();
    let (waiting_tx, waiting_rx) = mpsc::channel();
    let waiting_coordinator = Arc::clone(&coordinator);
    let waiting = thread::spawn(move || {
        waiting_tx.send(()).unwrap();
        match waiting_coordinator.begin_apply(RuntimeApplyIntent::LocalControlReload) {
            Ok(permit) => {
                permit.finish("succeeded");
                Ok(())
            }
            Err(err) => Err(err),
        }
    });
    waiting_rx.recv().unwrap();
    let stop_coordinator = Arc::clone(&coordinator);
    let stop = thread::spawn(move || {
        let permit = stop_coordinator.begin_stop()?;
        permit.finish("stopped");
        Ok::<(), String>(())
    });
    while coordinator.stop_epoch.load(Ordering::Acquire) == 0 {
        thread::yield_now();
    }
    first.finish("succeeded");

    let waiting_result = waiting.join().unwrap();
    assert_eq!(
        waiting_result.unwrap_err(),
        "runtime apply intent was superseded by stop"
    );
    stop.join().unwrap().unwrap();
    assert_eq!(coordinator.summary()["lastResult"], json!("stopped"));
}

#[test]
fn begin_apply_rejects_after_gate_wait_timeout() {
    let coordinator = Arc::new(RuntimeApplyCoordinator::with_gate_wait_timeout(
        Duration::from_millis(150),
    ));
    let first = coordinator
        .begin_apply(RuntimeApplyIntent::ApiReload)
        .unwrap();
    let started_at = Instant::now();
    let rejected = coordinator.begin_apply(RuntimeApplyIntent::LocalControlReload);
    let elapsed = started_at.elapsed();
    let message = match rejected {
        Err(message) => message,
        Ok(_) => panic!("begin_apply should be rejected while the gate is busy"),
    };
    assert!(
        message.contains("gate busy") && message.contains("intent rejected"),
        "unexpected rejection message: {message}"
    );
    assert!(
        elapsed >= Duration::from_millis(150),
        "rejection should only happen after the gate wait timeout, got {elapsed:?}"
    );
    // The stuck holder keeps the gate; once it finishes, later applies work.
    first.finish("succeeded");
    let later = coordinator
        .begin_apply(RuntimeApplyIntent::LocalControlReload)
        .unwrap();
    later.finish("succeeded");
    assert_eq!(coordinator.summary()["lastResult"], json!("succeeded"));
}
