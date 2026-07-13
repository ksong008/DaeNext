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
