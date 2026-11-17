use super::*;
use std::collections::HashMap;
use std::sync::Condvar;
use std::thread::{ThreadId, current};

#[derive(Debug, Default)]
struct SchedulerHooks {
    workers: Mutex<HashMap<ThreadId, bool>>,
    changed: Condvar,
}

impl ResidentAllocatorRuntimeHooks for SchedulerHooks {
    fn thread_start(&self) {
        self.workers.lock().unwrap().insert(current().id(), false);
    }

    fn thread_stop(&self) {
        self.workers.lock().unwrap().remove(&current().id());
        self.changed.notify_all();
    }

    fn thread_poll(&self) {
        *self
            .workers
            .lock()
            .unwrap()
            .get_mut(&current().id())
            .unwrap() = false;
    }

    fn thread_park(&self) {
        *self
            .workers
            .lock()
            .unwrap()
            .get_mut(&current().id())
            .unwrap() = true;
        self.changed.notify_all();
    }

    fn activate(&self, _handle: tokio::runtime::Handle) {}
    fn deactivate(&self) {}
}

impl SchedulerHooks {
    fn wait_for_parked_workers(&self, expected: usize) -> bool {
        let (workers, _) = self
            .changed
            .wait_timeout_while(
                self.workers.lock().unwrap(),
                Duration::from_secs(3),
                |workers| workers.len() != expected || !workers.values().all(|parked| *parked),
            )
            .unwrap();
        workers.len() == expected && workers.values().all(|parked| *parked)
    }
}

#[test]
fn resident_executor_forwards_park_and_unpark_through_the_allocator_adapter() {
    let hooks = Arc::new(SchedulerHooks::default());
    let mut executor = ResidentRuntimeExecutor::new(
        dae_resident_runtime::ResidentRuntimeExecutorConfig::new(4, 2 * 1024 * 1024),
        Arc::new(ResidentAllocatorRuntimeHooksAdapter {
            inner: hooks.clone(),
        }),
    )
    .unwrap();
    let initially_parked = hooks.wait_for_parked_workers(4);
    let resumed = Arc::clone(&hooks);
    let (tx, rx) = std::sync::mpsc::channel();
    executor.handle().spawn(async move {
        tx.send(resumed.workers.lock().unwrap()[&current().id()])
            .unwrap();
    });
    let running_parked_state = rx.recv_timeout(Duration::from_secs(3));
    let parked_again = hooks.wait_for_parked_workers(4);
    executor.shutdown(Duration::from_secs(1));

    assert!(
        initially_parked,
        "not all distinct workers received the park hook"
    );
    assert!(
        !running_parked_state.unwrap(),
        "unpark must invalidate the parked state before running tasks"
    );
    assert!(
        parked_again,
        "resumed workers did not receive the park hook again"
    );
    assert!(hooks.workers.lock().unwrap().is_empty());
}
