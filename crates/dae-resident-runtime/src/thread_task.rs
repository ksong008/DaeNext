use std::sync::mpsc::{Receiver, sync_channel};
use std::thread::JoinHandle;

use crate::ResidentRuntimeTaskRole;

#[derive(Debug)]
pub struct ResidentRuntimeTask {
    pub name: &'static str,
    pub kind: &'static str,
    pub handle: Option<JoinHandle<()>>,
    pub completion: Option<Receiver<ResidentRuntimeTaskExit>>,
    pub role: ResidentRuntimeTaskRole,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResidentRuntimeTaskExit {
    Completed,
    Panicked,
}

pub fn registered_resident_runtime_task(
    name: &'static str,
    kind: &'static str,
    role: ResidentRuntimeTaskRole,
    handle: JoinHandle<()>,
) -> ResidentRuntimeTask {
    ResidentRuntimeTask {
        name,
        kind,
        handle: Some(handle),
        completion: None,
        role,
    }
}

pub fn spawn_resident_runtime_thread<F>(
    name: &'static str,
    kind: &'static str,
    role: ResidentRuntimeTaskRole,
    stack_bytes: Option<usize>,
    run: F,
) -> ResidentRuntimeTask
where
    F: FnOnce() + Send + 'static,
{
    let (completion_tx, completion_rx) = sync_channel(1);
    let mut builder = std::thread::Builder::new().name(name.to_owned());
    if let Some(stack_bytes) = stack_bytes {
        builder = builder.stack_size(stack_bytes);
    }
    let handle = builder
        .spawn(move || {
            let exit = std::panic::catch_unwind(std::panic::AssertUnwindSafe(run))
                .map_or(ResidentRuntimeTaskExit::Panicked, |_| {
                    ResidentRuntimeTaskExit::Completed
                });
            let _ = completion_tx.send(exit);
        })
        .unwrap_or_else(|error| panic!("spawn resident runtime thread {name}: {error}"));
    ResidentRuntimeTask {
        name,
        kind,
        handle: Some(handle),
        completion: Some(completion_rx),
        role,
    }
}
