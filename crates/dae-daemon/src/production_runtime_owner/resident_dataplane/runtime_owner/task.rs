use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::mpsc::{self, Receiver};

#[derive(Debug)]
pub(super) struct ResidentRuntimeTask {
    pub(super) name: &'static str,
    pub(super) kind: &'static str,
    pub(super) handle: Option<JoinHandle<()>>,
    pub(super) completion: Option<Receiver<ResidentRuntimeTaskExit>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ResidentRuntimeTaskExit {
    Completed,
    Panicked,
}

pub(super) fn registered_resident_runtime_task(
    name: &'static str,
    kind: &'static str,
    handle: JoinHandle<()>,
) -> ResidentRuntimeTask {
    ResidentRuntimeTask {
        name,
        kind,
        handle: Some(handle),
        completion: None,
    }
}

pub(super) fn spawn_resident_runtime_task<F>(
    name: &'static str,
    kind: &'static str,
    stack_bytes: Option<usize>,
    run: F,
) -> ResidentRuntimeTask
where
    F: FnOnce() + Send + 'static,
{
    let (completion_tx, completion_rx) = mpsc::sync_channel(1);
    let mut builder = thread::Builder::new().name(name.to_owned());
    if let Some(stack_bytes) = stack_bytes {
        builder = builder.stack_size(stack_bytes);
    }
    let handle = builder
        .spawn(move || {
            let exit = match catch_unwind(AssertUnwindSafe(run)) {
                Ok(()) => ResidentRuntimeTaskExit::Completed,
                Err(_) => ResidentRuntimeTaskExit::Panicked,
            };
            let _ = completion_tx.send(exit);
        })
        .unwrap_or_else(|err| panic!("spawn resident runtime thread {name}: {err}"));
    ResidentRuntimeTask {
        name,
        kind,
        handle: Some(handle),
        completion: Some(completion_rx),
    }
}
