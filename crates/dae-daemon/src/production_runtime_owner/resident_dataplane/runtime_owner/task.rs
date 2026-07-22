use super::*;
#[cfg(test)]
use std::panic::{AssertUnwindSafe, catch_unwind};
#[cfg(test)]
use std::sync::mpsc;
use std::sync::mpsc::Receiver;

#[derive(Debug)]
pub(super) struct ResidentRuntimeTask {
    pub(super) name: &'static str,
    pub(super) kind: &'static str,
    pub(super) handle: Option<JoinHandle<()>>,
    pub(super) completion: Option<Receiver<ResidentRuntimeTaskExit>>,
    pub(super) role: ResidentRuntimeTaskRole,
}

pub(in crate::production_runtime_owner::resident_dataplane) struct ResidentAsyncRuntimeTask {
    pub(in crate::production_runtime_owner::resident_dataplane) name: &'static str,
    pub(in crate::production_runtime_owner::resident_dataplane) kind: &'static str,
    pub(in crate::production_runtime_owner::resident_dataplane) role: ResidentRuntimeTaskRole,
    pub(in crate::production_runtime_owner::resident_dataplane) handle: tokio::task::JoinHandle<()>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::production_runtime_owner::resident_dataplane) enum ResidentRuntimeTaskRole {
    Workload,
    Generation,
    Transport,
}

impl ResidentRuntimeTaskRole {
    pub(in crate::production_runtime_owner::resident_dataplane) const fn name(
        self,
    ) -> &'static str {
        match self {
            Self::Workload => "workload",
            Self::Generation => "generation",
            Self::Transport => "transport",
        }
    }
}

#[derive(Default)]
pub(in crate::production_runtime_owner::resident_dataplane) struct ResidentAsyncRuntimeShutdown {
    pub(in crate::production_runtime_owner::resident_dataplane) joined: usize,
    pub(in crate::production_runtime_owner::resident_dataplane) cancelled: usize,
    pub(in crate::production_runtime_owner::resident_dataplane) panicked: usize,
    pub(in crate::production_runtime_owner::resident_dataplane) timed_out: usize,
    pub(in crate::production_runtime_owner::resident_dataplane) results: Vec<Value>,
    pub(in crate::production_runtime_owner::resident_dataplane) pending:
        Vec<ResidentAsyncRuntimeTask>,
}

pub(in crate::production_runtime_owner::resident_dataplane) fn registered_resident_async_runtime_task(
    name: &'static str,
    kind: &'static str,
    role: ResidentRuntimeTaskRole,
    handle: tokio::task::JoinHandle<()>,
) -> ResidentAsyncRuntimeTask {
    ResidentAsyncRuntimeTask {
        name,
        kind,
        role,
        handle,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ResidentRuntimeTaskExit {
    #[cfg(test)]
    Completed,
    Panicked,
}

pub(super) fn registered_resident_runtime_task(
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

#[cfg(test)]
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
        role: ResidentRuntimeTaskRole::Workload,
    }
}
