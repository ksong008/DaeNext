use serde_json::Value;

pub struct ResidentAsyncRuntimeTask {
    pub name: &'static str,
    pub kind: &'static str,
    pub role: ResidentRuntimeTaskRole,
    pub handle: tokio::task::JoinHandle<()>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResidentRuntimeTaskRole {
    Workload,
    Generation,
    Transport,
}

impl ResidentRuntimeTaskRole {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Workload => "workload",
            Self::Generation => "generation",
            Self::Transport => "transport",
        }
    }
}

#[derive(Default)]
pub struct ResidentAsyncRuntimeShutdown {
    pub joined: usize,
    pub cancelled: usize,
    pub panicked: usize,
    pub timed_out: usize,
    pub results: Vec<Value>,
    pub pending: Vec<ResidentAsyncRuntimeTask>,
}

pub fn registered_resident_async_runtime_task(
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
