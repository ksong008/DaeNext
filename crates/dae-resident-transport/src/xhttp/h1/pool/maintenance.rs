use crate::owner_cleanup::cleanup_lock;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, Weak};

pub(super) trait IdlePool: Send + Sync {
    fn sweep(&self, now: tokio::time::Instant);
}

#[derive(Default)]
struct State {
    pools: HashMap<usize, Weak<dyn IdlePool>>,
    task: Option<tokio::task::AbortHandle>,
}

#[derive(Default)]
struct Maintenance {
    state: Mutex<State>,
}

// One tracked timer per executor, with only weak pool entries. No task/thread
// per pool and no runtime kept alive. Empty registries stop immediately, and a
// registration serialized with task exit starts maintenance again if needed.
static EXECUTORS: OnceLock<Mutex<HashMap<tokio::runtime::Id, Weak<Maintenance>>>> = OnceLock::new();

pub(super) struct Registration {
    owner: Arc<Maintenance>,
    id: usize,
    runtime_id: tokio::runtime::Id,
}

impl Registration {
    pub(super) fn is_running_on(&self, runtime: &tokio::runtime::Handle) -> bool {
        self.runtime_id == runtime.id()
            && cleanup_lock(&self.owner.state)
                .task
                .as_ref()
                .is_some_and(|task| !task.is_finished())
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        let mut state = cleanup_lock(&self.owner.state);
        state.pools.remove(&self.id);
        if state.pools.is_empty()
            && let Some(task) = state.task.take()
        {
            task.abort();
        }
    }
}

pub(super) fn register(pool: Arc<dyn IdlePool>) -> Registration {
    let runtime = tokio::runtime::Handle::current();
    let owner = {
        let mut executors = cleanup_lock(EXECUTORS.get_or_init(Mutex::default));
        executors.retain(|_, owner| owner.strong_count() != 0);
        executors
            .entry(runtime.id())
            .or_default()
            .upgrade()
            .unwrap_or_else(|| {
                let owner = Arc::new(Maintenance::default());
                executors.insert(runtime.id(), Arc::downgrade(&owner));
                owner
            })
    };
    let id = Arc::as_ptr(&pool) as *const () as usize;
    {
        let mut state = cleanup_lock(&owner.state);
        state.pools.insert(id, Arc::downgrade(&pool));
        if state.task.is_none() {
            let task_owner = Arc::clone(&owner);
            let task = runtime.spawn(async move {
                // Reuse the transport idle-maintenance cadence, capped at half
                // the H1 TTL. Idle storage is released within TTL + 15 seconds
                // while the executor is scheduled; borrowed clients are absent.
                let interval = dae_resident_core::MeekTransportResourceProfile::selected()
                    .idle_janitor_interval()
                    .min(super::IDLE_TTL / 2);
                let mut ticks = tokio::time::interval(interval);
                ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    ticks.tick().await;
                    let pools = {
                        let mut state = cleanup_lock(&task_owner.state);
                        state.pools.retain(|_, pool| pool.strong_count() != 0);
                        if state.pools.is_empty() {
                            state.task = None;
                            return;
                        }
                        state
                            .pools
                            .values()
                            .filter_map(Weak::upgrade)
                            .collect::<Vec<_>>()
                    };
                    let now = tokio::time::Instant::now();
                    for pool in pools {
                        pool.sweep(now);
                    }
                }
            });
            state.task = Some(task.abort_handle());
        }
    }
    Registration {
        owner,
        id,
        runtime_id: runtime.id(),
    }
}
