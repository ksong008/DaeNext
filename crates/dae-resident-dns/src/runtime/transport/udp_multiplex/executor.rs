use std::sync::Arc;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use super::{
    ResidentDnsUdpActorRegistration, ResidentDnsUdpMultiplexHandle, open_connected_dns_udp_socket,
    start_udp_multiplex_actor,
};
use crate::ResidentDnsUdpRuntimeConfig;
use dae_resident_core::ResidentDataplaneMetrics;

mod lifecycle;
mod pool;

use self::lifecycle::{ResidentDnsUdpActorTask, join_dns_udp_actor_tasks};
use self::pool::ResidentDnsUdpActorPool;

pub struct ResidentDnsUdpActorExecutor {
    runtime_config: ResidentDnsUdpRuntimeConfig,
    metrics: Arc<ResidentDataplaneMetrics>,
    shared_runtime: Option<tokio::runtime::Handle>,
    pool: tokio::sync::Mutex<Option<Arc<ResidentDnsUdpActorPool>>>,
    actors: std::sync::Mutex<Vec<ResidentDnsUdpActorTask>>,
    closing: std::sync::atomic::AtomicBool,
}

struct ResidentDnsOwnedTask<T> {
    task: tokio::task::JoinHandle<T>,
}

impl<T> Future for ResidentDnsOwnedTask<T> {
    type Output = Result<T, tokio::task::JoinError>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.task).poll(context)
    }
}

impl<T> Drop for ResidentDnsOwnedTask<T> {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Default for ResidentDnsUdpActorExecutor {
    fn default() -> Self {
        Self::new(
            ResidentDnsUdpRuntimeConfig::standalone(),
            Arc::new(ResidentDataplaneMetrics::default()),
        )
    }
}

impl ResidentDnsUdpActorExecutor {
    pub fn new(
        runtime_config: ResidentDnsUdpRuntimeConfig,
        metrics: Arc<ResidentDataplaneMetrics>,
    ) -> Self {
        Self {
            runtime_config,
            metrics,
            shared_runtime: None,
            pool: tokio::sync::Mutex::new(None),
            actors: std::sync::Mutex::new(Vec::new()),
            closing: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub fn new_on(
        runtime_config: ResidentDnsUdpRuntimeConfig,
        metrics: Arc<ResidentDataplaneMetrics>,
        runtime: tokio::runtime::Handle,
    ) -> Self {
        Self {
            runtime_config,
            metrics,
            shared_runtime: Some(runtime),
            pool: tokio::sync::Mutex::new(None),
            actors: std::sync::Mutex::new(Vec::new()),
            closing: std::sync::atomic::AtomicBool::new(false),
        }
    }

    #[cfg(all(test, feature = "dns-runtime-tests"))]
    pub async fn open_handle(
        &self,
        target: std::net::SocketAddr,
        mark: u32,
    ) -> Result<ResidentDnsUdpMultiplexHandle, String> {
        self.open_handle_with_config(target, mark, self.runtime_config.clone())
            .await
    }

    pub async fn open_handle_with_config(
        &self,
        target: std::net::SocketAddr,
        mark: u32,
        runtime_config: ResidentDnsUdpRuntimeConfig,
    ) -> Result<ResidentDnsUdpMultiplexHandle, String> {
        let metrics = Arc::clone(&self.metrics);
        self.spawn_actor(move || async move {
            let socket =
                open_connected_dns_udp_socket(target, mark, runtime_config.socket_buffer_bytes)
                    .await?;
            Ok(start_udp_multiplex_actor(
                target,
                socket,
                &runtime_config,
                metrics,
            ))
        })
        .await
    }

    pub async fn spawn_actor<T, Build, BuildFuture>(&self, build: Build) -> Result<T, String>
    where
        T: Send + 'static,
        Build: FnOnce() -> BuildFuture + Send + 'static,
        BuildFuture: std::future::Future<Output = Result<ResidentDnsUdpActorRegistration<T>, String>>
            + Send
            + 'static,
    {
        if self.closing.load(std::sync::atomic::Ordering::Acquire) {
            return Err("shared DNS UDP actor executor is closing".to_owned());
        }
        let runtime_handle = self.runtime_handle().await?;
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        runtime_handle.spawn(run_dns_udp_actor_build(ready_tx, build));
        let opened = ready_rx
            .await
            .map_err(|_| "shared DNS UDP actor exited before initialization".to_owned())??;
        self.register_actor(opened).await
    }

    pub async fn execute_owned_task<T, Task>(&self, task: Task) -> Result<T, String>
    where
        T: Send + 'static,
        Task: Future<Output = T> + Send + 'static,
    {
        if self.closing.load(std::sync::atomic::Ordering::Acquire) {
            return Err("shared DNS transport task executor is closing".to_owned());
        }
        let runtime_handle = self.runtime_handle().await?;
        if self.closing.load(std::sync::atomic::Ordering::Acquire) {
            return Err("shared DNS transport task executor is closing".to_owned());
        }
        ResidentDnsOwnedTask {
            task: runtime_handle.spawn(task),
        }
        .await
        .map_err(|error| format!("shared DNS transport owner task failed: {error}"))
    }

    async fn pool(&self) -> Result<Arc<ResidentDnsUdpActorPool>, String> {
        let mut pool = self.pool.lock().await;
        if self.closing.load(std::sync::atomic::Ordering::Acquire) {
            return Err("shared DNS UDP actor executor is closing".to_owned());
        }
        if let Some(pool) = pool.as_ref() {
            return Ok(Arc::clone(pool));
        }
        let opened = Arc::new(ResidentDnsUdpActorPool::new(
            self.runtime_config.actor_worker_threads,
            self.runtime_config.worker_stack_bytes,
        )?);
        *pool = Some(Arc::clone(&opened));
        Ok(opened)
    }

    async fn runtime_handle(&self) -> Result<tokio::runtime::Handle, String> {
        if let Some(runtime) = &self.shared_runtime {
            return Ok(runtime.clone());
        }
        self.pool().await?.runtime_handle()
    }

    async fn register_actor<T>(
        &self,
        opened: ResidentDnsUdpActorRegistration<T>,
    ) -> Result<T, String>
    where
        T: Send + 'static,
    {
        let ResidentDnsUdpActorRegistration {
            handle,
            lifecycle,
            completion,
            task,
        } = opened;
        self.reap_finished_actors().await?;
        let mut task = Some(task);
        let closing = {
            let mut actors = self
                .actors
                .lock()
                .map_err(|_| "shared DNS UDP actor registry lock poisoned".to_owned())?;
            if self.closing.load(std::sync::atomic::Ordering::Acquire) {
                true
            } else {
                let Some(task) = task.take() else {
                    return Err("shared DNS UDP actor task is missing".to_owned());
                };
                actors.push(ResidentDnsUdpActorTask {
                    lifecycle: lifecycle.clone(),
                    completion: Arc::clone(&completion),
                    task,
                });
                false
            }
        };
        if closing {
            if let Some(lifecycle) = lifecycle.upgrade() {
                lifecycle.stop();
            }
            if let Some(task) = task {
                let _ = task.await;
                completion.finish();
            }
            return Err("shared DNS UDP actor executor closed during initialization".to_owned());
        }
        Ok(handle)
    }

    async fn reap_finished_actors(&self) -> Result<(), String> {
        let mut finished = {
            let mut actors = self
                .actors
                .lock()
                .map_err(|_| "shared DNS UDP actor registry lock poisoned".to_owned())?;
            let mut finished = Vec::new();
            let mut active = Vec::with_capacity(actors.len());
            for actor in std::mem::take(&mut *actors) {
                if actor.task.is_finished() {
                    finished.push(actor);
                } else {
                    active.push(actor);
                }
            }
            *actors = active;
            finished
        };
        if finished.is_empty() {
            return Ok(());
        }
        let deadline =
            tokio::time::Instant::now() + dae_resident_core::RESIDENT_RUNTIME_TASK_JOIN_GRACE;
        let (_, panicked, timed_out) = join_dns_udp_actor_tasks(&mut finished, deadline).await;
        if panicked == 0 && timed_out == 0 {
            Ok(())
        } else {
            Err(format!(
                "reap completed shared DNS UDP actors: panicked={panicked} timedOut={timed_out}"
            ))
        }
    }

    pub async fn join_actor_task(
        &self,
        task_id: tokio::task::Id,
        completion: Arc<super::ResidentDnsUdpActorCompletion>,
        deadline: tokio::time::Instant,
    ) -> Result<(), String> {
        let actor = {
            let mut actors = self
                .actors
                .lock()
                .map_err(|_| "shared DNS UDP actor registry lock poisoned".to_owned())?;
            actors
                .iter()
                .position(|actor| actor.task.id() == task_id)
                .map(|index| actors.swap_remove(index))
        };
        let Some(actor) = actor else {
            return if completion.wait(deadline).await {
                Ok(())
            } else {
                Err("shared DNS UDP actor join completion timeout".to_owned())
            };
        };
        let mut actors = vec![actor];
        let (joined, panicked, timed_out) = join_dns_udp_actor_tasks(&mut actors, deadline).await;
        if joined == 1 && panicked == 0 && timed_out == 0 {
            Ok(())
        } else {
            Err(format!(
                "join shared DNS UDP actor: joined={joined} panicked={panicked} timedOut={timed_out}"
            ))
        }
    }

    pub async fn shutdown(&self, deadline: tokio::time::Instant) -> serde_json::Value {
        self.closing
            .store(true, std::sync::atomic::Ordering::Release);
        let mut actors = match self.actors.lock() {
            Ok(mut registered) => std::mem::take(&mut *registered),
            Err(_) => {
                return serde_json::json!({
                    "status": "fail",
                    "error": "shared DNS UDP actor registry lock poisoned",
                });
            }
        };
        for actor in &actors {
            if let Some(lifecycle) = actor.lifecycle.upgrade() {
                lifecycle.stop();
            }
        }
        let task_count = actors.len();
        let (joined, panicked, timed_out) = join_dns_udp_actor_tasks(&mut actors, deadline).await;
        let tasks_reaped = joined.saturating_add(panicked).saturating_add(timed_out) == task_count;
        let pool = self.pool.lock().await.take();
        let runtime_shutdown = match pool {
            Some(pool) => pool.shutdown(deadline).await,
            None => Ok(()),
        };
        let shutdown_safe = tasks_reaped && panicked == 0 && runtime_shutdown.is_ok();
        let graceful = shutdown_safe && timed_out == 0;
        let completion_mode = if !shutdown_safe {
            "incomplete"
        } else if timed_out != 0 {
            "forced-bounded"
        } else if graceful {
            "graceful"
        } else {
            "completed-degraded"
        };
        serde_json::json!({
            "status": if shutdown_safe { "pass" } else { "fail" },
            "safetyStatus": if shutdown_safe { "pass" } else { "fail" },
            "graceful": graceful,
            "completionMode": completion_mode,
            "generation": self.runtime_config.generation,
            "taskCount": task_count,
            "joined": joined,
            "panicked": panicked,
            "timedOut": timed_out,
            "forced": timed_out,
            "detached": if tasks_reaped { 0 } else { task_count.saturating_sub(joined.saturating_add(panicked).saturating_add(timed_out)) },
            "tasksReaped": tasks_reaped,
            "runtime": match runtime_shutdown {
                Ok(()) => serde_json::json!({"status": "pass"}),
                Err(err) => serde_json::json!({"status": "fail", "error": err}),
            },
        })
    }

    #[cfg(all(test, feature = "dns-runtime-tests"))]
    pub fn for_test_worker_count(worker_count: usize) -> Self {
        let mut runtime_config = ResidentDnsUdpRuntimeConfig::standalone();
        runtime_config.direct_shards = worker_count.max(1);
        runtime_config.actor_worker_threads = worker_count.max(1);
        Self::new(
            runtime_config,
            Arc::new(ResidentDataplaneMetrics::default()),
        )
    }

    #[cfg(all(test, feature = "dns-runtime-tests"))]
    pub async fn pool_worker_count(&self) -> Option<usize> {
        self.pool
            .lock()
            .await
            .as_ref()
            .and_then(|pool| pool.worker_count())
    }

    #[cfg(all(test, feature = "dns-runtime-tests"))]
    pub async fn pool_identity(&self) -> Option<usize> {
        self.pool
            .lock()
            .await
            .as_ref()
            .map(|pool| Arc::as_ptr(pool) as usize)
    }
}

async fn run_dns_udp_actor_build<T, Build, BuildFuture>(
    mut ready: tokio::sync::oneshot::Sender<Result<ResidentDnsUdpActorRegistration<T>, String>>,
    build: Build,
) where
    T: Send + 'static,
    Build: FnOnce() -> BuildFuture + Send + 'static,
    BuildFuture: std::future::Future<Output = Result<ResidentDnsUdpActorRegistration<T>, String>>
        + Send
        + 'static,
{
    if ready.is_closed() {
        return;
    }
    let opened = tokio::select! {
        biased;
        _ = ready.closed() => return,
        opened = build() => opened,
    };
    let _ = ready.send(opened);
}

impl Drop for ResidentDnsUdpActorExecutor {
    fn drop(&mut self) {
        self.closing
            .store(true, std::sync::atomic::Ordering::Release);
        if let Ok(mut actors) = self.actors.lock() {
            for actor in actors.drain(..) {
                if let Some(lifecycle) = actor.lifecycle.upgrade() {
                    lifecycle.stop();
                }
                actor.task.abort();
            }
        }
    }
}

#[cfg(all(test, feature = "dns-runtime-tests"))]
mod tests;
