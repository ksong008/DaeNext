use std::future::Future;

use super::*;

pub async fn wait_for_endpoint_idle_until<F>(
    idle: F,
    deadline: ProxiedDoh3CleanupDeadline,
) -> ProxiedDoh3EndpointCompletion
where
    F: Future<Output = ()>,
{
    match time::timeout_at(deadline.instant(), idle).await {
        Ok(()) => ProxiedDoh3EndpointCompletion::Idle,
        Err(_) => ProxiedDoh3EndpointCompletion::ForcedDrop,
    }
}

pub async fn finish_or_abort_driver_task_until(
    mut driver_task: tokio::task::JoinHandle<()>,
    deadline: ProxiedDoh3CleanupDeadline,
) -> Result<ProxiedDoh3DriverCompletion, String> {
    match time::timeout_at(deadline.instant(), &mut driver_task).await {
        Ok(joined) => joined
            .map(|()| ProxiedDoh3DriverCompletion::Finished)
            .map_err(|error| format!("join proxied DoH3 driver task: {error}")),
        Err(_) => {
            driver_task.abort();
            match driver_task.await {
                Ok(()) => Ok(ProxiedDoh3DriverCompletion::Finished),
                Err(error) if error.is_cancelled() => Ok(ProxiedDoh3DriverCompletion::Aborted),
                Err(error) => Err(format!("abort and join proxied DoH3 driver task: {error}")),
            }
        }
    }
}
