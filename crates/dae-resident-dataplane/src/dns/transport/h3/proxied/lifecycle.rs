use std::future::Future;

use super::*;
#[cfg(test)]
use crate::dns::{
    ProxyDnsRequestContext, ProxyDnsRequestError, ProxyDnsRequestFailure, ProxyDnsRequestStage,
};
#[cfg(test)]
use crate::udp::ResidentProxyUdpBridgeShutdownCompletion;

#[cfg(test)]
mod cleanup;
mod model;
mod tasks;

pub(super) use self::model::{
    ProxiedDoh3CleanupDeadline, ProxiedDoh3CleanupOutcome, ProxiedDoh3DriverCompletion,
    ProxiedDoh3EndpointCompletion,
};

#[cfg(test)]
pub(super) const PROXIED_DOH3_CANCELLED: &str = "proxied DNS over HTTP/3 request cancelled";

#[cfg(test)]
pub(super) struct ProxiedDoh3Cancellation {
    sender: Option<tokio::sync::oneshot::Sender<()>>,
}

#[cfg(test)]
impl ProxiedDoh3Cancellation {
    pub(super) fn new(sender: tokio::sync::oneshot::Sender<()>) -> Self {
        Self {
            sender: Some(sender),
        }
    }

    pub(super) fn disarm(&mut self) {
        self.sender = None;
    }
}

#[cfg(test)]
impl Drop for ProxiedDoh3Cancellation {
    fn drop(&mut self) {
        if let Some(sender) = self.sender.take() {
            let _ = sender.send(());
        }
    }
}

#[cfg(test)]
pub(super) trait ProxiedDoh3ExchangeTarget: Send {
    fn exchange(&mut self) -> impl Future<Output = Result<Vec<u8>, ProxyDnsRequestError>> + Send;

    fn discard_client(&mut self) -> bool;

    fn close_connection(&mut self) -> bool;

    fn close_endpoint_and_wait_idle(
        &mut self,
        deadline: ProxiedDoh3CleanupDeadline,
    ) -> impl Future<Output = Result<Option<ProxiedDoh3EndpointCompletion>, String>> + Send;

    fn finish_driver(
        &mut self,
        deadline: ProxiedDoh3CleanupDeadline,
    ) -> impl Future<Output = Result<Option<ProxiedDoh3DriverCompletion>, String>> + Send;

    fn shutdown_bridge(
        &mut self,
        deadline: ProxiedDoh3CleanupDeadline,
    ) -> impl Future<Output = Result<Option<ResidentProxyUdpBridgeShutdownCompletion>, String>> + Send;

    fn observe_cleanup(&self, outcome: &ProxiedDoh3CleanupOutcome);
}

#[cfg(test)]
pub(super) async fn run_cancelable_proxied_doh3_exchange<T>(
    target: T,
) -> Result<Vec<u8>, ProxyDnsRequestError>
where
    T: ProxiedDoh3ExchangeTarget + 'static,
{
    run_cancelable_proxied_doh3_exchange_with_context(target, None).await
}

#[cfg(test)]
async fn run_cancelable_proxied_doh3_exchange_with_context<T>(
    target: T,
    context: Option<ProxyDnsRequestContext>,
) -> Result<Vec<u8>, ProxyDnsRequestError>
where
    T: ProxiedDoh3ExchangeTarget + 'static,
{
    let (cancel, cancelled) = tokio::sync::oneshot::channel();
    let owner_task = tokio::spawn(run_owned_proxied_doh3_exchange_with_context(
        target, cancelled, context,
    ));
    let mut cancellation = ProxiedDoh3Cancellation::new(cancel);
    let result = owner_task.await.map_err(|error| {
        ProxyDnsRequestError::new(
            ProxyDnsRequestStage::Cleanup,
            ProxyDnsRequestFailure::Network,
            format!("proxied DNS over HTTP/3 owner task failed: {error}"),
        )
    })?;
    cancellation.disarm();
    result
}

#[cfg(test)]
pub(super) async fn run_proxied_doh3_exchange_with_context<T>(
    target: T,
    context: ProxyDnsRequestContext,
) -> Result<Vec<u8>, ProxyDnsRequestError>
where
    T: ProxiedDoh3ExchangeTarget + 'static,
{
    run_cancelable_proxied_doh3_exchange_with_context(target, Some(context)).await
}

#[cfg(test)]
pub(super) async fn run_owned_proxied_doh3_exchange<T>(
    mut target: T,
    mut cancelled: tokio::sync::oneshot::Receiver<()>,
) -> Result<Vec<u8>, ProxyDnsRequestError>
where
    T: ProxiedDoh3ExchangeTarget,
{
    run_owned_proxied_doh3_exchange_with_outcome(&mut target, &mut cancelled, None)
        .await
        .0
}

#[cfg(test)]
async fn run_owned_proxied_doh3_exchange_with_context<T>(
    mut target: T,
    mut cancelled: tokio::sync::oneshot::Receiver<()>,
    context: Option<ProxyDnsRequestContext>,
) -> Result<Vec<u8>, ProxyDnsRequestError>
where
    T: ProxiedDoh3ExchangeTarget,
{
    run_owned_proxied_doh3_exchange_with_outcome(&mut target, &mut cancelled, context)
        .await
        .0
}

#[cfg(test)]
async fn run_owned_proxied_doh3_exchange_with_outcome<T>(
    target: &mut T,
    cancelled: &mut tokio::sync::oneshot::Receiver<()>,
    context: Option<ProxyDnsRequestContext>,
) -> (
    Result<Vec<u8>, ProxyDnsRequestError>,
    ProxiedDoh3CleanupOutcome,
)
where
    T: ProxiedDoh3ExchangeTarget,
{
    let exchange = tokio::select! {
        biased;
        _ = cancelled => Err(ProxyDnsRequestError::new(
            ProxyDnsRequestStage::Read,
            ProxyDnsRequestFailure::Cancelled,
            PROXIED_DOH3_CANCELLED,
        )),
        result = run_proxied_doh3_exchange_phase(target, context) => result,
    };
    let cleanup = cleanup::cleanup_proxied_doh3_exchange(target).await;
    target.observe_cleanup(&cleanup);
    let result = cleanup::merge_exchange_and_cleanup_result(exchange, &cleanup);
    (result, cleanup)
}

#[cfg(test)]
async fn run_proxied_doh3_exchange_phase<T>(
    target: &mut T,
    context: Option<ProxyDnsRequestContext>,
) -> Result<Vec<u8>, ProxyDnsRequestError>
where
    T: ProxiedDoh3ExchangeTarget,
{
    match context {
        Some(context) => {
            context
                .run_typed(ProxyDnsRequestStage::Read, target.exchange())
                .await
        }
        None => target.exchange().await,
    }
}

pub(super) async fn wait_for_endpoint_idle_until<F>(
    idle: F,
    deadline: ProxiedDoh3CleanupDeadline,
) -> ProxiedDoh3EndpointCompletion
where
    F: Future<Output = ()>,
{
    tasks::wait_for_endpoint_idle_until(idle, deadline).await
}

pub(super) async fn finish_or_abort_driver_task_until(
    driver_task: tokio::task::JoinHandle<()>,
    deadline: ProxiedDoh3CleanupDeadline,
) -> Result<ProxiedDoh3DriverCompletion, String> {
    tasks::finish_or_abort_driver_task_until(driver_task, deadline).await
}

#[cfg(test)]
pub(super) async fn run_owned_proxied_doh3_exchange_observed<T>(
    mut target: T,
    mut cancelled: tokio::sync::oneshot::Receiver<()>,
) -> (
    Result<Vec<u8>, ProxyDnsRequestError>,
    ProxiedDoh3CleanupOutcome,
)
where
    T: ProxiedDoh3ExchangeTarget,
{
    run_owned_proxied_doh3_exchange_with_outcome(&mut target, &mut cancelled, None).await
}
