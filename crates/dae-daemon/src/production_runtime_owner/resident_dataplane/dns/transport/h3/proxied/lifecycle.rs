use std::future::Future;

use super::*;
use crate::production_runtime_owner::resident_dataplane::RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE;
use crate::production_runtime_owner::resident_dataplane::dns::{
    ProxyDnsRequestContext, ProxyDnsRequestError, ProxyDnsRequestFailure, ProxyDnsRequestStage,
};

pub(super) const PROXIED_DOH3_CANCELLED: &str = "proxied DNS over HTTP/3 request cancelled";

pub(super) struct ProxiedDoh3Cancellation {
    sender: Option<tokio::sync::oneshot::Sender<()>>,
}

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

impl Drop for ProxiedDoh3Cancellation {
    fn drop(&mut self) {
        if let Some(sender) = self.sender.take() {
            let _ = sender.send(());
        }
    }
}

pub(super) trait ProxiedDoh3ExchangeTarget: Send {
    fn exchange(&mut self) -> impl Future<Output = Result<Vec<u8>, ProxyDnsRequestError>> + Send;

    fn discard_client(&mut self);

    fn close_connection(&mut self);

    fn close_endpoint_and_wait_idle(&mut self) -> impl Future<Output = Result<(), String>> + Send;

    fn finish_driver(&mut self) -> impl Future<Output = Result<(), String>> + Send;

    fn shutdown_bridge(&mut self) -> impl Future<Output = Result<(), String>> + Send;
}

pub(super) async fn run_cancelable_proxied_doh3_exchange<T>(
    target: T,
) -> Result<Vec<u8>, ProxyDnsRequestError>
where
    T: ProxiedDoh3ExchangeTarget + 'static,
{
    let (cancel, cancelled) = tokio::sync::oneshot::channel();
    let owner_task = tokio::spawn(run_owned_proxied_doh3_exchange(target, cancelled));
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

pub(super) async fn run_proxied_doh3_exchange_with_context<T>(
    target: T,
    context: ProxyDnsRequestContext,
) -> Result<Vec<u8>, ProxyDnsRequestError>
where
    T: ProxiedDoh3ExchangeTarget + 'static,
{
    context
        .run_typed(
            ProxyDnsRequestStage::Read,
            run_cancelable_proxied_doh3_exchange(target),
        )
        .await
}

pub(super) async fn run_owned_proxied_doh3_exchange<T>(
    mut target: T,
    mut cancelled: tokio::sync::oneshot::Receiver<()>,
) -> Result<Vec<u8>, ProxyDnsRequestError>
where
    T: ProxiedDoh3ExchangeTarget,
{
    let exchange = tokio::select! {
        biased;
        _ = &mut cancelled => Err(ProxyDnsRequestError::new(
            ProxyDnsRequestStage::Read,
            ProxyDnsRequestFailure::Cancelled,
            PROXIED_DOH3_CANCELLED,
        )),
        result = target.exchange() => result,
    };
    let cleanup_failures = cleanup_proxied_doh3_exchange(&mut target).await;
    merge_exchange_and_cleanup_result(exchange, cleanup_failures)
}

async fn cleanup_proxied_doh3_exchange<T>(target: &mut T) -> Vec<String>
where
    T: ProxiedDoh3ExchangeTarget,
{
    target.discard_client();
    target.close_connection();

    let mut failures = Vec::new();
    if let Err(error) = target.close_endpoint_and_wait_idle().await {
        failures.push(error);
    }
    if let Err(error) = target.finish_driver().await {
        failures.push(error);
    }
    if let Err(error) = target.shutdown_bridge().await {
        failures.push(error);
    }
    failures
}

fn merge_exchange_and_cleanup_result(
    exchange: Result<Vec<u8>, ProxyDnsRequestError>,
    cleanup_failures: Vec<String>,
) -> Result<Vec<u8>, ProxyDnsRequestError> {
    if cleanup_failures.is_empty() {
        return exchange;
    }

    let cleanup = cleanup_failures.join("; ");
    match exchange {
        Ok(_) => Err(ProxyDnsRequestError::new(
            ProxyDnsRequestStage::Cleanup,
            ProxyDnsRequestFailure::Network,
            format!("proxied DNS over HTTP/3 cleanup failed: {cleanup}"),
        )),
        Err(error) => Err(ProxyDnsRequestError::new(
            ProxyDnsRequestStage::Cleanup,
            ProxyDnsRequestFailure::Network,
            format!("exchange_error={error}; proxied DNS over HTTP/3 cleanup failed: {cleanup}"),
        )),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProxiedDoh3DriverCompletion {
    Finished,
    Aborted,
}

pub(super) async fn finish_or_abort_driver_task(
    driver_task: tokio::task::JoinHandle<()>,
) -> Result<ProxiedDoh3DriverCompletion, String> {
    finish_or_abort_driver_task_with_grace(driver_task, RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE).await
}

pub(super) async fn finish_or_abort_driver_task_with_grace(
    mut driver_task: tokio::task::JoinHandle<()>,
    graceful_close: std::time::Duration,
) -> Result<ProxiedDoh3DriverCompletion, String> {
    tokio::select! {
        joined = &mut driver_task => joined
            .map(|()| ProxiedDoh3DriverCompletion::Finished)
            .map_err(|error| format!("join proxied DoH3 driver task: {error}")),
        _ = time::sleep(graceful_close) => {
            driver_task.abort();
            match driver_task.await {
                Ok(()) => Ok(ProxiedDoh3DriverCompletion::Finished),
                Err(error) if error.is_cancelled() => Ok(ProxiedDoh3DriverCompletion::Aborted),
                Err(error) => Err(format!("abort and join proxied DoH3 driver task: {error}")),
            }
        }
    }
}
