use super::*;
use crate::udp::ResidentProxyUdpBridgeShutdownCompletion;

use super::lifecycle::{
    ProxiedDoh3CleanupDeadline, ProxiedDoh3DriverCompletion, ProxiedDoh3EndpointCompletion,
    finish_or_abort_driver_task_until, wait_for_endpoint_idle_until,
};

#[derive(Default)]
pub(super) struct ProxiedDoh3Resources {
    pub(super) bridge: Option<ResidentProxyUdpBridge>,
    pub(super) endpoint: Option<ObservedQuicEndpoint>,
    pub(super) connection: Option<quinn::Connection>,
    pub(super) client: Option<h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>>,
    pub(super) driver_task: Option<tokio::task::JoinHandle<()>>,
}

impl ProxiedDoh3Resources {
    pub(super) fn discard_client(&mut self) -> bool {
        self.client.take().is_some()
    }

    pub(super) fn close_connection(&mut self) -> bool {
        if let Some(connection) = self.connection.take() {
            connection.close(0_u32.into(), PROXIED_DOH3_CLOSE_REASON);
            true
        } else {
            false
        }
    }

    pub(super) async fn close_endpoint_and_wait_idle(
        &mut self,
        deadline: ProxiedDoh3CleanupDeadline,
    ) -> Option<ProxiedDoh3EndpointCompletion> {
        let endpoint = self.endpoint.take()?;
        endpoint.close(0_u32.into(), PROXIED_DOH3_CLOSE_REASON);
        let completion = wait_for_endpoint_idle_until(endpoint.wait_idle(), deadline).await;
        drop(endpoint);
        Some(completion)
    }

    pub(super) async fn finish_driver(
        &mut self,
        deadline: ProxiedDoh3CleanupDeadline,
    ) -> Result<Option<ProxiedDoh3DriverCompletion>, String> {
        let Some(driver_task) = self.driver_task.take() else {
            return Ok(None);
        };
        finish_or_abort_driver_task_until(driver_task, deadline)
            .await
            .map(Some)
    }

    pub(super) async fn shutdown_bridge(
        &mut self,
        deadline: ProxiedDoh3CleanupDeadline,
    ) -> Result<Option<ResidentProxyUdpBridgeShutdownCompletion>, String> {
        let Some(bridge) = self.bridge.take() else {
            return Ok(None);
        };
        bridge
            .shutdown_and_join_until(deadline.instant())
            .await
            .map(Some)
    }

    #[cfg(test)]
    pub(super) fn from_parts(
        bridge: ResidentProxyUdpBridge,
        endpoint: ObservedQuicEndpoint,
        connection: quinn::Connection,
        client: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
        driver_task: tokio::task::JoinHandle<()>,
    ) -> Self {
        Self {
            bridge: Some(bridge),
            endpoint: Some(endpoint),
            connection: Some(connection),
            client: Some(client),
            driver_task: Some(driver_task),
        }
    }
}
