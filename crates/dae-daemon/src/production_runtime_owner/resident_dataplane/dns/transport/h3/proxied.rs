use super::super::quic::{append_dns_proxy_udp_bridge_error, managed_dns_quic_endpoint_context};
use super::super::wire::resident_dns_quic_client_config;
use super::*;
use crate::production_runtime_owner::resident_dataplane::udp::ResidentProxyUdpBridgeShutdownCompletion;

const PROXIED_DOH3_CLOSE_REASON: &[u8] = b"proxied dns h3 exchange complete";

mod lifecycle;
mod request;
mod resources;

use self::lifecycle::{
    ProxiedDoh3CleanupDeadline, ProxiedDoh3CleanupOutcome, ProxiedDoh3DriverCompletion,
    ProxiedDoh3EndpointCompletion, ProxiedDoh3ExchangeTarget,
};
use self::request::forward_proxied_dns_h3_request;
use self::resources::ProxiedDoh3Resources;

#[cfg(test)]
use self::lifecycle::{
    PROXIED_DOH3_CANCELLED, ProxiedDoh3Cancellation, run_owned_proxied_doh3_exchange,
};

#[cfg(test)]
mod tests;

#[allow(clippy::too_many_arguments)]
pub(super) async fn forward_dns_h3_to_proxy_async(
    upstream: &ResidentDnsUpstream,
    remote: SocketAddr,
    payload: &[u8],
    proxy: Arc<ResidentProxyPlan>,
    metrics: Arc<ResidentDataplaneMetrics>,
    hysteria2_owner_registry: Hysteria2OwnerRegistryHandle,
    tuic_owner_registry: TuicOwnerRegistryHandle,
    context: ProxyDnsRequestContext,
) -> Result<Vec<u8>, ProxyDnsRequestError> {
    lifecycle::run_proxied_doh3_exchange_with_context(
        ProxiedDoh3Exchange::new(
            upstream.clone(),
            remote,
            payload.to_vec(),
            proxy,
            metrics,
            hysteria2_owner_registry,
            tuic_owner_registry,
            context,
        ),
        context,
    )
    .await
}

struct ProxiedDoh3Exchange {
    upstream: ResidentDnsUpstream,
    remote: SocketAddr,
    payload: Vec<u8>,
    proxy: Arc<ResidentProxyPlan>,
    metrics: Arc<ResidentDataplaneMetrics>,
    hysteria2_owner_registry: Hysteria2OwnerRegistryHandle,
    tuic_owner_registry: TuicOwnerRegistryHandle,
    context: ProxyDnsRequestContext,
    resources: ProxiedDoh3Resources,
}

impl ProxiedDoh3Exchange {
    #[allow(clippy::too_many_arguments)]
    fn new(
        upstream: ResidentDnsUpstream,
        remote: SocketAddr,
        payload: Vec<u8>,
        proxy: Arc<ResidentProxyPlan>,
        metrics: Arc<ResidentDataplaneMetrics>,
        hysteria2_owner_registry: Hysteria2OwnerRegistryHandle,
        tuic_owner_registry: TuicOwnerRegistryHandle,
        context: ProxyDnsRequestContext,
    ) -> Self {
        Self {
            upstream,
            remote,
            payload,
            proxy,
            metrics,
            hysteria2_owner_registry,
            tuic_owner_registry,
            context,
            resources: ProxiedDoh3Resources::default(),
        }
    }

    async fn open_bridge(&mut self) -> Result<(), ProxyDnsRequestError> {
        let bridge = self
            .context
            .run(
                ProxyDnsRequestStage::OwnerAcquire,
                ProxyDnsRequestFailure::Network,
                open_resident_proxy_udp_bridge_async(
                    Arc::clone(&self.proxy),
                    self.remote,
                    Some(self.hysteria2_owner_registry.clone()),
                    Some(self.tuic_owner_registry.clone()),
                    Some(dae_runtime_control::AbsoluteDeadline::at(
                        self.context.deadline().into_std(),
                    )),
                ),
            )
            .await?;
        self.resources.bridge = Some(bridge);
        Ok(())
    }

    async fn connect(&mut self) -> Result<(), ProxyDnsRequestError> {
        let bridge_addr = self
            .resources
            .bridge
            .as_ref()
            .ok_or_else(|| {
                ProxyDnsRequestError::new(
                    ProxyDnsRequestStage::OwnerAcquire,
                    ProxyDnsRequestFailure::Protocol,
                    "proxied DoH3 UDP bridge is unavailable",
                )
            })?
            .local_addr();
        self.context.ensure(ProxyDnsRequestStage::OwnerAcquire)?;
        let config = resident_dns_quic_client_config(DNS_DOH3_ALPN).map_err(|error| {
            ProxyDnsRequestError::new(
                ProxyDnsRequestStage::Authenticate,
                ProxyDnsRequestFailure::Protocol,
                error,
            )
        })?;
        let open_context = managed_dns_quic_endpoint_context(
            QuicEndpointProtocol::DnsOverHttp3,
            &self.upstream,
            self.remote,
            &self.proxy,
        );
        let deadline =
            dae_runtime_control::AbsoluteDeadline::at(self.context.deadline().into_std());
        let cancellation = dae_runtime_control::OwnerCancellationSignal::new();
        self.resources.endpoint = Some(
            open_marked_quic_endpoint_for_remote(
                self.proxy.mark,
                bridge_addr,
                open_context,
                deadline,
                &cancellation,
            )
            .map_err(|error| {
                ProxyDnsRequestError::new(
                    ProxyDnsRequestStage::OwnerAcquire,
                    ProxyDnsRequestFailure::Network,
                    error,
                )
            })?,
        );
        let connecting = {
            let endpoint = match self.resources.endpoint.as_mut() {
                Some(endpoint) => endpoint,
                None => {
                    return Err(ProxyDnsRequestError::new(
                        ProxyDnsRequestStage::Connect,
                        ProxyDnsRequestFailure::Protocol,
                        "proxied DoH3 endpoint is unavailable",
                    ));
                }
            };
            endpoint.set_default_client_config(config);
            match endpoint.connect(bridge_addr, &self.upstream.target.host) {
                Ok(connecting) => connecting,
                Err(error) => {
                    endpoint.mark_failed();
                    return Err(ProxyDnsRequestError::new(
                        ProxyDnsRequestStage::Connect,
                        ProxyDnsRequestFailure::Network,
                        format!("connect DoH3 endpoint: {error}"),
                    ));
                }
            }
        };
        let connection = match self
            .context
            .run(
                ProxyDnsRequestStage::Authenticate,
                ProxyDnsRequestFailure::Network,
                connecting,
            )
            .await
        {
            Ok(connection) => connection,
            Err(error) => {
                if let Some(endpoint) = self.resources.endpoint.as_ref() {
                    endpoint.mark_failed();
                }
                return Err(ProxyDnsRequestError::new(
                    error.stage(),
                    error.failure(),
                    format!(
                        "connect DNS H3 upstream {} {}: {error}",
                        self.upstream.tag, self.upstream.target.authority
                    ),
                ));
            }
        };
        self.resources.connection = Some(connection);
        Ok(())
    }

    async fn open_h3_client(&mut self) -> Result<(), ProxyDnsRequestError> {
        let connection = match self.resources.connection.as_ref() {
            Some(connection) => connection.clone(),
            None => {
                if let Some(endpoint) = self.resources.endpoint.as_ref() {
                    endpoint.mark_failed();
                }
                return Err(ProxyDnsRequestError::new(
                    ProxyDnsRequestStage::Authenticate,
                    ProxyDnsRequestFailure::Protocol,
                    "proxied DoH3 connection is unavailable",
                ));
            }
        };
        let h3_connection = h3_quinn::Connection::new(connection);
        let h3_client = self
            .context
            .run(
                ProxyDnsRequestStage::Authenticate,
                ProxyDnsRequestFailure::Network,
                h3::client::new(h3_connection),
            )
            .await;
        let (mut driver, client) = match h3_client {
            Ok(client) => client,
            Err(error) => {
                if let Some(endpoint) = self.resources.endpoint.as_ref() {
                    endpoint.mark_failed();
                }
                return Err(ProxyDnsRequestError::new(
                    error.stage(),
                    error.failure(),
                    format!("create DNS H3 client: {error}"),
                ));
            }
        };
        if let Some(endpoint) = self.resources.endpoint.as_ref() {
            endpoint.mark_ready();
        }
        self.resources.driver_task = Some(tokio::spawn(async move {
            let _ = poll_fn(|cx| driver.poll_close(cx)).await;
        }));
        self.resources.client = Some(client);
        Ok(())
    }

    async fn perform_request(&mut self) -> Result<Vec<u8>, ProxyDnsRequestError> {
        let Self {
            upstream,
            payload,
            context,
            resources,
            ..
        } = self;
        let context = *context;
        let client = resources.client.as_mut().ok_or_else(|| {
            ProxyDnsRequestError::new(
                ProxyDnsRequestStage::Send,
                ProxyDnsRequestFailure::Protocol,
                "proxied DoH3 client is unavailable",
            )
        })?;
        forward_proxied_dns_h3_request(upstream, payload, client, context).await
    }

    fn append_bridge_error(&self, error: ProxyDnsRequestError) -> ProxyDnsRequestError {
        match self.resources.bridge.as_ref() {
            Some(bridge) => ProxyDnsRequestError::new(
                error.stage(),
                error.failure(),
                append_dns_proxy_udp_bridge_error(error.to_string(), bridge),
            ),
            None => error,
        }
    }
}

impl ProxiedDoh3ExchangeTarget for ProxiedDoh3Exchange {
    async fn exchange(&mut self) -> Result<Vec<u8>, ProxyDnsRequestError> {
        let generation = self.proxy.execution_plan().runtime_generation();
        let result = scope_quic_endpoint_observation(
            QuicEndpointCallerClass::ManagedDns,
            Some(generation),
            async {
                self.open_bridge().await?;
                self.connect().await?;
                self.open_h3_client().await?;
                self.perform_request().await
            },
        )
        .await;
        result.map_err(|error| {
            let error = self.append_bridge_error(error);
            ProxyDnsRequestError::new(
                error.stage(),
                error.failure(),
                format!("forward DNS H3 via proxied UDP {}: {error}", self.remote),
            )
        })
    }

    fn discard_client(&mut self) -> bool {
        self.resources.discard_client()
    }

    fn close_connection(&mut self) -> bool {
        self.resources.close_connection()
    }

    async fn close_endpoint_and_wait_idle(
        &mut self,
        deadline: ProxiedDoh3CleanupDeadline,
    ) -> Result<Option<ProxiedDoh3EndpointCompletion>, String> {
        Ok(self.resources.close_endpoint_and_wait_idle(deadline).await)
    }

    async fn finish_driver(
        &mut self,
        deadline: ProxiedDoh3CleanupDeadline,
    ) -> Result<Option<ProxiedDoh3DriverCompletion>, String> {
        self.resources.finish_driver(deadline).await
    }

    async fn shutdown_bridge(
        &mut self,
        deadline: ProxiedDoh3CleanupDeadline,
    ) -> Result<Option<ResidentProxyUdpBridgeShutdownCompletion>, String> {
        self.resources.shutdown_bridge(deadline).await
    }

    fn observe_cleanup(&self, outcome: &ProxiedDoh3CleanupOutcome) {
        outcome.record_metrics(&self.metrics);
    }
}
