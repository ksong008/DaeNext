use super::super::quic::append_dns_proxy_udp_bridge_error;
use super::super::wire::resident_dns_quic_client_config;
use super::*;

const PROXIED_DOH3_CLOSE_REASON: &[u8] = b"proxied dns h3 exchange complete";

mod lifecycle;
mod request;

use self::lifecycle::{ProxiedDoh3ExchangeTarget, finish_or_abort_driver_task};
use self::request::forward_proxied_dns_h3_request;

#[cfg(test)]
use self::lifecycle::{
    PROXIED_DOH3_CANCELLED, ProxiedDoh3Cancellation, ProxiedDoh3DriverCompletion,
    run_owned_proxied_doh3_exchange,
};

#[cfg(test)]
mod tests;

pub(super) async fn forward_dns_h3_to_proxy_async(
    upstream: &ResidentDnsUpstream,
    remote: SocketAddr,
    payload: &[u8],
    proxy: Arc<ResidentProxyPlan>,
    context: ProxyDnsRequestContext,
) -> Result<Vec<u8>, ProxyDnsRequestError> {
    lifecycle::run_proxied_doh3_exchange_with_context(
        ProxiedDoh3Exchange::new(upstream.clone(), remote, payload.to_vec(), proxy, context),
        context,
    )
    .await
}

struct ProxiedDoh3Exchange {
    upstream: ResidentDnsUpstream,
    remote: SocketAddr,
    payload: Vec<u8>,
    proxy: Arc<ResidentProxyPlan>,
    context: ProxyDnsRequestContext,
    bridge: Option<ResidentProxyUdpBridge>,
    endpoint: Option<quinn::Endpoint>,
    connection: Option<quinn::Connection>,
    client: Option<h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>>,
    driver_task: Option<tokio::task::JoinHandle<()>>,
}

impl ProxiedDoh3Exchange {
    fn new(
        upstream: ResidentDnsUpstream,
        remote: SocketAddr,
        payload: Vec<u8>,
        proxy: Arc<ResidentProxyPlan>,
        context: ProxyDnsRequestContext,
    ) -> Self {
        Self {
            upstream,
            remote,
            payload,
            proxy,
            context,
            bridge: None,
            endpoint: None,
            connection: None,
            client: None,
            driver_task: None,
        }
    }

    async fn open_bridge(&mut self) -> Result<(), ProxyDnsRequestError> {
        let bridge = self
            .context
            .run(
                ProxyDnsRequestStage::OwnerAcquire,
                ProxyDnsRequestFailure::Network,
                open_resident_proxy_udp_bridge_async(Arc::clone(&self.proxy), self.remote),
            )
            .await?;
        self.bridge = Some(bridge);
        Ok(())
    }

    async fn connect(&mut self) -> Result<(), ProxyDnsRequestError> {
        let bridge_addr = self
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
        self.endpoint = Some(
            open_marked_quic_endpoint_for_remote(self.proxy.mark, bridge_addr).map_err(
                |error| {
                    ProxyDnsRequestError::new(
                        ProxyDnsRequestStage::OwnerAcquire,
                        ProxyDnsRequestFailure::Network,
                        error,
                    )
                },
            )?,
        );
        let connecting = {
            let endpoint = self.endpoint.as_mut().ok_or_else(|| {
                ProxyDnsRequestError::new(
                    ProxyDnsRequestStage::Connect,
                    ProxyDnsRequestFailure::Protocol,
                    "proxied DoH3 endpoint is unavailable",
                )
            })?;
            endpoint.set_default_client_config(config);
            endpoint
                .connect(bridge_addr, &self.upstream.target.host)
                .map_err(|error| {
                    ProxyDnsRequestError::new(
                        ProxyDnsRequestStage::Connect,
                        ProxyDnsRequestFailure::Network,
                        format!("connect DoH3 endpoint: {error}"),
                    )
                })?
        };
        let connection = self
            .context
            .run(
                ProxyDnsRequestStage::Authenticate,
                ProxyDnsRequestFailure::Network,
                connecting,
            )
            .await
            .map_err(|error| {
                ProxyDnsRequestError::new(
                    error.stage(),
                    error.failure(),
                    format!(
                        "connect DNS H3 upstream {} {}: {error}",
                        self.upstream.tag, self.upstream.target.authority
                    ),
                )
            })?;
        self.connection = Some(connection);
        Ok(())
    }

    async fn open_h3_client(&mut self) -> Result<(), ProxyDnsRequestError> {
        let connection = self
            .connection
            .as_ref()
            .ok_or_else(|| {
                ProxyDnsRequestError::new(
                    ProxyDnsRequestStage::Authenticate,
                    ProxyDnsRequestFailure::Protocol,
                    "proxied DoH3 connection is unavailable",
                )
            })?
            .clone();
        let h3_connection = h3_quinn::Connection::new(connection);
        let (mut driver, client) = self
            .context
            .run(
                ProxyDnsRequestStage::Authenticate,
                ProxyDnsRequestFailure::Network,
                h3::client::new(h3_connection),
            )
            .await
            .map_err(|error| {
                ProxyDnsRequestError::new(
                    error.stage(),
                    error.failure(),
                    format!("create DNS H3 client: {error}"),
                )
            })?;
        self.driver_task = Some(tokio::spawn(async move {
            let _ = poll_fn(|cx| driver.poll_close(cx)).await;
        }));
        self.client = Some(client);
        Ok(())
    }

    async fn perform_request(&mut self) -> Result<Vec<u8>, ProxyDnsRequestError> {
        let Self {
            upstream,
            payload,
            client,
            context,
            ..
        } = self;
        let context = *context;
        let client = client.as_mut().ok_or_else(|| {
            ProxyDnsRequestError::new(
                ProxyDnsRequestStage::Send,
                ProxyDnsRequestFailure::Protocol,
                "proxied DoH3 client is unavailable",
            )
        })?;
        forward_proxied_dns_h3_request(upstream, payload, client, context).await
    }

    fn append_bridge_error(&self, error: ProxyDnsRequestError) -> ProxyDnsRequestError {
        match self.bridge.as_ref() {
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
        let result = async {
            self.open_bridge().await?;
            self.connect().await?;
            self.open_h3_client().await?;
            self.perform_request().await
        }
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

    fn discard_client(&mut self) {
        self.client = None;
    }

    fn close_connection(&mut self) {
        if let Some(connection) = self.connection.take() {
            connection.close(0_u32.into(), PROXIED_DOH3_CLOSE_REASON);
        }
    }

    async fn close_endpoint_and_wait_idle(&mut self) -> Result<(), String> {
        let Some(endpoint) = self.endpoint.take() else {
            return Ok(());
        };
        endpoint.close(0_u32.into(), PROXIED_DOH3_CLOSE_REASON);
        endpoint.wait_idle().await;
        Ok(())
    }

    async fn finish_driver(&mut self) -> Result<(), String> {
        let Some(driver_task) = self.driver_task.take() else {
            return Ok(());
        };
        finish_or_abort_driver_task(driver_task).await.map(|_| ())
    }

    async fn shutdown_bridge(&mut self) -> Result<(), String> {
        if let Some(bridge) = self.bridge.take() {
            bridge.shutdown_and_join().await?;
        }
        Ok(())
    }
}
