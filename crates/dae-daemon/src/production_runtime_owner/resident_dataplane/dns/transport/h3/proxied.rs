use super::super::quic::append_dns_proxy_udp_bridge_error;
use super::super::wire::resident_dns_quic_client_config;
use super::*;

const PROXIED_DOH3_CLOSE_REASON: &[u8] = b"proxied dns h3 exchange complete";

mod lifecycle;

use self::lifecycle::{ProxiedDoh3ExchangeTarget, finish_or_abort_driver_task};

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
) -> Result<Vec<u8>, String> {
    lifecycle::run_cancelable_proxied_doh3_exchange(ProxiedDoh3Exchange::new(
        upstream.clone(),
        remote,
        payload.to_vec(),
        proxy,
    ))
    .await
}

struct ProxiedDoh3Exchange {
    upstream: ResidentDnsUpstream,
    remote: SocketAddr,
    payload: Vec<u8>,
    proxy: Arc<ResidentProxyPlan>,
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
    ) -> Self {
        Self {
            upstream,
            remote,
            payload,
            proxy,
            bridge: None,
            endpoint: None,
            connection: None,
            client: None,
            driver_task: None,
        }
    }

    async fn open_bridge(&mut self) -> Result<(), String> {
        let bridge =
            open_resident_proxy_udp_bridge_async(Arc::clone(&self.proxy), self.remote).await?;
        self.bridge = Some(bridge);
        Ok(())
    }

    async fn connect(&mut self) -> Result<(), String> {
        let bridge_addr = self
            .bridge
            .as_ref()
            .ok_or_else(|| "proxied DoH3 UDP bridge is unavailable".to_owned())?
            .local_addr();
        self.endpoint = Some(open_marked_quic_endpoint_for_remote(
            self.proxy.mark,
            bridge_addr,
        )?);
        let config = resident_dns_quic_client_config(DNS_DOH3_ALPN)?;
        let connecting = {
            let endpoint = self
                .endpoint
                .as_mut()
                .ok_or_else(|| "proxied DoH3 endpoint is unavailable".to_owned())?;
            endpoint.set_default_client_config(config);
            endpoint
                .connect(bridge_addr, &self.upstream.target.host)
                .map_err(|error| format!("connect DoH3 endpoint: {error}"))?
        };
        let connection = time::timeout(RESIDENT_UDP_RESPONSE_TIMEOUT, connecting)
            .await
            .map_err(|_| "DNS H3 handshake timeout".to_owned())?
            .map_err(|error| {
                format!(
                    "connect DNS H3 upstream {} {}: {error}",
                    self.upstream.tag, self.upstream.target.authority
                )
            })?;
        self.connection = Some(connection);
        Ok(())
    }

    async fn open_h3_client(&mut self) -> Result<(), String> {
        let connection = self
            .connection
            .as_ref()
            .ok_or_else(|| "proxied DoH3 connection is unavailable".to_owned())?
            .clone();
        let h3_connection = h3_quinn::Connection::new(connection);
        let (mut driver, client) = time::timeout(
            RESIDENT_UDP_RESPONSE_TIMEOUT,
            h3::client::new(h3_connection),
        )
        .await
        .map_err(|_| "create proxied DNS H3 client timeout".to_owned())?
        .map_err(|error| format!("create DNS H3 client: {error:?}"))?;
        self.driver_task = Some(tokio::spawn(async move {
            let _ = poll_fn(|cx| driver.poll_close(cx)).await;
        }));
        self.client = Some(client);
        Ok(())
    }

    async fn perform_request(&mut self) -> Result<Vec<u8>, String> {
        let Self {
            upstream,
            payload,
            client,
            ..
        } = self;
        let client = client
            .as_mut()
            .ok_or_else(|| "proxied DoH3 client is unavailable".to_owned())?;
        forward_dns_h3_with_client_async(upstream, payload, client).await
    }

    fn append_bridge_error(&self, error: String) -> String {
        match self.bridge.as_ref() {
            Some(bridge) => append_dns_proxy_udp_bridge_error(error, bridge),
            None => error,
        }
    }
}

impl ProxiedDoh3ExchangeTarget for ProxiedDoh3Exchange {
    async fn exchange(&mut self) -> Result<Vec<u8>, String> {
        let result = async {
            self.open_bridge().await?;
            self.connect().await?;
            self.open_h3_client().await?;
            self.perform_request().await
        }
        .await;
        result
            .map_err(|error| self.append_bridge_error(error))
            .map_err(|error| format!("forward DNS H3 via proxied UDP {}: {error}", self.remote))
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
