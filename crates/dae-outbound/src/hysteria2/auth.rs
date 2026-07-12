use std::future::poll_fn;

use bytes::Bytes;
use h3::client;
use http::{Request, StatusCode};

use crate::error::OutboundError;

const URL_HOST: &str = "hysteria";
const URL_PATH: &str = "/auth";
const REQUEST_HEADER_AUTH: &str = "Hysteria-Auth";
const RESPONSE_HEADER_UDP_ENABLED: &str = "Hysteria-UDP";
const COMMON_HEADER_CC_RX: &str = "Hysteria-CC-RX";
const COMMON_HEADER_PADDING: &str = "Hysteria-Padding";
const AUTH_REQUEST_PADDING: &str = "0=256-2048,c,256-2048,c,256-2048,c,256-2048,c,256-2048";
const STATUS_AUTH_OK: u16 = 233;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hysteria2AuthReport {
    pub status: u16,
    pub udp_enabled: bool,
    pub rx: u64,
    pub rx_auto: bool,
    pub auth_ok: bool,
}

pub struct Hysteria2AuthenticatedSession {
    report: Hysteria2AuthReport,
    _h3: Hysteria2H3Client,
}

impl Hysteria2AuthenticatedSession {
    pub fn report(&self) -> &Hysteria2AuthReport {
        &self.report
    }
}

struct Hysteria2H3Client {
    client: client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    driver_task: tokio::task::JoinHandle<()>,
}

impl Drop for Hysteria2H3Client {
    fn drop(&mut self) {
        self.driver_task.abort();
    }
}

pub async fn authenticate_hysteria2_connection(
    connection: quinn::Connection,
    auth: &str,
    rx: u64,
) -> Result<Hysteria2AuthenticatedSession, OutboundError> {
    let h3_connection = h3_quinn::Connection::new(connection);
    let (mut driver, client) = client::new(h3_connection)
        .await
        .map_err(|err| bad_auth(format!("create Hysteria2 h3 client: {err:?}")))?;
    let driver_task = tokio::spawn(async move {
        let _ = poll_fn(|cx| driver.poll_close(cx)).await;
    });
    let mut h3 = Hysteria2H3Client {
        client,
        driver_task,
    };
    let mut request_stream = h3
        .client
        .send_request(
            Request::post(format!("https://{URL_HOST}{URL_PATH}"))
                .header(REQUEST_HEADER_AUTH, auth)
                .header(COMMON_HEADER_CC_RX, rx.to_string())
                .header(COMMON_HEADER_PADDING, AUTH_REQUEST_PADDING)
                .body(())
                .map_err(|err| bad_auth(format!("build Hysteria2 auth request: {err}")))?,
        )
        .await
        .map_err(|err| bad_auth(format!("send Hysteria2 auth request: {err:?}")))?;
    request_stream
        .finish()
        .await
        .map_err(|err| bad_auth(format!("finish Hysteria2 auth request: {err:?}")))?;
    let response = request_stream
        .recv_response()
        .await
        .map_err(|err| bad_auth(format!("recv Hysteria2 auth response: {err:?}")))?;
    while request_stream
        .recv_data()
        .await
        .map_err(|err| bad_auth(format!("drain Hysteria2 auth response body: {err:?}")))?
        .is_some()
    {}
    let status = response.status();
    let udp_enabled = response
        .headers()
        .get(RESPONSE_HEADER_UDP_ENABLED)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<bool>().ok())
        .unwrap_or(false);
    let rx_header = response
        .headers()
        .get(COMMON_HEADER_CC_RX)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let rx_auto = rx_header == "auto";
    let rx = if rx_auto {
        0
    } else {
        rx_header.parse::<u64>().unwrap_or(0)
    };
    let want_status = StatusCode::from_u16(STATUS_AUTH_OK)
        .map_err(|err| bad_auth(format!("build Hysteria2 auth status: {err}")))?;
    Ok(Hysteria2AuthenticatedSession {
        report: Hysteria2AuthReport {
            status: status.as_u16(),
            udp_enabled,
            rx,
            rx_auto,
            auth_ok: status == want_status,
        },
        _h3: h3,
    })
}

fn bad_auth(message: impl Into<String>) -> OutboundError {
    OutboundError::BadHysteria2(message.into())
}

#[cfg(test)]
mod tests;
