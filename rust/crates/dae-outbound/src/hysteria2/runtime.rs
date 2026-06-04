use std::future::poll_fn;

use h3::client;
use http::{Request, StatusCode};
use tokio::io::AsyncWriteExt;

use crate::error::OutboundError;

use super::wire::build_tcp_request_stream;

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hysteria2TcpResponseHead {
    pub ok: bool,
    pub message: String,
}

pub async fn authenticate_hysteria2_connection(
    connection: quinn::Connection,
    auth: &str,
    rx: u64,
) -> Result<Hysteria2AuthReport, OutboundError> {
    let h3_connection = h3_quinn::Connection::new(connection);
    let (mut driver, mut client) = client::new(h3_connection)
        .await
        .map_err(|err| bad_runtime(format!("create Hysteria2 h3 client: {err:?}")))?;
    let driver_task = tokio::spawn(async move { poll_fn(|cx| driver.poll_close(cx)).await });
    let mut request_stream = client
        .send_request(
            Request::post(format!("https://{URL_HOST}{URL_PATH}"))
                .header(REQUEST_HEADER_AUTH, auth)
                .header(COMMON_HEADER_CC_RX, rx.to_string())
                .header(COMMON_HEADER_PADDING, AUTH_REQUEST_PADDING)
                .body(())
                .map_err(|err| bad_runtime(format!("build Hysteria2 auth request: {err}")))?,
        )
        .await
        .map_err(|err| bad_runtime(format!("send Hysteria2 auth request: {err:?}")))?;
    request_stream
        .finish()
        .await
        .map_err(|err| bad_runtime(format!("finish Hysteria2 auth request: {err:?}")))?;
    let response = request_stream
        .recv_response()
        .await
        .map_err(|err| bad_runtime(format!("recv Hysteria2 auth response: {err:?}")))?;
    while request_stream
        .recv_data()
        .await
        .map_err(|err| bad_runtime(format!("drain Hysteria2 auth response body: {err:?}")))?
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
    drop(client);
    driver_task.abort();

    let want_status = StatusCode::from_u16(STATUS_AUTH_OK)
        .map_err(|err| bad_runtime(format!("build Hysteria2 auth status: {err}")))?;
    Ok(Hysteria2AuthReport {
        status: status.as_u16(),
        udp_enabled,
        rx,
        rx_auto,
        auth_ok: status == want_status,
    })
}

pub async fn write_hysteria2_tcp_request(
    send: &mut quinn::SendStream,
    target: &str,
) -> Result<(), OutboundError> {
    let request = build_tcp_request_stream(target, &[])?;
    send.write_all(&request)
        .await
        .map_err(|err| bad_runtime(format!("write Hysteria2 TCP request: {err}")))?;
    send.flush()
        .await
        .map_err(|err| bad_runtime(format!("flush Hysteria2 TCP request: {err}")))
}

pub async fn read_hysteria2_tcp_response(
    recv: &mut quinn::RecvStream,
) -> Result<Hysteria2TcpResponseHead, OutboundError> {
    let status = read_u8(recv, "read Hysteria2 TCP response status").await?;
    let message_len = read_quic_varint(recv, "read Hysteria2 TCP response message length").await?;
    if message_len > 2048 {
        return Err(bad_runtime("invalid Hysteria2 TCP response message length"));
    }
    let mut message = vec![0_u8; message_len as usize];
    recv.read_exact(&mut message)
        .await
        .map_err(|err| bad_runtime(format!("read Hysteria2 TCP response message: {err}")))?;
    let padding_len = read_quic_varint(recv, "read Hysteria2 TCP response padding length").await?;
    if padding_len > 4096 {
        return Err(bad_runtime("invalid Hysteria2 TCP response padding length"));
    }
    if padding_len > 0 {
        let mut padding = vec![0_u8; padding_len as usize];
        recv.read_exact(&mut padding)
            .await
            .map_err(|err| bad_runtime(format!("read Hysteria2 TCP response padding: {err}")))?;
    }
    let message = String::from_utf8(message)
        .map_err(|err| bad_runtime(format!("Hysteria2 TCP response message utf8: {err}")))?;
    Ok(Hysteria2TcpResponseHead {
        ok: status == 0,
        message,
    })
}

async fn read_u8(recv: &mut quinn::RecvStream, label: &str) -> Result<u8, OutboundError> {
    let mut byte = [0_u8; 1];
    recv.read_exact(&mut byte)
        .await
        .map_err(|err| bad_runtime(format!("{label}: {err}")))?;
    Ok(byte[0])
}

async fn read_quic_varint(recv: &mut quinn::RecvStream, label: &str) -> Result<u64, OutboundError> {
    let first = read_u8(recv, label).await?;
    let len = 1_usize << (first >> 6);
    let mut value = u64::from(first & 0x3f);
    if len > 1 {
        let mut rest = vec![0_u8; len - 1];
        recv.read_exact(&mut rest)
            .await
            .map_err(|err| bad_runtime(format!("{label}: {err}")))?;
        for byte in rest {
            value = (value << 8) | u64::from(byte);
        }
    }
    Ok(value)
}

fn bad_runtime(message: impl Into<String>) -> OutboundError {
    OutboundError::BadHysteria2(message.into())
}
