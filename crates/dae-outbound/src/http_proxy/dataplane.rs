use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::error::OutboundError;

use super::request::{self, HttpConnectOptions};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpConnectExchangeReport {
    pub proxy: String,
    pub target: String,
    pub status: u16,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub true_dataplane: bool,
}

pub fn connect_exchange(
    proxy: &str,
    options: &HttpConnectOptions,
    payload: &[u8],
    timeout: Duration,
) -> Result<HttpConnectExchangeReport, OutboundError> {
    let mut stream =
        TcpStream::connect(proxy).map_err(|err| OutboundError::BadHttpProxy(err.to_string()))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|err| OutboundError::BadHttpProxy(err.to_string()))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|err| OutboundError::BadHttpProxy(err.to_string()))?;

    connect_exchange_over_stream(&mut stream, proxy, options, payload)
}

pub fn connect_exchange_over_stream<S>(
    stream: &mut S,
    proxy: &str,
    options: &HttpConnectOptions,
    payload: &[u8],
) -> Result<HttpConnectExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let connect_request = request::connect_request(options)?;
    stream
        .write_all(&connect_request)
        .map_err(|err| OutboundError::BadHttpProxy(err.to_string()))?;

    let response = read_http_head(stream)?;
    let status = request::parse_connect_response(&response)?;
    if status != 200 {
        return Err(OutboundError::BadHttpProxy(format!(
            "http proxy status: {status}"
        )));
    }

    stream
        .write_all(payload)
        .map_err(|err| OutboundError::BadHttpProxy(err.to_string()))?;
    let mut echoed_payload = vec![0_u8; payload.len()];
    stream
        .read_exact(&mut echoed_payload)
        .map_err(|err| OutboundError::BadHttpProxy(err.to_string()))?;

    Ok(HttpConnectExchangeReport {
        proxy: proxy.to_owned(),
        target: options.target.clone(),
        status,
        payload_len: payload.len(),
        echoed_payload,
        true_dataplane: true,
    })
}

fn read_http_head(stream: &mut impl Read) -> Result<Vec<u8>, OutboundError> {
    let mut response = Vec::new();
    let mut buf = [0_u8; 512];
    loop {
        let n = stream
            .read(&mut buf)
            .map_err(|err| OutboundError::BadHttpProxy(err.to_string()))?;
        if n == 0 {
            break;
        }
        response.extend_from_slice(&buf[..n]);
        if response.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(response);
        }
        if response.len() > 8192 {
            return Err(OutboundError::BadHttpProxy(
                "response header too large".to_owned(),
            ));
        }
    }
    Err(OutboundError::BadHttpProxy(
        "incomplete response header".to_owned(),
    ))
}
