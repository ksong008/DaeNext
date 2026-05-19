use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::error::OutboundError;
use crate::shared_transport::ir;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrpcLifecycleOptions {
    pub address: String,
    pub service_name: String,
    pub server_name: String,
    pub dialer_id: String,
    pub allow_insecure: bool,
    pub mark: u32,
    pub mptcp: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrpcCacheReport {
    pub key: String,
    pub reused: bool,
    pub live_entries: usize,
    pub use_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrpcLifecycleReport {
    pub transport: &'static str,
    pub service_name: String,
    pub cache_key: String,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub stream_harness: bool,
    pub full_grpc_http2_stack: bool,
    pub default_go_path: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GrpcLifecycleCache {
    entries: HashMap<String, usize>,
    closed_entries: usize,
}

impl GrpcLifecycleOptions {
    pub fn new(
        address: impl Into<String>,
        service_name: impl Into<String>,
        server_name: impl Into<String>,
        dialer_id: impl Into<String>,
        allow_insecure: bool,
        mark: u32,
        mptcp: bool,
    ) -> Self {
        Self {
            address: address.into(),
            service_name: service_name.into(),
            server_name: server_name.into(),
            dialer_id: dialer_id.into(),
            allow_insecure,
            mark,
            mptcp,
        }
    }

    pub fn cache_key(&self) -> String {
        ir::grpc_cache_key(
            &self.address,
            &self.server_name,
            &self.dialer_id,
            self.allow_insecure,
            self.mark,
            self.mptcp,
        )
    }
}

impl GrpcLifecycleCache {
    pub fn get_or_insert(&mut self, options: &GrpcLifecycleOptions) -> GrpcCacheReport {
        let key = options.cache_key();
        let reused = self.entries.contains_key(&key);
        let use_count = {
            let count = self.entries.entry(key.clone()).or_insert(0);
            *count += 1;
            *count
        };
        GrpcCacheReport {
            key,
            reused,
            live_entries: self.entries.len(),
            use_count,
        }
    }

    pub fn clean(&mut self) -> usize {
        let closed = self.entries.len();
        self.entries.clear();
        self.closed_entries += closed;
        closed
    }

    pub fn closed_entries(&self) -> usize {
        self.closed_entries
    }
}

pub fn grpc_stream_preface(service_name: &str) -> Vec<u8> {
    let service_name = if service_name.is_empty() {
        "GunService"
    } else {
        service_name
    };
    format!(
        "POST /{service_name}/Tun HTTP/2\r\ncontent-type: application/grpc\r\nte: trailers\r\n\r\n"
    )
    .into_bytes()
}

pub fn grpc_hunk_frame(payload: &[u8]) -> Result<Vec<u8>, OutboundError> {
    if payload.len() > u32::MAX as usize {
        return Err(OutboundError::BadSharedTransport(
            "grpc hunk too large".to_owned(),
        ));
    }
    let mut frame = Vec::with_capacity(payload.len() + 5);
    frame.push(0);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

pub fn read_grpc_hunk_frame(stream: &mut impl Read) -> Result<Vec<u8>, OutboundError> {
    let mut head = [0_u8; 5];
    stream
        .read_exact(&mut head)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    if head[0] != 0 {
        return Err(OutboundError::BadSharedTransport(
            "compressed grpc hunk unsupported in stage21 harness".to_owned(),
        ));
    }
    let len = u32::from_be_bytes([head[1], head[2], head[3], head[4]]) as usize;
    let mut payload = vec![0_u8; len];
    stream
        .read_exact(&mut payload)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    Ok(payload)
}

pub fn grpc_hunk_exchange(
    endpoint: &str,
    options: &GrpcLifecycleOptions,
    payload: &[u8],
    timeout: Duration,
) -> Result<GrpcLifecycleReport, OutboundError> {
    let mut stream = TcpStream::connect(endpoint)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    set_timeout(&stream, timeout)?;
    stream
        .write_all(&grpc_stream_preface(&options.service_name))
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    stream
        .write_all(&grpc_hunk_frame(payload)?)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    let echoed_payload = read_grpc_hunk_frame(&mut stream)?;
    Ok(GrpcLifecycleReport {
        transport: "grpc-hunk",
        service_name: if options.service_name.is_empty() {
            "GunService".to_owned()
        } else {
            options.service_name.clone()
        },
        cache_key: options.cache_key(),
        payload_len: payload.len(),
        echoed_payload,
        stream_harness: true,
        full_grpc_http2_stack: false,
        default_go_path: true,
    })
}

fn set_timeout(stream: &TcpStream, timeout: Duration) -> Result<(), OutboundError> {
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))
}
