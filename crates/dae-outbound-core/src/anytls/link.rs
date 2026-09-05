use dae_netutil::{MagicNetworkEncoding, encode_magic_network_with_encoding};
use sha2::{Digest, Sha256};
use url::Url;

use crate::error::OutboundError;
use crate::socks5::Socks5Address;

use super::contract;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnyTLSLink {
    pub raw: String,
    pub name: String,
    pub auth: String,
    pub host: String,
    pub hostname: String,
    pub sni: String,
    pub tls_server_name: String,
    pub insecure: bool,
    pub protocol: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnyTLSUnderlayContract {
    pub input_network: String,
    pub input_mark: u32,
    pub input_mptcp: bool,
    pub input_encoded: Vec<u8>,
    pub underlay_network: String,
    pub underlay_mark: u32,
    pub underlay_mptcp: bool,
    pub underlay_encoded: Vec<u8>,
    pub same_encoded_value: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MagicNetwork {
    network: String,
    mark: u32,
    mptcp: bool,
}

impl AnyTLSLink {
    pub fn parse(raw: &str) -> Result<Self, OutboundError> {
        if !raw.starts_with("anytls://") {
            return Err(OutboundError::BadAnyTLS("invalid parameters".to_owned()));
        }
        let url = Url::parse(raw).map_err(|err| OutboundError::BadAnyTLS(err.to_string()))?;
        if url.scheme() != "anytls" {
            return Err(OutboundError::BadAnyTLS(format!(
                "unsupported scheme: {}",
                url.scheme()
            )));
        }
        let query = url.query_pairs().collect::<Vec<_>>();
        let hostname = url.host_str().unwrap_or_default().to_owned();
        let host = format_host_port(&hostname, url.port());
        let sni = query_value(&query, "peer")
            .filter(|value| !value.is_empty())
            .or_else(|| query_value(&query, "sni").filter(|value| !value.is_empty()))
            .unwrap_or_else(|| hostname.clone());
        let tls_server_name = if sni.is_empty() {
            contract::EMPTY_SNI_SERVER_NAME.to_owned()
        } else {
            sni.clone()
        };
        Ok(Self {
            raw: raw.to_owned(),
            name: url.fragment().unwrap_or_default().to_owned(),
            auth: url.username().to_owned(),
            host,
            hostname,
            sni,
            tls_server_name,
            insecure: query_value(&query, "insecure").as_deref() == Some("1"),
            protocol: "anytls".to_owned(),
        })
    }

    pub fn address(&self) -> String {
        self.host.clone()
    }

    pub fn export_url(&self) -> String {
        self.raw.clone()
    }
}

pub fn auth_key(auth: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(auth.as_bytes());
    hasher.finalize().into()
}

pub fn handshake_auth_bytes(auth: &str) -> Vec<u8> {
    let mut out = auth_key(auth).to_vec();
    // anytls-go writes the packet-0 padding length as a big-endian u16.
    // The default padding is 30 bytes, so the wire prefix is 00 1e.
    out.extend_from_slice(&(30_u16).to_be_bytes());
    // anytls-go's default packet-0 padding is the fixed 30-byte range. The
    // server consumes this padding before creating the session; omitting it
    // changes the observable first record from 64 to 34 bytes.
    out.resize(out.len() + 30, 0);
    out
}

pub fn settings_bytes() -> Vec<u8> {
    format!(
        "v=2\nclient=dae\npadding-md5={}",
        contract::DEFAULT_PADDING_MD5
    )
    .into_bytes()
}

pub fn frame(cmd: u8, sid: u32, data: &[u8]) -> Result<Vec<u8>, OutboundError> {
    if data.len() > u16::MAX as usize {
        return Err(OutboundError::BadAnyTLS(format!(
            "anytls frame payload too large: {} bytes",
            data.len()
        )));
    }
    let mut out = vec![0_u8; contract::HEADER_OVERHEAD_SIZE + data.len()];
    out[0] = cmd;
    out[1..5].copy_from_slice(&sid.to_be_bytes());
    out[5..7].copy_from_slice(&(data.len() as u16).to_be_bytes());
    out[7..].copy_from_slice(data);
    Ok(out)
}

pub fn socks_addr(target: &str) -> Result<Vec<u8>, OutboundError> {
    Socks5Address::parse(target)?.encode()
}

pub fn packet_first_write(target: &str, payload: &[u8]) -> Result<Vec<u8>, OutboundError> {
    if payload.len() > u16::MAX as usize {
        return Err(OutboundError::BadAnyTLS(format!(
            "anytls udp payload too large: {} bytes",
            payload.len()
        )));
    }
    let addr = socks_addr(target)?;
    let mut out = Vec::with_capacity(1 + addr.len() + 2 + payload.len());
    out.push(1);
    out.extend_from_slice(&addr);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

pub fn packet_next_write(payload: &[u8]) -> Result<Vec<u8>, OutboundError> {
    if payload.len() > u16::MAX as usize {
        return Err(OutboundError::BadAnyTLS(format!(
            "anytls udp payload too large: {} bytes",
            payload.len()
        )));
    }
    let mut out = Vec::with_capacity(2 + payload.len());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

pub fn udp_stream_target(input: &str) -> Result<String, OutboundError> {
    let addr = Socks5Address::parse(input)?;
    Ok(format!("{}:{}", contract::UDP_MAGIC_DOMAIN, addr.port()))
}

pub fn underlay_contract(
    network: &str,
    mark: u32,
    mptcp: bool,
) -> Result<AnyTLSUnderlayContract, OutboundError> {
    let input = MagicNetwork {
        network: network.to_owned(),
        mark,
        mptcp,
    };
    let input_encoded = input.encode()?;
    let underlay = MagicNetwork {
        network: "tcp".to_owned(),
        mark,
        mptcp,
    };
    let underlay_encoded = underlay.encode()?;
    Ok(AnyTLSUnderlayContract {
        input_network: input.network,
        input_mark: input.mark,
        input_mptcp: input.mptcp,
        same_encoded_value: input_encoded == underlay_encoded,
        input_encoded,
        underlay_network: underlay.network,
        underlay_mark: underlay.mark,
        underlay_mptcp: underlay.mptcp,
        underlay_encoded,
    })
}

fn query_value(
    query: &[(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)],
    key: &str,
) -> Option<String> {
    query
        .iter()
        .find(|(candidate, _)| candidate.as_ref() == key)
        .map(|(_, value)| value.to_string())
}

fn format_host_port(host: &str, port: Option<u16>) -> String {
    match port {
        Some(port) if host.contains(':') && !host.starts_with('[') => format!("[{host}]:{port}"),
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    }
}

impl MagicNetwork {
    fn encode(&self) -> Result<Vec<u8>, OutboundError> {
        encode_magic_network_with_encoding(
            &self.network,
            self.mark,
            self.mptcp,
            MagicNetworkEncoding::Framed,
        )
        .map_err(|error| OutboundError::BadAnyTLS(format!("magic-network: {error}")))
    }
}
