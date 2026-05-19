use std::io::{Read, Write};

use crate::error::OutboundError;
use crate::socks5::Socks5Address;

use super::metadata::{TrojanMetadata, TrojanNetwork};
use super::packet::{self, CRLF};

pub const PASSWORD_SHA224_HEX_LEN: usize = 56;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrojanTcpExchangeReport {
    pub proxy: String,
    pub target: String,
    pub password_sha224_hex: String,
    pub command: u8,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub true_dataplane: bool,
    pub default_go_path: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrojanTcpRequest {
    pub password_sha224_hex: String,
    pub command: u8,
    pub metadata: TrojanMetadata,
    pub target: String,
    pub payload: Vec<u8>,
    pub header_len: usize,
}

pub fn tcp_exchange_over_stream<S>(
    stream: &mut S,
    proxy: &str,
    password: &str,
    target: &str,
    payload: &[u8],
) -> Result<TrojanTcpExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let metadata = TrojanMetadata::parse("tcp", target)?;
    let target = metadata.authority();
    let request = packet::tcp_request_header(password, "tcp", &target, payload)?;
    stream
        .write_all(&request)
        .map_err(|err| OutboundError::BadTrojan(err.to_string()))?;

    let mut echoed_payload = vec![0_u8; payload.len()];
    stream
        .read_exact(&mut echoed_payload)
        .map_err(|err| OutboundError::BadTrojan(err.to_string()))?;

    Ok(TrojanTcpExchangeReport {
        proxy: proxy.to_owned(),
        target,
        password_sha224_hex: packet::password_sha224_hex(password),
        command: TrojanNetwork::Tcp.byte(),
        payload_len: payload.len(),
        echoed_payload,
        true_dataplane: true,
        default_go_path: true,
    })
}

pub fn read_tcp_request_from_stream<S>(
    stream: &mut S,
    payload_len: usize,
) -> Result<TrojanTcpRequest, OutboundError>
where
    S: Read,
{
    let mut password = [0_u8; PASSWORD_SHA224_HEX_LEN];
    read_exact(stream, &mut password, "trojan password sha224 hex")?;
    if !password.iter().all(u8::is_ascii_hexdigit) {
        return Err(OutboundError::BadTrojan(
            "trojan password sha224 is not lowercase hex".to_owned(),
        ));
    }
    let password_sha224_hex = String::from_utf8(password.to_vec())
        .map_err(|err| OutboundError::BadTrojan(err.to_string()))?;

    read_crlf(stream, "after trojan password")?;

    let mut command = [0_u8; 1];
    read_exact(stream, &mut command, "trojan command")?;
    if command[0] != TrojanNetwork::Tcp.byte() {
        return Err(OutboundError::BadTrojan(format!(
            "unexpected trojan tcp command: {}",
            command[0]
        )));
    }

    let address_bytes = read_socks5_address_bytes(stream)?;
    let (address, consumed) = Socks5Address::decode(&address_bytes)?;
    if consumed != address_bytes.len() {
        return Err(OutboundError::BadTrojan(format!(
            "trailing trojan target metadata bytes: {}",
            address_bytes.len() - consumed
        )));
    }
    read_crlf(stream, "after trojan target metadata")?;

    let mut payload = vec![0_u8; payload_len];
    read_exact(stream, &mut payload, "trojan tcp payload")?;
    let metadata = TrojanMetadata {
        network: TrojanNetwork::Tcp,
        address,
    };
    let target = metadata.authority();
    Ok(TrojanTcpRequest {
        password_sha224_hex,
        command: command[0],
        metadata,
        target,
        payload,
        header_len: PASSWORD_SHA224_HEX_LEN + CRLF.len() + 1 + address_bytes.len() + CRLF.len(),
    })
}

fn read_crlf(stream: &mut impl Read, context: &str) -> Result<(), OutboundError> {
    let mut crlf = [0_u8; 2];
    read_exact(stream, &mut crlf, context)?;
    if crlf != *CRLF {
        return Err(OutboundError::BadTrojan(format!(
            "bad CRLF {context}: {crlf:02x?}"
        )));
    }
    Ok(())
}

fn read_exact(stream: &mut impl Read, buf: &mut [u8], context: &str) -> Result<(), OutboundError> {
    stream
        .read_exact(buf)
        .map_err(|err| OutboundError::BadTrojan(format!("read {context} failed: {err}")))
}

fn read_socks5_address_bytes(stream: &mut impl Read) -> Result<Vec<u8>, OutboundError> {
    let mut atyp = [0_u8; 1];
    read_exact(stream, &mut atyp, "trojan address type")?;
    let mut out = atyp.to_vec();
    match atyp[0] {
        1 => {
            let mut rest = [0_u8; 6];
            read_exact(stream, &mut rest, "trojan ipv4 address")?;
            out.extend_from_slice(&rest);
        }
        3 => {
            let mut len = [0_u8; 1];
            read_exact(stream, &mut len, "trojan domain length")?;
            out.extend_from_slice(&len);
            let mut rest = vec![0_u8; len[0] as usize + 2];
            read_exact(stream, &mut rest, "trojan domain address")?;
            out.extend_from_slice(&rest);
        }
        4 => {
            let mut rest = [0_u8; 18];
            read_exact(stream, &mut rest, "trojan ipv6 address")?;
            out.extend_from_slice(&rest);
        }
        value => {
            return Err(OutboundError::BadTrojan(format!(
                "bad trojan address type: {value}"
            )));
        }
    }
    Ok(out)
}
