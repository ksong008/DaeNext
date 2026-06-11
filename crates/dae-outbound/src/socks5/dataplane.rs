use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::error::OutboundError;

use super::address::Socks5Address;
use super::handshake::{self, Socks5Command};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Socks5TcpExchangeReport {
    pub proxy: String,
    pub target: String,
    pub method: u8,
    pub bind: String,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub true_dataplane: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Socks5UdpAssociateControlReport {
    pub proxy: String,
    pub target: String,
    pub method: u8,
    pub bind: String,
    pub control_connection_retained: bool,
    pub true_dataplane: bool,
}

pub fn tcp_connect_exchange(
    proxy: &str,
    target: &str,
    username: &str,
    password: &str,
    payload: &[u8],
    timeout: Duration,
) -> Result<Socks5TcpExchangeReport, OutboundError> {
    let mut stream =
        TcpStream::connect(proxy).map_err(|err| OutboundError::BadSocks5Reply(err.to_string()))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|err| OutboundError::BadSocks5Reply(err.to_string()))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|err| OutboundError::BadSocks5Reply(err.to_string()))?;

    tcp_connect_exchange_over_stream(&mut stream, proxy, target, username, password, payload)
}

pub fn tcp_connect_exchange_over_stream<S>(
    stream: &mut S,
    proxy: &str,
    target: &str,
    username: &str,
    password: &str,
    payload: &[u8],
) -> Result<Socks5TcpExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let target = Socks5Address::parse(target)?;
    let method = authenticate(stream, username, password)?;

    let request = handshake::request(Socks5Command::Connect, &target)?;
    stream
        .write_all(&request)
        .map_err(|err| OutboundError::BadSocks5Reply(err.to_string()))?;

    let mut reply_head = [0_u8; 3];
    stream
        .read_exact(&mut reply_head)
        .map_err(|err| OutboundError::BadSocks5Reply(err.to_string()))?;
    let mut reply_bytes = reply_head.to_vec();
    reply_bytes.extend(read_socks5_address_bytes(&mut *stream)?);
    let parsed_reply = handshake::parse_server_reply(&reply_bytes)?;

    stream
        .write_all(payload)
        .map_err(|err| OutboundError::BadSocks5Reply(err.to_string()))?;
    let mut echoed_payload = vec![0_u8; payload.len()];
    stream
        .read_exact(&mut echoed_payload)
        .map_err(|err| OutboundError::BadSocks5Reply(err.to_string()))?;

    Ok(Socks5TcpExchangeReport {
        proxy: proxy.to_owned(),
        target: target.authority(),
        method,
        bind: parsed_reply.bind.authority(),
        payload_len: payload.len(),
        echoed_payload,
        true_dataplane: true,
    })
}

pub fn udp_associate_control_over_stream<S>(
    stream: &mut S,
    proxy: &str,
    target: &str,
    username: &str,
    password: &str,
) -> Result<Socks5UdpAssociateControlReport, OutboundError>
where
    S: Read + Write,
{
    let target = Socks5Address::parse(target)?;
    let method = authenticate(stream, username, password)?;
    let request = handshake::request(Socks5Command::UdpAssociate, &target)?;
    stream
        .write_all(&request)
        .map_err(|err| OutboundError::BadSocks5Reply(err.to_string()))?;

    let mut reply_head = [0_u8; 3];
    stream
        .read_exact(&mut reply_head)
        .map_err(|err| OutboundError::BadSocks5Reply(err.to_string()))?;
    let mut reply_bytes = reply_head.to_vec();
    reply_bytes.extend(read_socks5_address_bytes(&mut *stream)?);
    let parsed_reply = handshake::parse_server_reply(&reply_bytes)?;

    Ok(Socks5UdpAssociateControlReport {
        proxy: proxy.to_owned(),
        target: target.authority(),
        method,
        bind: parsed_reply.bind.authority(),
        control_connection_retained: true,
        true_dataplane: true,
    })
}

fn authenticate<S>(stream: &mut S, username: &str, password: &str) -> Result<u8, OutboundError>
where
    S: Read + Write,
{
    let greeting = handshake::greeting(username, password);
    stream
        .write_all(&greeting)
        .map_err(|err| OutboundError::BadSocks5Reply(err.to_string()))?;

    let mut method_selection = [0_u8; 2];
    stream
        .read_exact(&mut method_selection)
        .map_err(|err| OutboundError::BadSocks5Reply(err.to_string()))?;
    let method = handshake::parse_method_selection(&method_selection)?;

    if method == handshake::AUTH_PASSWORD {
        let auth = handshake::username_password_auth(username, password)?;
        stream
            .write_all(&auth)
            .map_err(|err| OutboundError::BadSocks5Auth(err.to_string()))?;
        let mut auth_reply = [0_u8; 2];
        stream
            .read_exact(&mut auth_reply)
            .map_err(|err| OutboundError::BadSocks5Auth(err.to_string()))?;
        if auth_reply[0] != handshake::PASSWORD_AUTH_VERSION || auth_reply[1] != 0 {
            return Err(OutboundError::BadSocks5Auth(format!(
                "auth rejected: {:02x?}",
                auth_reply
            )));
        }
    }
    Ok(method)
}

fn read_socks5_address_bytes(stream: &mut impl Read) -> Result<Vec<u8>, OutboundError> {
    let mut atyp = [0_u8; 1];
    stream
        .read_exact(&mut atyp)
        .map_err(|err| OutboundError::BadSocks5Reply(err.to_string()))?;
    let mut out = atyp.to_vec();
    match atyp[0] {
        1 => {
            let mut rest = [0_u8; 6];
            stream
                .read_exact(&mut rest)
                .map_err(|err| OutboundError::BadSocks5Reply(err.to_string()))?;
            out.extend_from_slice(&rest);
        }
        3 => {
            let mut len = [0_u8; 1];
            stream
                .read_exact(&mut len)
                .map_err(|err| OutboundError::BadSocks5Reply(err.to_string()))?;
            out.extend_from_slice(&len);
            let mut rest = vec![0_u8; len[0] as usize + 2];
            stream
                .read_exact(&mut rest)
                .map_err(|err| OutboundError::BadSocks5Reply(err.to_string()))?;
            out.extend_from_slice(&rest);
        }
        4 => {
            let mut rest = [0_u8; 18];
            stream
                .read_exact(&mut rest)
                .map_err(|err| OutboundError::BadSocks5Reply(err.to_string()))?;
            out.extend_from_slice(&rest);
        }
        value => {
            return Err(OutboundError::BadSocks5Reply(format!(
                "bad reply address type: {value}"
            )));
        }
    }
    Ok(out)
}
